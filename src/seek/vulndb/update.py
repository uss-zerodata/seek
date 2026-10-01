"""Building the database: download, parse, and commit - one source at a time.

Each source is ingested in one transaction. An error or a cancel rolls that
source back, and the database stays exactly as it was for it; sources already
committed stay committed. Every request is one of `sources.Urls`' fixed URLs.

Incremental where the source allows:

- NVD: when the last NVD update is under eight days old, only the rolling
  `modified` feed; otherwise each yearly feed whose `.meta` hash changed;
- OSV: a conditional request (`If-None-Match` / `If-Modified-Since`), so an
  unchanged archive is not downloaded again;
- endoflife.date: small, fetched whole.
"""

from __future__ import annotations

import gzip
import io
import json
import sqlite3
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from seek.vulndb import eol, sources, store
from seek.vulndb import progress as progress_mod

# source, done, total, activity - `done`/`total` measure the source's whole job
# (download and index together), so one bar covers it; see `progress.Tracker`.
Progress = Callable[[str, int, int, str], None]
USER_AGENT = "seek-vulndb (+https://github.com/uss-zerodata)"
# Smallest first: endoflife.date is seconds, NVD is minutes. An update that is
# interrupted, cancelled or fails part-way still leaves the quick answers in.
SOURCES = ("eol", "cpe", "osv", "nvd")
# What a first download of each source weighs, measured 2026-10: stated before
# the first update is confirmed, and by the command before it starts.
DOWNLOAD_ESTIMATE_MB = {"eol": 1, "cpe": 85, "osv": 220, "nvd": 400}
FIRST_DOWNLOAD_ESTIMATE_MB = sum(DOWNLOAD_ESTIMATE_MB.values())


class Cancelled(Exception):
    """The user asked the update to stop."""


@dataclass(slots=True)
class Result:
    source: str
    records: int = 0
    bytes: int = 0
    skipped: bool = False          # nothing changed upstream
    error: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Fetcher:
    """HTTP GETs, with a record of every URL requested - the test that no
    request carries session data reads `requested`."""

    user_agent: str = USER_AGENT
    timeout: float = 60.0
    requested: list[str] = field(default_factory=list)
    cancel: threading.Event | None = None

    def open(self, url: str, headers: dict[str, str] | None = None):
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled
        self.requested.append(url)
        request = urllib.request.Request(url, headers={"User-Agent": self.user_agent,
                                                       **(headers or {})})
        return urllib.request.urlopen(request, timeout=self.timeout)  # noqa: S310 - fixed https URLs

    def get(self, url: str, on_chunk: Callable[[int], None] | None = None) -> bytes:
        with self.open(url) as response:
            return self._read(response, on_chunk=on_chunk)

    def _read(self, response, sink=None, on_chunk: Callable[[int], None] | None = None
              ) -> bytes:
        """The body, chunk by chunk - `on_chunk` hears the running byte count, which
        is what a progress bar moves on."""
        chunks = []
        received = 0
        while True:
            if self.cancel is not None and self.cancel.is_set():
                raise Cancelled
            chunk = response.read(1 << 18)
            if not chunk:
                break
            received += len(chunk)
            if sink is not None:
                sink.write(chunk)
            else:
                chunks.append(chunk)
            if on_chunk is not None:
                on_chunk(received)
        return b"".join(chunks)


def _of(done: int, total: int) -> str:
    return (f"{progress_mod.megabytes(done)} of {progress_mod.megabytes(total)}" if total
            else progress_mod.megabytes(done))


def _meta_set(con: sqlite3.Connection, key: str, value: str) -> None:
    con.execute("insert or replace into meta values (?, ?)", (key, value))


def _meta_get(con: sqlite3.Connection, key: str) -> str:
    row = con.execute("select value from meta where key = ?", (key,)).fetchone()
    return row[0] if row and row[0] is not None else ""


class _Tx:
    """One source, one transaction: commit on success, roll back otherwise."""

    def __init__(self, con: sqlite3.Connection) -> None:
        self.con = con

    def __enter__(self) -> sqlite3.Connection:
        self.con.execute("begin immediate")
        return self.con

    def __exit__(self, kind, exc, tb) -> bool:
        self.con.execute("commit" if kind is None else "rollback")
        return False


# --- NVD ------------------------------------------------------------------------


def _store_cve(con: sqlite3.Connection, row: sources.CveRow) -> None:
    con.execute("delete from crit where cve_id = ?", (row.id,))
    con.execute("delete from cve_ref where cve_id = ?", (row.id,))
    if row.rejected:
        con.execute("delete from cve where id = ?", (row.id,))
        return
    con.execute("insert or replace into cve values (?, ?, ?, ?, ?, ?, ?, ?)",
                (row.id, row.published, row.modified, row.summary, row.severity,
                 row.score, row.vector, row.cwe))
    con.executemany("insert into cve_ref values (?, ?)", [(row.id, u) for u in row.refs])
    con.executemany("insert into crit values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(row.id, *c) for c in row.criteria])


def _ingest_feed(con: sqlite3.Connection, data: bytes, cancel,
                 report: Callable[[int, int], None]) -> int:
    """Store one feed's CVEs. `report(read, count)` hears how far into the
    compressed feed the parse is, which is what makes indexing measurable."""
    count = 0
    raw = io.BytesIO(data)
    with gzip.open(raw, "rt", encoding="utf-8") as stream:
        for item in sources.iter_json_array(stream, "vulnerabilities"):
            row = sources.parse_nvd_item(item)
            if row is not None:
                _store_cve(con, row)
                count += 1
            if count % 500 == 0:
                if cancel is not None and cancel.is_set():
                    raise Cancelled
                report(raw.tell(), count)
    report(len(data), count)
    return count


def update_nvd(con, fetch: Fetcher, urls: sources.Urls, progress: Progress,
               full: bool, today: date, now: float) -> Result:
    result = Result("nvd")
    last = _meta_get(con, "nvd.updated_at")
    recent = (not full and last and now - float(last) < sources.NVD_MODIFIED_DAYS * 86400)
    feeds: list[str] = ([sources.NVD_MODIFIED] if recent else
                        [str(y) for y in range(sources.NVD_FIRST_YEAR, today.year + 1)])
    # Every feed's .meta first: which feeds changed, and how big they are, is
    # what gives the step a total - otherwise the bar could only count feeds,
    # and the 2024 feed is a hundred times the 2002 one.
    wanted: list[tuple[str, str, int]] = []
    for i, feed in enumerate(feeds):
        progress("nvd", i, len(feeds), f"checking feed {feed} for changes")
        meta = sources.parse_nvd_meta(fetch.get(urls.nvd_meta(feed)).decode("utf-8",
                                                                            "replace"))
        sha = meta.get("sha256", "")
        if sha and not full and _meta_get(con, f"nvd.sha.{feed}") == sha:
            continue
        size = int(meta.get("gzSize") or 0)
        wanted.append((feed, sha, size))
    known = sum(size for _f, _s, size in wanted)
    total = 2 * known                         # download it, then read it back
    base = 0
    with _Tx(con):
        for feed, sha, size in wanted:
            def downloaded(n: int, feed=feed, size=size, start=base) -> None:
                progress("nvd", start + n, total, f"downloading {feed} · {_of(n, size)}")
            data = fetch.get(urls.nvd_year(feed), downloaded)
            base += len(data)
            result.bytes += len(data)

            def indexed(read: int, count: int, feed=feed, start=base) -> None:
                progress("nvd", start + read, total, f"indexing {feed} · {count:,} CVEs")
            result.records += _ingest_feed(con, data, fetch.cancel, indexed)
            base += len(data)
            if sha:
                _meta_set(con, f"nvd.sha.{feed}", sha)
        progress("nvd", max(total, base), max(total, base), "done")
        result.skipped = result.records == 0
        _meta_set(con, "nvd.updated_at", str(now))
    return result


# --- the CPE dictionary ------------------------------------------------------------


def update_cpe(con, fetch: Fetcher, urls: sources.Urls, progress: Progress,
               full: bool, tmp_dir: Path) -> Result:
    """Every released version NVD knows, per product - the list a version
    family is expanded against. One tar of JSON chunks, streamed; skipped when
    its `.meta` hash is unchanged."""
    import tarfile

    result = Result("cpe")
    meta = sources.parse_nvd_meta(fetch.get(urls.cpe_meta()).decode("utf-8", "replace"))
    sha = meta.get("sha256", "")
    if sha and not full and _meta_get(con, "cpe.sha") == sha:
        result.skipped = True
        return result
    size = int(meta.get("gzSize") or 0)
    with tempfile.TemporaryFile(dir=tmp_dir) as archive:
        with fetch.open(urls.cpe_dictionary()) as response:
            size = size or int(response.headers.get("Content-Length") or 0)
            fetch._read(response, archive, lambda n: progress(
                "cpe", n, 2 * size, f"downloading · {_of(n, size)}"))
        result.bytes = archive.tell()
        size = size or result.bytes
        archive.seek(0)
        with _Tx(con), tarfile.open(fileobj=archive, mode="r:gz") as tar:
            con.execute("delete from rel")
            batch: list[tuple[str, str, str]] = []
            for member in tar:
                if not member.isfile() or not member.name.endswith(".json"):
                    continue
                stream = tar.extractfile(member)
                if stream is None:
                    continue
                text = io.TextIOWrapper(stream, encoding="utf-8")
                for item in sources.iter_json_array(text, "products"):
                    row = sources.parse_cpe_name(item)
                    if row is not None:
                        batch.append(row)
                    if len(batch) >= 20_000:
                        con.executemany("insert into rel values (?, ?, ?)", batch)
                        result.records += len(batch)
                        batch.clear()
                        if fetch.cancel is not None and fetch.cancel.is_set():
                            raise Cancelled
                        # How far into the downloaded archive the tar has read.
                        progress("cpe", size + min(archive.tell(), size), 2 * size,
                                 f"indexing · {result.records:,} releases")
            con.executemany("insert into rel values (?, ?, ?)", batch)
            result.records += len(batch)
            _meta_set(con, "cpe.sha", sha)
            progress("cpe", 2 * size, 2 * size, f"done · {result.records:,} releases")
    return result


# --- OSV ------------------------------------------------------------------------


def update_osv(con, fetch: Fetcher, urls: sources.Urls, progress: Progress,
               full: bool, tmp_dir: Path) -> Result:
    result = Result("osv")
    packages = sorted(set(eol.OSV_PACKAGES.values()))
    headers = {}
    if not full:
        if _meta_get(con, "osv.etag"):
            headers["If-None-Match"] = _meta_get(con, "osv.etag")
        if _meta_get(con, "osv.last_modified"):
            headers["If-Modified-Since"] = _meta_get(con, "osv.last_modified")
    with tempfile.TemporaryFile(dir=tmp_dir) as archive:
        try:
            with fetch.open(urls.osv_npm(), headers) as response:
                etag = response.headers.get("ETag", "")
                modified = response.headers.get("Last-Modified", "")
                size = int(response.headers.get("Content-Length") or 0)
                fetch._read(response, archive, lambda n: progress(
                    "osv", n, 2 * size, f"downloading · {_of(n, size)}"))
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                result.skipped = True
                return result
            raise
        result.bytes = archive.tell()
        size = size or result.bytes
        archive.seek(0)
        with _Tx(con), zipfile.ZipFile(archive) as z:
            con.execute("delete from osv")
            con.execute("delete from osv_range")
            names = z.namelist()
            for i, name in enumerate(names):
                if i % 2000 == 0:
                    if fetch.cancel is not None and fetch.cancel.is_set():
                        raise Cancelled
                    progress("osv", size + size * i // max(1, len(names)), 2 * size,
                             f"indexing · {i:,} of {len(names):,} advisories")
                try:
                    record = json.loads(z.read(name))
                except (ValueError, KeyError):
                    continue
                row = sources.parse_osv(record, packages)
                if row is None:
                    continue
                con.execute("insert or replace into osv values (?, ?, ?, ?, ?, ?, ?)",
                            (row.id, ",".join(row.aliases), row.summary, row.severity,
                             row.score, row.modified, row.url))
                con.executemany("insert into osv_range values (?, ?, ?, ?, ?, ?)",
                                [(row.id, *r) for r in row.ranges])
                result.records += 1
            progress("osv", 2 * size, 2 * size, f"done · {result.records:,} advisories kept")
            _meta_set(con, "osv.etag", etag)
            _meta_set(con, "osv.last_modified", modified)
    return result


# --- endoflife.date ---------------------------------------------------------------


def update_eol(con, fetch: Fetcher, urls: sources.Urls, progress: Progress) -> Result:
    result = Result("eol")
    known = set(json.loads(fetch.get(urls.eol_all())))
    slugs = sorted(set(eol.SLUGS.values()))
    rows: list[tuple[str, ...]] = []
    for i, slug in enumerate(slugs):
        progress("eol", i, len(slugs), f"release data · {slug}")
        if slug not in known:
            result.notes.append(f"endoflife.date does not know '{slug}'")
            continue
        data = fetch.get(urls.eol_product(slug))
        result.bytes += len(data)
        rows += sources.parse_eol(slug, json.loads(data))
    with _Tx(con):
        con.execute("delete from eol")
        con.executemany("insert into eol values (?, ?, ?, ?, ?, ?, ?)", rows)
    result.records = len(rows)
    progress("eol", len(slugs), len(slugs), "done")
    return result


# --- the whole update -------------------------------------------------------------


def run(path: Path, progress: Progress | None = None, cancel: threading.Event | None = None,
        which: Iterable[str] = SOURCES, full: bool = False,
        urls: sources.Urls | None = None, fetcher: Fetcher | None = None,
        today: date | None = None, now: float | None = None) -> list[Result]:
    """Update the database at `path`, source by source. Never raises for a
    source's failure: it is reported on that source's `Result`, and the others
    still run. `Cancelled` stops the whole update, after rolling back."""
    progress = progress or (lambda *_: None)
    urls = urls or sources.Urls()
    fetch = fetcher or Fetcher()
    fetch.cancel = cancel
    today = today or date.today()
    now = now if now is not None else time.time()
    con = store.open_write(path)
    results: list[Result] = []
    try:
        for source in which:
            try:
                if source == "nvd":
                    r = update_nvd(con, fetch, urls, progress, full, today, now)
                elif source == "cpe":
                    r = update_cpe(con, fetch, urls, progress, full, path.parent)
                elif source == "osv":
                    r = update_osv(con, fetch, urls, progress, full, path.parent)
                elif source == "eol":
                    r = update_eol(con, fetch, urls, progress)
                else:
                    raise ValueError(f"unknown source {source!r}")
            except Cancelled:
                results.append(Result(source, error="cancelled"))
                break
            except (OSError, urllib.error.URLError, ValueError, zipfile.BadZipFile,
                    sqlite3.DatabaseError, json.JSONDecodeError) as exc:
                r = Result(source, error=f"{type(exc).__name__}: {exc}")
            results.append(r)
            if not r.error:
                with _Tx(con):
                    _meta_set(con, f"{source}.updated_at", str(now))
                    _meta_set(con, f"{source}.bytes", str(r.bytes))
                    _meta_set(con, "updated_at", str(now))
    finally:
        # Fold the write-ahead log into the file, so the file alone is the whole
        # database - which is what gets copied to an offline machine.
        try:
            con.execute("pragma wal_checkpoint(truncate)")
        except sqlite3.DatabaseError:
            pass
        con.close()
    return results
