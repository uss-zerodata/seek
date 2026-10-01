"""The vulnerability database: one SQLite file of public data.

Written only by `update`, one transaction per source, in WAL mode - so a failed
or cancelled update leaves the previous data exactly as it was, and a session
reading the file meanwhile keeps reading it. Sessions open it read-only, the
same way `gowitness.results` opens a capture database that may still be written.

Nothing from a scan is ever stored here. It holds NVD CVE records (with only the
*vulnerable* CPE criteria - the "running on" platform of a configuration is
dropped at ingest), OSV advisories for the tracked library packages, and
endoflife.date release cycles.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from seek import paths

SCHEMA_VERSION = 1

_SCHEMA = """
create table if not exists meta (key text primary key, value text);
create table if not exists cve (
    id text primary key, published text, modified text, summary text,
    severity text, score real, vector text, cwe text);
create table if not exists cve_ref (cve_id text, url text);
create index if not exists cve_ref_id on cve_ref (cve_id);
create table if not exists crit (
    cve_id text, part text, vendor text, product text, version text, update_ text,
    start_incl text, start_excl text, end_incl text, end_excl text);
create index if not exists crit_vp on crit (vendor, product);
create index if not exists crit_id on crit (cve_id);
create table if not exists osv (
    id text primary key, aliases text, summary text, severity text, score real,
    modified text, url text);
create table if not exists osv_range (
    osv_id text, package text, introduced text, fixed text, last_affected text,
    exact text);
create index if not exists osv_range_pkg on osv_range (package);
create index if not exists osv_range_id on osv_range (osv_id);
create table if not exists rel (vendor text, product text, version text);
create index if not exists rel_vp on rel (vendor, product);
create table if not exists eol (
    slug text, cycle text, released text, eol text, latest text, latest_date text,
    lts text, primary key (slug, cycle));
"""


def default_path() -> Path:
    return paths.state_dir() / "vulndb.sqlite3"


def resolve(configured: str = "") -> Path:
    return Path(configured).expanduser() if configured else default_path()


@dataclass(frozen=True, slots=True)
class Criterion:
    cve_id: str
    part: str
    version: str
    update: str
    start_incl: str
    start_excl: str
    end_incl: str
    end_excl: str


@dataclass(frozen=True, slots=True)
class CveRecord:
    id: str
    summary: str
    severity: str
    score: float | None
    vector: str
    published: str
    url: str


@dataclass(frozen=True, slots=True)
class OsvRange:
    osv_id: str
    introduced: str
    fixed: str
    last_affected: str
    exact: str


@dataclass(frozen=True, slots=True)
class OsvRecord:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    score: float | None
    url: str


@dataclass(frozen=True, slots=True)
class Cycle:
    slug: str
    cycle: str
    released: str
    eol: str           # an ISO date, "true", "false" or ""
    latest: str
    latest_date: str
    lts: str


def open_write(path: Path) -> sqlite3.Connection:
    """For `update` only: creates the file, sets WAL, ensures the schema."""
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, isolation_level=None)
    con.execute("pragma journal_mode=wal")
    con.executescript(_SCHEMA)
    con.execute("insert or replace into meta values ('schema', ?)", (str(SCHEMA_VERSION),))
    return con


class Store:
    """A read-only view of the database. Missing is a state, not an error."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._con: sqlite3.Connection | None = None
        if path.exists():
            try:
                con = sqlite3.connect(f"file:{path}?mode=ro", uri=True,
                                      check_same_thread=False)
                con.execute("select 1 from meta limit 1")
                self._con = con
            except sqlite3.DatabaseError:
                self._con = None

    @property
    def missing(self) -> bool:
        return self._con is None

    def close(self) -> None:
        if self._con is not None:
            self._con.close()
            self._con = None

    def _rows(self, sql: str, args: tuple = ()) -> list[tuple]:
        if self._con is None:
            return []
        try:
            return list(self._con.execute(sql, args))
        except sqlite3.DatabaseError:
            return []

    # --- meta -------------------------------------------------------------------

    def meta(self, key: str) -> str:
        rows = self._rows("select value from meta where key = ?", (key,))
        return rows[0][0] if rows and rows[0][0] is not None else ""

    @property
    def generation(self) -> str:
        """Changes whenever any update commits - what a cached lookup is keyed on."""
        return self.meta("updated_at")

    def updated_at(self) -> float | None:
        value = self.meta("updated_at")
        try:
            return float(value) if value else None
        except ValueError:
            return None

    def age_days(self, now: float | None = None) -> float | None:
        """Days since the last update committed; `None` when there never was one."""
        when = self.updated_at()
        if when is None:
            return None
        return ((now if now is not None else time.time()) - when) / 86400

    def counts(self) -> dict[str, int]:
        return {table: (self._rows(f"select count(*) from {table}") or [(0,)])[0][0]
                for table in ("cve", "osv", "eol", "rel")}

    # --- lookups ----------------------------------------------------------------

    def criteria(self, vendor: str, product: str) -> list[Criterion]:
        return [Criterion(*r) for r in self._rows(
            "select cve_id, part, version, update_, start_incl, start_excl, end_incl,"
            " end_excl from crit where vendor = ? and product = ?", (vendor, product))]

    def product_cve_count(self, vendor: str, product: str) -> int:
        rows = self._rows("select count(distinct cve_id) from crit"
                          " where vendor = ? and product = ?", (vendor, product))
        return rows[0][0] if rows else 0

    def cves(self, ids: list[str]) -> dict[str, CveRecord]:
        out: dict[str, CveRecord] = {}
        for chunk in range(0, len(ids), 500):
            part = ids[chunk:chunk + 500]
            marks = ",".join("?" * len(part))
            for r in self._rows(
                    "select id, summary, severity, score, vector, published from cve"
                    f" where id in ({marks})", tuple(part)):
                out[r[0]] = CveRecord(r[0], r[1] or "", r[2] or "", r[3], r[4] or "",
                                      r[5] or "", f"https://nvd.nist.gov/vuln/detail/{r[0]}")
        return out

    def osv_ranges(self, package: str) -> list[OsvRange]:
        return [OsvRange(*r) for r in self._rows(
            "select osv_id, introduced, fixed, last_affected, exact from osv_range"
            " where package = ?", (package,))]

    def osv(self, ids: list[str]) -> dict[str, OsvRecord]:
        out: dict[str, OsvRecord] = {}
        for chunk in range(0, len(ids), 500):
            part = ids[chunk:chunk + 500]
            marks = ",".join("?" * len(part))
            for r in self._rows(f"select id, aliases, summary, severity, score, url from osv"
                                f" where id in ({marks})", tuple(part)):
                aliases = tuple(a for a in (r[1] or "").split(",") if a)
                out[r[0]] = OsvRecord(r[0], aliases, r[2] or "", r[3] or "", r[4], r[5] or "")
        return out

    def releases(self, vendor: str, product: str) -> list[str]:
        """Every version NVD's CPE dictionary knows for a product - what a
        version family (`3.8`) is expanded into to see how much of it a range
        covers. The CPE `update` field is already joined on (`8.9p1`)."""
        return [r[0] for r in self._rows(
            "select version from rel where vendor = ? and product = ?", (vendor, product))]

    def cycles(self, slug: str) -> list[Cycle]:
        return [Cycle(*r) for r in self._rows(
            "select slug, cycle, released, eol, latest, latest_date, lts from eol"
            " where slug = ?", (slug,))]
