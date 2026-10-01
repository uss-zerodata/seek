"""`seek vulndb update` and `seek vulndb status`, as plain functions over a
config and an output stream, so the CLI is a thin wrapper and tests need no
terminal."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from typing import TextIO

from seek.config import Config
from seek.vulndb import progress as progress_mod
from seek.vulndb import store, update
from seek.vulndb.sources import Urls


def _age(days: float | None) -> str:
    if days is None:
        return "never updated"
    if days < 1:
        return f"{days * 24:.0f} h old"
    return f"{days:.0f} d old"


def status(config: Config, out: TextIO) -> int:
    path = store.resolve(config.vulndb_path)
    s = store.Store(path)
    if s.missing:
        out.write(f"no vulnerability database at {path}\n"
                  "run `seek vulndb update` to build one (downloads public NVD, OSV and "
                  "endoflife.date data)\n")
        return 1
    counts = s.counts()
    out.write(f"{path}\n")
    out.write(f"  {_age(s.age_days())}, stale after {config.vulndb_stale_days} d\n")
    for source, table in (("eol", "eol"), ("cpe", "rel"), ("osv", "osv"), ("nvd", "cve")):
        when = s.meta(f"{source}.updated_at")
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(when))) if when else "never"
        out.write(f"  {source:<4} {counts[table]:>8} records   updated {stamp}\n")
    s.close()
    return 0


def run_update(config: Config, out: TextIO, which: Iterable[str] = update.SOURCES,
               full: bool = False, urls: Urls | None = None,
               cancel: threading.Event | None = None) -> int:
    path = store.resolve(config.vulndb_path)
    which = list(which)
    out.write(f"updating {path}\n")
    if store.Store(path).missing:
        size = sum(update.DOWNLOAD_ESTIMATE_MB.get(s, 0) for s in which)
        out.write(f"  first update: about {size} MB to download, then indexed - "
                  "this takes a while; the bar shows how far it is\n")
    tracker = progress_mod.Tracker(which)
    interactive = hasattr(out, "isatty") and out.isatty()
    width = [0]
    last = [0.0, ""]

    def progress(source: str, done: int, total: int, activity: str) -> None:
        tracker(source, done, total, activity)
        now = time.monotonic()
        if now - last[0] < 0.2 and not (total and done >= total):
            return
        last[0] = now
        line = f"  {tracker.line()}"
        if interactive:
            # One line, redrawn in place; padded so a shorter line erases a longer.
            out.write("\r" + line.ljust(width[0]))
            width[0] = max(width[0], len(line))
        elif line != last[1]:
            out.write(line + "\n")
        last[1] = line
        out.flush()

    def finish_line() -> None:
        if interactive and width[0]:
            out.write("\r" + " " * width[0] + "\r")
            width[0] = 0

    results = update.run(path, progress, cancel, which, full, urls)
    finish_line()
    failed = False
    for r in results:
        if r.error:
            failed = True
            out.write(f"  {r.source}: FAILED - {r.error} (its previous data is kept)\n")
        elif r.skipped:
            out.write(f"  {r.source}: unchanged\n")
        else:
            out.write(f"  {r.source}: {r.records:,} records, {r.bytes / 1e6:.1f} MB\n")
        for note in r.notes:
            out.write(f"  {r.source}: {note}\n")
    out.write(f"done in {tracker.elapsed()}\n")
    return 1 if failed else 0
