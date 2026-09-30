"""`seek vulndb update` and `seek vulndb status`, as plain functions over a
config and an output stream, so the CLI is a thin wrapper and tests need no
terminal."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from typing import TextIO

from seek.config import Config
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
    for source, table in (("nvd", "cve"), ("osv", "osv"), ("eol", "eol")):
        when = s.meta(f"{source}.updated_at")
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(float(when))) if when else "never"
        out.write(f"  {source:<4} {counts[table]:>8} records   updated {stamp}\n")
    s.close()
    return 0


def run_update(config: Config, out: TextIO, which: Iterable[str] = update.SOURCES,
               full: bool = False, urls: Urls | None = None,
               cancel: threading.Event | None = None) -> int:
    path = store.resolve(config.vulndb_path)
    out.write(f"updating {path}\n")
    last: dict[str, str] = {}

    def progress(source: str, done: int, total: int, unit: str) -> None:
        line = f"  {source}: {done}/{total} {unit}" if total else f"  {source}: {done} {unit}"
        if last.get(source) != line:
            last[source] = line
            out.write(line + "\r")
            out.flush()

    results = update.run(path, progress, cancel, which, full, urls)
    failed = False
    for r in results:
        if r.error:
            failed = True
            out.write(f"\n  {r.source}: FAILED - {r.error} (its previous data is kept)\n")
        elif r.skipped:
            out.write(f"\n  {r.source}: unchanged\n")
        else:
            out.write(f"\n  {r.source}: {r.records} records, {r.bytes / 1e6:.1f} MB\n")
        for note in r.notes:
            out.write(f"  {r.source}: {note}\n")
    return 1 if failed else 0
