#!/usr/bin/env python3
"""Build `capture.sqlite3` from a real gowitness capture.

The fixture is a real database rather than hand-written SQL, because the point
of the reader's tests is that it survives the schema gowitness actually writes -
including the parts that surprised us: the screenshot column is `filename` (the
JSON called it `file_name`), header keys arrive lowercased, and
`response_reason` is empty over HTTP/2. A fixture built by hand would have had
none of those, and a future gowitness whose layout drifts should show up here as
a test failure rather than as a crash in the field.

Only weight is removed: response bodies and the recorded content of network
logs, which are megabytes and which nothing reads. Every row, column and
relationship is kept, so the reader is still exercised against the real shape.

    uv run python tests/fixtures/gowitness/make_fixture.py <a-real-gowitness.sqlite3>

A capture to build one from:

    docker run --rm -v "$(pwd)":/data -w /data ghcr.io/sensepost/gowitness \\
      scan file -f /data/urls.txt --write-db --log-scan-errors
"""

from __future__ import annotations

import shutil
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).parent
TARGET = HERE / "capture.sqlite3"


def blank(cur: sqlite3.Cursor, table: str, column: str) -> None:
    """Empty one heavy column, if this database has it at all."""
    tables = {r[0] for r in cur.execute(
        "select name from sqlite_master where type='table'")}
    if table not in tables:
        return
    columns = {r[1] for r in cur.execute(f"pragma table_info({table})")}
    if column in columns:
        cur.execute(f"update {table} set {column} = ''")


def main(source: Path) -> None:
    if not source.exists():
        raise SystemExit(f"no such capture database: {source}")
    shutil.copy(source, TARGET)
    con = sqlite3.connect(TARGET)
    cur = con.cursor()
    blank(cur, "results", "html")
    blank(cur, "network_logs", "content")
    con.commit()
    cur.execute("vacuum")
    con.commit()

    counts = []
    for table in ("results", "headers", "technologies", "console_logs",
                  "cookies", "network_logs", "tls", "tls_san_lists"):
        try:
            counts.append(f"{table}={cur.execute(f'select count(*) from {table}').fetchone()[0]}")
        except sqlite3.DatabaseError:
            counts.append(f"{table}=absent")
    con.close()
    print(f"wrote {TARGET.relative_to(HERE.parents[2])} "
          f"({TARGET.stat().st_size // 1024} KiB)")
    print("  " + "  ".join(counts))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(Path(sys.argv[1]))
