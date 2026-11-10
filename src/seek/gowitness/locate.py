"""Finding gowitness captures wherever they are, and the screenshots they name.

A capture used to be read from one place only: `gowitness/` directly under the
directory the viewer was opened on, which is where this app writes one. A
capture run by hand lands wherever gowitness was started - beside the scans, in
a `web/` directory, three levels down in a per-target folder - and was simply
never seen. So the directories given on the command line are walked for
results databases the same way they are walked for nmap XML.

The database stores each screenshot as a bare file name. gowitness writes the
images to `./screenshots/` relative to where it ran by default, so the
database's own `screenshots/` is tried first, then its own directory; failing
both, the file is looked up by name below the database and then below the
directories given - the screenshots may have been moved beside the database,
or the database moved away from them.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

SQLITE_MAGIC = b"SQLite format 3\x00"
DB_SUFFIXES = frozenset({".sqlite3", ".sqlite", ".db"})
IMAGE_SUFFIXES = frozenset({".png", ".jpeg", ".jpg", ".webp"})
SHOTS_DIRNAME = "screenshots"


def is_gowitness_db(path: Path) -> bool:
    """A SQLite file with gowitness's `results` table - and nothing else.

    An engagement directory can hold any number of other SQLite files (a
    browser profile, another tool's state); they are passed over silently
    rather than reported as broken captures. Opened read-only, because a
    capture may still be writing to it.
    """
    try:
        with path.open("rb") as fh:
            if fh.read(len(SQLITE_MAGIC)) != SQLITE_MAGIC:
                return False
    except OSError:
        return False
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error:
        return False
    try:
        columns = {row[1] for row in con.execute("PRAGMA table_info(results)")}
        return "url" in columns
    except sqlite3.Error:
        return False
    finally:
        con.close()


def _walk(root: Path) -> Iterable[Path]:
    """Every file below `root`: dot directories and symlinked ones skipped,
    unreadable ones passed over - the same rules as the scan search."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir():
                    if not entry.is_symlink() and not entry.name.startswith("."):
                        stack.append(entry)
                else:
                    yield entry
            except OSError:
                continue


def find_databases(paths: Iterable[Path]) -> list[Path]:
    """Every gowitness results database at or below `paths`, each once.

    A directory is searched all the way down; a file named directly is taken
    if it is one. Deduplicated by resolved path, so a directory and one of its
    subdirectories do not list a capture twice.
    """
    seen: dict[Path, Path] = {}
    for root in paths:
        root = Path(root)
        found = ([root] if root.is_file() else
                 (p for p in _walk(root) if p.suffix.lower() in DB_SUFFIXES))
        for path in found:
            try:
                key = path.resolve()
            except OSError:
                continue
            if key not in seen and is_gowitness_db(path):
                seen[key] = path
    return sorted(seen.values())


class ShotIndex:
    """Image files by name below some directories, built on first use.

    Shared by every database a run reads, so the directories given are walked
    for images at most once however many captures are found - and not at all
    while every screenshot is where gowitness put it.
    """

    def __init__(self, roots: Iterable[Path] = ()) -> None:
        self.roots = [Path(r) for r in roots]
        self._by_name: dict[str, Path] | None = None

    def get(self, name: str) -> Path | None:
        if self._by_name is None:
            self._by_name = {}
            for root in self.roots:
                if root.is_dir():
                    for path in _walk(root):
                        if path.suffix.lower() in IMAGE_SUFFIXES:
                            self._by_name.setdefault(path.name, path)
        return self._by_name.get(name)


class ShotFinder:
    """Where one database's screenshots actually are.

    Nearest first: the database's own `screenshots/`, its own directory, then
    anywhere below it (its own index - the same URL captured twice writes the
    same file name, and the copy beside *this* database is the right one), and
    only then below the directories given.
    """

    def __init__(self, db: Path, shared: ShotIndex | None = None) -> None:
        self.base = Path(db).parent
        self.local = ShotIndex([self.base])
        self.shared = shared

    def __call__(self, name: str) -> Path | None:
        if not name:
            return None
        # gowitness stores a bare file name; a database is read defensively, so
        # a path in that column (`../x`, `/etc/x`) is cut to its name here.
        given = Path(Path(name).name)
        for candidate in (self.base / SHOTS_DIRNAME / given, self.base / given):
            if candidate.exists():
                return candidate
        found = self.local.get(given.name)
        if found is None and self.shared is not None:
            found = self.shared.get(given.name)
        # Unfound, the conventional place: opening it then says the screenshot
        # is gone and where it was looked for, rather than saying nothing.
        return found or self.base / SHOTS_DIRNAME / given.name
