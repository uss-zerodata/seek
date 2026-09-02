"""Content-search support: binary detection and a byte-budgeted content cache."""

from __future__ import annotations

import sys
import threading
from collections import OrderedDict
from pathlib import Path

from seek.config import Config
from seek.engine.format import format_lines

_SNIFF_BYTES = 8192

# A cached line costs its characters *plus* the str object header. Counting only
# `len(line)` undercounts by ~49 bytes per line, so a budget expressed in
# characters can retain several times its nominal size. This is still an
# approximation for non-ASCII text (CPython widens to 2 or 4 bytes per
# character), but it is the right order of magnitude instead of the wrong one.
_STR_OVERHEAD = sys.getsizeof("")


def _measure(lines: list[str]) -> int:
    return sum(len(line) + _STR_OVERHEAD for line in lines)


class ContentCache:
    """Caches decoded file text up to a total byte budget.

    Files that do not fit stay uncached and are re-read from disk on every
    search. Eviction is least-recently-used, and all bookkeeping is O(1) per
    access: an ordered mapping replaces the previous list, whose ``remove`` and
    ``pop(0)`` made cache hits linear in the number of cached files.
    """

    def __init__(
        self,
        budget_bytes: int,
        size_cap: int = 5 * 1024 * 1024,
        config: Config | None = None,
    ) -> None:
        self.budget = budget_bytes
        self.size_cap = size_cap
        self._config = config
        # Live switch for the in-session formatting toggle. Formatted and raw
        # content cannot share an entry, so flipping it clears the cache.
        self.format_content = bool(config and config.format_content)
        # path -> (lines, origin, measured size); oldest-first for LRU eviction.
        self._data: OrderedDict[Path, tuple[list[str], list[int] | None, int]] = (
            OrderedDict()
        )
        self._bytes = 0
        self._binary: set[Path] = set()
        # Paths the size cap cut short, so a reader can say so rather than
        # presenting a partial file as a whole one.
        self._truncated: set[Path] = set()
        # Overlapping (cooperatively cancelled) search threads can call lines()
        # concurrently; serialise the cache bookkeeping.
        self._lock = threading.Lock()

    def _read(self, path: Path) -> tuple[list[str] | None, bool, bool]:
        """Return ``(lines, is_binary, truncated)``. ``(None, False, False)``
        means unreadable.

        Reads the sniff header *first* and stops there if the file is binary, so
        a large binary costs one header read rather than a full one, and never
        reads more than ``size_cap`` bytes of a text file.
        """
        try:
            with path.open("rb") as fh:
                head = fh.read(_SNIFF_BYTES)
                if b"\x00" in head:
                    return None, True, False  # binary: the rest is never read
                if len(head) < _SNIFF_BYTES:
                    raw, truncated = head, False
                else:
                    rest = fh.read(max(0, self.size_cap - len(head)) + 1)
                    raw = head + rest
                    truncated = len(raw) > self.size_cap
                    if truncated:
                        raw = raw[: self.size_cap]
        except OSError:
            return None, False, False
        lines = raw.decode("utf-8", errors="replace").splitlines()
        # The cap can land mid-line; drop that fragment so no half-line is ever
        # reported as a match.
        if truncated and lines and not raw.endswith((b"\n", b"\r")):
            lines.pop()
        return lines, False, truncated

    def lines(self, path: Path) -> list[str] | None:
        """The file's indexed lines, or ``None`` if binary or unreadable."""
        got = self.content(path)
        return None if got is None else got[0]

    def content(self, path: Path) -> tuple[list[str], list[int] | None] | None:
        """Return ``(lines, origin)`` for ``path``, from cache or disk.

        ``origin[i]`` is the 1-based line of the stored file that indexed line
        ``i`` came from, or ``None`` when the file was not reformatted and line
        numbers are exact. ``None`` overall means binary or unreadable.
        """
        with self._lock:
            if path in self._binary:
                return None
            entry = self._data.get(path)
            if entry is not None:
                self._data.move_to_end(path)
                return entry[0], entry[1]

        # Read outside the lock: holding it across disk I/O made every
        # overlapping search thread queue behind one slow file. Two threads
        # racing on the same path simply read it twice, which is idempotent and
        # cheaper than serialising all readers.
        lines, is_binary, was_truncated = self._read(path)

        with self._lock:
            if is_binary:
                self._binary.add(path)
                return None
            if lines is None:
                return None
            if was_truncated:
                self._truncated.add(path)
            else:
                self._truncated.discard(path)
            if self.format_content and self._config is not None:
                lines, origin = format_lines(lines, path, self._config)
            else:
                origin = None
            if path not in self._data:
                size = _measure(lines)
                if size <= self.budget:
                    self._insert(path, lines, origin, size)
            return lines, origin

    def _insert(
        self, path: Path, lines: list[str], origin: list[int] | None, size: int
    ) -> None:
        while self._data and self._bytes + size > self.budget:
            _victim, (_old, _o, old_size) = self._data.popitem(last=False)
            self._bytes -= old_size
        self._data[path] = (lines, origin, size)
        self._bytes += size

    def clear(self) -> None:
        """Drop everything. Used when the formatting toggle flips, since a
        formatted and an unformatted view of a file cannot share an entry."""
        with self._lock:
            self._data.clear()
            self._binary.clear()
            self._truncated.clear()
            self._bytes = 0

    def was_truncated(self, path: Path) -> bool:
        """Did ``size_cap`` cut this file short when it was last read?"""
        with self._lock:
            return path in self._truncated

    @property
    def cached_bytes(self) -> int:
        return self._bytes
