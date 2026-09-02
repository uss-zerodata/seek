"""Persistent query history, recalled with Alt+Up / Alt+Down."""

from __future__ import annotations

from pathlib import Path

from seek.paths import history_file

_MAX = 500


class History:
    def __init__(self, entries: list[str], path: Path | None) -> None:
        self._entries = entries
        self._path = path
        self._cursor = len(entries)  # points one past the end

    @classmethod
    def load(cls, path: Path | None = None) -> History:
        target = path or history_file()
        try:
            lines = target.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        return cls([line for line in lines if line.strip()], target)

    @property
    def entries(self) -> list[str]:
        return list(self._entries)

    def add(self, query: str) -> None:
        query = query.strip()
        if not query:
            return
        if self._entries and self._entries[-1] == query:
            self._cursor = len(self._entries)
            return
        self._entries.append(query)
        del self._entries[:-_MAX]
        self._cursor = len(self._entries)
        self._persist()

    def prev(self) -> str | None:
        if not self._entries or self._cursor == 0:
            return None
        self._cursor -= 1
        return self._entries[self._cursor]

    def next(self) -> str | None:
        if self._cursor >= len(self._entries) - 1:
            self._cursor = len(self._entries)
            return ""
        self._cursor += 1
        return self._entries[self._cursor]

    def _persist(self) -> None:
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text("\n".join(self._entries) + "\n", encoding="utf-8")
        except OSError:
            pass
