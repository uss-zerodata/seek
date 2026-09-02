"""Core data types shared across the walk, engine, and UI."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class MatchKind(StrEnum):
    FILENAME = "filename"
    DIRNAME = "dirname"
    CONTENT = "content"

    @property
    def marker(self) -> str:
        return {"filename": "f", "dirname": "d", "content": "c"}[self.value]


@dataclass(slots=True)
class Candidate:
    """A path discovered by the walk."""

    path: Path
    is_dir: bool
    is_symlink: bool = False
    rel: str = ""  # path relative to the current search root, POSIX-style
    name: str = ""  # basename of `rel`, precomputed for the matcher

    def __post_init__(self) -> None:
        if not self.name and self.rel:
            self.name = self.rel.rsplit("/", 1)[-1]


@dataclass(slots=True)
class Result:
    """A single ranked match shown as one row in the result list."""

    kind: MatchKind
    path: Path
    rel: str
    score: int
    # matched character positions for highlighting: into `line_text` for CONTENT
    # results, otherwise into `label`.
    spans: list[int] = field(default_factory=list)
    # content matches only:
    line_no: int | None = None       # line in the file as stored (user-facing)
    line_text: str | None = None
    # Position in the *indexed* text, which differs from `line_no` when the file
    # was re-indented for indexing (see engine/format.py). Used to position the
    # preview and detail view, and as the identity key - many formatted lines
    # can share one original line number.
    view_line: int | None = None

    @property
    def label(self) -> str:
        if self.kind is MatchKind.CONTENT and self.line_no is not None:
            return f"{self.rel}:{self.line_no}"
        return self.rel

    def identity(self) -> tuple[str, int | None]:
        """Stable key for multi-select persistence across requery.

        Keyed on `view_line`, not `line_no`: a reformatted minified file maps
        every match to line 1, so `line_no` would collide and marking one match
        would mark its neighbours.
        """
        return (str(self.path), self.view_line or self.line_no)

    def format_output(self, absolute: bool) -> str:
        base = str(self.path) if absolute else self.rel
        if self.kind is MatchKind.CONTENT and self.line_no is not None:
            return f"{base}:{self.line_no}"
        return base


class ResultSetState(StrEnum):
    EMPTY_QUERY = "empty_query"  # show the tree view
    NO_MATCH = "no_match"  # non-empty query, nothing matched
    RESULTS = "results"


@dataclass(slots=True)
class ResultSet:
    state: ResultSetState
    results: list[Result] = field(default_factory=list)
    generation: int = 0
    scanning: bool = False
    total: int = 0  # total matches before the display cap was applied
    partial: bool = False  # a progressive update, more results still coming
