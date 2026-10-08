"""Render a depth-limited directory tree, coloured, applying the walk's exclusions.

The heading above this tree states the semantics in effect - hidden files shown,
`.gitignore` honoured or not, noise dirs pruned - so the tree has to apply them.
It used to prune only `noise_dirs`, ignoring `.gitignore` and `exclude_globs`
entirely, and so listed files a search from the same root would never return.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from rich.text import Text
from textual.widgets.option_list import Option

from seek.config import Config
from seek.models import MatchKind, Result
from seek.tui.results import RowList
from seek.walk import Exclusions, _real_key

# Extension -> Rich colour for file names in the tree.
_EXT_COLOR: dict[str, str] = {
    ".py": "green", ".pyi": "green",
    ".rs": "red", ".go": "cyan", ".c": "blue", ".h": "blue", ".cpp": "blue",
    ".js": "yellow", ".mjs": "yellow", ".ts": "blue", ".tsx": "blue", ".jsx": "yellow",
    ".rb": "red", ".java": "red", ".kt": "magenta", ".swift": "red", ".lua": "blue",
    ".sh": "green", ".bash": "green", ".zsh": "green", ".fish": "green",
    ".md": "bright_cyan", ".rst": "cyan", ".txt": "default", ".adoc": "cyan",
    ".toml": "yellow", ".yaml": "yellow", ".yml": "yellow", ".json": "yellow",
    ".ini": "yellow", ".cfg": "yellow", ".conf": "yellow", ".env": "yellow",
    ".html": "bright_red", ".htm": "bright_red", ".css": "magenta", ".scss": "magenta",
    ".png": "magenta", ".jpg": "magenta", ".jpeg": "magenta", ".gif": "magenta",
    ".svg": "magenta", ".webp": "magenta", ".ico": "magenta", ".pdf": "bright_red",
    ".zip": "bright_magenta", ".tar": "bright_magenta", ".gz": "bright_magenta",
    ".xz": "bright_magenta", ".zst": "bright_magenta", ".7z": "bright_magenta",
    ".lock": "bright_black", ".log": "bright_black",
}


# Never sort more than this many entries of one directory: the tree shows at
# most `max_entries` overall, so reading a huge directory in full is wasted.
_SCAN_CAP = 5000


def _file_style(name: str) -> str:
    dot = name.rfind(".")
    if name.startswith(".") and dot == 0:
        return "bright_black"  # dotfile
    ext = name[dot:].lower() if dot > 0 else ""
    return _EXT_COLOR.get(ext, "default")


@dataclass(slots=True)
class TreeRow:
    """One line of the tree. ``path`` is None for a line that names nothing -
    an unreadable directory, the `…` where the entry budget ran out."""

    text: Text
    path: Path | None = None
    rel: str = ""
    is_dir: bool = False


def tree_rows(
    root: Path,
    config: Config,
    *,
    max_depth: int = 3,
    max_entries: int = 400,
) -> tuple[list[TreeRow], bool]:
    """The tree below ``root``, one row per line, and whether it was truncated."""
    exclusions = Exclusions(config)
    theme = config.theme
    dir_style = theme.get("tree_dir", "bold blue")
    branch_style = theme.get("tree_branch", "bright_black")

    rows: list[TreeRow] = []
    state = {"count": 0, "truncated": False}
    # Directories reached through a symlink are followed, as the walk follows
    # them; the same real-path guard stops a cycle.
    visited: set[tuple[int, int] | str] = {_real_key(root)}

    def entries_of(dir_path: Path, rel_prefix: str) -> list[tuple[os.DirEntry, str, bool]] | None:
        try:
            # Bounded before sorting: sorting the raw iterator enumerated a
            # million-entry directory in full to display forty of them.
            scanned = list(islice(os.scandir(dir_path), _SCAN_CAP))
        except OSError:
            return None
        kept: list[tuple[os.DirEntry, str, bool]] = []
        for entry in scanned:
            rel = f"{rel_prefix}/{entry.name}" if rel_prefix else entry.name
            try:
                is_dir = entry.is_dir()
            except OSError:
                continue
            if exclusions.skips(rel, entry.name, is_dir):
                continue
            kept.append((entry, rel, is_dir))
        kept.sort(key=lambda item: (not item[2], item[0].name.lower()))
        return kept

    def walk(dir_path: Path, rel_prefix: str, prefix: str, depth: int) -> None:
        if depth > max_depth or state["truncated"]:
            return
        exclusions.push(dir_path, rel_prefix, depth)
        try:
            kept = entries_of(dir_path, rel_prefix)
            if kept is None:
                line = Text(prefix + "└── ", style=branch_style)
                line.append("<unreadable>", style="red")
                rows.append(TreeRow(line))
                return
            for i, (entry, rel, is_dir) in enumerate(kept):
                if state["count"] >= max_entries:
                    state["truncated"] = True
                    rows.append(TreeRow(Text(prefix + "└── …", style=branch_style)))
                    return
                last = i == len(kept) - 1
                line = Text(prefix + ("└── " if last else "├── "), style=branch_style)
                state["count"] += 1
                if not is_dir:
                    line.append(entry.name, style=_file_style(entry.name))
                    rows.append(TreeRow(line, Path(entry.path), rel, False))
                    continue
                line.append(entry.name + "/", style=dir_style)
                rows.append(TreeRow(line, Path(entry.path), rel, True))
                key = _real_key(Path(entry.path))
                if key in visited:
                    continue  # symlink cycle or hardlinked dir
                visited.add(key)
                walk(Path(entry.path), rel, prefix + ("    " if last else "│   "),
                     depth + 1)
        finally:
            exclusions.pop_to(depth)

    walk(root, "", "", 1)
    return rows, state["truncated"]


def _truncation_note(max_entries: int, max_depth: int) -> str:
    return f"… tree truncated at {max_entries} entries / depth {max_depth}"


def render_tree(
    root: Path,
    config: Config,
    *,
    max_depth: int = 3,
    max_entries: int = 400,
) -> Text:
    rows, truncated = tree_rows(root, config, max_depth=max_depth, max_entries=max_entries)
    out = Text()
    out.append(f"{root.name or root}/\n", style=config.theme.get("tree_dir", "bold blue"))
    for row in rows:
        out.append_text(row.text)
        out.append("\n")
    if truncated:
        out.append(f"\n{_truncation_note(max_entries, max_depth)}\n", style="bright_black")
    return out


class TreeList(RowList):
    """The empty-query tree as a list with a cursor: every entry is a row that
    can be viewed, opened and marked like a search result.

    A row stands for a filename or directory ``Result``, so every action that
    works on the result list works here without knowing which list it is on.
    Top-down, unlike the result list: a tree reads from its root.
    """

    DEFAULT_CSS = """
    TreeList { height: 1fr; border: none; padding: 0; }
    """

    MAX_DEPTH = 3
    MAX_ENTRIES = 400

    def __init__(self, config: Config, **kwargs) -> None:
        super().__init__(config, **kwargs)
        self._rows: list[TreeRow] = []

    def set_root(self, root: Path) -> None:
        rows, truncated = tree_rows(
            root, self._config, max_depth=self.MAX_DEPTH, max_entries=self.MAX_ENTRIES
        )
        if truncated:
            rows.append(TreeRow(Text(
                _truncation_note(self.MAX_ENTRIES, self.MAX_DEPTH), style="bright_black"
            )))
        self._rows = rows
        self.results = [
            None if row.path is None else Result(
                kind=MatchKind.DIRNAME if row.is_dir else MatchKind.FILENAME,
                path=row.path, rel=row.rel, score=0,
            )
            for row in rows
        ]
        self.marked &= {r.identity() for r in self.results if r is not None}
        self.clear_options()
        self.add_options([self._render_at(i) for i in range(len(rows))])
        if rows:
            self.highlighted = 0
            self.scroll_to_highlight()

    def select_path(self, path: Path) -> None:
        """Put the cursor on ``path``'s row, if the tree shows it."""
        for i, row in enumerate(self._rows):
            if row.path == path:
                self.highlighted = i
                self.scroll_to_highlight()
                return

    def ranked(self) -> list[Result]:
        return [r for r in self.results if r is not None]

    def _render_at(self, index: int) -> Option:
        row, result = self._rows[index], self.results[index]
        marked = result is not None and result.identity() in self.marked
        text = Text(no_wrap=True)
        text.append("● " if marked else "  ", style=self._t("selected"))
        text.append_text(row.text)
        # OptionList wraps and ignores `no_wrap`, so the row is cut to the width
        # here, as the result list cuts its own.
        text.truncate(self._budget(), overflow="ellipsis")
        return Option(text)
