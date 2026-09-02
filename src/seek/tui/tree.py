"""Render a depth-limited directory tree, coloured, applying the walk's exclusions.

The heading above this tree states the semantics in effect - hidden files shown,
`.gitignore` honoured or not, noise dirs pruned - so the tree has to apply them.
It used to prune only `noise_dirs`, ignoring `.gitignore` and `exclude_globs`
entirely, and so listed files a search from the same root would never return.
"""

from __future__ import annotations

import os
from itertools import islice
from pathlib import Path

from rich.text import Text

from seek.config import Config
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


def render_tree(
    root: Path,
    config: Config,
    *,
    max_depth: int = 3,
    max_entries: int = 400,
) -> Text:
    exclusions = Exclusions(config)
    theme = config.theme
    dir_style = theme.get("tree_dir", "bold blue")
    branch_style = theme.get("tree_branch", "bright_black")

    out = Text()
    out.append(f"{root.name or root}/\n", style=dir_style)
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
                out.append(prefix + "└── ", style=branch_style)
                out.append("<unreadable>\n", style="red")
                return
            for i, (entry, rel, is_dir) in enumerate(kept):
                if state["count"] >= max_entries:
                    state["truncated"] = True
                    out.append(prefix + "└── …\n", style=branch_style)
                    return
                last = i == len(kept) - 1
                out.append(prefix + ("└── " if last else "├── "), style=branch_style)
                state["count"] += 1
                if not is_dir:
                    out.append(entry.name + "\n", style=_file_style(entry.name))
                    continue
                out.append(entry.name + "/\n", style=dir_style)
                key = _real_key(Path(entry.path))
                if key in visited:
                    continue  # symlink cycle or hardlinked dir
                visited.add(key)
                walk(Path(entry.path), rel, prefix + ("    " if last else "│   "),
                     depth + 1)
        finally:
            exclusions.pop_to(depth)

    walk(root, "", "", 1)
    if state["truncated"]:
        out.append(
            f"\n… tree truncated at {max_entries} entries / depth {max_depth}\n",
            style="bright_black",
        )
    return out
