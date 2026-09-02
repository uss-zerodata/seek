"""Streaming filesystem walk.

``walk()`` yields :class:`Candidate` records as it goes so the UI can display
results before the scan finishes. It follows symlinked directories but tracks
visited real paths to break cycles, prunes ``.git`` plus a configurable noise
set, optionally applies ``.gitignore`` rules, and applies the positional path
scope.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from seek.config import Config
from seek.models import Candidate
from seek.scope import Scope

ALWAYS_PRUNE = {".git"}


class _Gitignore:
    """Layered .gitignore/.ignore matcher, lazily built per directory.

    A layer applies to the directory it was read from and everything below it,
    and to nothing else. Both halves of that need the layer's own depth: the
    depth to drop a layer once the walk leaves its subtree, and the base path to
    refuse a layer that is not an ancestor of what is being tested. Deriving the
    depth from the base's slash count instead (as this used to) left a sibling's
    rules on the stack, so a `.gitignore` in one directory hid files in the
    directory walked after it.
    """

    def __init__(self) -> None:
        try:
            import pathspec  # noqa: F401

            self._pathspec = pathspec
        except ModuleNotFoundError:
            self._pathspec = None
        # (depth, dir_rel, spec); dir_rel is "" for the walk root.
        self._stack: list[tuple[int, str, object]] = []

    @property
    def available(self) -> bool:
        return self._pathspec is not None

    def push(self, dir_path: Path, dir_rel: str, depth: int) -> None:
        if self._pathspec is None:
            return
        patterns: list[str] = []
        for name in (".gitignore", ".ignore"):
            f = dir_path / name
            try:
                if f.is_file():
                    patterns.extend(f.read_text(encoding="utf-8").splitlines())
            except OSError:
                continue
        if patterns:
            try:
                spec = self._pathspec.PathSpec.from_lines("gitignore", patterns)
            except (KeyError, ValueError):
                spec = self._pathspec.PathSpec.from_lines("gitwildmatch", patterns)
            self._stack.append((depth, dir_rel, spec))

    def pop_to(self, depth: int) -> None:
        """Drop every layer the walk has left behind - siblings included."""
        while self._stack and self._stack[-1][0] >= depth:
            self._stack.pop()

    def ignored(self, rel: str, is_dir: bool) -> bool:
        if self._pathspec is None:
            return False
        target = rel + "/" if is_dir else rel
        for _depth, base, spec in self._stack:
            if not base:
                sub = target
            elif target.startswith(base + "/"):
                sub = target[len(base) + 1 :]
            else:
                continue  # not below this layer's directory; its rules do not apply
            if spec.match_file(sub):
                return True
        return False


class Exclusions:
    """The prune / ignore / exclude decisions the walk makes, as one object.

    Reusable because more than the walk needs them: the empty-query tree
    advertises these exact semantics in its heading ("hidden files shown ·
    .gitignore honoured · noise dirs pruned"), so it has to apply them. It used
    to prune only `noise_dirs`, and so displayed files a search would never
    return.

    Layered state (the `.gitignore` stack) is pushed on entering a directory and
    dropped with :meth:`pop_to` on leaving it, so callers must walk in
    depth order and report the depth they are at.
    """

    def __init__(self, config: Config) -> None:
        self.prune = set(ALWAYS_PRUNE)
        if config.apply_noise_excludes:
            self.prune |= set(config.noise_dirs)
        self.exclude_globs = list(config.exclude_globs)
        self._gitignore = _Gitignore() if config.honor_gitignore else None

    def push(self, dir_path: Path, dir_rel: str, depth: int) -> None:
        if self._gitignore is not None:
            self._gitignore.push(dir_path, dir_rel, depth)

    def pop_to(self, depth: int) -> None:
        if self._gitignore is not None:
            self._gitignore.pop_to(depth)

    def skips(self, rel: str, name: str, is_dir: bool) -> bool:
        """Should this entry be left out entirely?"""
        if is_dir and name in self.prune:
            return True
        if self._gitignore is not None and self._gitignore.ignored(rel, is_dir):
            return True
        return _excluded_glob(rel, name, self.exclude_globs)


def _real_key(path: Path) -> tuple[int, int] | str:
    try:
        st = path.stat()
        if st.st_ino:
            return (st.st_dev, st.st_ino)
    except OSError:
        pass
    return os.path.realpath(path)


def walk(
    root: Path,
    config: Config,
    scope: Scope,
    *,
    on_error: callable | None = None,
) -> Iterator[Candidate]:
    root = root.resolve()
    exclusions = Exclusions(config)
    visited: set[tuple[int, int] | str] = {_real_key(root)}

    # Explicit stack walk so we can push/pop gitignore layers and detect cycles.
    stack: list[tuple[Path, str, int]] = [(root, "", 0)]
    while stack:
        current, current_rel, depth = stack.pop()
        exclusions.pop_to(depth)
        exclusions.push(current, current_rel, depth)
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            if on_error:
                on_error(current, exc)
            continue
        # Deterministic order: dirs and files sorted by name.
        entries.sort(key=lambda e: e.name)
        for entry in entries:
            name = entry.name
            rel = f"{current_rel}/{name}" if current_rel else name
            try:
                is_dir = entry.is_dir()
                is_symlink = entry.is_symlink()
            except OSError as exc:
                if on_error:
                    on_error(Path(entry.path), exc)
                continue

            if exclusions.skips(rel, name, is_dir):
                continue

            cand = Candidate(
                path=Path(entry.path), is_dir=is_dir, is_symlink=is_symlink, rel=rel
            )
            if scope.accepts(rel, name, is_dir):
                yield cand

            if is_dir:
                key = _real_key(Path(entry.path))
                if key in visited:
                    continue  # symlink cycle or hardlinked dir
                visited.add(key)
                stack.append((Path(entry.path), rel, depth + 1))


def rebase(candidates: Iterable[Candidate], rel_root: str) -> list[Candidate]:
    """Re-express a completed walk as if it had started at ``rel_root``.

    Files are assumed stable for the lifetime of a session, so re-rooting into a
    directory the walk already visited - or popping a breadcrumb back up - can
    filter the scan already in hand instead of hitting the filesystem again.
    ``rel_root`` is relative to the root the candidates were walked from; an
    empty string returns the whole set unchanged. The manual refresh is the
    explicit escape hatch when the tree really has changed underneath.
    """
    if not rel_root:
        return list(candidates)
    prefix = f"{rel_root}/"
    cut = len(prefix)
    return [
        Candidate(
            path=c.path, is_dir=c.is_dir, is_symlink=c.is_symlink, rel=c.rel[cut:]
        )
        for c in candidates
        if c.rel.startswith(prefix)
    ]


def _excluded_glob(rel: str, name: str, globs: Sequence[str]) -> bool:
    from fnmatch import fnmatch

    for g in globs:
        target = rel if "/" in g else name
        if fnmatch(target, g):
            return True
    return False
