"""Positional path-scope patterns: fd-style globs or regexes, smart-case.

A glob with no ``/`` matches a path's basename at any depth; a glob with ``/``
matches the path relative to the search root. With ``regex=True`` each pattern
is a regular expression matched (unanchored / partial) against the relative
path. Matching is smart-case: case-insensitive unless the pattern contains an
uppercase character.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import translate


class ScopeError(ValueError):
    """An invalid regex pattern was supplied."""


@dataclass(slots=True)
class _Pat:
    regex: re.Pattern
    basename_only: bool


@dataclass(slots=True)
class Scope:
    patterns: list[_Pat]

    @property
    def is_unrestricted(self) -> bool:
        return not self.patterns

    def accepts(self, rel: str, name: str, is_dir: bool) -> bool:
        """Is this path in scope? True when it matches any pattern.

        Only decides whether a path is *reported*. Descent is not its business:
        `walk` descends into every directory regardless, so a pattern still
        matches things arbitrarily deep below a directory that does not match it
        itself.
        """
        if not self.patterns:
            return True
        for pat in self.patterns:
            target = name if pat.basename_only else rel
            if pat.regex.search(target):
                return True
        return False


def _smart_flags(pattern: str) -> int:
    return 0 if any(c.isupper() for c in pattern) else re.IGNORECASE


def build_scope(patterns: list[str], *, regex: bool) -> Scope:
    compiled: list[_Pat] = []
    for raw in patterns:
        flags = _smart_flags(raw)
        if regex:
            try:
                rx = re.compile(raw, flags)
            except re.error as exc:
                raise ScopeError(f"invalid regex {raw!r}: {exc}") from exc
            compiled.append(_Pat(rx, basename_only=False))
        else:
            basename_only = "/" not in raw
            rx = re.compile(translate(raw), flags)
            compiled.append(_Pat(rx, basename_only=basename_only))
    return Scope(compiled)
