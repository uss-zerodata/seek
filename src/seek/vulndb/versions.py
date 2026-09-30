"""Version order, as release order rather than text order.

`1.10` comes after `1.9`, `8.9p1` after `8.9` and before `8.10`, `1.0rc1`
before `1.0`, `2.4.41` before `2.4.100`. A version is cut into runs of digits and
runs of letters; separators carry no meaning. A letter run is a *qualifier* of
the number before it: a pre-release marker (`rc`, `beta`, …) puts the version
before the bare release, anything else (`p1`, `e`, `ubuntu`) after it.

Some versions cannot be placed at all - `3.X - 4.X`, `2.*`, `5.x`. `compare`
answers `None` for those, and `None` propagates: a range that cannot be decided
is never reported as affecting a version, and never as not affecting it.
"""

from __future__ import annotations

import re
from functools import lru_cache

_SEGMENT = re.compile(r"\d+|[a-z]+")
# A range or a wildcard: nothing about it can be ordered.
_UNDECIDABLE = re.compile(r"\s|(^|[.\-_])(x|\*)($|[.\-_])|\bto\b")
# Pre-release markers, in their own order; all of them precede the release.
_PRE = {"dev": 0, "snapshot": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "pre": 3,
        "preview": 3, "c": 4, "rc": 4, "cr": 4}

Segments = tuple[int | str, ...]


@lru_cache(maxsize=16384)
def segments(version: str) -> Segments | None:
    """The comparable parts of a version, or `None` if it cannot be ordered."""
    v = version.strip().lower().removeprefix("v")
    if not v or v in ("-", "*") or _UNDECIDABLE.search(v):
        return None
    parts = _SEGMENT.findall(v)
    if not parts or not parts[0].isdigit():
        return None
    return tuple(int(p) if p.isdigit() else p for p in parts)


def _tail_sign(rest: Segments) -> int:
    """How a version compares to its own prefix, given what follows: a
    pre-release marker makes it smaller, zeros change nothing, anything else
    makes it larger."""
    for part in rest:
        if isinstance(part, str):
            return -1 if part in _PRE else 1
        if part != 0:
            return 1
    return 0


def _compare_segments(a: Segments, b: Segments) -> int:
    for x, y in zip(a, b, strict=False):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            px, py = _PRE.get(x), _PRE.get(y)
            if px is not None and py is not None:
                return (px > py) - (px < py)
            if px is not None:
                return -1
            if py is not None:
                return 1
            return -1 if x < y else 1
        # A number against a qualifier of the number before it: a pre-release
        # qualifier loses to anything, a post-release one to a further number.
        return 1 if isinstance(x, int) else -1
    if len(a) == len(b):
        return 0
    if len(a) > len(b):
        return _tail_sign(a[len(b):])
    return -_tail_sign(b[len(a):])


def compare(a: str, b: str) -> int | None:
    """-1, 0 or 1 by release order; `None` when either cannot be ordered."""
    sa, sb = segments(a), segments(b)
    if sa is None or sb is None:
        return None
    return _compare_segments(sa, sb)


def in_range(version: str, exact: str = "", start_incl: str = "", start_excl: str = "",
             end_incl: str = "", end_excl: str = "") -> bool | None:
    """Whether `version` is inside the criterion - `None` when that cannot be
    decided. An exact version of `*` with no bounds means every version."""
    if segments(version) is None:
        return None
    if exact and exact not in ("*",):
        if exact == "-":
            return None
        c = compare(version, exact)
        return None if c is None else c == 0
    checks = ((start_incl, lambda c: c >= 0), (start_excl, lambda c: c > 0),
              (end_incl, lambda c: c <= 0), (end_excl, lambda c: c < 0))
    undecided = False
    for bound, ok in checks:
        if not bound:
            continue
        c = compare(version, bound)
        if c is None:
            undecided = True
            continue
        if not ok(c):
            return False
    return None if undecided else True
