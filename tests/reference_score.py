"""Frozen copy of the scorer as it was before the `search-performance` change.

This is the reference implementation `test_score_equivalence` checks the live
scorer against: the optimisations in that change are only allowed to make
scoring *faster*, never to change which lines match, what they score, or which
positions are highlighted.

It reads only a `Term`'s data (`text` / `type` / `negated` / `case_sensitive`)
and reimplements the matching itself, so it stays independent even if
`seek.engine.query` internals are optimised too. Do not "fix" or optimise this
file — its whole value is that it does not change.
"""

from __future__ import annotations

from seek.engine.query import ParsedQuery, Term, TermType

_SCORE_MATCH = 16
_BONUS_BOUNDARY = 8
_BONUS_CAMEL = 7
_BONUS_CONSECUTIVE = 12
_BONUS_FIRST_CHAR = 8
_PENALTY_GAP_START = -3
_PENALTY_GAP_EXTEND = -1
_SEPARATORS = set("/\\._- \t")


def _char_class_boundary(text: str, i: int) -> int:
    if i == 0:
        return _BONUS_BOUNDARY + _BONUS_FIRST_CHAR
    prev = text[i - 1]
    cur = text[i]
    if prev in _SEPARATORS:
        return _BONUS_BOUNDARY
    if prev.islower() and cur.isupper():
        return _BONUS_CAMEL
    if prev.isdigit() != cur.isdigit():
        return _BONUS_CAMEL
    return 0


def _greedy(needle: str, hay: str, *, reverse: bool) -> list[int] | None:
    positions: list[int] = []
    if reverse:
        h = len(hay) - 1
        for c in reversed(needle):
            while h >= 0 and hay[h] != c:
                h -= 1
            if h < 0:
                return None
            positions.append(h)
            h -= 1
        positions.reverse()
    else:
        h = 0
        for c in needle:
            while h < len(hay) and hay[h] != c:
                h += 1
            if h >= len(hay):
                return None
            positions.append(h)
            h += 1
    return positions


def _score_positions(text: str, positions: list[int]) -> int:
    total = 0
    in_gap = False
    for idx, pos in enumerate(positions):
        total += _SCORE_MATCH
        total += _char_class_boundary(text, pos)
        if idx > 0:
            prev = positions[idx - 1]
            if pos == prev + 1:
                total += _BONUS_CONSECUTIVE
                in_gap = False
            else:
                total += _PENALTY_GAP_START if not in_gap else 0
                total += _PENALTY_GAP_EXTEND * (pos - prev - 1)
                in_gap = True
    total -= positions[0] // 4
    return total


def score(term_text: str, text: str, *, case_sensitive: bool = False):
    if not term_text:
        return (0, [])
    hay = text if case_sensitive else text.lower()
    needle = term_text if case_sensitive else term_text.lower()

    best: tuple[int, list[int]] | None = None
    start = hay.find(needle)
    while start != -1:
        positions = list(range(start, start + len(needle)))
        s = _score_positions(text, positions) + _BONUS_CONSECUTIVE * len(needle)
        if best is None or s > best[0]:
            best = (s, positions)
        start = hay.find(needle, start + 1)
    if best is not None:
        return best

    forward = _greedy(needle, hay, reverse=False)
    if forward is None:
        return None
    backward = _greedy(needle, hay, reverse=True)
    candidates = [forward] + ([backward] if backward else [])
    scored = [(_score_positions(text, p), p) for p in candidates]
    return max(scored, key=lambda t: t[0])


def _fuzzy_ok(needle: str, hay: str) -> bool:
    it = iter(hay)
    return all(c in it for c in needle)


def _matches(term: Term, text: str) -> bool:
    """Frozen copy of `Term.matches` - the boolean gate used for negation."""
    if not term.text:
        return not term.negated
    hay = text if term.case_sensitive else text.lower()
    needle = term.text if term.case_sensitive else term.text.lower()
    if term.type is TermType.EXACT:
        hit = needle in hay
    elif term.type is TermType.PREFIX:
        hit = hay.startswith(needle)
    elif term.type is TermType.SUFFIX:
        hit = hay.endswith(needle)
    elif term.type is TermType.EQUAL:
        hit = hay == needle
    else:
        hit = _fuzzy_ok(needle, hay)
    return hit != term.negated


def _term_score(term: Term, text: str):
    if term.type is TermType.PREFIX:
        hay = text if term.case_sensitive else text.lower()
        needle = term.text if term.case_sensitive else term.text.lower()
        if not hay.startswith(needle):
            return None
        pos = list(range(len(needle)))
        return (_score_positions(text, pos) + 20, pos)
    if term.type is TermType.SUFFIX:
        hay = text if term.case_sensitive else text.lower()
        needle = term.text if term.case_sensitive else term.text.lower()
        if not hay.endswith(needle):
            return None
        pos = list(range(len(text) - len(needle), len(text)))
        return (_score_positions(text, pos) + 20, pos)
    if term.type is TermType.EQUAL:
        hay = text if term.case_sensitive else text.lower()
        needle = term.text if term.case_sensitive else term.text.lower()
        if hay != needle:
            return None
        return (_score_positions(text, list(range(len(text)))) + 40, list(range(len(text))))
    return score(term.text, text, case_sensitive=term.case_sensitive)


def match_spans(query: ParsedQuery, text: str):
    if query.is_empty:
        return None
    total = 0
    spans: set[int] = set()
    for term in query.terms:
        if term.negated:
            if not _matches(term, text):
                return None
            continue
        res = _term_score(term, text)
        if res is None:
            return None
        s, positions = res
        total += s
        spans.update(positions)
    return (total, sorted(spans))
