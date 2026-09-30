"""fzf-style scoring for a single term and for a whole parsed query.

Public interface (kept stable so the scorer can be swapped):

    score(term_text, text, *, case_sensitive=False) -> (int, list[int]) | None
    match_spans(parsed_query, text) -> (int, list[int]) | None

``score`` returns the match score and the sorted list of matched character
positions in ``text``. ``None`` means no match.
"""

from __future__ import annotations

from seek.engine.query import ParsedQuery, Term, TermType, fuzzy_ok

# Tunable weights (roughly fzf's model).
_SCORE_MATCH = 16
_BONUS_BOUNDARY = 8
_BONUS_CAMEL = 7
_BONUS_CONSECUTIVE = 12
_BONUS_FIRST_CHAR = 8
_PENALTY_GAP_START = -3
_PENALTY_GAP_EXTEND = -1
_SEPARATORS = set("/\\._- \t")


def _char_class_boundary(text: str, i: int) -> int:
    """Bonus for the character at ``i`` starting a new 'word'."""
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
    # `n` is hoisted: `len(hay)` in the inner condition was re-evaluated once per
    # character and dominated the profile (11.7M calls on a 370k-line corpus).
    n = len(hay)
    positions: list[int] = []
    if reverse:
        h = n - 1
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
            while h < n and hay[h] != c:
                h += 1
            if h >= n:
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
    # Prefer earlier overall matches slightly.
    total -= positions[0] // 4
    return total


def score(
    term_text: str, text: str, *, case_sensitive: bool = False
) -> tuple[int, list[int]] | None:
    if not term_text:
        return (0, [])
    hay = text if case_sensitive else text.lower()
    needle = term_text if case_sensitive else term_text.lower()
    return _score(needle, text, hay)


def _score(needle: str, text: str, hay: str) -> tuple[int, list[int]] | None:
    """``needle`` and ``hay`` must already be folded the same way."""
    # Exact substring is the strongest signal; find the best-placed occurrence.
    start = hay.find(needle)
    if start != -1:
        n = len(needle)
        # Occurrences differ only by their boundary bonuses and the
        # `- positions[0] // 4` earliness penalty. Boundary bonus per character
        # is capped at _BONUS_BOUNDARY once past index 0, so this is an upper
        # bound on any occurrence starting at `p`; once it cannot beat the best
        # so far, no later occurrence can either. Same answer, bounded work on
        # lines that repeat the needle many times.
        ceiling = (
            (_SCORE_MATCH + _BONUS_BOUNDARY + _BONUS_CONSECUTIVE) * n
            + _BONUS_CONSECUTIVE * (n - 1)
        )
        best: tuple[int, list[int]] | None = None
        while start != -1:
            positions = list(range(start, start + n))
            s = _score_positions(text, positions) + _BONUS_CONSECUTIVE * n
            if best is None or s > best[0]:
                best = (s, positions)
            start = hay.find(needle, start + 1)
            if start != -1 and ceiling - start // 4 <= best[0]:
                break
        return best

    # No substring occurrence: reject in C before the per-character Python loop.
    if not fuzzy_ok(needle, hay):
        return None

    forward = _greedy(needle, hay, reverse=False)
    if forward is None:
        return None
    backward = _greedy(needle, hay, reverse=True)
    candidates = [forward] + ([backward] if backward else [])
    scored = [(_score_positions(text, p), p) for p in candidates]
    return max(scored, key=lambda t: t[0])


def _term_score(
    term: Term, text: str, lowered: str | None = None
) -> tuple[int, list[int]] | None:
    """``lowered`` is ``text.lower()`` when the caller already has it, so a
    multi-term query folds each line once instead of once per term."""
    if term.case_sensitive:
        hay = text
    else:
        hay = lowered if lowered is not None else text.lower()
    needle = term.needle
    if term.type is TermType.PREFIX:
        if not hay.startswith(needle):
            return None
        pos = list(range(len(needle)))
        return (_score_positions(text, pos) + 20, pos)
    if term.type is TermType.SUFFIX:
        if not hay.endswith(needle):
            return None
        pos = list(range(len(text) - len(needle), len(text)))
        return (_score_positions(text, pos) + 20, pos)
    if term.type is TermType.EQUAL:
        if hay != needle:
            return None
        return (_score_positions(text, list(range(len(text)))) + 40, list(range(len(text))))
    if not term.text:
        return (0, [])
    # An exact term is a substring or nothing. The scorer below falls back to a
    # subsequence match when the substring is absent, which made `'8080` match
    # "80 … 80" - right for a fuzzy term, wrong for this one.
    if term.type is TermType.EXACT and needle not in hay:
        return None
    # EXACT and FUZZY are both scored by the scorer proper.
    return _score(needle, text, hay)


def match_score(query: ParsedQuery, text: str) -> int | None:
    """Total score for ``text``, without collecting the match spans.

    Makes the same accept/reject decision and returns the same total as
    :func:`match_spans`. Use it on the scanning hot path and call
    ``match_spans`` only for the results that survive the result cap - the
    spans of a match that is about to be discarded are never worth building.
    """
    if query.is_empty:
        return None
    lowered = text.lower() if query.needs_fold else text
    total = 0
    for term in query.terms:
        if term.negated:
            if not term.matches(text, lowered):
                return None
            continue
        res = _term_score(term, text, lowered)
        if res is None:
            return None
        total += res[0]
    return total


def match_spans(query: ParsedQuery, text: str) -> tuple[int, list[int]] | None:
    """Score ``text`` against every term. AND semantics; negation gates only."""
    if query.is_empty:
        return None
    lowered = text.lower() if query.needs_fold else text
    total = 0
    spans: set[int] = set()
    for term in query.terms:
        if term.negated:
            if not term.matches(text, lowered):
                return None
            continue
        res = _term_score(term, text, lowered)
        if res is None:
            return None
        s, positions = res
        total += s
        spans.update(positions)
    return (total, sorted(spans))
