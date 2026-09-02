"""Parser for fzf-style extended query syntax.

Grammar (whitespace-separated terms, combined with AND):

    bare        fuzzy match
    'text       exact substring match
    ^text       prefix-anchored (exact) match
    text$       suffix-anchored (exact) match
    ^text$      whole-string exact match
    !text       negate any of the above (also !^t, !t$, !'t)

Smart-case is decided per term: case-insensitive unless the term text has an
uppercase character.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class TermType(StrEnum):
    FUZZY = "fuzzy"
    EXACT = "exact"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    EQUAL = "equal"


def fuzzy_ok(needle: str, hay: str) -> bool:
    """Is ``needle`` a subsequence of ``hay``? Both must already be folded.

    This is the cheap reject the scorer runs before its per-character Python
    loop. Two C-level steps, both linear and neither able to backtrack:

    1. ``needle[0] not in hay`` - one scan that discards most lines outright.
    2. ``c in it`` over a *shared* string iterator, which advances in C and so
       makes one pass over ``hay`` in total.

    A compiled regex (``m.*?a.*?i.*?n``) was measured as an alternative and
    rejected: it is faster only when the needle's characters are rare, and it
    backtracks catastrophically when they are common - the needle ``main.p``
    did not finish at all on a 368k-line corpus. See design.md decision 1.
    """
    if not needle:
        return True
    if needle[0] not in hay:
        return False
    it = iter(hay)
    return all(c in it for c in needle)


@dataclass(slots=True, frozen=True)
class Term:
    text: str
    type: TermType
    negated: bool
    case_sensitive: bool
    # Case-folded `text`, derived in __post_init__ so it is computed once per
    # query rather than once per line. Excluded from equality/repr so two
    # identical parses still compare equal.
    needle: str = field(default="", compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "needle", self.text if self.case_sensitive else self.text.lower()
        )

    def matches(self, text: str, lowered: str | None = None) -> bool:
        """Boolean test used for AND/negation gating (ignores score).

        ``lowered`` is ``text.lower()`` when the caller already has it, so a
        multi-term query folds each line once instead of once per term.
        """
        if not self.text:
            return not self.negated
        if self.case_sensitive:
            hay = text
        else:
            hay = lowered if lowered is not None else text.lower()
        needle = self.needle
        if self.type is TermType.EXACT:
            hit = needle in hay
        elif self.type is TermType.PREFIX:
            hit = hay.startswith(needle)
        elif self.type is TermType.SUFFIX:
            hit = hay.endswith(needle)
        elif self.type is TermType.EQUAL:
            hit = hay == needle
        else:  # FUZZY
            hit = fuzzy_ok(needle, hay)
        return hit != self.negated


@dataclass(slots=True, frozen=True)
class ParsedQuery:
    raw: str
    terms: tuple[Term, ...]
    # True when at least one term is case-insensitive, i.e. when a caller has to
    # fold the text it is matching. Derived; excluded from equality/repr.
    needs_fold: bool = field(default=True, compare=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "needs_fold", any(not t.case_sensitive for t in self.terms)
        )

    @property
    def is_empty(self) -> bool:
        return not self.terms

    @property
    def positive_terms(self) -> tuple[Term, ...]:
        return tuple(t for t in self.terms if not t.negated)

    @property
    def content_query_len(self) -> int:
        """Length of the longest positive term - gates content search."""
        pos = [len(t.text) for t in self.terms if not t.negated and t.text]
        return max(pos) if pos else 0

    def matches(self, text: str) -> bool:
        lowered = text.lower() if self.needs_fold else text
        return all(t.matches(text, lowered) for t in self.terms)


def _implies(new: Term, old: Term) -> bool:
    """Does matching ``new`` guarantee matching ``old``?

    Deliberately conservative: it only returns True for cases that are provable,
    because the failure mode of getting this wrong is silently missing results.
    """
    if new == old:
        return True
    if new.negated or old.negated:
        # Extending a negated term excludes *fewer* candidates, so it widens.
        return False
    if new.case_sensitive != old.case_sensitive:
        # Smart-case flipped, so the two terms fold their text differently.
        return False
    if old.type is TermType.FUZZY:
        # Every term type asserts that its text occurs in the candidate, so if
        # `old.text` is a prefix of `new.text` it is also a subsequence of it,
        # and old's fuzzy test must hold. A prefix is what typing produces.
        return new.text.startswith(old.text)
    if old.type is TermType.EXACT:
        # A longer substring/prefix/whole-string match contains the old one.
        return new.type in (
            TermType.EXACT, TermType.PREFIX, TermType.EQUAL
        ) and new.text.startswith(old.text)
    if old.type is TermType.PREFIX:
        return new.type in (
            TermType.PREFIX, TermType.EQUAL
        ) and new.text.startswith(old.text)
    # SUFFIX / EQUAL: appending re-types the term (`ma$` + `x` parses as the
    # fuzzy term `ma$x`, which matches text the suffix term never did), so
    # nothing but an exact repeat is safe.
    return False


def can_narrow(old: ParsedQuery, new: ParsedQuery) -> bool:
    """True when every candidate matching ``new`` must already match ``old``.

    When it holds, a search for ``new`` can run over ``old``'s results instead
    of over every candidate. Requires that all but the last of ``old``'s terms
    are carried over unchanged, that the last one is narrowed rather than
    replaced, and allows any number of extra terms (an extra AND conjunct only
    ever narrows).
    """
    if old.is_empty or new.is_empty:
        return False
    if len(new.terms) < len(old.terms):
        return False
    head = len(old.terms) - 1
    if new.terms[:head] != old.terms[:head]:
        return False
    return _implies(new.terms[head], old.terms[head])


_TOKEN_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\S+")


def _split_tokens(raw: str) -> list[str]:
    # Keep single-quoted spans together; otherwise split on whitespace.
    return _TOKEN_RE.findall(raw)


def parse_query(raw: str) -> ParsedQuery:
    terms: list[Term] = []
    for tok in _split_tokens(raw):
        negated = tok.startswith("!")
        body = tok[1:] if negated else tok
        if not body:
            continue
        ttype = TermType.FUZZY
        if body.startswith("'"):
            # 'exact  or  'exact'  (trailing quote optional)
            inner = body[1:]
            if len(inner) >= 2 and inner.endswith("'") and not inner.endswith("\\'"):
                inner = inner[:-1]
            text = inner.replace("\\'", "'")
            ttype = TermType.EXACT
        else:
            prefix = body.startswith("^")
            suffix = body.endswith("$") and not body.endswith("\\$")
            text = body
            if prefix:
                text = text[1:]
            if suffix:
                text = text[:-1]
            text = text.replace("\\$", "$")
            if prefix and suffix:
                ttype = TermType.EQUAL
            elif prefix:
                ttype = TermType.PREFIX
            elif suffix:
                ttype = TermType.SUFFIX
        if not text:
            continue
        case_sensitive = any(c.isupper() for c in text)
        terms.append(Term(text, ttype, negated, case_sensitive))
    return ParsedQuery(raw=raw, terms=tuple(terms))


