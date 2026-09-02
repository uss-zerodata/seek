"""The scorer optimisations must not change results.

Every optimisation in the `search-performance` change is checked against
`reference_score`, a frozen copy of the pre-change scorer: same match/no-match
decision, same score, same highlighted positions, for every query shape.
"""

from __future__ import annotations

import pytest
import reference_score

from seek.engine.query import parse_query
from seek.engine.score import match_spans, score

# Lines deliberately covering: word boundaries, camelCase, digits, separators,
# repeated characters (the substring-occurrence scan), unicode, empty, and long
# lines with the match at the very end.
CORPUS = [
    "",
    "a",
    "self",
    "        self.value = other.value",
    "def main(argv: list[str]) -> int:",
    "class WidgetHandler(BaseHandler):",
    "MAIN_CONFIG_PATH = '/etc/main.conf'",
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "abababababababababababab",
    "main main main main main",
    "src/seek/engine/score.py",
    "x = 1  # mainly a comment about MainWindow and main_helper",
    "camelCaseIdentifier2024Version",
    "  \t mixed\twhitespace  and-dashes_and.dots ",
    "ünïcödé päth/tö/fïlé.txt",
    "z" * 300 + "main",
    "no match on this line at all",
    "MAIN",
    "Main",
    "m-a-i-n",
    "__main__.py",
]

QUERIES = [
    # fuzzy
    "m", "ma", "main", "mn", "mnh", "self", "value",
    # exact
    "'main", "'self.", "'  ", "'aa",
    # anchors
    "^main", "^def", "main$", ".py$", "^main$", "^self$",
    # negation
    "!main", "!'def", "!^x", "!py$",
    # multi-term (AND)
    "main py", "def main", "self value", "ma !py", "^src .py$",
    "'def main", "camel case", "main main",
    # smart-case
    "Main", "MAIN", "WidgetHandler", "Self",
    # unicode / punctuation
    "ünï", "path/to", "a-b", "2024",
    # no-match shapes
    "zzqqnotthere", "qqq", "!",
]


@pytest.mark.parametrize("query_text", QUERIES)
def test_match_spans_matches_the_reference(query_text):
    query = parse_query(query_text)
    for text in CORPUS:
        got = match_spans(query, text)
        want = reference_score.match_spans(query, text)
        assert got == want, (
            f"match_spans diverged\n  query={query_text!r}\n  text={text!r}\n"
            f"  got ={got!r}\n  want={want!r}"
        )


@pytest.mark.parametrize("case_sensitive", [False, True])
def test_score_matches_the_reference(case_sensitive):
    needles = ["", "m", "ma", "main", "self", "aa", "abab", "zzz", "Main", "ünï", "."]
    for needle in needles:
        for text in CORPUS:
            got = score(needle, text, case_sensitive=case_sensitive)
            want = reference_score.score(needle, text, case_sensitive=case_sensitive)
            assert got == want, (
                f"score diverged\n  needle={needle!r} cs={case_sensitive}\n"
                f"  text={text!r}\n  got ={got!r}\n  want={want!r}"
            )


def test_reference_agrees_with_term_matches_gate():
    """The frozen `_matches` copy must track `Term.matches` while it is unchanged."""
    for query_text in ("main", "'def", "^src", "py$", "^main$"):
        for term in parse_query(query_text).terms:
            for text in CORPUS:
                assert reference_score._matches(term, text) == term.matches(text)
