"""Rendering of one row in the result list: span placement and width budgeting."""

from pathlib import Path

from rich.text import Text

from seek.config import Config
from seek.engine.query import parse_query
from seek.engine.score import match_spans
from seek.models import MatchKind, Result
from seek.tui.results import ResultsList, _expand_tabs


def _content_result(line: str, query: str) -> Result:
    """A content match scored exactly the way the engine scores one."""
    found = match_spans(parse_query(query), line)
    assert found is not None, f"{query!r} must match {line!r}"
    return Result(
        kind=MatchKind.CONTENT,
        path=Path("/tmp/f.py"),
        rel="f.py",
        score=found[0],
        spans=found[1],
        line_no=1,
        line_text=line,
        view_line=1,
    )


def _highlighted(option_text: Text, style: str) -> str:
    """The characters the row drew in ``style``."""
    plain = option_text.plain
    marked = set()
    for span in option_text.spans:
        if span.style == style:
            marked.update(range(span.start, span.end))
    return "".join(plain[i] for i in sorted(marked) if i < len(plain))


def _row_text(result: Result) -> Text:
    rl = ResultsList(Config())
    return rl._render_row(result).prompt


def test_expand_tabs_matches_str_expandtabs():
    for s in ["", "no tabs", "\t", "a\t", "ab\tc", "\t\tx", "abcd\te", "a\tb\tc"]:
        expanded, cols = _expand_tabs(s)
        assert expanded == s.expandtabs(4)
        assert len(cols) == len(s)


def test_tab_indented_match_highlights_the_matched_characters():
    """Spans index the line as stored; the row draws it with tabs expanded.

    Shifting stored offsets by the *expanded* indent width mixed two coordinate
    systems, so a match on a tab-indented line highlighted the wrong characters
    entirely - `user` in `\\t\\tif user_name:` lit up the `i` of `if`.
    """
    style = Config().theme["match"]
    text = _row_text(_content_result("\t\tif user_name:", "user"))
    assert _highlighted(text, style) == "user"


def test_space_indented_match_still_highlights_correctly():
    style = Config().theme["match"]
    text = _row_text(_content_result("    if user_name:", "user"))
    assert _highlighted(text, style) == "user"


def test_tabs_in_the_middle_of_a_line_shift_the_match_too():
    style = Config().theme["match"]
    text = _row_text(_content_result("a\tb\tuser_name", "user"))
    assert _highlighted(text, style) == "user"


def test_name_row_highlights_the_basename_not_the_directory_prefix():
    """A name result is scored against its basename, so its spans are too.

    The row draws the whole relative path, so applying basename offsets to it
    unshifted highlighted the leading directory instead: `main` in
    `src/main.py` lit up `src/`.
    """
    found = match_spans(parse_query("main"), "main.py")  # as the engine scores it
    assert found is not None
    r = Result(kind=MatchKind.FILENAME, path=Path("/tmp/src/main.py"),
               rel="src/main.py", score=found[0], spans=found[1])
    assert _highlighted(_row_text(r), Config().theme["match"]) == "main"


def test_name_row_at_the_root_still_highlights_correctly():
    found = match_spans(parse_query("main"), "main.py")
    assert found is not None
    r = Result(kind=MatchKind.FILENAME, path=Path("/tmp/main.py"),
               rel="main.py", score=found[0], spans=found[1])
    assert _highlighted(_row_text(r), Config().theme["match"]) == "main"


def test_deeply_nested_name_row_highlights_the_basename():
    found = match_spans(parse_query("widget"), "widget.py")
    assert found is not None
    r = Result(kind=MatchKind.FILENAME, path=Path("/tmp/a/b/c/widget.py"),
               rel="a/b/c/widget.py", score=found[0], spans=found[1])
    assert _highlighted(_row_text(r), Config().theme["match"]) == "widget"
