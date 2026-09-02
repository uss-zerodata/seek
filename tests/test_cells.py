"""Trimming text to a width measured in terminal cells, not characters."""

import pytest
from rich.cells import cell_len

from seek.tui.cells import clip_cells, clip_window, fit_back, fit_forward

CJK = "日本語のファイル名がとても長い場合のテスト.txt"
ASCII = "src/some/quite/long/path/to/a/file/name.py"
MIXED = "src/日本語/main.py 説明テキストが続く"


@pytest.mark.parametrize("text", [CJK, ASCII, MIXED])
@pytest.mark.parametrize("budget", [8, 12, 20, 30, 200])
def test_clip_cells_never_exceeds_its_budget(text, budget):
    """Budgeting with `len()` let a CJK row run to roughly twice its width.

    In the scan viewer's `DataTable`, whose columns are laid out at fixed
    widths, that overruns the column rather than merely the pane.
    """
    assert cell_len(clip_cells(text, budget)) <= budget


@pytest.mark.parametrize("text", [CJK, ASCII, MIXED])
@pytest.mark.parametrize("budget", [8, 12, 20, 30, 200])
@pytest.mark.parametrize("anchor", ["head", "tail", "match"])
def test_clip_window_never_exceeds_its_budget(text, budget, anchor):
    out, _ = clip_window(text, [0], budget, anchor)
    assert cell_len(out) <= budget


def test_a_short_string_is_returned_untouched():
    assert clip_cells(ASCII, 200) == ASCII
    assert clip_window(ASCII, [1, 2], 200, "head") == (ASCII, [1, 2])


def test_spans_still_point_at_the_matched_characters_across_wide_text():
    s = "aaa日本語MATCHbbb"
    spans = list(range(s.index("MATCH"), s.index("MATCH") + 5))
    out, mapped = clip_window(s, spans, 14, "match")
    assert "".join(out[p] for p in mapped) == "MATCH"


def test_tail_anchor_keeps_the_end_of_the_string():
    out, _ = clip_window(ASCII, [], 20, "tail")
    assert out.endswith("name.py")
    assert out.startswith("…")


def test_fit_helpers_agree_with_cell_len():
    for s in [CJK, ASCII, MIXED]:
        for budget in (0, 1, 5, 13, 40):
            end = fit_forward(s, 0, budget)
            assert cell_len(s[:end]) <= budget
            start = fit_back(s, len(s), budget)
            assert cell_len(s[start:]) <= budget
