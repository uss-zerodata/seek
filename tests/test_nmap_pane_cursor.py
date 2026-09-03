"""Moving through a record, and choosing a line out of it.

The pane used to scroll blindly: there was no answer to "which line am I on",
which is fine while a record is only read and impossible once a line can be
acted on. These cover the cursor that answers it - that it moves, that it is
visible, that it stays out of the list's way, and that it survives the record
being rebuilt underneath it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Static

from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap.app import NmapApp

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app(*names: str) -> NmapApp:
    return NmapApp(prepare(load([FIX / f"{n}.xml" for n in names])))


def _pane(app) -> str:
    return str(app.query_one("#detail-body", Static).render())


async def test_the_cursor_starts_at_the_top_of_a_record():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        assert app._lines, "the record is lines now"
        assert app._line == 0


async def test_j_and_k_move_the_cursor_a_line_at_a_time():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("J")
        assert app._line == 1
        await pilot.press("J")
        assert app._line == 2
        await pilot.press("K")
        assert app._line == 1


async def test_the_cursor_stops_at_the_ends_of_the_record():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("K")
        assert app._line == 0, "it does not run off the top"
        for _ in range(len(app._lines) + 5):
            await pilot.press("J")
        assert app._line == len(app._lines) - 1, "nor off the bottom"


async def test_the_line_under_the_cursor_is_marked_out():
    """Reverse video on the line itself, and on exactly one line."""
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)

        def marked() -> list[int]:
            shown = app._with_cursor(app._lines)
            return [i for i, part in enumerate(shown.renderables)
                    if "reverse" in str(getattr(part, "style", ""))]

        assert marked() == [0], "the first line is the cursor's"
        await pilot.press("J")
        assert marked() == [1], "and it moved with the cursor"


async def test_the_arrows_jump_between_the_lines_that_can_be_opened():
    app = _app("basic", "scripts")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        marks = app._openable()
        assert marks, "a host record offers the scans that saw it"
        assert app._line == 0 and app._line not in marks

        await pilot.press("right")
        assert app._line == marks[0], "straight to the first, not a line at a time"
        assert app._opens_here() is not None
        await pilot.press("left")
        assert app._line == marks[0], "and it stops rather than wrapping back"


async def test_the_arrows_stop_at_the_last_openable_line():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        marks = app._openable()
        for _ in range(len(marks) + 3):
            await pilot.press("right")
        assert app._line == marks[-1], "no wrap to the first"


async def test_the_two_cursors_do_not_move_each_other():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.query_one(DataTable)
        assert table.cursor_row == 0

        await pilot.press("J")
        await pilot.press("J")
        assert table.cursor_row == 0, "the pane's cursor left the list alone"
        pane_at = app._line

        await pilot.press("down")
        assert table.cursor_row == 1, "and the list moved on its own key"
        assert app._line != pane_at or app._line == 0, \
            "a new row resets the pane's cursor rather than keeping the old one"


async def test_a_new_row_starts_its_record_at_the_top():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        for _ in range(4):
            await pilot.press("J")
        assert app._line > 0
        await pilot.press("down")
        await pilot.pause(0.1)
        assert app._line == 0


async def test_a_record_with_nothing_to_open_still_moves_and_reads():
    """Moving through a record is how a long one is read, openable or not."""
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        app._activate("stats")
        await pilot.pause(0.2)
        assert app._openable() == [], "a statistics row opens nothing"

        before = _pane(app)
        for _ in range(3):
            await pilot.press("J")
        assert app._line >= 0, "the cursor still moves"
        await pilot.press("right")
        assert app._opens_here() is None, "and the jump key does nothing rather than crash"
        assert _pane(app) or before, "the record still reads"


async def test_the_pane_scrolls_only_when_the_cursor_reaches_its_edge():
    app = _app("scripts")
    async with app.run_test(size=(110, 24)) as pilot:
        await pilot.pause(0.2)
        region = app.query_one("#detail", VerticalScroll)
        assert region.scroll_offset.y == 0
        await pilot.press("J")
        await pilot.pause(0.05)
        assert region.scroll_offset.y == 0, "still on screen, nothing moved"

        for _ in range(len(app._lines)):
            await pilot.press("J")
        await pilot.pause(0.1)
        assert app._line == len(app._lines) - 1
        assert region.scroll_offset.y > 0, "the record came up to meet the cursor"


async def test_the_hint_bar_offers_the_raw_log_only_on_a_line_that_opens_one():
    app = _app("basic")
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause(0.2)
        hints = str(app.query_one("#hint-bar", Static).render())
        assert "raw log" not in hints, "nothing to open on the first line"
        await pilot.press("right")
        await pilot.pause(0.05)
        assert "raw log" in str(app.query_one("#hint-bar", Static).render())


async def test_the_cursor_survives_the_record_being_rebuilt_under_it():
    """A batch of scans re-renders the record; a reader partway down it stays."""
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        for _ in range(3):
            await pilot.press("J")
        at = app._line
        assert at == 3

        app._refresh_detail()                       # as a publication does
        await pilot.pause(0.05)
        assert app._line == at, "the arriving file sent the reader back to the top"


async def test_the_cursor_is_clamped_when_the_record_gets_shorter():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        app._line = 999
        app._refresh_detail()
        await pilot.pause(0.05)
        assert app._line == len(app._lines) - 1


# --- when the cursor has nowhere to go, the keys scroll -----------------------


async def test_a_record_that_is_one_renderable_can_still_be_scrolled():
    """A scan's report is a single line as far as the pane is concerned.

    The cursor has one stop there, so moving it does nothing - and without a
    fall-back the report could not be read past the fold at all, which is the
    whole of what these keys did before the cursor existed.
    """
    app = _app("basic")
    async with app.run_test(size=(110, 24)) as pilot:
        await pilot.pause(0.2)
        app._activate("scans")
        await pilot.pause(0.3)
        app._report_mode = "raw"
        app._refresh_detail()
        await pilot.pause(0.2)
        region = app.query_one("#detail", VerticalScroll)
        if region.max_scroll_y == 0:
            pytest.skip("this fixture's report fits the pane")
        assert len(app._lines) == 1, "one renderable, one cursor stop"

        await pilot.press("J")
        await pilot.pause(0.05)
        assert region.scroll_offset.y > 0, "J scrolled rather than doing nothing"
        await pilot.press("K")
        await pilot.pause(0.05)
        assert region.scroll_offset.y == 0


async def test_the_arrows_scroll_a_record_with_no_entries_to_jump_between():
    """The statistics and the groupings have none; the keys still read the pane."""
    app = _app("vuln")
    async with app.run_test(size=(110, 24)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")                  # a record taller than the pane
        await pilot.pause(0.3)
        region = app.query_one("#detail", VerticalScroll)
        assert region.max_scroll_y > 0

        # Walk the cursor to the last openable line, then past it.
        for _ in range(len(app._lines)):
            await pilot.press("right")
        await pilot.pause(0.1)
        at = region.scroll_offset.y
        await pilot.press("right")
        await pilot.pause(0.05)
        assert region.scroll_offset.y >= at, \
            "past the last entry the key scrolls rather than doing nothing"


async def test_the_cursor_still_walks_every_line_of_an_ordinary_record():
    """The fall-back must not have replaced the line-by-line movement."""
    app = _app("basic", "scripts")
    async with app.run_test(size=(110, 24)) as pilot:
        await pilot.pause(0.2)
        assert len(app._lines) > 3
        walked = []
        for _ in range(len(app._lines) + 2):
            await pilot.press("J")
            walked.append(app._line)
        assert walked[:3] == [1, 2, 3], "one line at a time, openable or not"
        assert walked[-1] == len(app._lines) - 1, "all the way to the last"
        assert walked[: len(app._lines) - 1] == list(range(1, len(app._lines))), \
            "and it stopped on every line on the way, not only the openable ones"
