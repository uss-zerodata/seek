"""The record pane's line cursor, as in a text editor.

`←`/`→` and `h`/`l` move it a line; `↑`/`↓` and `j`/`k` stay with the list.
Every line is a stop, lines that open something are styled as links, and the
record scrolls to keep the cursor in view.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.containers import VerticalScroll
from textual.widgets import DataTable, Static

from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap.app import NmapApp

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app(*names: str) -> NmapApp:
    return NmapApp(prepare(load([FIX / f"{n}.xml" for n in names])))


def _pane(app) -> str:
    return str(app.query_one("#detail-body", Static).render())


def _marked(app) -> list[int]:
    shown = app._with_cursor(app._lines)
    return [i for i, part in enumerate(shown.renderables)
            if "reverse" in str(getattr(part, "style", ""))]


async def _tall(pilot, app) -> VerticalScroll:
    """A host record taller than the pane."""
    await pilot.pause(0.2)
    await pilot.press("enter")
    await pilot.pause(0.3)
    region = app.query_one("#detail", VerticalScroll)
    assert region.max_scroll_y > 2, "the fixture's record fits the pane"
    return region


async def test_the_cursor_starts_at_the_top_of_a_record():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        assert app._lines and app._line == 0
        assert _marked(app) == [0]


@pytest.mark.parametrize("down,up", [("right", "left"), ("l", "h")])
async def test_arrows_and_vim_keys_move_the_cursor_a_line_at_a_time(down, up):
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press(down)
        assert app._line == 1 and _marked(app) == [1]
        await pilot.press(down)
        assert app._line == 2
        await pilot.press(up)
        assert app._line == 1


async def test_the_cursor_stops_at_the_ends_of_the_record():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("left")
        assert app._line == 0, "it does not run off the top"
        for _ in range(len(app._lines) + 5):
            await pilot.press("right")
        assert app._line == len(app._lines) - 1, "nor off the bottom"


async def test_every_line_is_a_stop():
    app = _app("basic", "scripts")
    async with app.run_test(size=(110, 24)) as pilot:
        await pilot.pause(0.2)
        walked = []
        for _ in range(len(app._lines) - 1):
            await pilot.press("right")
            walked.append(app._line)
        assert walked == list(range(1, len(app._lines))), "openable or not"


async def test_the_record_follows_the_cursor_both_ways():
    """Down to the end and back up: the record moves in both directions."""
    app = _app("vuln")
    async with app.run_test(size=(110, 24)) as pilot:
        region = await _tall(pilot, app)
        await pilot.press("right")
        await pilot.pause(0.05)
        assert region.scroll_offset.y == 0, "still on screen, nothing moved"
        for _ in range(len(app._lines)):
            await pilot.press("right")
        await pilot.pause(0.1)
        assert region.scroll_offset.y > 0, "the record came up to meet the cursor"
        for _ in range(len(app._lines)):
            await pilot.press("left")
        await pilot.pause(0.1)
        assert app._line == 0 and region.scroll_offset.y == 0, "and went back down"


async def test_the_cursor_stays_in_view():
    app = _app("vuln")
    async with app.run_test(size=(110, 24)) as pilot:
        region = await _tall(pilot, app)
        for key in ["right"] * len(app._lines) + ["left"] * (len(app._lines) // 2):
            await pilot.press(key)
            row, top = app._row_of(app._line), region.scroll_offset.y
            assert top <= row < top + region.size.height


async def test_lines_that_open_something_are_styled_as_links():
    app = _app("basic", "scripts")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        marks = app._openable()
        assert marks, "a host record offers the scans that saw it"
        for i, line in enumerate(app._lines):
            linked = any("underline" in str(span.style) for span in line.text.spans)
            assert linked == (i in marks), f"line {i}: {line.text.plain!r}"


async def test_o_is_offered_only_on_a_link():
    app = _app("basic")
    async with app.run_test(size=(150, 40)) as pilot:
        await pilot.pause(0.2)
        hints = str(app.query_one("#hint-bar", Static).render())
        assert "raw log" not in hints, "nothing to open on the first line"
        for _ in range(app._openable()[0]):
            await pilot.press("right")
        await pilot.pause(0.05)
        assert app._opens_here() is not None
        assert "raw log" in str(app.query_one("#hint-bar", Static).render())


async def test_the_list_and_the_pane_do_not_move_each_other():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        table = app.query_one(DataTable)
        await pilot.press("right")
        await pilot.press("l")
        assert table.cursor_row == 0, "the pane's keys left the list alone"
        assert app._line == 2
        for key in ("down", "j"):
            before = table.cursor_row
            await pilot.press(key)
            await pilot.pause(0.1)
            assert table.cursor_row == before + 1, f"{key} moves the list"
            assert app._line == 0, "and a new record starts at its top"


async def test_the_old_scroll_keys_are_gone():
    keys = {k.strip() for b in NmapApp.BINDINGS for k in b.key.split(",")}
    assert not {"J", "K"} & keys


async def test_the_cursor_survives_the_record_being_rebuilt_under_it():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        for _ in range(3):
            await pilot.press("right")
        app._refresh_detail()                       # as a publication does
        await pilot.pause(0.05)
        assert app._line == 3, "the arriving file sent the reader back to the top"


async def test_the_cursor_is_clamped_when_the_record_gets_shorter():
    app = _app("basic")
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause(0.2)
        app._line = 999
        app._refresh_detail()
        await pilot.pause(0.05)
        assert app._line == len(app._lines) - 1


async def test_a_record_that_is_one_block_scrolls_instead():
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
        await pilot.press("right")
        await pilot.pause(0.05)
        assert region.scroll_offset.y == 1
        await pilot.press("left")
        await pilot.pause(0.05)
        assert region.scroll_offset.y == 0
