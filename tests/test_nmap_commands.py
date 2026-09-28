"""Every action is reachable by name from the command palette."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.command import CommandPalette
from textual.widgets import DataTable, OptionList, Tabs

from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap.app import NmapApp
from seek.tui.nmap.commands import ScanCommands, _commands

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app() -> NmapApp:
    return NmapApp(prepare(load([FIX / "basic.xml"])))


async def _palette(pilot, text: str):
    await pilot.press("ctrl+p")
    await pilot.pause(0.4)
    for ch in text:
        await pilot.press(ch)
    await pilot.pause(0.6)


async def test_the_provider_is_registered():
    assert ScanCommands in NmapApp.COMMANDS


async def test_ctrl_p_opens_the_palette():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("ctrl+p")
        await pilot.pause(0.5)
        assert isinstance(app.screen, CommandPalette)


async def test_every_bound_action_has_a_command():
    """A key and a command entry should never drift apart."""
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        titles = " ".join(t for t, _, _ in _commands(app)).lower()
        for expected in ("hosts", "services", "statistics", "group by service",
                         "group by product", "group by port", "next overview",
                         "previous overview", "only up hosts", "open selected",
                         "back", "first row", "last row", "page down", "page up",
                         "scroll detail", "detail", "reverse sort", "filter",
                         "export", "help", "quit", "sort by"):
            assert expected in titles, f"no command for {expected!r}"


async def test_sort_commands_follow_the_active_overview():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        sorts = [t for t, _, _ in _commands(app) if t.startswith("Sort by")]
        assert sorts == [f"Sort by {c}" for c in app.view.columns]
        await pilot.press("v")
        await pilot.pause(0.3)
        sorts = [t for t, _, _ in _commands(app) if t.startswith("Sort by")]
        assert sorts == [f"Sort by {c}" for c in app.view.columns]
        assert "Sort by Product" in sorts


async def test_every_command_carries_help_text():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        for title, subtitle, _ in _commands(app):
            assert subtitle, f"{title} has no description"


async def test_running_a_command_switches_the_overview():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        await _palette(pilot, "statis")
        assert app.screen.query_one(OptionList).option_count >= 1
        await pilot.press("enter")
        await pilot.pause(0.6)
        assert app.query_one(Tabs).active == "stats"
        assert not isinstance(app.screen, CommandPalette)


async def test_running_a_sort_command_orders_the_list():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        await _palette(pilot, "sort by svcs")
        await pilot.press("enter")
        await pilot.pause(0.6)
        assert app._sort_col == 4
        assert [r.cells[4] for r in app._rows] == ["0", "1", "2"]


async def test_a_navigation_command_moves_the_selection():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        assert app.query_one(DataTable).cursor_row == 0
        await _palette(pilot, "last row")
        await pilot.press("enter")
        await pilot.pause(0.6)
        assert app.query_one(DataTable).cursor_row == len(app._rows) - 1


async def test_the_palette_lists_commands_before_anything_is_typed():
    app = _app()
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("ctrl+p")
        await pilot.pause(0.8)
        assert app.screen.query_one(OptionList).option_count > 10
