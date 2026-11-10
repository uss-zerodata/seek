"""Long work, and how the viewer says it is working.

A projection over a large engagement is seconds of work. These cover the three
things that has to mean for the user: it happens off the event loop, it says
how far it has got, and it can be abandoned.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from textual.widgets import DataTable, Static

from seek.nmap.merge import load
from seek.nmap.models import Host, ScanSet, Service
from seek.nmap.views import prepare
from seek.tui.nmap import app as app_mod
from seek.tui.nmap import views as vdefs
from seek.tui.nmap.app import NmapApp

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app() -> NmapApp:
    return NmapApp(prepare(load([FIX / "basic.xml"])))


def _pane(app) -> str:
    """What the tab's own message area says - the loading state lives there."""
    return str(app.query_one("#empty", Static).render())


def _listing(prefix: str, count: int) -> vdefs.View:
    """A view of exactly `count` rows, so chunking can be counted."""
    rows = [vdefs.Row(cells=(f"{prefix}{i}", "", "", "", "", ""),
                      text=f"{prefix}{i}") for i in range(count)]
    return vdefs.View(title="Listing", columns=vdefs.HOST_COLUMNS,
                      build=lambda _scans: rows, kind="hosts", tab="hosts")


def _chunks_of(monkeypatch, size: int) -> None:
    """Hand the table `size` rows per turn, whatever the machine's speed.

    The fill is budgeted in time, not rows, so a fixture list would otherwise
    go over in a single pass and there would be no instalments to observe.
    """
    monkeypatch.setattr(app_mod, "_FILL_CHUNK", size)
    monkeypatch.setattr(app_mod, "_FILL_STEP", size)
    monkeypatch.setattr(app_mod, "_FILL_BUDGET", 0.0)


def _slow_view(released: threading.Event) -> vdefs.View:
    """A view whose rows take as long as the test wants them to."""
    def build(_scans):
        released.wait(5)
        return [vdefs.Row(cells=("held", "", "", "", "", ""), text="held")]

    return vdefs.View(title="Held", columns=vdefs.HOST_COLUMNS, build=build,
                      kind="hosts", tab="hosts")


async def test_a_slow_view_is_built_off_the_event_loop(monkeypatch):
    """The list waits, the app does not: keys still arrive while it builds."""
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    released = threading.Event()
    app = _app()
    async with app.run_test() as pilot:
        app.stack = [_slow_view(released)]
        app._refresh_view()
        await pilot.pause(0.2)

        assert app._busy is not None, "the build is in a thread"
        assert "reading" in _pane(app) and "Esc" in _pane(app), \
            "and the tab's own area says so, with the way out"
        assert app.query_one(DataTable).row_count == 0

        released.set()
        await pilot.pause(0.5)
        assert app._busy is None
        assert [r.cells[0] for r in app._rows] == ["held"], "the rows arrive"


async def test_a_slow_build_can_be_abandoned_with_escape(monkeypatch):
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    released = threading.Event()
    app = _app()
    try:
        async with app.run_test() as pilot:
            app.stack = [_slow_view(released)]
            app._refresh_view()
            await pilot.pause(0.2)
            assert app._busy is not None

            await pilot.press("escape")
            await pilot.pause(0.1)
            assert app._busy is None, "the app stops waiting at once"
            assert "Stopped reading" in _pane(app)
            assert "come back" in _pane(app), "and says how to get the rows"
    finally:
        released.set()


async def test_the_indicator_counts_the_work_it_can_count(monkeypatch):
    """A scan history knows how many scans there are, so it draws a bar."""
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    app = _app()
    async with app.run_test() as pilot:
        # Let the tab's own build finish first: with the threshold at zero even
        # three hosts go to a worker, and its reports would otherwise land on
        # top of the one being staged here.
        await pilot.pause(0.3)
        app._busy = app_mod._Busy(what="the scan history", view=None,
                                  token=app._build_token + 1,
                                  done=3, total=12, unit="scans")
        app._show_busy()
        await pilot.pause(0.05)
        pane = _pane(app)
        assert "the scan history" in pane
        assert "3 of 12 scans" in pane
        assert "█" in pane and "░" in pane, "a determinate bar, not a spinner"
        app._busy = None


async def test_an_overview_over_a_large_model_draws_a_bar_naming_hosts():
    """Every tab, not only the Scans tab, once the model is worth a wait.

    Nothing is monkeypatched: the set is genuinely over the threshold at which
    the viewer takes a projection off the event loop, which is the condition
    the requirement is written against. The reports collected here are the
    ones the projection really produced, and they are then handed to the one
    renderer that draws any report - so what is asserted is what is shown.
    """
    big = ScanSet(
        hosts=[Host(address=f"10.1.{i // 254}.{i % 254}", reason="echo-reply",
                    services=[Service(protocol="tcp", port=443, state="open",
                                      name="https", product="nginx")])
               for i in range(app_mod._BACKGROUND_ABOVE + 700)],
        sources=["big.xml"])
    app = NmapApp(big)
    seen: list[tuple[int, int, str]] = []
    async with app.run_test() as pilot:
        received = app._on_build_progress

        def watch(token, done, total, unit):
            seen.append((done, total, unit))
            received(token, done, total, unit)

        app._on_build_progress = watch
        app._activate("stats")
        app._refresh_view()
        await pilot.pause(0.6)

        assert seen, "a projection this size goes to a worker, and it reports"
        assert {unit for _, _, unit in seen} == {"hosts"}
        assert seen[-1][1] == len(big.hosts), "counted against the model's hosts"

        # A report from partway through, not the opening `0 of N`: the bar has
        # to have both halves in it for "determinate" to mean anything.
        done, total, unit = next(r for r in seen if 0 < r[0] < r[1])
        app._busy = app_mod._Busy(what="statistics", view=None,
                                  token=app._build_token + 1,
                                  done=done, total=total, unit=unit)
        app._show_busy()
        await pilot.pause(0.05)
        pane = _pane(app)
        assert "█" in pane and "░" in pane, "a determinate bar, not a spinner"
        assert f"{done} of {total} hosts" in pane, \
            f"and it names what it counts: {pane!r}"
        app._busy = None


async def test_an_uncountable_step_shows_no_bar_at_all():
    """A total of zero is "cannot count yet", which is not a bar at nothing."""
    app = _app()
    async with app.run_test() as pilot:
        await pilot.pause(0.3)
        app._busy = app_mod._Busy(what="the scans", view=None,
                                  token=app._build_token + 1, done=7, total=0)
        app._show_busy()
        await pilot.pause(0.05)
        pane = _pane(app)
        assert "reading the scans" in pane and "Esc" in pane
        assert "█" not in pane and "░" not in pane, "no bar against a total of zero"
        app._busy = None


async def test_a_refresh_reports_in_the_status_bar_not_over_the_rows():
    """Re-reading after a scan must not flash away rows that are still true."""
    app = _app()
    async with app.run_test() as pilot:
        rows_before = app.query_one(DataTable).row_count
        app._busy = app_mod._Busy(what="the scans again", view=None, token=1,
                                  done=2, total=4, unit="files", refresh=True)
        app._show_busy()
        await pilot.pause(0.05)
        assert app.query_one(DataTable).row_count == rows_before, \
            "the list stays where it is"
        note = app._busy_note()
        assert note is not None and "reading the scans again" in note.plain
        assert "2/4" in note.plain and "Esc" in note.plain
        app._busy = None


async def test_rows_are_built_once_per_model():
    """Sorting, resizing and filtering must not re-project the whole model."""
    app = _app()
    calls = []
    view = vdefs.View(
        title="Counted", columns=vdefs.HOST_COLUMNS,
        build=lambda scans: calls.append(1) or [
            vdefs.Row(cells=("one", "", "", "", "", ""), text="one")],
        kind="hosts", tab="hosts")
    async with app.run_test() as pilot:
        app.stack = [view]
        app._refresh_view()
        app._refresh_view()
        app._reload_rows()
        await pilot.pause(0.1)
        assert len(calls) == 1, f"built {len(calls)} times for one model"

        app.scans = prepare(load([FIX / "basic.xml"]))
        app._refresh_view()
        await pilot.pause(0.1)
        assert len(calls) == 2, "a new model is built again"


async def test_a_running_scan_does_not_restart_the_history_build(monkeypatch):
    """Its rows are rebuilt on every line the scan prints - the history is not.

    Without this the Scans tab would start a fresh background build for each
    line of nmap output, which is the opposite of what the cache is for.
    """
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    app = _app()
    async with app.run_test() as pilot:
        await pilot.pause(0.3)                      # the tab's own build settles
        view = app._scans_view()
        assert app._needs_building(view), "cold: the history has to be built"

        app._scan_history()                         # as the background build does
        assert not app._needs_building(view), "warm: only the rows are rebuilt"
        assert app._rows_now(view) is not None, "so a log line refreshes inline"
        assert app._busy is None
        await pilot.pause(0.05)


async def test_a_long_list_reaches_the_table_a_chunk_at_a_time(monkeypatch):
    """The first screenful is there at once; the rest follows without blocking."""
    _chunks_of(monkeypatch, 2)
    app = _app()
    async with app.run_test() as pilot:
        app.stack = [_listing("h", 7)]
        app._refresh_view()
        table = app.query_one(DataTable)
        assert table.row_count == 2, "the first chunk is in before anything else runs"
        assert app._filling, "and the status line says the rest is coming"

        await pilot.pause(0.5)
        assert table.row_count == 7 and not app._filling
        assert [r.cells[0] for r in app._rows] == [f"h{i}" for i in range(7)]


async def test_the_cursor_is_placed_once_and_then_left_alone(monkeypatch):
    """A list still filling belongs to the reader, not to the fill.

    The cursor used to be repositioned on every chunk, so a list long enough
    to take seconds to hand over could not be moved around while it arrived -
    each frame dragged the selection back to the row the fill had chosen.
    """
    _chunks_of(monkeypatch, 2)
    app = _app()
    async with app.run_test() as pilot:
        app.stack = [_listing("h", 40)]
        app._refresh_view()
        table = app.query_one(DataTable)
        assert app._filling, "the rest is still coming"
        assert table.cursor_row == 0, "placed on the first chunk"

        table.move_cursor(row=1)
        for _ in range(6):
            await pilot.pause(0.02)
            assert table.cursor_row == 1, \
                "a chunk landing must not take the selection back"
        await pilot.pause(0.5)
        assert not app._filling and table.row_count == 40
        assert table.cursor_row == 1, "and it is still where it was left"


async def test_a_new_list_abandons_the_chunks_still_queued(monkeypatch):
    _chunks_of(monkeypatch, 2)
    app = _app()
    async with app.run_test() as pilot:
        app.stack = [_listing("a", 9)]
        app._refresh_view()
        app.stack = [_listing("b", 1)]
        app._refresh_view()
        await pilot.pause(0.5)
        assert app.query_one(DataTable).row_count == 1, \
            "no leftovers from the list that was replaced"
        assert [r.cells[0] for r in app._rows] == ["b0"]


async def test_switching_tab_while_a_list_is_still_filling(monkeypatch):
    """A queued row has the old view's cells; the new view has other columns.

    Handing one to the other is an error rather than a cosmetic mismatch, so
    re-laying the header has to abandon whatever was still queued.
    """
    _chunks_of(monkeypatch, 2)
    app = _app()
    async with app.run_test() as pilot:
        app.stack = [_listing("a", 40)]
        app._refresh_view()
        assert app._filling
        app._activate("services")               # eight columns, not six
        await pilot.pause(0.5)
        assert app.view.kind == "services"
        assert app.query_one(DataTable).row_count == len(app._rows)


async def test_the_scans_tab_is_never_cached():
    """A live run's elapsed time moves without the model changing."""
    app = _app()
    async with app.run_test() as pilot:
        view = app._scans_view()
        assert not view.cacheable
        assert not view.cached_for(app.scans)
        await pilot.pause(0.05)
