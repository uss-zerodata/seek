"""The Inventory tab and the Software block, in the terminal viewer."""

from __future__ import annotations

from pathlib import Path

import pytest
from textual.widgets import DataTable, Tabs

from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import record as record_mod
from seek.tui.nmap.app import NmapApp
from seek.tui.nmap.detail import as_group

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app() -> NmapApp:
    return NmapApp(prepare(load([FIX / "inventory.xml"])))


async def _inventory(pilot, app):
    await pilot.pause(0.3)
    app.query_one(Tabs).active = "inventory"
    await pilot.pause(0.5)


def _text(lines) -> str:
    import io

    from rich.console import Console
    console = Console(width=160, record=True, file=io.StringIO())
    console.print(as_group(lines))
    return console.export_text()


async def test_the_inventory_tab_lists_products_and_versions():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        assert app.view.kind == "inventory"
        rows = {(r.cells[0], r.cells[1]): r for r in app._rows}
        assert ("nginx", "1.16.1") in rows
        assert rows[("nginx", "1.16.1")].cells[5:7] == ("1", "1")
        assert ("Postfix", "—") in rows, "an unversioned product is a row of its own"
        assert rows[("Linux", "—")].cells[9] == "os"
        assert rows[("websockets", "8.1")].cells[8] == "no CPE"
        assert rows[("nginx", "1.16.1")].cells[2] == "no vulndb", "no database is a state"


async def test_drilling_into_a_version_and_going_back():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        idx = next(i for i, r in enumerate(app._rows) if r.cells[0] == "nginx")
        app.query_one(DataTable).move_cursor(row=idx)
        await pilot.pause(0.1)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.view.kind == "inventory-detail"
        assert [(r.cells[0], r.cells[2]) for r in app._rows] == [("198.51.100.10", "80/tcp")]
        assert app._active_tab == "inventory"
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert app.view.kind == "inventory"
        assert app._rows[app.query_one(DataTable).cursor_row].cells[0] == "nginx"


async def test_filtering_by_source_and_by_conflict():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        app._set_filter("http-server-header")
        app._reload_rows()
        await pilot.pause(0.3)
        assert [r.cells[0] for r in app._rows] == ["nginx"]
        app._set_filter("conflict")
        app._reload_rows()
        await pilot.pause(0.3)
        assert [r.cells[0] for r in app._rows] == ["OpenSSH"]


async def test_sorting_by_the_conflict_column_brings_conflicts_together():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        await pilot.press("8")
        await pilot.pause(0.2)
        await pilot.press("8")
        await pilot.pause(0.2)
        flags = [r.cells[7] for r in app._rows]  # Conflict
        first = flags.index("conflict")
        assert flags[first:first + flags.count("conflict")] == ["conflict"] * flags.count(
            "conflict")


async def test_a_service_record_lists_its_software_with_sources():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        host = next(h for h in app.scans.hosts if h.address == "198.51.100.10")
        svc = next(s for s in host.services if s.port == 22)
        from seek.tui.nmap import detail
        shown = _text(detail.render(svc, host, inventory=app.session.inventory()))
        assert "Software (1)" in shown
        assert "OpenSSH 8.2p1" in shown and "conflicting versions" in shown
        assert "cpe:2.3:a:openbsd:openssh:8.2p1" in shown
        assert "banner" in shown and "8.9p1" in shown


async def test_the_record_pane_and_the_reader_show_the_block():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        idx = next(i for i, r in enumerate(app._rows) if r.cells[0] == "OpenSSH")
        app.query_one(DataTable).move_cursor(row=idx)
        await pilot.press("enter")
        await pilot.pause(0.3)
        row = app._rows[0]
        for full in (False, True):
            lines, _title = record_mod.record_lines(row, app.view.title, app.session,
                                                    full=full)
            shown = _text(lines)
            assert "Software" in shown and "conflicting versions" in shown


async def test_an_entry_record_says_where_it_runs():
    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        row = next(r for r in app._rows if r.cells[0] == "OpenSSH")
        lines, _ = record_mod.record_lines(row, "Inventory", app.session)
        shown = _text(lines)
        assert "Conflicting versions" in shown
        assert "8.2p1 (nmap), 8.9p1 (banner)" in shown
        assert "Runs on (1)" in shown


async def test_the_export_dialog_writes_the_inventory_of_the_view(monkeypatch):
    import json

    from textual.widgets import OptionList

    captured = {}
    monkeypatch.setattr("seek.actions.copy_to_clipboard",
                        lambda text: captured.update(text=text))

    async def choose(pilot, app, choice):
        options = app.screen.query_one(OptionList)
        options.highlighted = options.get_option_index(choice)
        await pilot.press("enter")
        await pilot.pause(0.3)

    app = _app()
    async with app.run_test(size=(160, 40)) as pilot:
        await _inventory(pilot, app)
        app._set_filter("conflict")
        app._reload_rows()
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.3)
        await choose(pilot, app, "inventory")
        await choose(pilot, app, "json")
        await choose(pilot, app, "clipboard")
    doc = json.loads(captured["text"])
    assert doc["schema"] == "seek.inventory"
    assert [(e["port"], e["product"]) for e in doc["entries"]] == [(22, "OpenSSH")]
