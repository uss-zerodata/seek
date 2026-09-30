"""The lookup in the terminal viewer: columns, filters, the Findings tab,
records, and the update that is offered but never started unasked."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
import vulndb_fixtures as fx
from rich.console import Console
from textual.widgets import DataTable, OptionList, Tabs

from seek.config import Config
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import record as record_mod
from seek.tui.nmap.app import NmapApp
from seek.tui.nmap.detail import as_group

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    return fx.database(tmp_path_factory.mktemp("vdb"))


def _app(db_path) -> NmapApp:
    return NmapApp(prepare(load([FIX / "inventory.xml"])),
                   Config(vulndb_path=str(db_path)))


async def _tab(pilot, app, tab):
    await pilot.pause(0.3)
    app.query_one(Tabs).active = tab
    await pilot.pause(0.5)


def _text(lines) -> str:
    console = Console(width=180, record=True, file=io.StringIO())
    console.print(as_group(lines))
    return console.export_text()


def _filter(app, text):
    app._set_filter(text)
    app._reload_rows()


async def test_the_inventory_says_support_vulns_and_the_worst(db):
    app = _app(db)
    async with app.run_test(size=(180, 40)) as pilot:
        await _tab(pilot, app, "inventory")
        rows = {(r.cells[0], r.cells[1]): r.cells for r in app._rows}
        nginx = rows[("nginx", "1.16.1")]
        assert nginx[2] == "EOL 2020-04-21"
        assert nginx[3] == "2" and nginx[4] == "7.7 high"
        tomcat = rows[("Apache Tomcat", "9.0.1")]
        assert tomcat[2] == "behind · 9.0.96 (ending soon)", "the 9 cycle ends 2026-12-01"
        assert tomcat[4].startswith("9.8"), "the scan's vulners finding counts"
        postfix = rows[("Postfix", "—")]
        assert postfix[3].startswith("?"), "an unversioned product is never 'none'"
        assert app._rows[0].cells[0] == "Apache Tomcat", "worst first by default"


async def test_filtering_by_support_severity_and_id(db):
    app = _app(db)
    async with app.run_test(size=(180, 40)) as pilot:
        await _tab(pilot, app, "inventory")
        _filter(app, "eol")
        await pilot.pause(0.3)
        assert {r.cells[0] for r in app._rows} == {"nginx"}
        _filter(app, "CVE-2099-0001")
        await pilot.pause(0.3)
        assert [(r.cells[0], r.cells[1]) for r in app._rows] == [("nginx", "1.16.1")]
        _filter(app, "critical")
        await pilot.pause(0.3)
        assert [r.cells[0] for r in app._rows] == ["Apache Tomcat"]


async def test_the_findings_tab_leads_from_a_cve_to_its_services(db):
    app = _app(db)
    async with app.run_test(size=(180, 40)) as pilot:
        await _tab(pilot, app, "findings")
        ids = [r.cells[0] for r in app._rows]
        assert {"CVE-2099-0001", "CVE-2099-0005", "CVE-2020-1938"} <= set(ids)
        idx = ids.index("CVE-2099-0001")
        app.query_one(DataTable).move_cursor(row=idx)
        await pilot.pause(0.1)
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert app.view.kind == "findings-detail"
        assert [(r.cells[0], r.cells[2]) for r in app._rows] == [("198.51.100.10", "80/tcp")]


async def test_a_service_record_lists_support_and_findings(db):
    app = _app(db)
    async with app.run_test(size=(180, 40)) as pilot:
        await _tab(pilot, app, "inventory")
        row = next(r for r in app._rows if r.cells[0] == "nginx" and r.cells[1] == "1.16.1")
        lines, _ = record_mod.record_lines(row, "Inventory", app.session)
        shown = _text(lines)
        assert "end of life since 2020-04-21" in shown
        assert "Known vulnerabilities (2)" in shown
        assert "CVE-2099-0001" in shown and "matched by version" in shown
        host = next(h for h in app.scans.hosts if h.address == "198.51.100.10")
        smtp = next(s for s in host.services if s.port == 25)
        from seek.tui.nmap import detail
        shown = _text(detail.render(smtp, host, inventory=app.session.inventory(),
                                    lookup=app.session.lookup()))
        assert "support" in shown


async def test_no_database_is_offered_once_and_never_fetched(tmp_path, monkeypatch):
    def forbidden(*_a, **_kw):
        raise AssertionError("nothing may be downloaded without confirmation")

    monkeypatch.setattr("seek.vulndb.update.run", forbidden)
    app = _app(tmp_path / "none.sqlite3")
    async with app.run_test(size=(180, 40)) as pilot:
        await pilot.pause(0.5)
        offers = [n for n in app._notifications if "press A" in str(n.message)]
        assert len(offers) == 1
        await pilot.press("A")
        await pilot.pause(0.3)
        assert type(app.screen).__name__ == "ChoiceScreen", "A asks before anything"
        options = app.screen.query_one(OptionList)
        options.highlighted = options.get_option_index("no")
        await pilot.press("enter")
        await pilot.pause(0.3)
        assert len(app.screen_stack) == 1
        app._offer_vulndb()
        await pilot.pause(0.1)
        assert len([n for n in app._notifications if "press A" in str(n.message)]) <= 1


async def test_a_fresh_database_is_not_offered(db):
    app = _app(db)
    async with app.run_test(size=(180, 40)) as pilot:
        await pilot.pause(0.5)
        assert not [n for n in app._notifications if "press A" in str(n.message)]
