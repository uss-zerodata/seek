"""`w` in the nmap viewer: start once, open at the selected row, stop on quit."""

from __future__ import annotations

import asyncio
import json
import socket
import urllib.request

import pytest
from test_web import NMAP, _captures, _database
from textual.widgets import DataTable, Static

from seek.config import Config
from seek.gowitness.detect import Probe
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import app as app_mod
from seek.tui.nmap.app import NmapApp

pytestmark = pytest.mark.asyncio


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def opened(monkeypatch):
    """Every browser the viewer would have opened, instead of opening it."""
    seen: list[str] = []
    monkeypatch.setattr(app_mod, "_open_browser", seen.append)
    return seen


def _app(tmp_path, port: int) -> NmapApp:
    paths = [NMAP / "basic.xml", NMAP / "vuln.xml"]
    app = NmapApp(prepare(load(paths)), Config(web_port=port), sources=paths,
                  scan_dir=tmp_path)
    app.gowitness = Probe(reason="not needed here")
    app.shots.add(_captures(_database(tmp_path)).all())
    return app


async def _press_w(pilot, app) -> None:
    await pilot.press("w")
    for _ in range(50):
        await pilot.pause(0.1)
        if app._web is not None and app._web.running:
            break
    await pilot.pause(0.2)


async def test_w_starts_the_interface_once_and_opens_the_selected_host(tmp_path, opened):
    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        address = app._current_row().target.address
        await _press_w(pilot, app)
        assert app._web.running
        assert opened[-1] == f"http://127.0.0.1:{port}/v/hosts?path=h%3A{address}"
        def fetch():
            # The server runs on this very loop: the request must not block it.
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/hosts",
                                        timeout=5) as r:
                return json.load(r)

        assert (await asyncio.to_thread(fetch))["total"] == 4, "the viewer's own model"

        server, task = app._web._server, app._web._task
        await pilot.press("down")
        await pilot.pause(0.1)
        other = app._current_row().target.address
        await pilot.press("w")                  # running: `w` asks first
        await pilot.pause(0.3)
        app.screen.choose("open")
        await _settled(pilot, lambda: opened[-1].endswith(other))
        assert (app._web._server, app._web._task) == (server, task), "reused"
        assert opened[-1].endswith(f"/v/hosts?path=h%3A{other}")
        status = str(app.query_one("#status", Static).render())
        assert f"web http://127.0.0.1:{port}" in status
        app._web.stop()


async def test_quitting_stops_the_interface(tmp_path, opened):
    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        await _press_w(pilot, app)
        web = app._web
        assert web.running
        await pilot.press("ctrl+q")
        await pilot.pause(0.5)
    for _ in range(30):                       # it finishes on the loop by itself
        if not web.running:
            break
        await asyncio.sleep(0.1)
    assert not web.running
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))


async def test_a_refused_address_is_a_notification_not_a_crash(tmp_path, opened):
    app = _app(tmp_path, _free_port())
    app.config.web_host = "0.0.0.0"
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("w")
        await pilot.pause(1.0)
        assert not app._web.running and opened == []
        assert any("loopback only" in str(n.message) for n in app._notifications)


async def test_w_and_W_are_separate_servers(tmp_path, opened):
    """`W` is gowitness's own report server; `w` does not replace it."""
    keys = {b.key: b.action for b in NmapApp.BINDINGS}
    assert keys["W"] == "report_server" and keys["w"] == "open_web"


async def test_the_web_interface_is_in_the_command_palette():
    from seek.tui.nmap.commands import _STATIC

    assert any("web" in title.lower() and method == "action_open_web"
               for title, _sub, method, _arg in _STATIC)


async def test_a_service_row_opens_that_service(tmp_path, opened):
    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        app._activate("services")
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        target = app._rows[table.cursor_row].target
        await _press_w(pilot, app)
        assert f"/v/services?path=s%3A{target.protocol}%2F{target.port}%2F" in opened[-1]
        app._web.stop()


async def test_i_offers_every_capture_of_a_service_in_the_browser(tmp_path, opened):
    from seek.tui.menu import ChoiceScreen

    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        assert app._current_row().target.address == "192.0.2.1"
        await pilot.press("enter")                     # its ports
        await pilot.pause(0.3)
        table = app.query_one(DataTable)
        table.move_cursor(row=next(i for i, r in enumerate(app._rows)
                                   if r.target.port == 80))
        await pilot.pause(0.1)
        await pilot.press("i")
        await pilot.pause(0.3)
        picker = app.screen
        assert isinstance(picker, ChoiceScreen)
        assert "All 2 side by side" in str(picker._choices[0][1])
        picker.choose("web")
        for _ in range(50):
            await pilot.pause(0.1)
            if opened:
                break
        assert opened[-1] == (f"http://127.0.0.1:{port}/"
                              "?address=192.0.2.1&protocol=tcp&port=80")
        app._web.stop()


# --- the session is shared with the browser ------------------------------------------


async def test_a_mark_from_the_browser_shows_in_the_terminal(tmp_path):
    from seek.nmap.export import Record

    app = _app(tmp_path, _free_port())
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        cursor = app.query_one(DataTable).cursor_row
        host = next(h for h in app.scans.hosts if h.address == "192.0.2.30")
        app.session.toggle((Record(host),), origin="web")
        await pilot.pause(0.3)
        row = next(r for r in app._rows if r.cells[0] == "192.0.2.30")
        assert app._mark_glyph(row) == "●"
        assert "1 marked" in str(app.query_one("#status", Static).render())
        assert app.query_one(DataTable).cursor_row == cursor, "the cursor stays put"


async def test_quitting_asks_about_a_scan_started_in_the_browser(tmp_path):
    import sys

    from seek.nmap.runner import ScanRun
    from seek.tui.menu import ChoiceScreen

    app = _app(tmp_path, _free_port())
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        tab = app._active_tab
        run = ScanRun(preset="from the browser",
                      argv=[sys.executable, "-c", "import time; time.sleep(30)"],
                      targets=["192.0.2.1"], out_base=tmp_path / "out")
        app.session.start_scan(run, origin="web")
        await pilot.pause(0.5)
        assert app._active_tab == tab, "a browser-started run does not move the terminal"
        await pilot.press("ctrl+q")
        await pilot.pause(0.5)
        assert isinstance(app.screen, ChoiceScreen), "the quit guard asks"
        assert app.is_running
        app.session.cancel_all()
        await pilot.pause(1.0)


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        return sock.connect_ex(("127.0.0.1", port)) == 0


async def _settled(pilot, test, tries: int = 50) -> None:
    for _ in range(tries):
        await pilot.pause(0.1)
        if test():
            return


async def test_w_while_running_asks_and_can_stop_it(tmp_path, opened, monkeypatch):
    from seek.tui.menu import ChoiceScreen

    copied = []
    monkeypatch.setattr(app_mod.actions, "copy_to_clipboard", copied.append)
    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        await _press_w(pilot, app)
        before = len(opened)
        await pilot.press("w")
        await pilot.pause(0.3)
        assert isinstance(app.screen, ChoiceScreen)
        app.screen.choose("open")
        await _settled(pilot, lambda: len(opened) > before)
        assert len(opened) == before + 1, "open: the browser again, as before"
        await pilot.press("w")
        await pilot.pause(0.3)
        app.screen.choose("copy")
        await pilot.pause(0.2)
        assert copied == [f"http://127.0.0.1:{port}"]
        await pilot.press("w")
        await pilot.pause(0.3)
        app.screen.choose("stop")
        await _settled(pilot, lambda: not app._web.running)
        assert not app._web.running and not _port_open(port)
        assert app.is_running, "the viewer carries on"
        await _press_w(pilot, app)
        assert app._web.running and _port_open(port), "w starts it again"


async def test_the_browsers_stop_stops_only_the_interface(tmp_path, opened):
    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        await _press_w(pilot, app)
        url = f"http://127.0.0.1:{port}"

        def stop():
            request = urllib.request.Request(url + "/api/v1/web/stop", data=b"{}",
                                             method="POST", headers={"Origin": url})
            with urllib.request.urlopen(request, timeout=5) as response:
                return json.load(response)

        assert (await asyncio.to_thread(stop)) == {"stopping": True, "ends": "web"}
        await _settled(pilot, lambda: not app._web.running)
        assert not _port_open(port) and app.is_running


async def test_stopping_leaves_a_running_scan_alone(tmp_path, opened):
    from seek.nmap.runner import ScanRun

    port = _free_port()
    app = _app(tmp_path, port)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        await _press_w(pilot, app)
        run = ScanRun(preset="stub", argv=["sleep", "3"], targets=["t"],
                      out_base=tmp_path / "o")
        app.session.start_scan(run, origin="tui")
        await pilot.pause(0.3)
        app.action_stop_web()
        await _settled(pilot, lambda: not app._web.running)
        assert run.running, "the scan carries on"
        app.session.cancel_all()
        await pilot.pause(0.5)


async def test_the_palette_says_when_there_is_nothing_to_stop(tmp_path, opened):
    said = []
    app = _app(tmp_path, _free_port())
    app.notify = lambda message, **_kw: said.append(str(message))
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        app.action_stop_web()
        assert "the web interface is not running" in said
