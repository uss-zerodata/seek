"""`w` in the nmap viewer: start once, open at the selected row, stop on quit."""

from __future__ import annotations

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
        assert opened[-1] == f"http://127.0.0.1:{port}/hosts/{address}"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/hosts", timeout=5) as r:
            assert json.load(r)["total"] == 4, "the viewer's own model"

        server, thread = app._web._server, app._web._thread
        await pilot.press("down")
        await pilot.pause(0.1)
        other = app._current_row().target.address
        await _press_w(pilot, app)
        assert (app._web._server, app._web._thread) == (server, thread), "reused"
        assert opened[-1].endswith(f"/hosts/{other}")
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
        assert f"/services/{target.protocol}/{target.port}?" in opened[-1]
        app._web.stop()
