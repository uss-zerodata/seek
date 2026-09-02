"""The capture, wired into the viewer.

No gowitness and no docker are needed: the probe is replaced, and where a
process would be started the runner is driven directly. What is under test is
the viewer's half - the export entry, the two runner slots, the quit guard, the
run list, and the two keys.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console
from textual.widgets import DataTable

from seek.config import Config
from seek.gowitness import results as gw
from seek.gowitness.capture import CaptureRun, capture_dir
from seek.gowitness.detect import Probe
from seek.nmap.merge import load
from seek.nmap.runner import ScanRun
from seek.nmap.views import prepare
from seek.runner import State
from seek.tui.menu import ChoiceScreen
from seek.tui.nmap.app import NmapApp

pytestmark = pytest.mark.asyncio

FIX = Path(__file__).parent / "fixtures" / "nmap"
SHOTS = Path(__file__).parent / "fixtures" / "gowitness" / "capture.jsonl"


def _app(tmp_path, *, available: bool = True, backend: str = "docker") -> NmapApp:
    paths = [FIX / "basic.xml"]
    cfg = Config()
    app = NmapApp(prepare(load(paths)), cfg, sources=paths, scan_dir=tmp_path)
    app.gowitness = (Probe(backend=backend, path="/usr/bin/docker",
                           image="ghcr.io/sensepost/gowitness")
                     if available else Probe(reason="docker is not on PATH, and "
                                                    "gowitness is not on PATH"))
    return app


def _capture(tmp_path, urls: list[str], **kw) -> CaptureRun:
    return CaptureRun(argv=["true"], paths=capture_dir(tmp_path), urls=urls,
                      backend="docker", **kw)


# --- two slots -----------------------------------------------------------


async def test_the_app_holds_a_slot_per_tool(tmp_path):
    """One `Runner` allows one run, so a slot per tool is exactly "serial
    within a tool, concurrent across them"."""
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        assert app.runner is not app.captures
        assert app.runner.busy() is None and app.captures.busy() is None


async def test_a_capture_and_a_scan_can_run_at_once(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        scan = ScanRun(argv=["sleep", "5"], preset="p", targets=["t"],
                       out_base=tmp_path / "s")
        shot = _capture(tmp_path, ["http://a:80"])
        app.runner._current, app.runner.runs = scan, [scan]
        app.captures._current, app.captures.runs = shot, [shot]
        assert app.runner.busy() is scan
        assert app.captures.busy() is shot, "the capture was not blocked by the scan"


async def test_a_second_capture_is_refused(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        running = _capture(tmp_path, ["http://a:80"])
        app.captures._current, app.captures.runs = running, [running]
        app._start_capture(list(app.scans.hosts and []) or [])
        await pilot.pause(0.3)
        assert len(app.captures.runs) == 1, "a second capture was started"


# --- the quit guard ------------------------------------------------------


async def test_the_quit_guard_covers_a_running_capture(tmp_path):
    """A capture is work in flight too - quitting throws it away."""
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        shot = _capture(tmp_path, ["http://a:80"])
        app.captures._current, app.captures.runs = shot, [shot]
        await pilot.press("q")
        await pilot.pause(0.4)
        assert isinstance(app.screen, ChoiceScreen), "quit was not guarded"
        assert app.is_running


async def test_quitting_is_unguarded_when_nothing_runs(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("q")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, ChoiceScreen)


# --- the run list --------------------------------------------------------


async def test_a_capture_appears_in_the_run_list_with_its_progress(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        shot = _capture(tmp_path, [f"http://a:{n}" for n in range(10)])
        shot.append("INFO result 🤖 target=http://a:0 status-code=200 title=x")
        shot.append("INFO result 🤖 target=http://a:1 status-code=200 title=y")
        app.captures.runs = [shot]
        app._activate("scans")
        await pilot.pause(0.4)
        row = next(r for r in app._rows if r.target is shot)
        assert "capture" in row.cells[0]
        assert row.cells[1] == "10 urls"
        assert "2/10 captured" in row.cells[4]


async def test_a_finished_capture_keeps_its_row(tmp_path):
    """A capture leaves no scan file, so nothing in the history replaces it."""
    app = _app(tmp_path)
    async with app.run_test(size=(110, 30)) as pilot:
        await pilot.pause(0.3)
        shot = _capture(tmp_path, ["http://a:80"])
        shot.state, shot.result = State.DONE, "1 captured"
        app.captures.runs = [shot]
        app._activate("scans")
        await pilot.pause(0.4)
        assert any(r.target is shot for r in app._rows)


async def test_the_capture_report_reads_three_ways(tmp_path):
    from seek.tui.nmap import scans as scan_views

    shot = _capture(tmp_path, ["http://a:80", "http://b:80"])
    shot.append("INFO result 🤖 target=http://a:80 status-code=200 title=x")
    shot.append('ERRO failed to witness target target=http://b:80 err="timeout"')
    def rendered(mode: str) -> str:
        console = Console(width=100, record=True, file=open("/dev/null", "w"))
        console.print(scan_views.capture_report(shot, mode))
        return console.export_text()

    overview = rendered("overview")
    assert "targets" in overview and "captured" in overview
    assert "timeout" in rendered("diff"), "failures are readable nowhere else"
    assert "http://a:80" in rendered("raw")


# --- the export entry ----------------------------------------------------


async def test_the_export_dialog_offers_a_capture(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.4)
        assert isinstance(app.screen, ChoiceScreen)
        ids = [cid for cid, _label in app.screen._choices]
        assert "capture" in ids
        assert "capture" not in app.screen._disabled


async def test_the_capture_entry_is_shown_but_disabled_when_unavailable(tmp_path):
    """A hidden feature is undiscoverable; a disabled one with its reason
    teaches what is missing."""
    app = _app(tmp_path, available=False)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.4)
        labels = dict(app.screen._choices)
        assert "capture" in labels, "the entry was hidden rather than disabled"
        assert "capture" in app.screen._disabled
        assert "not on PATH" in labels["capture"]


async def test_a_disabled_entry_cannot_be_chosen(tmp_path):
    app = _app(tmp_path, available=False)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("x")
        await pilot.pause(0.4)
        screen = app.screen
        screen.choose("capture")
        await pilot.pause(0.2)
        assert app.screen is screen, "a disabled choice was accepted"


# --- the status bar ------------------------------------------------------


async def test_the_status_bar_names_the_backend(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(140, 30)) as pilot:
        await pilot.pause(0.3)
        assert "gowitness docker" in app.gowitness.label()


async def test_the_status_bar_says_when_it_is_missing(tmp_path):
    app = _app(tmp_path, available=False)
    async with app.run_test(size=(140, 30)) as pilot:
        await pilot.pause(0.3)
        assert app.gowitness.label() == "◉ gowitness not found"


# --- the keys ------------------------------------------------------------


async def test_i_says_so_when_there_is_no_capture(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("i")
        await pilot.pause(0.3)
        assert app._record_captures() == []


async def test_i_offers_a_picker_when_a_record_has_several(tmp_path):
    """The detail pane is a report, not a list - so the picker is what selects."""
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        from seek.tui.nmap import detail as detail_pane
        host = next(h for h in app.scans.hosts for s in h.open_services
                    if detail_pane._service_urls(s, h))
        urls = [u for s in host.open_services
                for u in detail_pane._service_urls(s, host)]
        app.shots.add([gw.Capture(url=u, status=200, reason="OK",
                                  shot=tmp_path / "a.jpeg") for u in urls[:2]])
        app._select_target(host)
        await pilot.pause(0.2)
        found = app._record_captures()
        assert len(found) >= 2


async def test_a_failed_capture_offers_no_screenshot(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        from seek.tui.nmap import detail as detail_pane
        host, svc = next((h, s) for h in app.scans.hosts for s in h.open_services
                         if detail_pane._service_urls(s, h))
        url = detail_pane._service_urls(svc, host)[0]
        app.shots.add_failures({url: "connection refused"})
        capture = app.shots.get(url)
        assert capture.failed and capture.shot is None


async def test_W_refuses_before_anything_is_captured(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        await pilot.press("W")
        await pilot.pause(0.4)
        assert app._report_proc is None, "a server was started with no database"


async def test_the_report_server_is_stopped_on_exit(tmp_path):
    class _Proc:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        proc = _Proc()
        app._report_proc = proc
    assert proc.terminated, "a web server was left running behind a closed viewer"


# --- reading a capture directory on startup ------------------------------


async def test_an_external_capture_directory_is_read_at_startup(tmp_path):
    """What is on disk is used, whoever produced it - the same principle the
    scan history already follows."""
    paths = capture_dir(tmp_path)
    paths.root.mkdir(parents=True)
    paths.jsonl.write_text(SHOTS.read_text())
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        assert len(app.shots) == 7
        assert app.shots.get("https://sso.hektor.cc:443") is not None


async def test_no_capture_directory_is_not_an_error(tmp_path):
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        assert len(app.shots) == 0
        assert app.shots.problems == []


# --- refusing to capture nothing -----------------------------------------


async def test_a_selection_with_no_http_service_is_refused(tmp_path):
    """A capture of nothing looks like a capture that found nothing."""
    app = _app(tmp_path)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause(0.3)
        app._start_capture([])
        await pilot.pause(0.4)
        assert app.captures.runs == []
        assert app.query_one(DataTable) is not None
