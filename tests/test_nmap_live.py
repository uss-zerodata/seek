"""A running scan's finished hosts, read in before the scan ends.

nmap writes each finished host group to its XML while it runs and prints a
report line per host; the stand-in here does the same, then keeps running.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from seek.config import Config
from seek.nmap import session as session_mod
from seek.nmap.merge import load
from seek.nmap.runner import ScanRun, State
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.web.serve import HeadlessOwner

pytestmark = pytest.mark.slow

FIX = Path(__file__).parent / "fixtures" / "nmap"
NEW = "192.0.2.50"

# The XML so far: a host group written, `</nmaprun>` still to come.
def _partial(addr: str) -> str:
    return f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sS" start="1762000000" version="7.94">
<host><status state="up" reason="syn-ack"/><address addr="{addr}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
<service name="http-proxy" method="table" conf="3"/></port></ports></host>
"""


def _nmap(xml: Path, report: bool = True, then: str = "time.sleep(30)",
          addr: str = NEW) -> list[str]:
    code = (f"import pathlib, time; pathlib.Path({str(xml)!r}).write_text({_partial(addr)!r}); "
            + (f"print('Nmap scan report for {addr}', flush=True); " if report else "")
            + then)
    return [sys.executable, "-c", code]


def _session(tmp_path: Path) -> Session:
    paths = [FIX / "basic.xml"]
    session = Session(Config(nmap_path="/nonexistent/nmap"), list(paths), tmp_path,
                      databases=[], scans=prepare(load(paths)))
    session.owner = HeadlessOwner(session)
    return session


def _run(tmp_path: Path, name: str = "out", **kwargs) -> ScanRun:
    out = tmp_path / name
    return ScanRun(preset="Sweep", argv=_nmap(out.with_suffix(".xml"), **kwargs),
                   targets=["192.0.2.0/24"], out_base=out)


async def _until(test, seconds: float = 8.0) -> bool:
    for _ in range(int(seconds / 0.05)):
        if test():
            return True
        await asyncio.sleep(0.05)
    return test()


def _addresses(session: Session) -> set[str]:
    return {h.address for h in session.scans.hosts}


@pytest.fixture(autouse=True)
def _fast(monkeypatch):
    monkeypatch.setattr(session_mod, "LIVE_SETTLE", 0.05)


async def test_finished_hosts_are_in_the_model_while_the_scan_runs(tmp_path):
    session = _session(tmp_path)
    run = _run(tmp_path)
    task = session.start_scan(run)
    assert await _until(lambda: NEW in _addresses(session)), "read in while running"
    assert run.running
    assert "1 new host(s)" in session.diffs[id(run)].summary()
    assert run.xml_path in session.running_paths()
    assert not session.file_grew(run), "nothing new since: no second read"
    session.cancel("nmap", run)
    await task
    assert await _until(lambda: run.state is State.CANCELLED and not session.running_paths())
    await asyncio.sleep(0.5)                    # the final read
    assert NEW in _addresses(session), "a cancelled scan keeps what it finished"
    assert "1 new host(s)" in session.diffs[id(run)].summary(), "counted once, from the start"


async def test_no_report_line_reads_nothing(tmp_path):
    session = _session(tmp_path)
    run = _run(tmp_path, report=False)
    task = session.start_scan(run)
    await asyncio.sleep(0.6)
    assert NEW not in _addresses(session), "nmap said no host was finished"
    session.cancel("nmap", run)
    await task


async def test_reads_are_paced(tmp_path):
    session = _session(tmp_path)
    run = _run(tmp_path, then=(f"time.sleep(0.3); print('Nmap scan report for {NEW}', "
                               "flush=True); time.sleep(30)"))
    task = session.start_scan(run)
    assert await _until(lambda: NEW in _addresses(session))
    await asyncio.sleep(0.6)
    assert id(run) in session._live_timers, "the second report waits out the pause"
    session.cancel("nmap", run)
    await task
    assert id(run) not in session._live_timers, "the end clears it"


async def test_two_scans_ending_together_each_count_their_own(tmp_path):
    """Every read re-reads every source: the first scan's final read also takes
    in the second's file. Neither may count the other's hosts, and the second
    must not say "nothing new" for hosts only it found."""
    session = _session(tmp_path)
    one = _run(tmp_path, "one", addr="10.9.9.1", then="time.sleep(0.3)")
    two = _run(tmp_path, "two", addr="10.9.9.2", then="time.sleep(0.6)")
    await asyncio.gather(session.start_scan(one), session.start_scan(two))
    assert await _until(lambda: {"10.9.9.1", "10.9.9.2"} <= _addresses(session))
    await asyncio.sleep(0.5)
    assert session.diffs[id(one)].summary() == "1 new host(s)"
    assert session.diffs[id(two)].summary() == "1 new host(s)"
    assert not session.baselines, "dropped after the final read"


# --- in the viewer ------------------------------------------------------------------


def _app(tmp_path: Path):
    from seek.tui.nmap.app import NmapApp

    paths = [FIX / "basic.xml"]
    return NmapApp(prepare(load(paths)), Config(nmap_path="/nonexistent/nmap"),
                   sources=list(paths), scan_dir=tmp_path)


async def _settled(pilot, test, tries: int = 100) -> bool:
    for _ in range(tries):
        await pilot.pause(0.1)
        if test():
            return True
    return test()


async def test_the_viewer_reads_a_running_scan_quietly(tmp_path):
    from rich.text import Text

    from seek.tui.nmap import tabs

    app = _app(tmp_path)
    said: list[str] = []
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        app.notify = lambda text, **_kw: said.append(str(text))
        app._activate("hosts")
        await pilot.pause(0.3)
        await pilot.press("end")
        await pilot.pause(0.3)
        held = app._current_row().cells[0]
        run = _run(tmp_path, addr="10.9.9.9")      # sorts in above every row
        app.session.start_scan(run, origin="web")
        assert await _settled(pilot, lambda: "10.9.9.9" in {h.address for h in app.scans.hosts})
        assert run.running
        await pilot.pause(0.5)
        assert app._current_row().cells[0] == held, "the cursor follows its row, not its number"
        assert isinstance(app._live_note, Text) and "so far" in app._live_note.plain
        assert "so far" in str(app.query_one("#status").render())
        app._say_unread(app.scans)
        assert not any("incomplete" in s for s in said), "a running file is not cut off"
        rows = tabs.scans_view(app.session).build(app.scans)
        assert sum(1 for r in rows if r.target is run) == 1
        assert not any(getattr(r.target, "path", None) == run.xml_path for r in rows), \
            "listed once: as the run"
        app.session.cancel_all()
        assert await _settled(pilot, lambda: not run.running)
        assert await _settled(pilot, lambda: any("stops part-way" in s for s in said))
        assert "10.9.9.9" in {h.address for h in app.scans.hosts}


async def test_c_with_two_scans_asks_which(tmp_path):
    from seek.tui.menu import ChoiceScreen

    app = _app(tmp_path)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause(0.3)
        one = _run(tmp_path, report=False)
        two = ScanRun(preset="Other", argv=_nmap(tmp_path / "two.xml", report=False),
                      targets=["192.0.2.9"], out_base=tmp_path / "two")
        app.session.start_scan(one, origin="web")
        app.session.start_scan(two, origin="web")
        await pilot.pause(0.5)
        await pilot.press("c")
        await pilot.pause(0.3)
        assert isinstance(app.screen, ChoiceScreen), "two running: which one?"
        await pilot.press("down", "enter")
        assert await _settled(pilot, lambda: not two.running)
        assert one.running, "the other keeps running"
        app.session.cancel_all()
        assert await _settled(pilot, lambda: not one.running)
