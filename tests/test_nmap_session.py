"""The session: one model, runs and marks behind every front end."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from seek.config import Config
from seek.nmap.export import Record
from seek.nmap.merge import load
from seek.nmap.runner import ScanRun
from seek.nmap.session import Busy, Event, Session, Subscription
from seek.nmap.views import prepare
from seek.runner import State

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _session(tmp_path) -> Session:
    paths = [FIX / "basic.xml"]
    return Session(Config(nmap_path="/nonexistent/nmap"), paths, tmp_path,
                   databases=[], scans=prepare(load(paths)))


def _run(tmp_path, code: str) -> ScanRun:
    return ScanRun(preset="stub", argv=[sys.executable, "-c", code],
                   targets=["192.0.2.1"], out_base=tmp_path / "out")


class _Owner:
    def __init__(self):
        self.scans: list = []
        self.captures: list = []

    def scan_done(self, run):
        self.scans.append(run)

    def capture_done(self, run):
        self.captures.append(run)


async def test_a_run_streams_lines_and_tells_its_owner(tmp_path):
    session = _session(tmp_path)
    owner = _Owner()
    session.owner = owner
    events: list[Event] = []
    states: list[bool] = []          # a run is one object; its state moves on
    session.listen(lambda e: (events.append(e),
                              states.append(e.run.running) if e.type == "run" else None))
    await session.start_scan(_run(tmp_path, "print('one'); print('two')"), origin="web")
    kinds = [(e.type, e.origin) for e in events]
    assert ("line", "web") in kinds
    assert [e.text for e in events if e.type == "line"] == ["one", "two"]
    assert states == [True, False], "started, then ended"
    assert owner.scans and owner.scans[0].state is State.DONE


async def test_one_run_per_tool_whoever_asks(tmp_path):
    session = _session(tmp_path)
    first = session.start_scan(_run(tmp_path, "import time; time.sleep(5)"), origin="tui")
    await asyncio.sleep(0.2)
    with pytest.raises(Busy, match="a scan is already running: "):
        session.start_scan(_run(tmp_path, "print(1)"), origin="web")
    assert session.cancel("nmap") is not None
    await first
    assert session.runner.runs[0].state is State.CANCELLED


async def test_marks_are_shared_and_toggle_as_a_row_does(tmp_path):
    session = _session(tmp_path)
    events: list[Event] = []
    session.listen(events.append)
    host = session.scans.hosts[0]
    records = tuple(Record(host, s) for s in host.services)
    assert session.toggle(records, origin="web") is True
    assert list(session.marks) == [r.identity for r in records]
    assert session.toggle(records, origin="tui") is False, "all marked: unmark"
    assert not session.marks
    session.toggle(records[:1])
    session.clear_marks(origin="web")
    assert not session.marks
    assert [e.origin for e in events if e.type == "marks"] == ["web", "tui", "", "web"]


async def test_marks_follow_a_new_model(tmp_path):
    session = _session(tmp_path)
    host = session.scans.hosts[0]
    session.toggle((Record(host, host.services[0]),))
    session.publish(prepare(load([FIX / "basic.xml"])), origin="tui")
    (record,) = session.marks.values()
    assert record.host is session.scans.hosts[0], "re-found in the new model"


async def test_a_slow_subscriber_drops_lines_not_runs():
    sub = Subscription(queue=asyncio.Queue(3))
    for i in range(5):
        sub.put(Event("line", text=str(i)))
    sub.put(Event("model"))
    assert sub.dropped >= 2
    seen = [sub.queue.get_nowait() for _ in range(sub.queue.qsize())]
    assert seen[-1].type == "model", "what matters still arrives"


async def test_stopping_a_listener(tmp_path):
    session = _session(tmp_path)
    events: list[Event] = []
    stop = session.listen(events.append)
    stop()
    session.clear_marks()
    session.publish(session.scans)
    assert events == []


async def test_a_started_scan_is_remembered_without_its_targets(tmp_path):
    from seek.paths import state_dir

    session = _session(tmp_path)
    run = ScanRun(preset="stub", argv=[sys.executable, "-c", "print(1)", "-v",
                                       "192.0.2.77"],
                  targets=["192.0.2.77"], out_base=tmp_path / "out")
    await session.start_scan(run)
    stored = (state_dir() / "nmap-commands.json").read_text()
    assert "192.0.2.77" not in stored and str(tmp_path) not in stored
    recent, _frequent = session.earlier_commands()
    assert recent and recent[0].where == "history"
