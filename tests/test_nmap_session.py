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


async def test_scans_run_together_but_never_into_one_file(tmp_path):
    """A second scan is a warning, not a refusal - unless it would write the
    files a running scan writes."""
    session = _session(tmp_path)
    assert session.scan_warning() is None
    one = _run(tmp_path, "import time; time.sleep(5)")
    first = session.start_scan(one, origin="tui")
    await asyncio.sleep(0.2)
    assert "already running: stub" in session.scan_warning()
    with pytest.raises(Busy, match="already writing out"):
        session.start_scan(_run(tmp_path, "print(1)"), origin="web")
    two = ScanRun(preset="other", argv=[sys.executable, "-c", "import time; time.sleep(5)"],
                  targets=["192.0.2.2"], out_base=tmp_path / "out2")
    second = session.start_scan(two, origin="web")
    await asyncio.sleep(0.2)
    assert session.runner.active() == [one, two]
    assert session.cancel("nmap") is None, "two are running: which one?"
    assert session.cancel("nmap", two) is two
    await second
    assert two.state is State.CANCELLED and one.running
    assert session.cancel_all() == [one]
    await first
    assert one.state is State.CANCELLED


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


async def test_two_captures_in_the_same_moment_run_one(tmp_path):
    """`busy()` used to turn true a loop turn after the check: both passed."""
    from seek.gowitness.capture import CaptureRun, capture_dir
    from seek.gowitness.detect import Probe

    session = _session(tmp_path)
    session.gowitness = Probe(backend="native", path="/usr/bin/gowitness")

    def capture():
        return CaptureRun(argv=[sys.executable, "-c", "import time; time.sleep(0.5)"],
                          paths=capture_dir(tmp_path), urls=["http://192.0.2.1:80"])

    first = session.start_capture(capture())
    with pytest.raises(Busy):
        session.start_capture(capture())
    assert session.captures.runs == [session.captures.busy()]
    await first


async def test_a_second_scan_in_the_same_second_gets_its_own_files(tmp_path):
    from datetime import datetime

    from seek.nmap.presets import output_base

    when = datetime(2026, 11, 10, 12, 0, 0)
    first = output_base(tmp_path, "Quick", when)
    first.with_name(first.name + ".xml").write_text("")
    second = output_base(tmp_path, "Quick", when)
    assert second.name == first.name + "-2"
