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


# --- tags ----------------------------------------------------------------------------

from seek.nmap import tagfiles  # noqa: E402

WEB_NO_SSH = ("tags:\n  web-only:\n    issues: [{title: Exposed, severity: low}]\n"
              "    rules: [{when: [{port: 80}, {not: {port: 22/tcp}}]}]\n")


def _engagement(tmp_path, rules: str | None = WEB_NO_SSH) -> Session:
    eng = tmp_path / "eng"
    eng.mkdir(exist_ok=True)
    scan = eng / "basic.xml"
    scan.write_bytes((FIX / "basic.xml").read_bytes())
    if rules is not None:
        (eng / "seek-rules.yaml").write_text(rules)
    return Session(Config(nmap_path="/nonexistent/nmap"), [eng], eng, databases=[],
                   scans=prepare(load([scan])))


async def test_tags_are_computed_from_the_session_s_files_and_cached(tmp_path):
    session = _engagement(tmp_path)
    tags = session.tags()
    assert set(tags.hosts) == {"192.0.2.2"}, "192.0.2.1 has ssh open"
    assert session.tags() is tags, "nothing changed, nothing rebuilt"
    assert session.tags_ready() is tags


async def test_tags_ready_leaves_a_large_model_to_the_worker(tmp_path, monkeypatch):
    session = _engagement(tmp_path)
    monkeypatch.setattr(Session, "INLINE_TAG_HOSTS", 1)
    assert session.tags_ready() is None
    built = session.tags()
    assert session.tags_ready() is built


async def test_a_tag_added_in_one_front_end_reaches_the_others(tmp_path):
    session = _engagement(tmp_path)
    seen: list[Event] = []
    session.listen(seen.append)
    host = next(h for h in session.scans.hosts if h.address == "192.0.2.1")
    change = session.plan_tag([Record(host)], "explored", add=True)
    result = await session.apply_tag_change(change, origin="web")
    assert result.ok and result.saved == (tmp_path / "eng" / "seek-tags.yaml",)
    assert [(e.type, e.origin) for e in seen] == [("tags", "web")]
    assert "explored" in session.tags().of_host("192.0.2.1")


async def test_memory_changes_only_after_a_successful_write(tmp_path):
    session = _engagement(tmp_path)
    (tmp_path / "eng" / "seek-tags.yaml").write_text("entries: [unclosed\n")
    generation = session.tags_generation
    host = session.scans.hosts[0]
    result = await session.apply_tag_change(session.plan_tag([Record(host)], "x", True))
    assert not result.ok and "Fix the file first" in result.errors[0]
    assert (tmp_path / "eng" / "seek-tags.yaml").read_text() == "entries: [unclosed\n"
    assert session.tags_generation == generation + 1, "the error is announced"
    assert "x" not in session.tags().of_host(host.address)


async def test_a_bad_tag_name_is_refused_before_anything_is_written(tmp_path):
    session = _engagement(tmp_path)
    with pytest.raises(ValueError, match="not a tag name"):
        session.plan_tag([Record(session.scans.hosts[0])], "my tag", add=True)
    assert not (tmp_path / "eng" / "seek-tags.yaml").exists()


async def test_removal_reaches_a_subfolder_s_file_and_names_a_failure(tmp_path):
    session = _engagement(tmp_path, rules=None)
    eng = tmp_path / "eng"
    for sub in ("alice", "bob"):
        (eng / sub).mkdir()
        (eng / sub / "seek-tags.yaml").write_text(
            "entries:\n  - {tag: explored, host: 192.0.2.1}\n")
    await session.reload_tags()
    (eng / "bob" / "seek-tags.yaml.lock").write_text("1@elsewhere")
    tagfiles.LOCK_WAIT, saved_wait = 0.1, tagfiles.LOCK_WAIT
    try:
        host = next(h for h in session.scans.hosts if h.address == "192.0.2.1")
        result = await session.apply_tag_change(session.plan_tag([Record(host)], "explored",
                                                                 add=False))
    finally:
        tagfiles.LOCK_WAIT = saved_wait
    assert result.saved == (eng / "alice" / "seek-tags.yaml",)
    (error,) = result.errors
    assert "bob/seek-tags.yaml" in error and "being written by another seek" in error
    assert "explored" not in (eng / "alice" / "seek-tags.yaml").read_text()


async def test_a_copy_to_the_global_file_carries_no_address(tmp_path, monkeypatch):
    config = tmp_path / "config"
    session = _engagement(tmp_path)
    monkeypatch.setattr(Session, "_config_dir", lambda self: config)
    host = session.scans.hosts[0]
    await session.apply_tag_change(session.plan_tag([Record(host)], "web-only", True))
    result = await session.apply_tag_change(session.plan_copy_global("web-only"))
    text = (config / "tags.yaml").read_text()
    assert result.ok and "Exposed" in text and "192.0.2" not in text


NEW_HOST = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p 22,80 192.0.2.77" start="1767225600">
<scaninfo type="syn" protocol="tcp" numservices="2" services="22,80"/>
<host><status state="up" reason="syn-ack"/><address addr="192.0.2.77" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http"/></port></ports></host>
</nmaprun>
"""


async def test_a_new_model_with_a_matching_host_is_tagged(tmp_path):
    session = _engagement(tmp_path)
    before = session.tags()
    (tmp_path / "eng" / "live.xml").write_text(NEW_HOST)
    session.publish(prepare(load([tmp_path / "eng" / "basic.xml", tmp_path / "eng" / "live.xml"])))
    after = session.tags()
    assert set(after.hosts) == {"192.0.2.2", "192.0.2.77"}
    assert not after.of_host("192.0.2.77")["web-only"].uncertain, "22/tcp was probed"
    assert set(before.hosts) == {"192.0.2.2"}, "the old set is never changed"


async def test_a_finished_capture_retags_without_a_re_read(tmp_path):
    session = _engagement(tmp_path, rules=("tags:\n  login:\n"
                                           "    rules: [{when: [{port: 80, title: Login}]}]\n"))
    assert not session.tags().hosts
    from seek.gowitness.results import Capture
    session.shots.add([Capture("http://192.0.2.2", title="Login")])
    assert set(session.tags().hosts) == {"192.0.2.2"}


async def test_marks_survive_a_retag(tmp_path):
    session = _engagement(tmp_path)
    record = Record(session.scans.hosts[0])
    session.toggle([record])
    await session.reload_tags()
    session.tags()
    assert record.identity in session.marks


async def test_an_edited_rule_file_is_read_on_the_next_publication(tmp_path):
    session = _engagement(tmp_path)
    assert set(session.tags().hosts) == {"192.0.2.2"}
    import time
    time.sleep(0.01)
    (tmp_path / "eng" / "seek-rules.yaml").write_text(
        "tags:\n  any-web:\n    rules: [{when: [{port: 80}]}]\n")
    session.publish(session.scans)
    assert set(session.tags().hosts) == {"192.0.2.1", "192.0.2.2"}


async def test_a_row_s_tags_are_words_of_it_until_removed(tmp_path):
    from seek.tui.nmap import views as vdefs

    session = _engagement(tmp_path, rules=None)
    host = next(h for h in session.scans.hosts if h.address == "192.0.2.1")
    await session.apply_tag_change(session.plan_tag([Record(host)], "zebra-zd420", True))
    rows = vdefs.hosts_view().rows(session.scans)
    spec = session.filter_spec("zebra")
    assert [r.cells[0] for r in rows if session.row_matches(spec, r)] == ["192.0.2.1"]
    await session.apply_tag_change(session.plan_tag([Record(host)], "zebra-zd420", False))
    assert not [r for r in rows if session.row_matches(session.filter_spec("zebra"), r)]


async def test_the_filter_says_when_tags_are_not_ready(tmp_path, monkeypatch):
    session = _engagement(tmp_path)
    monkeypatch.setattr(Session, "INLINE_TAG_HOSTS", 0)
    spec = session.filter_spec("tag:web-only")
    assert spec.is_empty and any("tags not ready" in i for i in spec.ignored)
    session.tags()
    assert not session.filter_spec("tag:web-only").is_empty
