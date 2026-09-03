"""Opening an engagement without waiting for it to be read.

The viewer used to be handed a finished model; now it is handed the files and
reads them itself, with the screen already up. That buys the wait back, and it
costs three guarantees that have to hold every time: the interface answers
input throughout, the model only ever grows, and what arrives is the same model
a blocking read would have produced.
"""

from __future__ import annotations

import shutil
import threading
from pathlib import Path

import pytest
from textual.widgets import DataTable, Static

from seek.config import Config
from seek.nmap.merge import Pending, discover, load
from seek.nmap.views import prepare
from seek.tui.nmap import app as app_mod
from seek.tui.nmap.app import NmapApp

pytestmark = pytest.mark.asyncio
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _corpus(tmp_path: Path, copies: int = 1, names=("basic", "discovery", "scripts")):
    """`copies` of each fixture, under distinct names, in one directory."""
    for n in range(copies):
        for name in names:
            shutil.copy(FIX / f"{name}.xml", tmp_path / f"{name}-{n:03d}.xml")
    return discover([tmp_path])


def _held(monkeypatch, release: threading.Event, after: int = 2):
    """Make the reader block partway through, so "partway" is a real state.

    The fixtures parse in microseconds, so without this every assertion about
    what the interface looks like mid-read would be a race against the reader
    finishing.
    """
    real = app_mod.parse_file
    seen = []

    def held(path):
        seen.append(path)
        if len(seen) > after:
            release.wait(5)
        return real(path)

    monkeypatch.setattr(app_mod, "parse_file", held)


def _pane(app) -> str:
    return str(app.query_one("#empty", Static).render())


def _status(app) -> str:
    return str(app.query_one("#status", Static).render())


async def _until_read(pilot, app, limit: int = 100) -> None:
    for _ in range(limit):
        await pilot.pause(0.05)
        if app._reading is not None and app._reading.finished:
            return
    raise AssertionError("the read never finished")


async def test_the_viewer_answers_input_before_the_last_file_is_read(tmp_path,
                                                                     monkeypatch):
    """The screen is up and taking keys while the reading is genuinely stuck."""
    release = threading.Event()
    _held(monkeypatch, release)
    paths = _corpus(tmp_path, copies=12)
    app = NmapApp(Pending(paths))
    try:
        async with app.run_test() as pilot:
            await pilot.pause(app_mod._READ_QUIET + 0.3)
            assert app._reading is not None and not app._reading.finished
            assert app._reading.done < len(paths), "the reader is partway through"
            # A key, answered now rather than after the last file.
            await pilot.press("s")
            assert app._active_tab == "stats", "the keystroke was acted on"
            await pilot.press("escape")
            assert app._active_tab == "hosts", "and so is the next one"
            release.set()
            await _until_read(pilot, app)
    finally:
        release.set()


async def test_the_model_grows_only_by_addition(tmp_path):
    """Nothing that has been shown may disappear, and no file counts twice."""
    paths = _corpus(tmp_path, copies=6)
    app = NmapApp(Pending(paths))
    async with app.run_test() as pilot:
        seen: list[dict[str, int]] = []
        offer = app._offer

        def watch(scans, force=False):
            seen.append({h.address: len(h.services) for h in scans.hosts})
            offer(scans, force=force)

        app._offer = watch
        await _until_read(pilot, app)

        assert seen, "at least the final publication"
        for older, newer in zip(seen, seen[1:], strict=False):
            assert older.keys() <= newer.keys(), "a host that was listed vanished"
            for address, count in older.items():
                assert newer[address] >= count, \
                    f"{address} lost services between publications"
        assert len(app.scans.sources) == len(paths), "every file folded in"
        assert len(app.scans.sources) == len(set(app.scans.sources)), \
            "and none of them folded in twice"


async def test_a_hundred_quick_files_publish_on_the_cadence(tmp_path):
    """Re-projecting costs more than reading a file, so not once per file."""
    paths = _corpus(tmp_path, copies=34)               # 102 files
    assert len(paths) > 100
    app = NmapApp(Pending(paths))
    published = []
    async with app.run_test() as pilot:
        offer = app._offer

        def watch(scans, force=False):
            published.append(scans)
            offer(scans, force=force)

        app._offer = watch
        await _until_read(pilot, app)

    assert published, "the finished model is published"
    assert len(published) < 10, \
        f"{len(published)} publications for {len(paths)} files - that is per file"


async def test_a_streamed_read_ends_where_a_blocking_read_does(tmp_path):
    """One reading path, two entry points: the answer cannot differ."""
    paths = _corpus(tmp_path, copies=4)
    blocking = prepare(load([tmp_path]))
    app = NmapApp(Pending(paths))
    async with app.run_test() as pilot:
        await _until_read(pilot, app)
        streamed = app.scans

    assert [h.address for h in streamed.hosts] == [h.address for h in blocking.hosts]
    assert streamed.sources == blocking.sources
    assert streamed.disabled_ping == blocking.disabled_ping
    assert len(streamed.files) == len(blocking.files)
    for one, other in zip(streamed.hosts, blocking.hosts, strict=True):
        assert one.state == other.state and one.reason == other.reason
        assert one.hostnames == other.hostnames
        assert [(s.protocol, s.port, s.name, s.product, s.version)
                for s in one.services] == \
               [(s.protocol, s.port, s.name, s.product, s.version)
                for s in other.services]
        assert [len(s.vulnerabilities) for s in one.services] == \
               [len(s.vulnerabilities) for s in other.services], \
            "prepare ran over the streamed model too"
        assert [s.names for s in one.services] == [s.names for s in other.services]


async def test_the_empty_list_says_the_reading_is_not_finished(tmp_path,
                                                               monkeypatch):
    """A premature negative is the one thing an empty list must never be."""
    release = threading.Event()
    _held(monkeypatch, release, after=0)
    paths = _corpus(tmp_path, copies=20)
    app = NmapApp(Pending(paths))
    try:
        async with app.run_test() as pilot:
            await pilot.pause(app_mod._READ_QUIET + 0.3)
            assert app.query_one(DataTable).row_count == 0, "nothing read yet"
            pane = _pane(app)
            assert "Still reading" in pane, pane
            assert "files read" in pane and "host(s) so far" in pane, pane
            assert "recorded no hosts" not in pane, "that is the settled message"
            release.set()
            await _until_read(pilot, app)
    finally:
        release.set()


async def test_the_settled_no_hosts_message_is_a_different_one(tmp_path):
    """Read to the end, with nothing in it: that is a fact, and reads as one."""
    empty = tmp_path / "empty.xml"
    empty.write_text('<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n'
                     '<nmaprun scanner="nmap" args="nmap -sn" start="1700000000">'
                     '<runstats><finished time="1700000001"/></runstats></nmaprun>\n')
    app = NmapApp(Pending([empty]), Config(nmap_path="/nonexistent/nmap"))
    async with app.run_test() as pilot:
        await _until_read(pilot, app)
        await pilot.pause(0.1)
        pane = _pane(app)
        assert "recorded no hosts" in pane, pane
        assert "Still reading" not in pane and "Nothing could be read" not in pane
        assert app._exit_code == 0, "a file that read cleanly is not a failure"


async def test_reading_progress_is_in_the_status_line(tmp_path, monkeypatch):
    """Reading affects every tab, so it reports where the window reports."""
    release = threading.Event()
    _held(monkeypatch, release, after=3)
    paths = _corpus(tmp_path, copies=20)
    app = NmapApp(Pending(paths))
    try:
        async with app.run_test() as pilot:
            await pilot.pause(app_mod._READ_QUIET + 0.3)
            line = _status(app)
            assert "reading scans" in line and "files" in line, line
            assert "host(s) so far" in line, line
            release.set()
            await _until_read(pilot, app)
            await pilot.pause(0.1)
            assert "reading scans" not in _status(app), \
                "and stops saying so once it has finished"
    finally:
        release.set()


async def test_candidates_that_all_fail_open_report_and_exit_non_zero(tmp_path):
    """Not "an engagement with no hosts": files were found and none could be read."""
    for n in range(3):
        (tmp_path / f"broken-{n}.xml").write_text(
            '<?xml version="1.0"?>\n<!DOCTYPE nmaprun>\n<nmaprun><host')
    paths = [tmp_path / f"broken-{n}.xml" for n in range(3)]
    app = NmapApp(Pending(paths), Config(nmap_path="/nonexistent/nmap"))
    async with app.run_test() as pilot:
        await _until_read(pilot, app)
        await pilot.pause(0.1)
        pane = _pane(app)
        assert "Nothing could be read" in pane, pane
        assert "broken-0.xml" in pane, "and names the files that failed"
        assert app._exit_code == 1, "the shell has to be able to tell"


async def test_a_handful_of_files_says_nothing_at_all(tmp_path):
    """A read over in tens of milliseconds must not flash a message.

    The same rule the command's own search line follows: a report that appears
    and vanishes inside two frames says less than the rows it delayed. What
    the user sees for a small engagement is the headers, then the rows.
    """
    paths = _corpus(tmp_path)                       # three files
    app = NmapApp(Pending(paths))
    async with app.run_test() as pilot:
        await pilot.pause(0.01)
        assert not app.query_one("#empty", Static).has_class("-shown"), \
            "no message while the quiet window is open"
        assert "reading scans" not in _status(app), "and nothing in the status line"
        await _until_read(pilot, app)
        await pilot.pause(0.1)
        assert app.query_one(DataTable).row_count == len(app.scans.hosts)
        assert app._busy is None, "and no projection went to a worker either"


async def test_the_finished_model_path_does_not_stream(tmp_path):
    """A `ScanSet` in means the model is complete at mount, exactly as before."""
    app = NmapApp(prepare(load([FIX / "basic.xml"])))
    async with app.run_test() as pilot:
        await pilot.pause(0.05)
        assert app._reading is None, "nothing to read"
        assert app._to_read == []
        assert app.query_one(DataTable).row_count == len(app.scans.hosts)
        assert "reading" not in _status(app)
        assert not app.query_one("#empty", Static).has_class("-shown"), \
            "no spinner and no bar for a set that was ready at mount"
        assert app._busy is None, f"nothing was sent to a worker: {app._busy}"
        assert app_mod._BACKGROUND_ABOVE > len(app.scans.hosts)
