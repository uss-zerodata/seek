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
from textual.widgets import DataTable, Input, Static

from seek.config import Config
from seek.nmap.merge import Pending, discover, load
from seek.nmap.models import Host, ScanSet, Service
from seek.nmap.views import prepare
from seek.tui.nmap import app as app_mod
from seek.tui.nmap.app import NmapApp

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]
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

    def held(path, label=None):
        seen.append(path)
        if len(seen) > after:
            release.wait(5)
        return real(path, label)

    monkeypatch.setattr(app_mod, "parse_file", held)


def _grown(hosts: int) -> ScanSet:
    """A finished model of `hosts` hosts, as a batch would publish it."""
    return ScanSet(
        hosts=[Host(address=f"10.0.{i // 254}.{i % 254}", reason="echo-reply",
                    services=[Service(protocol="tcp", port=80, state="open",
                                      name="http")])
               for i in range(hosts)],
        sources=[f"scan-{i}.xml" for i in range(hosts // 20 + 1)])


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

        def watch(scans):
            seen.append({h.address: len(h.services) for h in scans.hosts})
            offer(scans)

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

        def watch(scans):
            published.append(scans)
            offer(scans)

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


# --- a batch must not take the list away -------------------------------------


async def test_a_new_batch_leaves_the_working_list_in_place(monkeypatch):
    """The whole point of opening early is lost if every batch clears the list.

    A model that has grown has to be re-projected, and that is a second of work
    at engagement scale - but the rows on screen were built from a subset of
    the same model and every one of them is still true, so they stay and the
    rebuild reports outside the list. The threshold is dropped to zero so the
    rebuild genuinely goes to a worker at fixture size.
    """
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    app = NmapApp(_grown(20))
    async with app.run_test() as pilot:
        await pilot.pause(0.4)
        table = app.query_one(DataTable)
        assert table.row_count == 20, "the first build is on screen"

        # No pause: `_offer` starts the rebuild synchronously, and at fixture
        # size it would finish inside any wait long enough to be worth writing.
        app._offer(_grown(40))
        assert app._busy is not None and app._busy.quiet, \
            "the rebuild reports outside the list"
        assert table.row_count == 20, "the rows the reader had are still there"
        assert not app.query_one("#empty", Static).has_class("-shown"), \
            "and no progress bar has taken the content area"

        await pilot.pause(0.5)
        assert table.row_count == 40, "and the grown list replaces it when ready"


async def test_escape_keeps_its_ordinary_meaning_during_a_batch_rebuild(monkeypatch):
    """There is nothing to stop waiting for: the list is on screen and working.

    A re-read after a scan is the opposite case and stays cancellable - the
    user asked for that one, and its status note says `Esc` stops it.
    """
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    app = NmapApp(_grown(20))
    async with app.run_test() as pilot:
        await pilot.pause(0.4)
        app.query_one("#filter", Input).value = "10.0.0"
        app._flush_filter()
        await pilot.pause(0.1)

        app._busy = app_mod._Busy(what="hosts", view=app.view,
                                  token=app._build_token + 1,
                                  refresh=True, quiet=True)
        app.action_back()
        assert app._busy is not None, "a quiet rebuild is not what Esc is for"
        assert app.query_one("#filter", Input).value == "", \
            "Esc cleared the filter, as it does when nothing is being waited on"
        quiet_note = app._busy_note()
        assert quiet_note is not None and "updating hosts" in quiet_note.plain, \
            "it still says what it is doing"
        assert "Esc stops waiting" not in quiet_note.plain, \
            "but does not offer to stop something the reader is not waiting for"

        app._busy = app_mod._Busy(what="the scans again", view=None,
                                  token=app._build_token + 2, refresh=True)
        note = app._busy_note()
        assert note is not None and "Esc stops waiting" in note.plain, \
            "a re-read the user asked for still says how to stop it"
        app.action_back()
        assert app._busy is None, "and Esc still stops it"
        await pilot.pause(0.1)


async def test_a_batch_arriving_under_a_build_is_not_published_over_it(monkeypatch):
    """A snapshot published under a running build strands it on a dead model.

    Its completion would then clear the table to build the newer one - which is
    what made a fast read show a bar per batch and never a list.
    """
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)
    app = NmapApp(_grown(20))
    async with app.run_test() as pilot:
        await pilot.pause(0.4)
        app._offer(_grown(40))
        building = app.scans
        app._offer(_grown(60))
        app._offer(_grown(80))
        assert app.scans is building, "nothing was published under the build"
        assert len(app._next_scans.hosts) == 80, "only the newest was parked"
        await pilot.pause(0.8)
        assert len(app.scans.hosts) == 80, "and it is taken once the build ends"
        assert app.query_one(DataTable).row_count == 80


async def test_the_cursor_follows_the_record_not_the_row_number(monkeypatch):
    """A batch replaces the host objects and inserts rows above them.

    `merge` copies a host before a later file writes to it, so the record the
    cursor is on is a *different object* after a batch even though it is the
    same host. Matching on the object alone therefore failed on exactly the
    hosts a batch had touched, and falling through to the row number put the
    cursor on whatever had since been inserted at that position.
    """
    monkeypatch.setattr(app_mod, "_BACKGROUND_ABOVE", 0)

    def model(addresses):
        return ScanSet(hosts=[Host(address=a, reason="echo-reply",
                                   services=[Service(protocol="tcp", port=80,
                                                     state="open", name="http")])
                              for a in addresses],
                       sources=["one.xml"])

    app = NmapApp(model(["10.0.0.5", "10.0.0.6", "10.0.0.7"]))
    async with app.run_test() as pilot:
        await pilot.pause(0.4)
        table = app.query_one(DataTable)
        table.move_cursor(row=1)
        assert app._rows[1].cells[0] == "10.0.0.6"

        # Every host object is new, two of them sort above the one the cursor
        # is on, and its row number therefore changes from 1 to 3.
        app._offer(model(["10.0.0.1", "10.0.0.2", "10.0.0.5",
                          "10.0.0.6", "10.0.0.7"]))
        await pilot.pause(0.5)

        assert table.row_count == 5
        assert app._rows[table.cursor_row].cells[0] == "10.0.0.6", \
            "the cursor stayed on the host, not on row 1"
        assert table.cursor_row == 3, "which is where that host now is"
