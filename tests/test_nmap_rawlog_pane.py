"""Opening a scan's own text from the record it describes.

The point of the feature is verification: what the viewer says a host or a port
is, checked against what nmap wrote about it. These cover the way in and the
way back, and the two states that are not a block of text - a scan that left no
output file, and one whose file cannot be read.
"""

from __future__ import annotations

import copy
import dataclasses
import threading
from pathlib import Path

import pytest
from rich.console import Console
from textual.widgets import DataTable, Static

from seek.config import Config
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import app as app_mod
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap.app import NmapApp
from seek.tui.nmap.reader import DetailReader

pytestmark = [pytest.mark.asyncio, pytest.mark.slow]
FIX = Path(__file__).parent / "fixtures" / "nmap"


def _app(*names: str, config: Config | None = None) -> NmapApp:
    return NmapApp(prepare(load([FIX / f"{n}.xml" for n in names])), config)


def _pane(app) -> str:
    """What the pane is showing, whatever its height happens to be.

    Rendered from the lines rather than from the visible region: a scoped block
    is often taller than the pane, and what is under test is the content, not
    how much of it fits at once.
    """
    console = Console(width=110, record=True, file=open("/dev/null", "w"))
    console.print(detail_pane.as_group(app._lines))
    return console.export_text()


async def _to_first_entry(pilot, app) -> None:
    await pilot.pause(0.2)
    assert app._openable(), "the record offers no scan to open"
    for _ in range(app._openable()[0]):
        await pilot.press("l")                  # the cursor, a line at a time
    await pilot.pause(0.05)
    assert app._opens_here() is not None


async def test_opening_an_entry_shows_what_that_scan_wrote_about_the_host():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)

        shown = _pane(app)
        assert "Nmap scan report for alpha.example (192.0.2.1)" in shown
        assert "Not shown: 997 filtered" in shown, \
            "the line nmap writes and the XML has no field for"
        assert "192.0.2.2" not in shown, "the rest of the file is not shown"


async def test_the_raw_state_says_which_scan_and_which_subject():
    """nmap's text names neither, and the reader has to know both."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        shown = _pane(app)
        assert "basic" in shown and "192.0.2.1" in shown
        assert "basic.nmap" in shown, "and the file it came out of"


async def test_a_service_record_opens_the_port_not_the_whole_host():
    app = _app("scripts")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        await pilot.press("enter")                  # into the host's services
        await pilot.pause(0.3)
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)

        shown = _pane(app)
        assert "443/tcp" in shown
        assert "ssl-cert" in shown, "the port's own script output came with it"
        assert "Host script results" not in shown, "but not the host's own text"


async def test_escape_goes_back_to_the_record_at_the_entry_it_was_opened_from():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        opened_at = app._line
        await pilot.press("o")
        await pilot.pause(0.1)
        assert app._raw is not None

        await pilot.press("escape")
        await pilot.pause(0.1)
        assert app._raw is None, "back to the record"
        assert "Nmap scan report" not in _pane(app)
        assert app._line == opened_at, "and at the entry it was opened from"
        assert app._opens_here() is not None


async def test_the_escape_hint_says_where_it_goes():
    app = _app("basic")
    async with app.run_test(size=(150, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        assert "back to the record" in str(app.query_one("#hint-bar", Static).render())


async def test_moving_the_list_drops_the_raw_state():
    """The text on screen is about the row that was left."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        assert app._raw is not None

        await pilot.press("down")
        await pilot.pause(0.2)
        assert app._raw is None
        assert "192.0.2.2" in _pane(app), "the new row's record, not the old text"


async def test_a_scan_with_no_output_file_is_reconstructed_and_labelled():
    app = _app("xml-only")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        assert "no output file" in _pane(app), "the entry says so before it is opened"
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)

        shown = _pane(app)
        assert "reconstructed from the XML" in shown, \
            "never presented as nmap's own text"
        assert "Nmap scan report for lone.example (198.51.100.7)" in shown
        assert "25/tcp" in shown


async def test_a_file_that_cannot_be_read_says_so_rather_than_showing_nothing():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        request = app._opens_here()
        request.entry.path = FIX / "gone.nmap"
        await pilot.press("o")
        await pilot.pause(0.1)
        assert "could not be read" in _pane(app)


async def test_a_host_the_scan_did_not_write_about_says_so():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        app.query_one("#detail-body", Static)
        table = app.query_one("DataTable")
        table.move_cursor(row=2)                    # 192.0.2.3, down, no report
        await pilot.pause(0.2)
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        assert "says nothing about 192.0.2.3" in _pane(app)


async def test_the_file_is_read_once_and_kept():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        assert app._files_read == {}, "nothing was read while the record drew"
        await pilot.press("o")
        await pilot.pause(0.1)
        assert list(app._files_read) == [FIX / "basic.nmap"]

        # Reopening must not go back to the disk.
        reads = []
        real = Path.read_text
        Path.read_text = lambda self, *a, **k: (reads.append(self), real(self, *a, **k))[1]
        try:
            await pilot.press("escape")
            await pilot.pause(0.05)
            await pilot.press("o")
            await pilot.pause(0.1)
        finally:
            Path.read_text = real
        assert reads == [], f"the file was read again: {reads}"


async def test_the_scans_tab_keeps_its_own_meaning_for_the_key():
    """`o` there cycles the report view; a scan's record opens nothing."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        app._activate("scans")
        await pilot.pause(0.3)
        assert app._openable() == [], "a scan's record is its report, not entries"

        before = app._report_mode
        await pilot.press("o")
        await pilot.pause(0.1)
        assert app._report_mode != before, "the key still cycles the report"
        assert app._raw is None


def _reader_text(reader) -> str:
    return "\n".join(line.plain for line in reader._lines)


async def _open_reader(pilot, app):
    await pilot.press("d")
    await pilot.pause(0.3)
    reader = app.screen
    assert isinstance(reader, DetailReader)
    return reader


async def test_the_reader_opens_whichever_state_the_pane_is_in():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        reader = await _open_reader(pilot, app)
        assert "Nmap scan report" not in _reader_text(reader), "the record, so far"
        await pilot.press("escape")
        await pilot.pause(0.2)

        await pilot.press("o")
        await pilot.pause(0.1)
        reader = await _open_reader(pilot, app)
        assert "Nmap scan report for alpha.example" in _reader_text(reader)
        assert "192.0.2.1" in reader._title and "basic" in reader._title


async def test_escape_in_the_reader_goes_from_the_text_to_the_record():
    """Opened on a scan's text, the reader goes back to the record first."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        reader = await _open_reader(pilot, app)

        await pilot.press("escape")
        await pilot.pause(0.2)
        assert app.screen is reader, "still in the reader"
        assert "Nmap scan report" not in _reader_text(reader), "on the record"
        assert reader._opens_here() is not None, "at the link it came from"

        await pilot.press("escape")
        await pilot.pause(0.2)
        assert not isinstance(app.screen, DetailReader)


async def test_the_reader_has_a_line_cursor_and_follows_links():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        reader = await _open_reader(pilot, app)
        assert reader._cursor == 0
        await pilot.press("j")
        assert reader._cursor == 1, "every line is a stop"
        await pilot.press("k")
        assert reader._cursor == 0

        links = [i for i, line in enumerate(reader._items) if line.opens is not None]
        assert links, "the record lists the scans that saw it"
        for _ in range(links[0]):
            await pilot.press("down")
        assert "o open" in reader._controls_text()
        await pilot.press("o")
        await pilot.pause(0.2)
        assert "Nmap scan report for alpha.example" in _reader_text(reader)
        assert app.query_one(DataTable).cursor_row == 0, "the list did not move"


async def test_the_arrows_in_the_text_step_between_scans_not_rows(monkeypatch):
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        # A second scan of the same host: the same file under another identity,
        # built once so the steps agree about which one is which.
        (entry,) = app._siblings(app._opens_here())
        pair = [entry, dataclasses.replace(entry, scan=copy.copy(entry.scan))]
        monkeypatch.setattr(app, "_siblings", lambda r: pair)
        await pilot.press("o")
        await pilot.pause(0.1)
        reader = await _open_reader(pilot, app)
        table = app.query_one(DataTable)
        assert "scan 1 of 2" in _reader_text(reader)

        await pilot.press("right")
        await pilot.pause(0.1)
        assert "scan 2 of 2" in _reader_text(reader), "the other scan's text"
        assert "Nmap scan report" in _reader_text(reader), "still nmap's text"
        assert table.cursor_row == 0, "not another row"
        await pilot.press("right")
        await pilot.pause(0.1)
        assert "scan 2 of 2" in _reader_text(reader), "it stops at the end"
        await pilot.press("left")
        await pilot.pause(0.1)
        assert "scan 1 of 2" in _reader_text(reader)


async def test_the_arrows_on_the_record_still_step_rows():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(0.2)
        reader = await _open_reader(pilot, app)
        first = reader._title
        await pilot.press("right")
        await pilot.pause(0.1)
        assert app.query_one(DataTable).cursor_row == 1
        assert reader._title != first and "Nmap scan report" not in _reader_text(reader)


def _held(monkeypatch, release: threading.Event):
    """Make the worker's read block, so "still reading" is a real state.

    A fixture is read in microseconds, so without this every assertion about
    the pane mid-read would be a race against the worker finishing.
    """
    real = Path.read_text

    def held(self, *args, **kwargs):
        if self.suffix == ".nmap":
            release.wait(5)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", held)


async def test_a_large_output_file_is_read_off_the_event_loop(monkeypatch):
    """Under the threshold it is instant; over it the pane says it is reading.

    The size is what decides, and it is known from the file without opening it -
    so the ordinary case never pays for the pathological one.
    """
    monkeypatch.setattr(app_mod, "_RAW_INLINE_MAX", 64)     # every file is "big"
    release = threading.Event()
    _held(monkeypatch, release)
    app = _app("basic")
    try:
        async with app.run_test(size=(120, 40)) as pilot:
            await _to_first_entry(pilot, app)
            await pilot.press("o")
            await pilot.pause(0.1)
            assert app._raw_pending is not None, "handed to a worker, not read inline"
            assert app._raw is None
            assert "reading" in _pane(app), "and the pane says so meanwhile"

            release.set()
            for _ in range(60):
                await pilot.pause(0.05)
                if app._raw is not None:
                    break
            assert app._raw is not None and app._raw_pending is None
            assert "Nmap scan report for alpha.example" in _pane(app)
    finally:
        release.set()


async def test_a_small_output_file_is_read_without_a_worker():
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        assert app._raw_pending is None, "no worker for a file this size"
        assert app._raw is not None, "it was there the moment the key was pressed"


async def test_escape_abandons_a_read_still_in_flight(monkeypatch):
    monkeypatch.setattr(app_mod, "_RAW_INLINE_MAX", 64)
    release = threading.Event()
    _held(monkeypatch, release)
    app = _app("basic")
    try:
        async with app.run_test(size=(120, 40)) as pilot:
            await _to_first_entry(pilot, app)
            opened_at = app._line
            await pilot.press("o")
            await pilot.pause(0.1)
            assert app._raw_pending is not None

            await pilot.press("escape")
            await pilot.pause(0.1)
            assert app._raw is None and app._raw_pending is None
            assert app._line == opened_at, "back where it was opened from"
            release.set()
            await pilot.pause(0.3)
            assert app._raw is None, "the abandoned read does not arrive later"
    finally:
        release.set()


# --- the arrows keep meaning "between entries" once one is open ---------------


async def test_the_arrows_read_the_raw_output_rather_than_leave_it():
    """Inside a scan's text ←/→ move the cursor, as everywhere in the pane."""
    app = _app("basic")
    async with app.run_test(size=(120, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        at = app._raw[0].entry.scan
        await pilot.press("right")
        await pilot.pause(0.05)
        assert app._raw is not None and app._raw[0].entry.scan is at
        assert app._line == 1, "the cursor moved a line"
        await pilot.press("left")
        await pilot.pause(0.05)
        assert app._line == 0


async def test_the_raw_state_says_which_scan_and_how_to_read_it():
    app = _app("basic")
    async with app.run_test(size=(150, 40)) as pilot:
        await _to_first_entry(pilot, app)
        await pilot.press("o")
        await pilot.pause(0.1)
        assert "scan 1 of" not in _pane(app), "one scan: no position to give"
        hints = str(app.query_one("#hint-bar", Static).render())
        assert "←→" in hints and "back to the record" in hints
        assert hints.count("Esc") == 1, "the way out is offered once"


async def test_the_raw_state_says_which_of_several_scans_it_is(monkeypatch):
    app = _app("basic")
    async with app.run_test(size=(150, 40)) as pilot:
        await _to_first_entry(pilot, app)
        real = app._siblings
        monkeypatch.setattr(app, "_siblings", lambda r: real(r) * 2)
        await pilot.press("o")
        await pilot.pause(0.1)
        assert "scan 1 of 2" in _pane(app)
