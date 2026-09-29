"""The scan viewer: one table, one filter, one breadcrumb.

Reuses the search session's conventions deliberately - the same fuzzy query
grammar in the filter, the same staged `Esc`, the same hint bar and status line -
so the two modes do not need separate mental models. Nothing here is persisted:
the files named on the command line are the whole truth for the run.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import RenderableType
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.timer import Timer
from textual.widgets import DataTable, Input, Static, Tab, Tabs

from seek import actions
from seek.config import Config
from seek.engine.score import match_spans
from seek.gowitness import capture as gw_capture
from seek.gowitness import detect as gw_detect
from seek.gowitness import locate as gw_locate
from seek.gowitness import results as gw_results
from seek.nmap import bulk, filtering, rawlog, timeline
from seek.nmap import export as exporter
from seek.nmap import merge as merge_mod
from seek.nmap import presets as presets_mod
from seek.nmap import views as proj
from seek.nmap.diff import ScanDiff, diff_from, snapshot
from seek.nmap.merge import Accumulator, Pending
from seek.nmap.models import Host, ScanSet, Service
from seek.nmap.parse import NmapParseError, parse_file
from seek.nmap.progress import FILES, Report
from seek.nmap.runner import Runner, ScanRun, State, elevation_help
from seek.runner import Run
from seek.tui.cells import cell_len, clip_cells, width_of
from seek.tui.menu import ChoiceScreen, MultiChoiceScreen, PromptScreen
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap import reader as reader_mod
from seek.tui.nmap import scans as scan_views
from seek.tui.nmap import views as vdefs
from seek.tui.nmap.commands import ScanCommands
from seek.tui.nmap.help import NmapHelpScreen
from seek.tui.nmap.reader import DetailReader
from seek.tui.nmap.scope import (
    CommandScreen,
    PresetScreen,
    ReviewScreen,
    ScopeScreen,
)

# The filter box keeps focus, exactly as the query box does in a search session,
# so every action is on a modifier - a bare digit has to reach the filter, since
# `443` is a thing you type.
# The overviews, in tab order. Drill-downs are not tabs: they push onto the
# stack above whichever overview they were opened from. The tab row still
# *follows* them - a drill-down that lands on another overview's subject marks
# that tab (see `_sync_tab`) - but only selecting a tab replaces the stack.
_TABS: list[tuple[str, str]] = [
    ("hosts", "Hosts"),
    ("services", "Services"),
    ("stats", "Statistics"),
    ("group-service", "By service"),
    ("group-product", "By product"),
    ("group-port", "By port"),
    ("names", "Names"),
    ("scans", "Scans"),
]
_GROUP_TABS = ("group-service", "group-product", "group-port")
# The marker column: one glyph and a space, in the search session's mark colour.
_MARK_W = 2
_MARK_STYLE = "bold bright_magenta"


# The loading state: a braille spinner turning on the app's own 0.2s tick, and
# a bar wherever the work can count itself.
_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_BAR_WIDTH = 24
# Rows handed to the table before the clock is consulted at all. Larger than
# any screen, so the list a reader can actually see is always there in the
# first pass.
_FILL_CHUNK = 200
# ...and after that, as many more as fit in this much of one turn. A fixed
# count is the wrong unit: it is either too small on a wide terminal, where a
# fifty-thousand-row projection then takes two seconds of frames to hand over,
# or too large on a narrow one, where the chunk itself becomes the pause. A
# budget is the thing actually being spent.
_FILL_BUDGET = 0.015
_FILL_STEP = 100                                    # rows between clock reads
# ...and this much of a turn to reach the row the reader was on, when it is
# further down than the first chunk. Leaving it to arrive with its own chunk
# means the list sits at the top until it does - a second of it on a large
# engagement, on every batch of scans, which is what "the selection jumps
# around" looks like from the outside. Longer than the ordinary budget and
# still well inside the fifth of a second the specs allow; a reader deeper in
# the list than this gets one scroll instead.
_FILL_REACH = 0.15
# Below this many hosts every projection here is a few milliseconds, so it is
# done inline; above it the wait is long enough to be worth a thread and a
# progress bar.
_BACKGROUND_ABOVE = 500
# The least time between two publications of a growing model, on the same
# principle the search engine applies to its result snapshots. Re-projecting an
# overview costs more than reading a file - 0.4 s for the host list against
# 12 ms a file - so publishing per file would spend the time it is trying to
# save. Publishing is also skipped outright when nothing new was read.
_PUBLISH_EVERY = 1.0
# A read shorter than this says nothing at all. A handful of scans is read in
# tens of milliseconds, and a message that appears and vanishes inside two
# frames says less than the rows it delayed - the same reason the command's own
# search line is seeded with its start time.
_READ_QUIET = 0.25
# How many scan output files to keep in memory at once. Stepping between the
# scans of one host re-reads nothing; a whole engagement's worth is not held.
_FILES_KEPT = 4
# Above this, a scan's output file is read and cut in a worker rather than
# between keystrokes. Measured: reading and cutting costs about 6 ms per MB, so
# 8 MB is ~50 ms and the fifth of a second the specs allow is not reached until
# roughly 30 MB. Every engagement this project has measured is well under it -
# 120 files over 24 200 hosts leave 14 MB - so the worker is for the `-p-` of a
# /16, not for the ordinary case.
_RAW_INLINE_MAX = 8_000_000
# After a batch is fully on screen, leave the reader alone for as long as
# putting it there took, up to this. Absorbing one means re-projecting the
# model and handing the table a list that can be fifty thousand rows long, and
# a read that publishes faster than that means the interface spends all of its
# time absorbing and none of it answering. Paced this way it spends at most
# half - which is what "the list is usable while the rest arrives" costs.
_ABSORB_HEADROOM = 1.5


class _Abandoned(Exception):
    """Raised inside a background build when its result is no longer wanted."""


def _bar(busy: _Busy) -> Text:
    """One report, drawn the one way - whichever step produced it.

    A step that can count itself gets a bar and the two figures with the unit
    it named; a step that cannot gets nothing but the spinner already above
    it, because a bar pinned at zero says less than no bar at all.
    """
    if not busy.total:
        return Text()
    done, total = min(busy.done, busy.total), busy.total
    filled = round(_BAR_WIDTH * done / total)
    out = Text()
    out.append("█" * filled, style="bold")
    out.append("░" * (_BAR_WIDTH - filled), style="dim")
    out.append(f"  {done} of {total} {busy.unit}".rstrip(), style="dim")
    return out


@dataclass(slots=True)
class _Busy:
    """A build running off the event loop, and how far it has got."""

    what: str
    view: object
    token: int
    done: int = 0
    total: int = 0
    # What `done` and `total` count - "files", "scans", "hosts". The producer
    # names it, so one renderer draws every step without a table mapping steps
    # to nouns; an empty unit is a step that is running but cannot count.
    unit: str = ""
    # A refresh has rows on screen already, and replacing them with a spinner
    # would flash away data that is still true; it reports in the status bar
    # instead. A first build has nothing to show and takes the content area.
    refresh: bool = False
    # A refresh nobody asked for: the model grew under a list that is still on
    # screen and still usable. It says what it is doing and otherwise stays out
    # of the way - no "Esc stops waiting", because there is nothing to wait
    # for and `Esc` has its ordinary meaning while the list works. A re-read
    # after a scan is the opposite: the user asked for it and has to be able
    # to stop it.
    quiet: bool = False


@dataclass(slots=True)
class _Reading:
    """A read in progress: how far through the candidate files it is.

    Separate from `_Busy` because the two are separate things and can be true
    at once. Reading affects every tab, so it reports in the status line and
    in an empty list's message; projecting belongs to one tab and keeps the
    content area. Told apart by where they appear, which is why neither needs
    to know about the other.
    """

    done: int = 0
    total: int = 0
    unit: str = FILES
    failures: list[tuple[str, str]] = field(default_factory=list)
    began: float = field(default_factory=time.monotonic)

    @property
    def finished(self) -> bool:
        return self.done >= self.total

    @property
    def showing(self) -> bool:
        """Is this read worth telling the user about yet?"""
        return not self.finished and time.monotonic() - self.began > _READ_QUIET


@dataclass(slots=True)
class _Mark:
    """Where the cursor was, and how the list was ordered, when a drill-down was
    opened - so `Esc` comes back to the row it was opened from.

    The row is remembered by identity first, by what it *is* second, and by
    position only as a last resort: a filter typed inside the drill-down, or
    cleared on the way out, changes which index the row you came from now sits
    at.

    The middle one is what a growing model needs. `merge` copies a host before
    a later file writes to it, so after a batch of scans the row the cursor was
    on is a *different object* describing the same host - object identity finds
    it only while nothing has touched it, and falling through to the index put
    the cursor on whatever had since been inserted at that position. `key` is
    the row's section and its first cell: an address, a name, a bucket label, a
    statistic - what the reader would call "the row I was on", and the one part
    of a row that a later scan cannot change.
    """

    target: object = None
    index: int = 0
    sort_col: int = 0
    sort_desc: bool = False
    key: tuple = ()
    # The filter the level was left with. The box is one widget shared by every
    # view, so a level's filter only survives a drill-down by being kept here.
    filter: str = ""

    def locate(self, rows: list[vdefs.Row]) -> int:
        if self.target is None and not self.key:
            return self.index
        found = -1
        for i, row in enumerate(rows):
            if self.target is not None and row.target is self.target:
                return i
            if (found < 0 and self.key and row.section == self.key[0]
                    and row.cells and row.cells[0] == self.key[1]):
                found = i
        return found if found >= 0 else self.index


class ScanTable(DataTable):
    """The list, with ←/→ reassigned.

    `DataTable` uses them to move between columns, which does nothing useful in
    row-cursor mode - so they move the record's line cursor below instead,
    leaving ↑/↓ to move the list. `h`/`l` are the same two keys, bound on the
    app. Binding the arrows here rather than on the app keeps them out of the
    filter box, where they still edit text.
    """

    BINDINGS = [
        Binding("left", "line(-1)", "Detail up", show=False),
        Binding("right", "line(1)", "Detail down", show=False),
    ]

    def action_line(self, direction: int) -> None:
        self.app.action_line(direction)


_HINTS = {
    "hosts": [("↑↓", "select"), ("←→", "read record"), ("↵", "services"), ("v", "swap"),
              ("1-9", "sort"), ("/", "filter"), ("u", "up"), ("r", "open ports"),
              ("s", "stats"), ("b", "group"), ("d", "detail"), ("m", "mark"), ("n", "scan"),
              ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
    "services": [("↑↓", "select"), ("←→", "read record"), ("↵", "hosts"), ("v", "swap"),
                 ("1-9", "sort"), ("/", "filter"), ("s", "stats"),
                 ("b", "group"), ("d", "detail"), ("m", "mark"), ("n", "scan"),
                 ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
    "host-detail": [("↑↓", "select"), ("←→", "read record"), ("↵", "same service everywhere"),
                    ("1-9", "sort"), ("u", "open only"),
                    ("/", "filter"), ("d", "detail"), ("D", "pane"), ("m", "mark"),
                    ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
    "group-hosts": [("↑↓", "select"), ("←→", "read record"), ("↵", "host"),
                    ("1-9", "sort"), ("/", "filter"), ("d", "detail"), ("m", "mark"),
                    ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
    "service-detail": [("↑↓", "select"), ("←→", "read record"), ("↵", "host"),
                       ("1-9", "sort"), ("/", "filter"), ("d", "detail"), ("m", "mark"),
                       ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
    "grouping": [("↑↓", "select"), ("←→", "read record"), ("↵", "hosts"),
                 ("b", "next grouping"), ("1-9", "sort"), ("/", "filter"),
                 ("d", "detail"), ("m", "mark"), ("x", "export"), ("w", "web"), ("?", "help"),
                 ("^P", "commands")],
    "names": [("↑↓", "select"), ("←→", "read record"), ("↵", "hosts"),
              ("1-9", "sort"), ("/", "filter"), ("d", "detail"),
              ("m", "mark"), ("n", "scan"), ("x", "export"), ("w", "web"), ("?", "help"),
              ("^P", "commands")],
    "scans": [("↑↓", "select"), ("d", "detail"), ("o", "report view"),
              ("p", "freeze log"), ("c", "cancel"), ("n", "new scan"), ("1-9", "sort"),
              ("/", "filter"), ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
    "stats": [("↑↓", "select"), ("↵", "open the figure"), ("1-9", "sort"),
              ("/", "filter"), ("s", "back"), ("d", "detail"),
              ("m", "mark"), ("x", "export"), ("w", "web"), ("?", "help"), ("^P", "commands")],
}

FILTER_HINTS = [("type", "to filter"), ("↵/Esc", "back to the list"),
                ("'x ^x !x", "exact / prefix / exclude")]


class NmapApp(App[int]):
    CSS = """
    /* Same conventions as the search session: ANSI themes collapse
       $panel/$surface/$boost to the terminal background, so regions are fenced
       by thin blue rules on the *bottom* of the upper element - never a fill -
       and rendered text carries its own colour. */
    #warn { height: auto; max-height: 2; padding: 0 1; }
    /* What this table is. The breadcrumb also sits here, so the path is visible
       where you are looking rather than only in the status line. */
    /* The overviews as tabs, so what is available is visible rather than
       something you have to know a key for. */
    Tabs { height: 2; }
    #title { height: 1; padding: 0 1; }
    #subtitle { height: auto; max-height: 2; padding: 0 1; color: $text-muted; }
    #list-area { height: 1fr; border-bottom: solid $primary; }
    DataTable { height: 1fr; padding: 0 1; }
    /* An empty list keeps its headers - they say what would be here - and the
       table shrinks to them so the message sits directly underneath. */
    DataTable.-empty { height: auto; }
    #empty { height: auto; padding: 1 2; text-align: center; display: none; }
    #empty.-shown { display: block; }
    /* Textual fills the header with $primary, which under an ANSI theme is raw
       bright blue behind default-coloured text - the same unreadable band this
       app removed from the search session's status bar. Carry the colour in the
       text instead and leave the background alone. */
    DataTable > .datatable--header {
        background: transparent;
        color: ansi_cyan;
        text-style: bold;
    }
    DataTable > .datatable--header-hover {
        background: transparent;
        color: ansi_cyan;
        text-style: bold underline;
    }
    /* The cursor is pure reverse video: the component's own grey-on-black plus
       `reverse` cancelled out to something arbitrary. */
    DataTable > .datatable--cursor {
        background: transparent;
        color: $text;
        text-style: reverse bold;
    }
    DataTable:focus > .datatable--cursor {
        background: transparent;
        color: $text;
        text-style: reverse bold;
    }
    DataTable > .datatable--hover { background: transparent; }

    /* Tabs: mark the active one with the accent rather than a fill. */
    Tabs Tab { color: $text-muted; }
    Tabs Tab.-active { color: $accent; text-style: bold; }
    Tabs Underline > .underline--bar { color: $accent; }

    /* Detail for the selected row; scrolls when the report is taller than it. */
    #detail { height: 45%; max-height: 20; padding: 0 1;
              border-bottom: solid $primary; }

    #status { height: 1; padding: 0 1; }
    #hint-bar { height: 1; color: $text-muted; padding: 0 1; }
    #filter-row { height: 1; }
    #prompt { width: 3; color: $accent; text-style: bold; content-align: center middle; }
    #filter { width: 1fr; height: 1; border: none; padding: 0; }
    """
    MIN_HEIGHT_FOR_DETAIL = 18
    # Ctrl+P lists every action by name, so nothing is reachable only by knowing
    # a key. The system provider stays for the theme/quit built-ins.
    COMMANDS = App.COMMANDS | {ScanCommands}
    BINDINGS = [
        # All bare keys: the table holds focus, so nothing needs a modifier -
        # and terminals steal too many of them (ctrl+s is XOFF, alt+digits
        # switch tabs in most emulators, tab is focus traversal).
        # `q` is `Esc`: it backs out one level and quits only from the top, so
        # a reflex `q` on a drill-down does not throw the session away.
        # Ctrl+Q (Textual's own) and Ctrl+C leave from anywhere.
        Binding("escape,q", "back", "Back", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("enter", "drill", "Open", show=False),
        Binding("v", "swap", "Next overview", show=False),
        Binding("V", "swap_back", "Previous overview", show=False),
        Binding("r", "open_ports", "Hosts with open ports only", show=False),
        Binding("s", "stats", "Statistics", show=False),
        Binding("b", "group", "Group by", show=False),
        Binding("u", "up", "Up hosts / open ports only", show=False),
        Binding("d", "open_detail", "Open detail", show=False),
        Binding("D", "toggle_detail", "Detail pane", show=False),
        # One key pair per axis, arrows and vim alike: ↑↓/jk move the list,
        # ←→/hl move the record's line cursor. The arrows are bound on the
        # table (`ScanTable`) so the filter box keeps them for editing.
        Binding("h", "line(-1)", "Detail up", show=False),
        Binding("l", "line(1)", "Detail down", show=False),
        Binding("n", "new_scan", "New scan", show=False),
        Binding("o", "report_mode", "Report view", show=False),
        Binding("p", "freeze_log", "Freeze the log", show=False),
        Binding("c", "cancel_scan", "Cancel the scan", show=False),
        Binding("m", "mark", "Mark", show=False),
        Binding("M", "clear_marks", "Clear marks", show=False),
        Binding("x", "export", "Export", show=False),
        Binding("i", "open_shot", "Open the screenshot", show=False),
        Binding("W", "report_server", "Web report", show=False),
        Binding("w", "open_web", "Web interface", show=False),
        Binding("question_mark", "help", "Help", show=False),
        Binding("up,k", "move(-1)", "Up", show=False),
        Binding("down,j", "move(1)", "Down", show=False),
        Binding("pageup", "page(-1)", "Page up", show=False),
        Binding("pagedown", "page(1)", "Page down", show=False),
        # DataTable binds home/end itself (column movement), so ours must win.
        Binding("home,g", "jump(0)", "First row", priority=True, show=False),
        Binding("end,G", "jump(1)", "Last row", priority=True, show=False),
        *[Binding(str(n), f"sort({n - 1})", f"Sort {n}", show=False)
          for n in range(1, 10)],
    ]

    def __init__(self, scans: ScanSet | Pending, config: Config | None = None,
                 sources: list[Path] | None = None,
                 scan_dir: Path | None = None) -> None:
        """Open on a finished model, or on the files that will become one.

        A `ScanSet` is the path this has always taken and is unchanged: the
        model is complete at mount and nothing streams. A `Pending` is the
        command's hand-over - candidate files, not yet read - and puts the
        viewer on screen first, filling as they are read. Two entry points
        rather than one because "the model is complete" is a real distinction
        the interface has to make, not an implementation detail: it is the
        difference between "no hosts" and "no hosts yet".
        """
        super().__init__()
        pending = scans if isinstance(scans, Pending) else None
        self.scans = ScanSet() if pending is not None else scans
        # Whatever was handed in is a published model like any other: freezing
        # it here is what keeps the first collection after mount from walking
        # the whole engagement.
        bulk.freeze()
        # The candidates to read once the screen is up, and how far that has
        # got. `None` throughout for a finished model, which is what every
        # "is anything still coming" question below asks.
        self._to_read: list[Path] = list(pending.paths) if pending else []
        # Set here rather than when the worker starts, so the very first frame
        # already says a read is under way: an empty list drawn before the
        # thread got its turn would be a premature negative for one frame,
        # which is exactly the thing the requirement forbids.
        self._reading: _Reading | None = (
            _Reading(done=0, total=len(self._to_read)) if self._to_read else None)
        self._read_token = 0
        # A snapshot that arrived while a projection was running. The newest
        # one supersedes the one waiting rather than queueing behind it: they
        # are alternatives, not a sequence, and only the last is still true.
        self._next_scans: ScanSet | None = None
        # When the batch currently being put on screen started going there, and
        # the wall-clock moment the next one may be taken.
        self._absorb_began = 0.0
        self.config = config or Config()
        # Where a scan writes, and what to re-read when one finishes. Both are
        # the launch directory unless the config says otherwise.
        self.sources: list[Path] = list(sources or [])
        # How scans are named for the whole run - the reading worker's and a
        # re-read after a finished scan's - so a file never changes its name
        # between the two. Built from the sources when a model was handed in.
        self._name: merge_mod.Naming = (
            pending.name if pending is not None else merge_mod.naming(self.sources))
        # Decided once: the status line asks on every redraw, and a `stat` per
        # source per draw is the kind of cost the record pane had to shed.
        self._several_dirs = sum(1 for p in self.sources if p.is_dir()) > 1
        # gowitness captures anywhere below the sources - found by the command
        # alongside the scans, or here when a model was handed in directly.
        self._databases: list[Path] = (
            list(pending.databases) if pending is not None and pending.databases is not None
            else gw_locate.find_databases(self.sources))
        self._shot_index = gw_locate.ShotIndex(p for p in self.sources if p.is_dir())
        self.scan_dir = Path(self.config.scan_output_dir or scan_dir or Path.cwd())
        self.nmap = presets_mod.probe(self.config.nmap_path)
        self.gowitness = gw_detect.probe(self.config.gowitness_mode,
                                         self.config.gowitness_path,
                                         self.config.gowitness_image)
        self.runner = Runner()
        # A second slot, not a second scheduler: one `Runner` allows one run,
        # so a slot per tool is exactly "serial within a tool, concurrent
        # across them" with no new concurrency logic to get wrong. nmap and a
        # capture do not contend - one is raw packets, the other is HTTP - and
        # a capture that had to wait out a long port scan would be useless in
        # the workflow it exists to serve.
        self.captures = Runner()
        self._report_proc: object | None = None
        # The viewer's own web interface: this model, every capture database,
        # served in-process so what it shows is what the list shows. Built on
        # the first `w`; FastAPI is not imported before then.
        self._web = None
        self._web_row: vdefs.Row | None = None
        # Which record the pane is currently showing, so that a re-render
        # of the same one leaves the reader's scroll position alone.
        self._detail_target: int | None = None
        # The record the pane is showing, and which of its lines the cursor is
        # on - any line, as in a text editor; a line that opens something is
        # styled as a link, and `o` opens it while the cursor is there.
        self._lines: list[detail_pane.Line] = []
        self._line = 0
        # The raw output the pane is showing instead of a record, if any, and
        # the line it was opened from - so leaving it lands where it was left
        # rather than at the top of the record.
        self._raw: tuple[rawlog.Request, rawlog.Excerpt] | None = None
        self._raw_from = 0
        # An entry whose file is too big to read between keystrokes, while the
        # worker reads it.
        self._raw_pending: rawlog.Request | None = None
        self._raw_token = 0
        # The last few `.nmap` files read, by path. Stepping between one host's
        # scans should not re-read, and a file can be tens of megabytes.
        self._files_read: dict[Path, str] = {}
        # Whether the log pane was at its end when it was last rendered - see
        # `_pinned_to_end`. True to begin with, so a run opens following.
        self._following = True
        # What has been captured, whoever captured it: the results database is
        # read on startup so a capture someone else ran is picked up, exactly as
        # the scan history reads scan files it did not produce. The database is
        # what an external run leaves - the documented workflow writes it and no
        # JSON Lines file at all.
        self.shots = gw_results.Captures()
        self._load_captures()
        self._diffs: dict[int, ScanDiff] = {}
        # The file history is expensive to build (it re-parses), so cache it and
        # rebuild only when the model changes - which `self.scans` identity marks,
        # since a finished scan is absorbed by replacing it.
        self._history: list[timeline.Scan] = []
        self._history_for: object = None
        # Which scans recorded which address. Derived from the model and kept
        # with it for the same reason the history is: the record pane redraws
        # on every movement of the list cursor.
        self._scanned: rawlog.Scanned | None = None
        self._scanned_for: object = None
        # A build running off the event loop, and what it has got through.
        self._busy: _Busy | None = None
        self._build_token = 0
        self._spin = 0
        self._after_build: tuple[bool, _Mark | None, bool] | None = None
        self._abandoned = ""            # what the last cancelled build was doing
        self._report_mode = "condensed"
        self._log_frozen = False
        self.stack: list[vdefs.View] = [vdefs.hosts_view()]
        # One mark per level pushed onto `stack`, so unwinding restores both the
        # cursor and the sort the level below was left in.
        self._marks: list[_Mark] = []
        # Each tab's overview as it was last left - filter, sort and cursor -
        # so switching back to a tab, or `Esc` to the first one, returns to it.
        self._tab_marks: dict[str, _Mark] = {}
        self._pending_mark: _Mark | None = None
        self._rows: list[vdefs.Row] = []
        # The view the rows on screen were built for. A rebuild for that same
        # view can leave them in place; a rebuild for a different one cannot,
        # because they are a different shape.
        self._rows_view: object = None
        # Filling the table is chunked once a list is long enough that doing it
        # in one pass would drop frames; these track where that has got to.
        self._filled = 0
        self._fill_plan: tuple[bool, _Mark | None, int] = (False, None, 0)
        self._cursor_to: int | None = None
        self._fill_gen = 0
        self._filling = False
        self._sort_col = 0
        self._sort_desc = False
        self._group_keys = ("service", "product", "port")
        self._group_at = 0
        self._only_up = False                   # `u` on the host list
        self._only_ports = False                # `r` on the host list
        self._only_open = False                 # `u` on a host's own port list
        self._show_detail = True
        self._reader: DetailReader | None = None
        self._active_tab = "hosts"
        self._widths: list[int] = []
        # What the header currently shows: view, widths and sort marker. A
        # re-lay that would produce the same header is skipped, because the
        # teardown takes every row in the table with it.
        self._laid: tuple | None = None
        self._last_width = 0
        self._spec = filtering.FilterSpec()
        self._filter_debounce: Timer | None = None
        # Marks are keyed by record identity, never by row: every view is rebuilt
        # from the model on every filter keystroke, sort, resize and tab switch,
        # so a mark held as an index or a row object would be stale at once. A
        # dict keeps the record itself (nothing to look up again at export time)
        # and its insertion order (which becomes the export order).
        self._marked: dict[tuple, exporter.Record] = {}
        self._unfiltered = 0
        # Non-zero when candidate files were found and not one of them could be
        # read: an engagement that could not be opened is not a successful run,
        # and the shell has to be able to tell.
        self._exit_code = 0

    # --- layout ------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(id="warn")
        yield Tabs(*[Tab(label, id=tid) for tid, label in _TABS], id="tabs")
        yield Static(id="title")
        yield Static(id="subtitle")
        with Vertical(id="list-area"):
            yield ScanTable(cursor_type="row", zebra_stripes=False)
            yield Static(id="empty")
        with VerticalScroll(id="detail"):
            yield Static(id="detail-body")
        yield Static(id="status")
        yield Static(id="hint-bar")
        with Horizontal(id="filter-row"):
            yield Static("❯", id="prompt")
            yield Input(placeholder="Filter (fuzzy: 'exact ^prefix !negate)…", id="filter")

    def on_mount(self) -> None:
        self.theme = "ansi-dark"
        # The table is what you browse, so it keeps focus; `/` opens the filter.
        # That frees every bare key for an action and lets the row cursor show.
        self.query_one(DataTable).focus()
        self._refresh_warning()
        if self.scans.failures:
            names = ", ".join(n for n, _ in self.scans.failures)
            self.notify(f"skipped unreadable: {names}", severity="warning")
        # Build immediately so the list is usable at once, then re-budget the
        # columns once the table has real geometry - preserving the selection,
        # because a rebuild that reset it would swallow anything pressed in the
        # meantime.
        for problem in self.config.preset_errors:
            self.notify(problem, severity="warning", timeout=15)
        self.query_one(Tabs).active = self._active_tab
        self._refresh_view()
        self.call_after_refresh(self._first_layout)
        if self._to_read:
            # The screen is up; now pay for the scans. Deferred to after the
            # first refresh so the interface is genuinely on and answering
            # before a thread starts competing with it for the interpreter.
            self.call_after_refresh(self._start_reading)
        elif not self.scans.hosts and self.nmap.available:
            # Nothing to read and something can be run: the scope editor is the
            # useful thing to show, not an empty host list.
            self.call_after_refresh(self.action_new_scan)

    def _first_layout(self) -> None:
        table = self.query_one(DataTable)
        width = table.scrollable_content_region.width or table.size.width
        if width and width != self._last_width:
            self._last_width = width
            self._refresh_view(preserve=True)
        # `Resize` is dispatched to the Screen, not the App, so `on_resize` on an
        # App is never called; poll instead, as the search session's tick does.
        self.set_interval(0.2, self._on_tick)

    # --- view plumbing -----------------------------------------------------

    @property
    def view(self) -> vdefs.View:
        return self.stack[-1]

    def _column_widths(self, rows: list[vdefs.Row]) -> list[int]:
        """Fit every column into the table's width, clipping the greediest.

        A row that runs off the right edge is unreadable and unscrollable, and
        the full value is a keypress away in the report below - so columns are
        trimmed to fit rather than allowed to overflow.
        """
        headers = [f"{i} {c}  " for i, c in enumerate(self.view.columns, start=1)]
        natural = [width_of(h) for h in headers]
        # Measured in the worker when these are the view's own rows, which is
        # every case that is big enough for the difference to matter.
        counted = self.view.measured(rows)
        if counted is not None:
            natural = [max(header, cell)
                       for header, cell in zip(natural, counted, strict=False)]
        else:
            for row in rows:
                for i, cell in enumerate(row.cells[:len(natural)]):
                    width = width_of(cell)
                    if width > natural[i]:
                        natural[i] = width
        table = self.query_one(DataTable)
        available = (table.scrollable_content_region.width
                     or table.size.width or 100) - 2 - _MARK_W
        per_column_padding = 2
        total = sum(natural) + per_column_padding * len(natural)
        if total <= available or not natural:
            return natural
        # Trim the widest column repeatedly until it fits; never below a floor
        # that still shows something useful.
        widths = list(natural)
        floor = 6
        while sum(widths) + per_column_padding * len(widths) > available:
            widest = max(range(len(widths)), key=lambda i: widths[i])
            if widths[widest] <= floor:
                break
            widths[widest] -= 1
        return widths

    def _refresh_view(self, preserve: bool = False, restore: _Mark | None = None,
                      growing: bool = False) -> None:
        # Built once and used for both halves. `_column_widths` and
        # `_reload_rows` each used to call `View.rows`, so every sort, tab
        # switch and resize recomputed the whole projection twice - for the
        # service and grouping overviews, twice over every host in the set.
        # Widths come from the *unfiltered* rows on purpose: columns that
        # re-budgeted as the filter narrowed would shift under the cursor.
        all_rows = self._rows_now(self.view, growing=growing)
        if all_rows is None:                        # being built off the event loop
            self._after_build = (preserve, restore, growing)
            return
        if growing and restore is None:
            # Marked here, not when the model was published: a rebuild takes a
            # second at engagement scale, the list stays usable throughout, and
            # the row to come back to is the one the cursor is on *now* - not
            # the one it was on when the batch arrived.
            restore = self._mark_current()
        table = self.query_one(DataTable)
        # Read before the clear: `DataTable.clear` resets the cursor to (0, 0),
        # so `preserve` used to read back a zero it had just written and a
        # resize dropped the selection to the top of the list.
        keep = table.cursor_row or 0
        self._lay_columns(all_rows)
        self._fill(self._narrow(all_rows), preserve=preserve, restore=restore, keep=keep)

    def _lay_columns(self, rows: list[vdefs.Row]) -> None:
        """Re-lay the header for the current view, budgeting from `rows`.

        Called with the rows when there are rows, and with none when they are
        still being built - the header of the view being opened is part of
        saying which view that is.
        """
        table = self.query_one(DataTable)
        widths = self._column_widths(rows)
        laid = (id(self.view), tuple(widths), self._sort_col, self._sort_desc)
        if laid == self._laid:
            # Nothing about the header changed, and tearing it down takes every
            # row with it. A read publishing into an open list hits this on
            # every batch: same view, same columns, same widths, and the rows
            # are about to be replaced by `_fill` anyway.
            self._refresh_title()
            self.query_one("#subtitle", Static).update(self.view.subtitle)
            return
        self._laid = laid
        # Every row still queued was built for the columns being replaced, and
        # a row with the wrong number of cells is an error, not a cosmetic
        # mismatch - so re-laying the header abandons them.
        self._fill_gen += 1
        self._filling = False
        table.clear(columns=True)
        self._widths = widths
        # The marker is a column of its own, outside `View.columns`, so the
        # numbered sort columns keep their indices and their `1`-`9` keys.
        table.add_column(" ", key="mark", width=_MARK_W)
        for i, col in enumerate(self.view.columns, start=1):
            marker = ""
            if i - 1 == self._sort_col:
                marker = " ↓" if self._sort_desc else " ↑"
            label = clip_cells(f"{i} {col}{marker}", self._widths[i - 1])
            table.add_column(label, key=str(i - 1), width=self._widths[i - 1])
        self._refresh_title()
        self.query_one("#subtitle", Static).update(self.view.subtitle)

    def _reload_rows(self, preserve: bool = False) -> None:
        # A mark left by `Esc` clearing the filter is spent on the next rebuild,
        # whichever path gets there - the debounce timer or the flush.
        restore, self._pending_mark = self._pending_mark, None
        rows = self._rows_now(self.view)
        if rows is None:
            self._after_build = (preserve, restore, False)
            return
        keep = self.query_one(DataTable).cursor_row or 0
        self._fill(self._narrow(rows), preserve=preserve, restore=restore, keep=keep)

    def _narrow(self, rows: list[vdefs.Row]) -> list[vdefs.Row]:
        """Apply the filter box and the current sort to ``rows``."""
        text = self.query_one("#filter", Input).value.strip()
        self._spec = filtering.parse_filter(text) if text else filtering.FilterSpec()
        self._unfiltered = sum(1 for r in rows if not r.heading)
        if not self._spec.is_empty:
            rows = [r for r in rows
                    if r.heading or filtering.matches(self._spec, r.text, r.addresses,
                                                      r.records)]
            rows = _drop_empty_sections(rows)
        col = min(self._sort_col, max(0, len(self.view.columns) - 1))
        # Two stable passes rather than one compound key: `reverse` belongs to
        # the column only. Reversing a single (rank, heading, value) key would
        # turn the sections upside down and push every heading to the bottom of
        # its own lines.
        rows.sort(key=lambda r: _key_at(r, col), reverse=self._sort_desc)
        rows.sort(key=lambda r: (r.section_rank, 0 if r.heading else 1))
        return rows

    # --- work that is too slow for the event loop --------------------------

    def _rows_now(self, view: vdefs.View,
                  growing: bool = False) -> list[vdefs.Row] | None:
        """This view's rows, or `None` while they are being built in a thread.

        Projecting a large model is seconds of work - long enough that doing it
        between keypresses freezes the app - but it is also pure, so it is
        cached on the view and only ever paid once per model. Small sets are
        built inline: a spinner that appears and vanishes says less than the
        rows it delayed.

        `growing` says that whatever is on screen was built from an earlier
        state of the *same* view and is still true - which is what a read publishing
        a grown model produces. The rows stay and the rebuild reports outside
        the list; without it every batch of scans would replace a working list
        with a progress bar, which is the opposite of opening early.
        """
        if len(self.scans.hosts) < _BACKGROUND_ABOVE or not self._needs_building(view):
            return view.rows(self.scans)
        if self._busy is not None and self._busy.view is view:
            return None                             # already being built
        self._build_token += 1
        # Only when there is something to keep: the first batch has no rows yet,
        # and a bar under the right column headings is the whole of what the
        # interface can honestly say then.
        quiet = growing and bool(self._rows) and self._rows_view is view
        self._busy = _Busy(what=self._building_label(view), view=view,
                           token=self._build_token, refresh=quiet, quiet=quiet)
        self._abandoned = ""
        if not quiet:
            # The header of the view being opened, before its rows exist: the
            # columns are what say which view the wait belongs to. A quiet
            # rebuild keeps the header it already has, along with the rows.
            self._lay_columns([])
        self._show_busy()
        self._build_rows(view, self.scans, self._build_token)
        return None

    def _needs_building(self, view: vdefs.View) -> bool:
        """Would asking this view for its rows do the expensive work again?

        The Scans tab is rebuilt on every line a running scan prints, because
        its rows carry that run's elapsed time - but the expensive half, the
        file history, is cached separately and is what makes the first build of
        that tab slow. So the question is about the history, not the rows.
        """
        if view.kind == "scans":
            return self._history_for is not self.scans
        return not view.cached_for(self.scans)

    def _building_label(self, view: vdefs.View) -> str:
        return "the scan history" if view.kind == "scans" else f"{view.title.lower()}"

    @work(thread=True, exclusive=True, group="rows")
    def _build_rows(self, view: vdefs.View, scans: ScanSet, token: int) -> None:
        """Build one view's rows off the event loop, reporting as it goes."""
        def report(done: int, total: int, unit: str) -> None:
            busy = self._busy
            if busy is None or busy.token != token:
                # Esc, or another view asked for its rows: stop at the first
                # boundary the work offers rather than finishing unwanted work.
                raise _Abandoned
            self.call_from_thread(self._on_build_progress, token, done, total, unit)

        try:
            # One of the two owners of a long phase: the collector is out of
            # the way for its length, and the interpreter comes back to the
            # event loop between keystrokes rather than at 5 ms boundaries.
            with bulk.bulk(), bulk.responsive():
                view.rows(scans, report)
                # Measured here too: it is a pass over every cell of every row,
                # and the event loop should not be the one making it.
                view.measure()
        except _Abandoned:
            return
        except Exception as exc:                      # noqa: BLE001 - report, never crash
            self.call_from_thread(self._on_build_failed, token, exc)
            return
        # The rows are cached on the view itself; the main thread only needs
        # to hear that they are there.
        self.call_from_thread(self._on_build_ready, token)

    def _on_build_progress(self, token: int, done: int, total: int,
                           unit: str) -> None:
        if self._busy is None or self._busy.token != token:
            return
        self._busy.done, self._busy.total, self._busy.unit = done, total, unit
        self._show_busy()

    def _on_build_ready(self, token: int) -> None:
        if self._busy is None or self._busy.token != token:
            return                                    # cancelled, or superseded
        self._busy = None
        preserve, restore, growing = self._after_build or (False, None, False)
        self._after_build = None
        # The rows are cached on the view now, so this second pass is the
        # ordinary synchronous one. It happens *before* any snapshot parked
        # while the build ran, and that order is the whole point: put what was
        # just built in front of the user, then let the newer model rebuild
        # behind it. Going straight to the newer one means a read that keeps
        # publishing never puts a list on screen at all.
        self._refresh_view(preserve=preserve, restore=restore, growing=growing)
        if not self._filling:
            # A fill that is still running calls back when it finishes; one
            # that completed in a single pass already has.
            self._take_parked()

    def _on_build_failed(self, token: int, exc: Exception) -> None:
        if self._busy is None or self._busy.token != token:
            return
        self._busy = None
        self._abandoned = f"{self.view.title} could not be built: {exc}"
        self.notify(self._abandoned, severity="error", timeout=12)
        self._fill([])
        self._take_parked()

    def _cancel_build(self) -> None:
        """Give up on the build in progress; Esc, and the 2-second rule."""
        busy, self._busy = self._busy, None
        self._after_build = None
        if busy is None:
            return
        if busy.refresh:
            # The rows on screen were never replaced, so there is nothing to
            # restore - they are simply out of date, not wrong, and saying so
            # is the whole of the recovery.
            self.notify(f"stopped updating {busy.what} · the rows shown are the "
                        "ones read so far" if busy.quiet else
                        "stopped re-reading · the list is one scan out of date",
                        severity="warning")
            self._refresh_status()
            self._take_parked()
            return
        self._abandoned = busy.what
        self._fill([])
        self._take_parked()

    def _show_busy(self) -> None:
        """The loading state, in the tab's own content area.

        A determinate bar wherever the work can count itself, a spinner where
        it cannot, and the way out on the same line - nothing else moves while
        this is on screen.
        """
        busy = self._busy
        if busy is None:
            return
        if busy.refresh:
            self._refresh_status()
            return
        try:
            pane = self.query_one("#empty", Static)
            table = self.query_one(DataTable)
        except NoMatches:
            return
        pane.set_class(True, "-shown")
        table.set_class(True, "-empty")
        message = Text(justify="center")
        frame = _SPINNER[self._spin % len(_SPINNER)]
        message.append(f"{frame} reading {busy.what}\n", style="bold")
        message.append_text(_bar(busy))
        message.append("\n")
        message.append("Esc stops waiting", style="dim")
        pane.update(message)

    def _fill(self, rows: list[vdefs.Row], preserve: bool = False,
              restore: _Mark | None = None, keep: int = 0) -> None:
        """Put `rows` in the table - the first screenful now, the rest after.

        Handing twenty thousand rows to the table at once is a second or two in
        which nothing renders and no key is read. The list a reader can see is
        the first fifty of them, so those go in immediately and the remainder
        follow a chunk per frame; the table is scrollable and complete either
        way, and the status line says while it is still filling.

        A set that fits in one chunk - which is every ordinary engagement, and
        every fixture - is filled in one pass, exactly as it always was.
        """
        self._rows = rows
        self._rows_view = self.view
        self._fill_plan = (preserve, restore, keep)
        # Where the cursor belongs in *this* list, resolved once against the
        # whole of it. Resolving it per chunk meant a long list dragged the
        # cursor back to the same row on every frame for the seconds it took to
        # arrive, so the list could not be moved around while it filled.
        index = 0
        if rows:
            if restore is not None:
                index = restore.locate(rows)
            elif preserve:
                index = keep
            index = max(0, min(len(rows) - 1, index))
        self._cursor_to: int | None = index if rows else None
        self._filled = 0
        # Anything still queued belongs to the list that was just replaced.
        self._fill_gen += 1
        self._filling = len(rows) > _FILL_CHUNK
        self.query_one(DataTable).clear()
        self._fill_more(self._fill_gen)

    def _fill_more(self, generation: int) -> None:
        """One chunk of rows, then either the next frame or the finishing work."""
        if generation != self._fill_gen:
            return                                  # a newer list is being filled
        try:
            table = self.query_one(DataTable)
        except NoMatches:
            return
        rows = self._rows
        query = self._spec.highlights or self._spec.query
        # A screenful without asking the clock, then as much more as the budget
        # allows - and far enough to reach the row the reader was on, when that
        # is close enough to be worth one longer turn. Leaving it to arrive with
        # its own chunk means the list sits at the top for a second first, which
        # is what "the selection jumps around" looks like from the outside.
        least = self._filled + _FILL_CHUNK
        began = time.perf_counter()
        deadline, reach = began + _FILL_BUDGET, began + _FILL_REACH
        end = self._filled
        while end < len(rows):
            stop = min(len(rows), end + _FILL_STEP)
            for row in rows[end:stop]:
                table.add_row(
                    Text(self._mark_glyph(row), style=_MARK_STYLE),
                    *(self._cell(c, query, self._width_at(n), row.style)
                      for n, c in enumerate(row.cells)))
            end = stop
            if end < least:
                continue                            # the screenful, always
            now = time.perf_counter()
            if (self._cursor_to is not None and end <= self._cursor_to
                    and now < reach):
                continue                            # still chasing the cursor
            if now >= deadline:
                break
        if self._filled == 0 and end:
            # The first chunk is on screen: whatever the loading state put up
            # comes down now rather than when the last chunk lands.
            self.query_one("#empty", Static).set_class(False, "-shown")
            table.set_class(False, "-empty")
        self._filled = end
        # Re-laying the columns (a resize) must not move the selection, and
        # neither must coming back out of a drill-down; only a genuine change
        # of the row set resets it to the top. Placed once, on the first chunk
        # that reaches it, and then left alone - the list belongs to the reader
        # from that moment, however much of it is still coming.
        if self._cursor_to is not None and self._cursor_to < end:
            table.move_cursor(row=self._cursor_to)
            self._cursor_to = None
            # The record, as soon as the cursor is on it rather than when the
            # last chunk lands: otherwise the pane spends the rest of the fill
            # reporting whatever happens to be at the top of the list.
            self._refresh_detail()
        if end < len(rows):
            # A timer rather than `call_after_refresh`: the next chunk has to
            # start whether or not the screen happened to need repainting, and
            # a millisecond is long enough for input and rendering to get their
            # turn in between.
            self.set_timer(0.001, lambda: self._fill_more(generation))
            self._refresh_status()
            return
        self._filling = False
        self._refresh_empty(rows)
        self._refresh_status()
        self._refresh_detail()
        self._absorbed()

    def _refresh_empty(self, rows: list[vdefs.Row]) -> None:
        """A list with nothing in it has to say why, and how to get out of it.

        Headers over blank space is the state a user cannot read: a filter that
        matches nothing looks exactly like a scan that found nothing.
        """
        try:
            pane = self.query_one("#empty", Static)
            table = self.query_one(DataTable)
        except NoMatches:
            return
        empty = not rows
        pane.set_class(empty, "-shown")
        table.set_class(empty, "-empty")
        if not empty:
            return
        query = self.query_one("#filter", Input).value.strip()
        reading = self._reading
        if reading is not None and reading.showing and not query:
            # Never a premature negative: an empty list during a read says the
            # read is still going, not that the engagement is empty.
            headline = "Still reading the scans"
            hint = (f"{reading.done} of {reading.total} {reading.unit} read · "
                    f"{len(self.scans.hosts)} host(s) so far")
        elif reading is not None and not reading.finished and not query:
            # Inside the quiet window: nothing yet is not news, and saying the
            # scan recorded no hosts before a file has been opened would be.
            headline = ""
            hint = ""
        elif (reading is not None and reading.failures
                and not self.scans.hosts and not query):
            # Candidates were found and none of them could be read. Saying
            # "this scan recorded no hosts" here would be a lie about the
            # engagement rather than a report about the files.
            names = ", ".join(n for n, _ in reading.failures)
            headline = "Nothing could be read"
            hint = f"{len(reading.failures)} file(s) failed: {names}"
        elif self._abandoned:
            headline = f"Stopped reading {self._abandoned}"
            hint = "nothing was lost · leave this tab and come back to read it again"
        elif query:
            headline = f'Nothing matches "{query}"'
            hint = f"Esc clears the filter · {self._unfiltered} row(s) without it"
        elif self._active_tab == "names":
            headline = "No name is known for any host"
            hint = ("the DNS names preset resolves them, and a TLS service's "
                    "certificate is read when it is scanned")
        elif self._active_tab == "scans" and not self.nmap.available:
            headline = "Scanning is unavailable"
            hint = f"{self.nmap.reason} · everything else in the viewer still works"
        elif self._active_tab == "scans":
            headline = "No scans yet"
            hint = "every scan file present shows here as a history · n runs one"
        elif self._only_open and self.view.kind == "host-detail":
            # Ahead of the next branch: a host's ports inherit the Hosts tab.
            headline = "No open port on this host"
            hint = "u lists every port the scan recorded, closed and filtered too"
        elif (self._only_up or self._only_ports) and self._active_tab == "hosts":
            # `r` is the narrower of the two, so it names the headline; the
            # hint names every key that is on, since each has to be undone.
            headline = "No host has an open port" if self._only_ports else "No host is up"
            keys = [k for on, k in ((self._only_up, "u"), (self._only_ports, "r")) if on]
            verb = "lists" if len(keys) == 1 else "list"
            hint = f"{' and '.join(keys)} {verb} every host the scan named"
        elif len(self.stack) > 1:
            headline = f"{self.view.title} has nothing to show"
            hint = "Esc goes back · ? for help"
        else:
            headline = "This scan recorded no hosts"
            hint = "the files named on the command line are the whole truth · ? for help"
        if not headline:
            pane.set_class(False, "-shown")
            return
        message = Text(justify="center")
        message.append(headline + "\n", style="bold")
        message.append(hint, style="dim")
        pane.update(message)

    def _width_at(self, index: int) -> int:
        return self._widths[index] if index < len(self._widths) else 0

    def _cell(self, value: str, query, width: int = 0, style: str = "") -> Text:
        """Render a cell, highlighting the characters the filter matched.

        Without this the filter narrows the list but never says *why* a row
        survived, which is the same thing the search session solves by
        highlighting matched characters in a result row.
        """
        shown = clip_cells(str(value), width) if width else str(value)
        cell = Text(shown, no_wrap=True, style=style)
        if query is None or not shown or style:
            # A styled row is a section heading: it carries no filter text, so
            # there is nothing on it for the filter to have matched.
            return cell
        # A structured filter hands a tuple, one query per term: each is
        # highlighted wherever it matches, since under OR a cell matches one.
        spans: set[int] = set()
        for each in (query if isinstance(query, tuple) else (query,)):
            found = match_spans(each, shown)
            if found is not None:
                spans.update(found[1])
        if spans:
            style = self.config.theme.get("match", "bold bright_yellow")
            for pos in spans:
                if 0 <= pos < len(shown):
                    cell.stylize(style, pos, pos + 1)
        return cell

    def _refresh_title(self) -> None:
        """The path taken below the active tab.

        At the top of an overview the tab already names it, so this row is only
        spent once there is somewhere to go back to.
        """
        try:
            bar = self.query_one("#title", Static)
        except NoMatches:
            return
        if len(self.stack) <= 1:
            bar.display = False
            return
        bar.display = True
        line = Text()
        for i, view in enumerate(self.stack):
            if i:
                line.append("  ›  ", style="dim")
            last = i == len(self.stack) - 1
            line.append(view.title, style="bold" if last else "dim")
        bar.update(line)

    def _busy_note(self) -> Text | None:
        """The refresh indicator: what is being re-read, and how far in."""
        busy = self._busy
        if busy is None or not busy.refresh:
            return None
        verb = "updating" if busy.quiet else "reading"
        note = Text(f"{_SPINNER[self._spin % len(_SPINNER)]} {verb} {busy.what}",
                    style="bold")
        if busy.total:
            note.append(f" {busy.done}/{busy.total} {busy.unit}".rstrip(), style="dim")
        if not busy.quiet:
            note.append("  ·  Esc stops waiting", style="dim")
        return note

    def _refresh_status(self) -> None:
        # A read and a projection can both be running; the read is the one that
        # belongs to the whole window, so it leads.
        left = self._read_note() or self._busy_note() or Text(
            f"{len(self.scans.hosts)} host(s) across "
            f"{len(self.scans.sources)} scan(s)", style="dim")
        shown = sum(1 for r in self._rows if not r.heading)
        right = Text(f"{shown} row{'s' if shown != 1 else ''}", style="bold")
        if self._filling:
            right.append(f"  ·  listing {self._filled} of {len(self._rows)}",
                         style="dim")
        if self._marked:
            right.append(f"  ·  {len(self._marked)} marked", style=_MARK_STYLE)
        total_runs = len(self.runner.runs) + len(self.captures.runs)
        if total_runs:
            right.append(f"  ·  {total_runs} run(s)", style="dim")
        if self._several_dirs:
            # Opened on several directories, output goes to only one of them.
            right.append(f"  ·  output → {_short(self.scan_dir)}", style="dim")
        # Symbol and words, never colour alone: whether a scan can be started at
        # all is worth knowing before reaching for the key that starts one.
        if self._sort_col < len(self.view.columns):
            arrow = "↓" if self._sort_desc else "↑"
            right.append(
                f"  ·  sorted by {self._sort_col + 1} {self.view.columns[self._sort_col]}"
                f" {arrow}", style="dim")
        # Gated on `include` specifically: `networks` counts the excludes too, so
        # a filter of only `!10.0.0.0/8` used to render a bare "· in " with
        # nothing after it.
        if self._spec.include:
            right.append("  ·  in " + " or ".join(str(n) for n in self._spec.include),
                         style="bold")
        if self._spec.exclude:
            right.append("  ·  not in " + ", ".join(str(n) for n in self._spec.exclude),
                         style="bold")
        if self._spec.expr is not None or self._spec.ignored:
            # How a structured filter was read, grouping spelled out, and what
            # it had to leave aside - a half-typed query is the normal case.
            right.append("  ·  where " if self._spec.expr is not None else "  ·  ",
                         style="dim")
            right.append(filtering.describe(self._spec), style="bold")
        # Last, because the line is clipped from the right on a narrow terminal
        # and which tools exist matters less than what the list is currently
        # showing. The two tool tokens sit adjacent with no separator between
        # them, so they read as one "what is here" cluster.
        right.append("  ·  ")
        right.append(self.nmap.label(),
                     style="bold" if self.nmap.available else "dim")
        right.append("  ")
        right.append(self.gowitness.label(),
                     style="bold" if self.gowitness.available else "dim")
        if self._report_proc is not None:
            right.append(f"  ◉ report :{self.config.gowitness_report_port}",
                         style="bold")
        if self._web is not None and self._web.running:
            right.append(f"  ◉ web {self._web.url}", style="bold")

        line = Text.assemble(left, "  ", right)
        try:
            self.query_one("#status", Static).update(line)
        except NoMatches:
            return
        in_filter = self.focused is self.query_one("#filter", Input)
        items = list(FILTER_HINTS if in_filter else _HINTS.get(self.view.kind, []))
        if not in_filter:
            # Only once there is something to open: the bar is a scarce
            # resource that already drops hints on a narrow terminal, and a key
            # that does nothing yet should not be spending it. The raw-log key
            # is the same rule at line granularity - it appears when the line
            # under the pane's cursor is one that opens something.
            if self._raw is not None:
                # The raw state has its own small set: the record's keys mean
                # nothing while it is showing, and a bar still offering them
                # would be describing a screen that is not there. `Esc` is
                # appended below, as it is for every other state.
                items = [("←→", "read")]
                items.append(("d", "full screen"))
            elif self._opens_here() is not None:
                items.insert(0, ("o", "raw log"))
            if self.shots and self.view.kind in ("hosts", "services", "host-detail"):
                items.append(("i", "shot"))
            items.append(("Esc", self._esc_label()))
        kept, dropped = _fit_hints(items, max(0, self.size.width - 2))
        hint = Text(no_wrap=True, overflow="ellipsis")
        for i, (key, verb) in enumerate(kept):
            if i:
                hint.append("   ")
            hint.append(key, style="bold")
            hint.append(f" {verb}", style="dim")
        if dropped:
            hint.append("   …", style="dim")
        self.query_one("#hint-bar", Static).update(hint)

    def _esc_label(self) -> str:
        if self._raw is not None or self._raw_pending is not None:
            return "back to the record"
        if self.focused is self.query_one("#filter", Input):
            return "back to the list"
        if self.query_one("#filter", Input).value.strip():
            return "clear filter"
        if len(self.stack) > 1:
            return "back"
        if self._active_tab != _TABS[0][0]:
            return "first tab"
        return "quit (asks while a scan runs)" if self.runner.busy() else "quit"

    # --- interaction -------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-filter after the same idle gap a search session waits for.

        Every keystroke re-filtered, re-sorted, cleared and re-added every
        `DataTable` row and ran `match_spans` per cell for the highlighting.
        `config.debounce_ms` already exists for exactly this and the viewer
        simply was not using it.
        """
        if event.input.id != "filter":
            return
        if self._filter_debounce is not None:
            self._filter_debounce.stop()
        delay = self.config.debounce_ms / 1000
        if delay <= 0:
            self._reload_rows()
            return
        self._filter_debounce = self.set_timer(delay, self._reload_rows)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter":
            self._flush_filter()
            self.query_one(DataTable).focus()
            self._refresh_status()

    def _flush_filter(self) -> None:
        """Apply a pending filter now - leaving the box must not lose a keystroke."""
        if self._filter_debounce is not None:
            self._filter_debounce.stop()
            self._filter_debounce = None
            self._reload_rows()

    def action_move(self, delta: int) -> None:
        table = self.query_one(DataTable)
        if table.row_count:
            table.move_cursor(row=max(0, min(table.row_count - 1,
                                             (table.cursor_row or 0) + delta)))

    def action_sort(self, index: int) -> None:
        """A number (or a click on the heading) picks the column, ascending;
        the same one again reverses it, and again flips it back.

        This was once the other way round - a number always sorted ascending
        and `r` reversed - because testers could not form a model of the
        toggle. It came back at the user's request, which freed `r` for the
        open-ports filter. "Same column" means the one currently sorted, which
        the arrow in its heading and the status line both name, so a list that
        opens sorted by its first column reverses on the first `1`.
        """
        if index >= len(self.view.columns):
            return
        if index == self._sort_col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_col = index
            self._sort_desc = False
        self._refresh_view()

    def action_stats(self) -> None:
        self._toggle_stats()

    def action_group(self) -> None:
        self._cycle_grouping()

    def action_up(self) -> None:
        self._toggle_up()

    def action_open_ports(self) -> None:
        self._toggle_open_ports()

    def _toggle_stats(self) -> None:
        self._activate("hosts" if self._active_tab == "stats" else "stats")

    def _cycle_grouping(self) -> None:
        if self._active_tab in _GROUP_TABS:
            index = (_GROUP_TABS.index(self._active_tab) + 1) % len(_GROUP_TABS)
            self._activate(_GROUP_TABS[index])
        else:
            self._activate(_GROUP_TABS[0])

    def _toggle_up(self) -> None:
        self._toggle_host_filter("_only_up")

    def _toggle_open_ports(self) -> None:
        self._toggle_host_filter("_only_ports")

    def _toggle_host_filter(self, flag: str) -> None:
        """`u` (up) and `r` (an open port): filters on the host list, not
        overviews of their own, so from another tab they go to the host list.

        On a host's port list both ask the same question of ports - which of
        these did the scan actually find open - and stay where they are rather
        than throwing the reader back to the host list. That flag is separate
        from the host-list ones: hiding closed ports is no reason to hide hosts.
        """
        if self.view.kind == "host-detail" and self.view.hosts:
            self._only_open = not self._only_open
            restore = self._mark_current()
            self.stack[-1] = vdefs.host_detail(self.view.hosts[0], self._only_open)
            self._refresh_view(restore=restore)
            return
        if self._active_tab != "hosts":
            self._activate("hosts")
        setattr(self, flag, not getattr(self, flag))
        self.stack[-1] = vdefs.hosts_view(self._only_up, self._only_ports)
        self._reset_sort()

    def _mark_current(self) -> _Mark:
        """Where the cursor is now, so a later `Esc` can put it back."""
        table = self.query_one(DataTable)
        index = table.cursor_row or 0
        row = self._rows[index] if 0 <= index < len(self._rows) else None
        return _Mark(target=row.target if row is not None else None,
                     key=(row.section, row.cells[0]) if row and row.cells else (),
                     index=index,
                     sort_col=self._sort_col, sort_desc=self._sort_desc,
                     filter=self.query_one("#filter", Input).value)

    def _set_filter(self, text: str) -> None:
        """Put a level's filter in the box without a keystroke's side effects.

        No `Changed`, so no debounced rebuild: the caller rebuilds once, with
        the cursor mark it is restoring, and a later rebuild without it would
        throw the cursor to the top.
        """
        if self._filter_debounce is not None:
            self._filter_debounce.stop()
            self._filter_debounce = None
        box = self.query_one("#filter", Input)
        if box.value != text:
            with box.prevent(Input.Changed):
                box.value = text

    def _reset_sort(self) -> None:
        self._sort_col, self._sort_desc = self.view.default_sort
        self._refresh_view()

    def _view_for_tab(self, tab_id: str) -> vdefs.View:
        if tab_id == "scans":
            return self._scans_view()
        if tab_id == "names":
            return vdefs.names_view()
        if tab_id == "services":
            return vdefs.services_view()
        if tab_id == "stats":
            return vdefs.statistics_view()
        if tab_id in _GROUP_TABS:
            return vdefs.grouping_view(tab_id.removeprefix("group-"))
        return vdefs.hosts_view(self._only_up, self._only_ports)

    def _scans_index(self) -> rawlog.Scanned:
        """The scan index for the model on screen, rebuilt when it is replaced."""
        if self._scanned_for is not self.scans or self._scanned is None:
            self._scanned = rawlog.Scanned(self.scans.files)
            self._scanned_for = self.scans
        return self._scanned

    def _scan_history(self, report: Report | None = None) -> list[timeline.Scan]:
        """The file history, rebuilt only when the model actually changes."""
        if self._history_for is not self.scans:
            # A report only when a background build handed one down: this is
            # the expensive half of the tab, and the only part of it worth
            # counting.
            self._history = timeline.build(self.scans.files, report)
            self._history_for = self.scans
        return self._history

    def _scans_view(self) -> vdefs.View:
        def build(_scans, report: Report | None = None) -> list[vdefs.Row]:
            history = self._scan_history(report)
            done = {str(s.path) for s in history if s.path}
            # A finished run is already in the history as its file; only runs
            # with no file yet (running, failed, cancelled) get their own row.
            live = [r for r in self.runner.runs
                    if r.state is not State.DONE or str(r.xml_path) not in done]
            # A capture leaves no scan file, so every one of them keeps its row
            # rather than being replaced by an entry in the file history.
            live += list(self.captures.runs)
            return scan_views.history_rows(history, live)

        return vdefs.View(
            title="Scans", columns=scan_views.SCANS_COLUMNS, build=build,
            kind="scans", tab="scans", default_sort=scan_views.SCANS_DEFAULT_SORT,
            # A live run's elapsed time and its log move without the model
            # changing, so these rows are rebuilt every refresh. The expensive
            # half - the file history - is cached in `_scan_history`.
            cacheable=False, reports=True,
        )

    def _activate(self, tab_id: str) -> None:
        """Switch overview. A tab replaces the stack: drill-downs belong to the
        overview they were opened from, not to a different one.

        The overview being left is remembered as it stands - its filter, sort
        and cursor, or as it was when the first drill-down left it - and the
        one being opened comes back the same way, so a tab is somewhere to
        return to rather than something rebuilt from scratch each visit.
        """
        if self.stack:
            # Filed under the overview at the bottom of the stack: a drill-down
            # can have moved the tab row on (`_sync_tab`), but the level these
            # belong to is still the one the stack started from.
            root = self.stack[0].tab or self._active_tab
            self._tab_marks[root] = (
                self._marks[0] if self._marks else self._mark_current())
        self._active_tab = tab_id
        self._abandoned = ""
        self.stack = [self._view_for_tab(tab_id)]
        self._marks.clear()
        tabs = self.query_one(Tabs)
        if tabs.active != tab_id:
            tabs.active = tab_id
        mark = self._tab_marks.get(tab_id)
        self._set_filter(mark.filter if mark is not None else "")
        if mark is None:
            self._reset_sort()
        else:
            self._sort_col, self._sort_desc = mark.sort_col, mark.sort_desc
            self._refresh_view(restore=mark)
        self.query_one(DataTable).focus()

    def _sync_tab(self) -> None:
        """Mark the tab whose subject is now on top of the stack.

        Opening a service from a host record shows that service across every
        host - the services overview's subject - so leaving the tab row on
        `Hosts` says the wrong thing about where the user is. The topmost view
        that claims a tab wins; a host's own record claims none, so it keeps the
        tab of whatever it was opened from. `_active_tab` is set *before* the
        widget, which makes `on_tabs_tab_activated` a no-op: only a tab the user
        selects replaces the stack.
        """
        tab = next((v.tab for v in reversed(self.stack) if v.tab), "")
        if not tab or tab == self._active_tab:
            return
        self._active_tab = tab
        tabs = self.query_one(Tabs)
        if tabs.active != tab:
            tabs.active = tab

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        tab_id = event.tab.id or "hosts"
        if tab_id != self._active_tab:
            self._activate(tab_id)
        else:
            self.query_one(DataTable).focus()

    def _cycle_tab(self, delta: int) -> None:
        order = [tid for tid, _ in _TABS]
        index = (order.index(self._active_tab) + delta) % len(order)
        self._activate(order[index])

    def action_swap(self) -> None:
        self._cycle_tab(1)

    def action_swap_back(self) -> None:
        self._cycle_tab(-1)

    def action_drill(self) -> None:
        """Open the selected row, from wherever it is.

        Every row leads somewhere, and the destinations chain: a host opens its
        services, a service opens the hosts running it, one of those opens that
        host's record again. Digging on is always available, so nothing has to
        be reached by unwinding back to an overview first.
        """
        table = self.query_one(DataTable)
        if table.cursor_row is None or not (0 <= table.cursor_row < len(self._rows)):
            return
        row = self._rows[table.cursor_row]
        # `drill` is what this row *opens*, when that is not the record the
        # detail pane below is reporting on.
        target = row.drill if row.drill is not None else row.target
        if target is None:
            return
        if isinstance(target, vdefs.View):
            # An aggregate line names its own destination - the hosts it counts,
            # or the grouping it totals. Pushed like any drill-down, so `Esc`
            # comes back to the figure rather than to a different tab.
            view = target
        elif isinstance(target, proj.ServiceGroup):
            view = vdefs.service_detail(target)
        elif isinstance(target, vdefs.Grouping):
            view = vdefs.grouping_detail(target)
        elif hasattr(target, "address"):
            view = vdefs.host_detail(target, self._only_open)
        elif hasattr(target, "port"):
            view = self._service_view(target)
        else:
            return
        self._marks.append(self._mark_current())
        # A filter belongs to the level it was typed on: the one pushed starts
        # unfiltered, and the one left gets its own back on `Esc`.
        self._set_filter("")
        self.stack.append(view)
        self._sync_tab()
        self._reset_sort()

    def _service_view(self, svc) -> vdefs.View:
        """One host's service, opened as that service across the whole set."""
        group = proj.group_for(self.scans.hosts, svc)
        if group is not None:
            return vdefs.service_detail(group)
        # Only a closed or filtered port gets here - it is in no overview row,
        # so fall back to every host that reports the same port at all.
        members = [(h, s) for h in self.scans.hosts for s in h.services
                   if s.port == svc.port and s.protocol == svc.protocol]
        return vdefs.grouping_detail(
            vdefs.Grouping(key="port", label=f"{svc.port}/{svc.protocol}",
                           members=members))

    def action_mark(self) -> None:
        """Mark what the row stands for - or unmark it, when it is all marked.

        A row marks its *records*, so one keypress on the `https` row of the
        service overview collects every host running it. Anything else would
        make a bucket row's mark state unrepresentable.
        """
        row = self._current_row()
        if row is None or not row.records:
            return
        keys = [r.identity for r in row.records]
        if all(k in self._marked for k in keys):
            for key in keys:
                self._marked.pop(key, None)
        else:
            for record in row.records:
                self._marked.setdefault(record.identity, record)
        self._reload_rows(preserve=True)

    def action_clear_marks(self) -> None:
        if not self._marked:
            return
        self._marked.clear()
        self._reload_rows(preserve=True)

    def _mark_glyph(self, row: vdefs.Row) -> str:
        """`●` when the whole row is marked, `◐` when only part of a bucket is.

        Showing `●` for a partly marked bucket would be a lie, and showing
        nothing would hide the marks entirely.
        """
        if not self._marked or not row.records:
            return ""
        marked = sum(1 for r in row.records if r.identity in self._marked)
        if not marked:
            return ""
        return "●" if marked == len(row.records) else "◐"

    # --- scanning ----------------------------------------------------------

    def _selected_run(self) -> ScanRun | None:
        row = self._current_row()
        target = row.target if row is not None else None
        return target if isinstance(target, ScanRun) else None

    def action_report_mode(self) -> None:
        """Open the entry under the pane's cursor, or cycle a scan's report.

        Two meanings, disjoint by construction rather than by precedence: a
        record that offers entries is never a scan's report, and a scan's
        report has no line to open. The hint bar shows whichever is live, so
        the key never silently does the other one.
        """
        request = self._opens_here()
        if request is not None:
            self._open_raw(request)
            return
        if self.view.kind != "scans":
            return
        index = scan_views.MODES.index(self._report_mode)
        self._report_mode = scan_views.MODES[(index + 1) % len(scan_views.MODES)]
        self._refresh_detail()

    def action_freeze_log(self) -> None:
        """Freeze the *view*, never the scan.

        nmap's timers run against the wall clock, so suspending the process
        would risk timing hosts out on resume. The pane header says which of the
        two this is.
        """
        if self.view.kind != "scans":
            return
        self._log_frozen = not self._log_frozen
        self._refresh_detail()
        self._refresh_status()

    def action_cancel_scan(self) -> None:
        running = self.runner.busy()
        if running is None:
            return
        if self.runner.cancel():
            self.notify(f"cancelling {running.preset}")

    def action_new_scan(self) -> None:
        self._start_scan_flow(None)

    @work(exclusive=True, group="modal")
    async def _start_scan_flow(self, targets: list[str] | None) -> None:
        """Scope → preset → command → review → run. Any step can back out."""
        if not self.nmap.available:
            self.notify(f"cannot scan: {self.nmap.reason}", severity="error")
            return
        running = self.runner.busy()
        if running is not None:
            self.notify(f"{running.preset} is still running — cancel it first (c)",
                        severity="warning")
            return
        if targets is None:
            targets = await self.push_screen_wait(ScopeScreen())
            if not targets:
                return

        presets = self.config.nmap_presets
        if not presets:
            self.notify("no scan presets configured", severity="error")
            return
        scope_line = ", ".join(targets[:4]) + (" …" if len(targets) > 4 else "")
        name = await self.push_screen_wait(PresetScreen(
            f"New scan · {len(targets)} target(s)", scope_line, presets))
        if name is None:
            return

        problem = presets_mod.writable(self.scan_dir)
        if problem is not None:
            self.notify(f"cannot write the scan here: {problem}", severity="error")
            return

        out_base = presets_mod.output_base(self.scan_dir, name)
        args = presets[name]
        if presets_mod.PORTS_PLACEHOLDER in args:
            # The reference workflow greps the open ports out of the previous
            # scan's .gnmap and feeds them to -p. The model already knows them.
            known = exporter.export_ports(exporter.records_for(self.scans.hosts))
            if not known or not known[0]:
                self.notify(f"{name}: no open port is known yet — run a service "
                            "scan first, or type the ports yourself",
                            severity="error", timeout=12)
                return
            args = args.replace(presets_mod.PORTS_PLACEHOLDER, known[0])
        command = " ".join([self.config.nmap_path, args, *targets])
        note = f"writes {out_base}.{{xml,nmap,gnmap}}"
        while True:
            edited = await self.push_screen_wait(
                CommandScreen(f"Scan · {name}", command, note))
            if edited is None:
                return
            try:
                args = presets_mod.parse_command(edited, self.config.nmap_path)
            except presets_mod.CommandError as exc:
                self.notify(str(exc), severity="error", timeout=10)
                command = edited
                continue
            break

        # The targets are whatever survived the edit, in the order given.
        scan_args = [a for a in args if a not in targets]
        chosen = [a for a in args if a in targets] or targets
        elevate = presets_mod.needs_root(scan_args) and os.geteuid() != 0
        argv = presets_mod.build_argv(self.config.nmap_path, scan_args, chosen,
                                      str(out_base), elevate)
        confirmed = await self.push_screen_wait(ReviewScreen(
            argv, chosen, str(out_base), elevate,
            presets_mod.privileged_labels(scan_args)))
        if not confirmed:
            return
        self._run_scan(ScanRun(preset=name, argv=argv, targets=chosen,
                               out_base=out_base, elevated=elevate))

    @work(group="scan")
    async def _run_scan(self, run: ScanRun) -> None:
        self._log_frozen = False
        self._report_mode = "raw"
        self.notify(f"started {run.preset}")
        await self.runner.run(run, self._on_scan_line, self._on_scan_done,
                              on_start=self._on_run_started)

    # --- captures ----------------------------------------------------------

    def _capture_urls(self, records: list) -> list[str]:
        """The HTTP(S) URLs of a selection, fully qualified.

        `export_urls` is reused rather than reimplemented: it already emits one
        URL per open HTTP service *and* per name the host answers to, carrying
        a scheme and an explicit port. That form is what stops gowitness
        deriving its own candidates, so the list that is written is the list
        that gets probed.
        """
        return exporter.export_urls(records)

    @work(exclusive=True, group="capture")
    async def _start_capture(self, records: list) -> None:
        """Capture the selection, if there is anything in it to capture."""
        if not self.gowitness.available:
            self.notify(f"gowitness unavailable: {self.gowitness.reason}",
                        severity="error", timeout=12)
            return
        if self.captures.busy() is not None:
            self.notify("a capture is already running", severity="warning")
            return
        urls = self._capture_urls(records)
        if not urls:
            # Refused rather than started: a capture of nothing looks like a
            # capture that found nothing, which is a different finding.
            self.notify("nothing to capture — no HTTP or HTTPS service in this "
                        "selection", severity="warning")
            return
        paths = gw_capture.capture_dir(self.scan_dir)
        try:
            gw_capture.write_urls(paths, urls)
        except OSError as exc:
            self.notify(f"could not write the URL list: {exc.strerror or exc}",
                        severity="error")
            return
        argv = gw_capture.scan_argv(
            self.gowitness, paths,
            chrome_path=self.config.gowitness_chrome_path,
            collect_all=self.config.gowitness_collect_all)
        run = gw_capture.CaptureRun(argv=argv, paths=paths, urls=urls,
                                    backend=self.gowitness.backend or "")
        await self._run_capture(run)

    async def _run_capture(self, run: gw_capture.CaptureRun) -> None:
        self._log_frozen = False
        self._report_mode = "raw"
        self.notify(f"capturing {run.scope} with gowitness ({run.backend})")
        # Shown as soon as it is listed rather than when it first speaks: a
        # container backend pulls its image before the tool runs at all, and a
        # capture that is nowhere in the Scans tab for the first few minutes
        # looks like a capture that never started.
        await self.captures.run(run, self._on_scan_line, self._on_capture_done,
                                on_start=self._on_run_started)

    def _on_run_started(self, run) -> None:
        """Put a just-started run on screen before it has produced anything."""
        self._activate("scans")
        self._reload_rows(preserve=True)
        self._select_target(run)

    def _on_capture_done(self, run) -> None:
        # Read back whatever it managed, whatever became of it: a capture that
        # was cancelled or died part way still wrote rows for the URLs it had
        # already reached, and those are results the operator waited for.
        self._load_captures()
        # The only place a failed target is recorded: gowitness writes it to
        # neither the results file nor the database.
        self.shots.add_failures(run.failures)
        if run.state is State.DONE:
            self.notify(f"capture: {run.result}")
        else:
            self.notify(f"capture: {run.result}",
                        severity="warning" if run.state is State.CANCELLED else "error")
        if self.view.kind == "scans":
            self._reload_rows(preserve=True)
        self._refresh_status()

    def _record_captures(self) -> list:
        """Every capture belonging to the row the cursor is on.

        A record can carry one or twenty, and the detail pane has no line
        cursor to point at one of them - so the row is what selects, and the
        picker below is what narrows.
        """
        row = self._current_row()
        if row is None:
            return []
        target = row.target
        host = row.host
        urls: list[str] = []
        if isinstance(target, Service):
            urls = exporter.service_urls(target, host)
        elif isinstance(target, Host):
            urls = [u for svc in target.open_services
                    for u in exporter.service_urls(svc, target)]
        elif host is not None:
            urls = [u for svc in host.open_services
                    for u in exporter.service_urls(svc, host)]
        return self.shots.for_urls(list(dict.fromkeys(urls)))

    @work(exclusive=True, group="modal")
    async def action_open_shot(self) -> None:
        """`i`: look at a capture's picture, since a terminal cannot show it."""
        found = self._record_captures()
        if not found:
            self.notify("no capture for this row", severity="warning")
            return
        chosen = found[0]
        if len(found) > 1:
            # The picker *is* the selection: the pane is a rendered report, not
            # a list, so there is no "selected line" for `i` to mean.
            choices = []
            disabled = set()
            for index, capture in enumerate(found):
                key = str(index)
                if capture.shot is None or capture.failed:
                    disabled.add(key)
                    why = capture.failure or "no screenshot"
                    choices.append((key, f"{capture.url} — {why}"))
                else:
                    status = capture.status or "—"
                    choices.append((key, f"{status}  {capture.url}"))
            picked = await self.push_screen_wait(
                ChoiceScreen("Open which capture?", choices, disabled=disabled))
            if picked is None:
                return
            chosen = found[int(picked)]
        if chosen.shot is None or chosen.failed:
            self.notify(f"no screenshot: {chosen.failure or 'it was never taken'}",
                        severity="warning")
            return
        if not chosen.shot.exists():
            self.notify(f"the screenshot is gone: {chosen.shot}", severity="error")
            return
        try:
            await asyncio.create_subprocess_exec(
                *actions.opener_argv(chosen.shot),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        except OSError as exc:
            self.notify(f"could not open it: {exc.strerror or exc}", severity="error")
            return
        self.notify(f"opened {chosen.shot.name}")

    @work(exclusive=True, group="report")
    async def action_report_server(self) -> None:
        """`W`: gowitness's own gallery, served from this capture's database."""
        if not self.gowitness.available:
            self.notify(f"gowitness unavailable: {self.gowitness.reason}",
                        severity="error")
            return
        paths = gw_capture.capture_dir(self.scan_dir)
        if not paths.db.exists():
            self.notify("nothing captured yet — run a capture from the export "
                        "dialog first", severity="warning")
            return
        host = self.config.gowitness_report_host
        port = self.config.gowitness_report_port
        url = f"http://{host}:{port}"
        # Land on the thing the cursor was on. The route is the report's own
        # client-side one, and the id exists only in the database - the JSON
        # Lines writer set every id to 0, which is one of the reasons the
        # database became the source. A failure recovered from a run's log has
        # no id, so it falls back to the gallery rather than building a link
        # that would not resolve.
        found = [c for c in self._record_captures() if c.row_id]
        if len(found) == 1:
            url = f"{url}/results/detail/{found[0].row_id}"
        if self._report_proc is None:
            argv = gw_capture.report_argv(self.gowitness, paths, host, port)
            try:
                self._report_proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL, start_new_session=True)
            except OSError as exc:
                self.notify(f"could not start the report server: "
                            f"{exc.strerror or exc}", severity="error")
                return
            self.notify(f"report server on {url}")
            self._refresh_status()
        with contextlib.suppress(OSError):
            await asyncio.create_subprocess_exec(
                *actions.opener_argv(url),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)

    def _capture_dirs(self) -> list[gw_capture.Paths]:
        """Where captures are: the one output goes to, then every results
        database found below the paths the viewer was opened on - at any depth
        and under any name, since a capture run by hand lands wherever
        gowitness was started, not only in `gowitness/` beside the scans."""
        own = gw_capture.capture_dir(self.scan_dir)
        found = [gw_capture.Paths(db.parent.resolve(), db.name) for db in self._databases]
        out: dict[Path, gw_capture.Paths] = {}
        for paths in [own, *found]:
            out.setdefault(paths.db, paths)
        return list(out.values())

    def _load_captures(self) -> None:
        """Read every capture database. Absence is the ordinary case, not an error.

        Read one by one rather than through `Captures.load`, so each database's
        own URLs are known: a run listed for it counts those, not everyone's.
        Each resolves its screenshots from where it is (`locate.ShotFinder`),
        with one image index shared between them.
        """
        dirs = self._capture_dirs()
        for paths in dirs:
            finder = gw_locate.ShotFinder(paths.db, self._shot_index)
            captures, problems = gw_results.read_database(paths.db, finder)
            self.shots.add(captures)
            self.shots.problems.extend(problems)
            where = ""
            if len(dirs) > 1:
                # Named like the scans beside it; two captures in directories
                # of the same name ("gowitness" twice) show where they are.
                where = self._name(paths.root)
                if where == paths.root.name:
                    where = _short(paths.root)
                if paths.db_name != gw_capture.DB_NAME:
                    where = f"{where}/{paths.db_name}"
            self._register_disk_capture(paths, [c.url for c in captures], where)

    def _register_disk_capture(self, paths: gw_capture.Paths, urls: list[str],
                               where: str = "") -> None:
        """List a capture that exists on disk but was not run in this session.

        Without this the Scans tab is empty after a restart even though the
        database and the screenshots are sitting there - the opposite of the
        rule the scan history follows, where what is on disk is listed whoever
        produced it.
        """
        if not paths.db.exists() or not urls:
            return
        # A run started here already stands for this directory; a second row
        # would be the same capture listed twice.
        if any(getattr(run, "paths", None) == paths for run in self.captures.runs):
            return
        self.captures.runs.append(
            gw_capture.from_disk(paths, urls, captured=len(urls), where=where))

    def snapshot(self):
        """`ModelSource`: what the web interface reads, as it stands now."""
        return self._web_source().snapshot()

    def _web_source(self):
        from seek.web.source import CachedSource

        if getattr(self, "_cached_source", None) is None:
            self._cached_source = CachedSource(lambda: self.scans, lambda: self.shots)
        return self._cached_source

    def action_open_web(self) -> None:
        """`w`: the web interface, at the page for the selected row.

        Started on first use and reused after that. The start - importing
        FastAPI, binding, waiting for uvicorn - and the model it indexes are
        both worth keeping off the event loop, so the work is a thread; the row
        is taken here, where the cursor is, and handed over by attribute
        because Textual reprs a worker's arguments.
        """
        self._web_row = self._current_row()
        self._open_web()

    @work(thread=True, exclusive=True, group="web")
    def _open_web(self) -> None:
        from seek.web.server import WebError, WebServer

        if self._web is None:
            self._web = WebServer(self, self.config.web_host, self.config.web_port)
        fresh = not self._web.running
        try:
            self._web.start()
            url = self._web.url_for(self._web_row)
        except WebError as exc:
            self.call_from_thread(self.notify, str(exc), severity="error")
            return
        if fresh:
            self.call_from_thread(self.notify, f"web interface on {self._web.url}")
            self.call_from_thread(self._refresh_status)
        _open_browser(url)

    def _stop_report_server(self) -> None:
        """Never leave a web server running behind a closed viewer."""
        process = self._report_proc
        self._report_proc = None
        if process is None:
            return
        with contextlib.suppress(Exception):
            process.terminate()

    def _select_target(self, target: object) -> None:
        """Move the cursor to the row that stands for `target`, if it is shown."""
        for index, row in enumerate(self._rows):
            if row.target is target:
                self.query_one(DataTable).move_cursor(row=index)
                self._refresh_detail()
                return

    def _on_scan_line(self, _line: str) -> None:
        """The run list carries progress; the pane carries the log."""
        if self.view.kind == "scans" and not self._log_frozen:
            self._reload_rows(preserve=True)

    def _on_scan_done(self, run: ScanRun) -> None:
        if run.state is State.DONE and run.xml_path.exists():
            self._absorb(run)
        elif run.state is State.FAILED and "sudo -n refused" in run.result:
            self.notify(elevation_help(self.config.nmap_path),
                        severity="error", timeout=20)
        else:
            self.notify(f"{run.preset}: {run.result}",
                        severity="warning" if run.state is State.CANCELLED else "error")
        if self.view.kind == "scans":
            self._reload_rows(preserve=True)
        self._refresh_detail()
        self._refresh_status()

    def _absorb(self, run: ScanRun) -> None:
        """Re-read every source plus the new file, off the event loop.

        Not an incremental merge: one loading path means a scan started here and
        one run outside are folded in by exactly the same rules. Re-reading a
        large engagement is seconds of work, so it happens in a thread and the
        list stays where it is until the new model is ready - the rows on
        screen are still true, they are simply one scan out of date.
        """
        # A directory source already covers the new file - it is searched all
        # the way down, so naming the file as well would only lengthen the list.
        covered = any(p.is_dir() and run.xml_path.is_relative_to(p) for p in self.sources)
        if not covered:
            self.sources.append(run.xml_path)
        # Anything still streaming in is about to be re-read from scratch, so
        # stop it rather than letting two readers publish over each other.
        self._read_token += 1
        self._reading = None
        self._next_scans = None
        self._build_token += 1
        self._busy = _Busy(what="the scans again", view=None,
                           token=self._build_token, refresh=True)
        self._show_busy()
        self._reread(run, list(self.sources), covered, self._build_token)

    @work(thread=True, exclusive=True, group="absorb")
    def _reread(self, run: ScanRun, paths: list[Path], covered: bool,
                token: int) -> None:
        from seek.nmap.merge import load
        from seek.nmap.views import prepare

        # Taken here rather than on the event loop: the model it reads is the
        # one being replaced, and nothing writes to it while this runs.
        before = snapshot(self.scans.hosts)

        def report(done: int, total: int, unit: str) -> None:
            busy = self._busy
            if busy is None or busy.token != token:
                raise _Abandoned
            self.call_from_thread(self._on_build_progress, token, done, total, unit)

        try:
            # The other owner of a long phase; see `_build_rows`.
            with bulk.bulk(), bulk.responsive():
                scans = prepare(load(paths, report, self._name))
        except _Abandoned:
            return
        except Exception as exc:                      # noqa: BLE001 - report, never crash
            self.call_from_thread(self._on_reread_failed, token, run, covered, exc)
            return
        self.call_from_thread(self._on_reread, token, run, scans, before)

    def _on_reread(self, token: int, run: ScanRun, scans: ScanSet,
                   before: dict) -> None:
        if self._busy is None or self._busy.token != token:
            return
        self._busy = None
        self._publish(scans)
        self._diffs[id(run)] = diff_from(before, self.scans.hosts)
        self._resolve_marks()
        self.notify(f"{run.preset}: {self._diffs[id(run)].summary()}")
        self._refresh_view(preserve=True)
        self._refresh_detail()
        self._refresh_status()

    def _on_reread_failed(self, token: int, run: ScanRun, covered: bool,
                          exc: Exception) -> None:
        if self._busy is not None and self._busy.token == token:
            self._busy = None
        self.notify(f"{self._name(run.xml_path)} could not be read: {exc}",
                    severity="error")
        if not covered and self.sources and self.sources[-1] == run.xml_path:
            self.sources.pop()
        self._refresh_status()

    # --- reading the engagement into the open viewer -----------------------

    def _start_reading(self) -> None:
        """Read the candidates handed to the constructor, off the event loop."""
        if not self._to_read:
            return
        self._read_token += 1
        self._reading = _Reading(done=0, total=len(self._to_read))
        self._refresh_status()
        self._read_scans(list(self._to_read), self._read_token)

    @work(thread=True, exclusive=True, group="read")
    def _read_scans(self, paths: list[Path], token: int) -> None:
        """Parse file by file, folding each into a set that keeps growing.

        The set is never handed out while it is being written to: `Accumulator`
        copies a host before a later file touches it again, so what the
        interface is holding is always a consolidation of whole files. What is
        published is therefore a new `ScanSet` every time - which is also what
        makes the projections' cache invalidate exactly right, since it keys on
        the model's identity and nothing else has to know a read happened.
        """
        acc = Accumulator()
        failures: list[tuple[str, str]] = []
        total = len(paths)
        last = 0.0
        unread = False                              # something new since publishing
        # One of the two owners of a long phase; see `_build_rows`.
        with bulk.bulk(), bulk.responsive():
            for done, path in enumerate(paths, start=1):
                if self._read_token != token:       # a re-read superseded this
                    return
                label = self._name(path)
                try:
                    acc.add(parse_file(path, label))
                    unread = True
                except NmapParseError as exc:
                    failures.append((label, str(exc)))
                except Exception as exc:            # noqa: BLE001 - never crash
                    failures.append((label, str(exc)))
                now = time.monotonic()
                snapshot = None
                if unread and now - last >= _PUBLISH_EVERY and done < total:
                    last, unread = now, False
                    snapshot = self._consolidate(acc, failures)
                self.call_from_thread(self._on_read_progress, token, done, total,
                                      snapshot)
            final = self._consolidate(acc, failures)
        self.call_from_thread(self._on_read_done, token, final)

    @staticmethod
    def _consolidate(acc: Accumulator, failures: list[tuple[str, str]]) -> ScanSet:
        """One immutable snapshot of the set as it stands.

        `prepare` runs over the hosts this snapshot is the first to show, not
        over the whole model: attaching names and vulnerabilities is idempotent
        but not free, and doing it to everything on every publication would
        cost more than reading the file that prompted it.
        """
        fresh = acc.fresh
        scans = acc.snapshot()
        scans.failures = list(failures)
        proj.prepare(scans, fresh)
        return scans

    def _on_read_progress(self, token: int, done: int, total: int,
                          scans: ScanSet | None) -> None:
        if self._read_token != token or self._reading is None:
            return
        self._reading.done, self._reading.total = done, total
        if scans is not None:
            self._offer(scans)
        else:
            self._refresh_status()

    def _on_read_done(self, token: int, scans: ScanSet) -> None:
        if self._read_token != token:
            return
        self._reading = _Reading(done=len(self._to_read), total=len(self._to_read),
                                 failures=list(scans.failures))
        read = len(self._to_read) - len(scans.failures)
        if scans.failures:
            names = ", ".join(n for n, _ in scans.failures)
            self.notify(f"skipped unreadable: {names}", severity="warning")
        # Candidates existed and not one of them could be read. That is not an
        # engagement with no hosts in it, and the process must not report it as
        # a clean run; the empty list says which files failed.
        if self._to_read and not read:
            self._exit_code = 1
        self._offer(scans)
        if not scans.hosts and not scans.failures and self.nmap.available:
            # Files that read cleanly and named nobody: the useful thing to
            # offer is a scan, exactly as it is for an empty directory.
            self.call_after_refresh(self.action_new_scan)

    def _offer(self, scans: ScanSet) -> None:
        """Take a snapshot now, or park it until the build running ends.

        Coalescing rather than queueing: a projection started against an older
        model is already the work this snapshot would repeat, and by the time
        it finishes there may be a newer snapshot still. Only the last one is
        true, so only the last one is kept.

        Nothing is ever published *under* a running build, not even the last
        snapshot of a read. Doing that leaves the build projecting a model that
        is no longer on screen, and its completion then replaces a working list
        with a bar for the rebuild - the exact failure that opening early
        exists to avoid. Every path that ends a build drains the park instead.
        """
        if self._busy is not None or self._filling:
            self._next_scans = scans
            return
        self._apply(scans)

    def _take_parked(self) -> None:
        """Apply the snapshot parked while the last one was going on screen."""
        if self._busy is not None or self._filling:
            return                                  # whatever ends will call back
        parked, self._next_scans = self._next_scans, None
        if parked is not None:
            self._offer(parked)

    def _absorbed(self) -> None:
        """A batch is fully on screen; decide when the next one may be taken.

        The pause is the cost of the batch just absorbed, so the pacing follows
        the size of the model rather than a number chosen in advance: a small
        engagement takes the next batch immediately, and a large one leaves the
        reader as much time to use the list as it spent replacing it.
        """
        wait = 0.0
        if self._absorb_began:
            wait = min(time.monotonic() - self._absorb_began, _ABSORB_HEADROOM)
            self._absorb_began = 0.0
        if wait > 0.05 and self._next_scans is not None:
            self.set_timer(wait, self._take_parked)
            return
        self._take_parked()

    def _apply(self, scans: ScanSet) -> None:
        """Put a grown model on screen without moving the cursor under the user.

        The cursor is preserved by record identity rather than by row index -
        the rows are rebuilt from the new model, and a host that was tenth is
        now fortieth once the batch before it has been folded in. `_refresh_view`
        takes that mark for itself at the moment it replaces the rows; marking
        here would pin the cursor to wherever it was when the batch arrived and
        undo any movement made while the rebuild ran.
        """
        self._absorb_began = time.monotonic()
        self._publish(scans)
        self._refresh_warning()
        self._refresh_view(growing=True)
        # No `_refresh_detail` here: the rows are not on screen yet, so the
        # record it would report is whichever one the table happens to hold.
        # The fill calls it the moment the cursor is on the right row.
        self._refresh_status()

    def _refresh_warning(self) -> None:
        """The `-Pn` overstatement banner, which a growing model can turn on."""
        try:
            warn = self.query_one("#warn", Static)
        except NoMatches:
            return
        warn.display = self.scans.overstated
        if self.scans.overstated:
            asserted, real = len(self.scans.asserted_up), len(self.scans.up)
            warn.update(Text(
                f"⚠  scan asserted {asserted} hosts up (-Pn) but only {real} are up "
                f"— an open port or host discovery", style="bold bright_yellow"))

    def _read_note(self) -> Text | None:
        """How far the read has got, for the status line. `None` once it has."""
        reading = self._reading
        if reading is None or not reading.showing:
            return None
        note = Text(f"{_SPINNER[self._spin % len(_SPINNER)]} reading scans "
                    f"{reading.done}/{reading.total} {reading.unit}", style="bold")
        note.append(f"  ·  {len(self.scans.hosts)} host(s) so far", style="dim")
        return note

    def _publish(self, scans: ScanSet) -> None:
        """Put a model on screen. The one place `self.scans` is ever replaced.

        The freeze/unfreeze pair lives here rather than at each call site
        because it is a pair: a model that stays in the permanent generation
        after it has been superseded is pinned there for the life of the run,
        and the only moment at which "the model being replaced is going away"
        is known is this one. Without cycles, the superseded model's objects
        are freed by reference counting as soon as the last view drops them.
        """
        bulk.unfreeze()
        self.scans = scans
        bulk.freeze()

    def _resolve_marks(self) -> None:
        """Marks point at records of the old model; re-find them in the new one."""
        if not self._marked:
            return
        live: dict[tuple, exporter.Record] = {}
        by_address = {h.address: h for h in self.scans.hosts}
        for key, record in self._marked.items():
            host = by_address.get(record.host.address)
            if host is None:
                continue
            if record.service is None:
                live[key] = exporter.Record(host)
                continue
            match = next((s for s in host.services
                          if (s.protocol, s.port) == (record.service.protocol,
                                                      record.service.port)), None)
            if match is not None:
                live[key] = exporter.Record(host, match)
        self._marked = live

    def action_filter(self) -> None:
        self.query_one("#filter", Input).focus()
        self._refresh_status()

    @work(exclusive=True, group="modal")
    async def action_help(self) -> None:
        await self.push_screen_wait(NmapHelpScreen())

    async def action_quit(self) -> None:
        """Textual's own quit - `ctrl+q` and the system palette - guarded too.

        Overridden rather than left alone: a guard one keypress can walk around
        is not a guard.
        """
        self._request_quit()

    def action_help_quit(self) -> None:
        """`ctrl+c` quits too, instead of Textual's "press ctrl+q" notice.

        Not a binding of our own: the filter box keeps `ctrl+c` for copy, and
        an App binding that pierced it would take that away.
        """
        self._request_quit()

    @work(exclusive=True, group="quit")
    async def _request_quit(self) -> None:
        """Leaving while a scan runs ends it, so ask first.

        A scan writes its output only when it finishes, so quitting mid-run
        throws the work away - which is worth one keypress of confirmation, and
        `Esc` is the answer that keeps scanning.
        """
        running = self.runner.busy() or self.captures.busy()
        if running is None:
            self.exit(self._exit_code)
            return
        answer = await self.push_screen_wait(ChoiceScreen(
            f"{running.label} has been running for "
            f"{scan_views.elapsed(running.elapsed)}. Quitting ends it, and a "
            f"run that does not finish writes no file.",
            [("stay", "Keep it running"), ("quit", "End it and quit")]))
        if answer == "quit":
            self.exit(self._exit_code)

    def on_unmount(self) -> None:
        """Never leave a scan running behind a closed viewer.

        The child is started in its own session so that cancelling reaches
        everything nmap spawns - which also means quitting without this would
        leave it scanning the target with nobody watching.
        """
        if self.runner.busy() is not None:
            self.runner.cancel()
        if self.captures.busy() is not None:
            self.captures.cancel()
        self._stop_report_server()
        if self._web is not None:
            self._web.stop()
        # And never leave the model pinned behind one either: the permanent
        # generation is process-wide, so a viewer that closes has to hand it
        # back - which matters to a test suite opening a hundred of them, not
        # to the command, which exits here.
        bulk.unfreeze()

    def action_reverse(self) -> None:
        self._sort_desc = not self._sort_desc
        self._refresh_view()

    def action_back(self) -> None:
        # The innermost state the viewer can be in, so the first one `Esc`
        # unwinds: the reader is looking at one entry of one record, and going
        # back means the record, not the list.
        if self._close_raw():
            return
        if self._busy is not None and not self._busy.quiet:
            # A build over a second or two has to be abandonable, and Esc is
            # already the key that means "out of this". A quiet rebuild is not
            # one of those: the list it is replacing is on screen and working,
            # so `Esc` still means back, or clear the filter.
            self._cancel_build()
            return
        box = self.query_one("#filter", Input)
        if self.focused is box:
            self._flush_filter()
            self.query_one(DataTable).focus()
            self._refresh_status()
            return
        if box.value.strip():
            # Widening the list must not throw the cursor to the top either -
            # the row that was selected is still there, further down.
            self._pending_mark = self._mark_current()
            box.value = ""
            self._flush_filter()
            self._refresh_status()
            return
        if len(self.stack) > 1:
            self.stack.pop()
            self._sync_tab()
            mark = self._marks.pop() if self._marks else None
            if mark is None:
                self._reset_sort()
                return
            self._set_filter(mark.filter)
            self._sort_col, self._sort_desc = mark.sort_col, mark.sort_desc
            self._refresh_view(restore=mark)
            return
        if self._active_tab != _TABS[0][0]:
            self._activate(_TABS[0][0])
            return
        self._request_quit()

    def on_data_table_row_selected(self, _event) -> None:
        self.action_drill()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        """A column heading is numbered and carries the sort arrow, so it looks
        interactive - clicking it must sort, as pressing its number does."""
        self.action_sort(event.column_index)

    def on_data_table_row_highlighted(self, _event) -> None:
        self._refresh_detail()

    def _current_row(self):
        table = self.query_one(DataTable)
        row = table.cursor_row
        if row is None or not (0 <= row < len(self._rows)):
            return None
        return self._rows[row]

    def _detail_content(self, row: vdefs.Row | None,
                        full: bool = False) -> tuple[list[detail_pane.Line], str]:
        """The lines and a title for the given row's record.

        The one place that decides what a row's detail *is* - both the inline
        pane and the full-screen reader (`d`) show exactly this, so the reader
        can never say something different from the pane it was opened from.

        Lines rather than one renderable because the pane is navigated by a
        cursor. A row whose record is a single block - a scan's report, a
        heading - is one line of it; nothing is lost, and the pane does not
        have to ask which kind of record it is holding.
        """
        target = row.target if row is not None else None
        if isinstance(target, timeline.Scan):
            return ([detail_pane.Line(scan_views.scan_report(target, self._report_mode))],
                    f"Scan · {target.label}")
        if isinstance(target, gw_capture.CaptureRun):
            # Checked before ScanRun and separately from it: a capture is a
            # `Run`, not a `ScanRun`, so an isinstance test against the scan
            # type alone drops it through to the record renderer, which knows
            # nothing about runs and returns an empty pane.
            return ([detail_pane.Line(
                        scan_views.report(target, self._report_mode, None,
                                          self._log_frozen, self._following))],
                    f"Capture · {target.scope}")
        if isinstance(target, ScanRun):
            return ([detail_pane.Line(
                        scan_views.report(target, self._report_mode,
                                          self._diffs.get(id(target)),
                                          self._log_frozen, self._following))],
                    f"Scan · {target.preset}")
        if row is not None and row.heading:
            return ([detail_pane.Line(Text(
                        f"{row.cells[0]}\n\n"
                        "Select a line under this heading to open what it counts.",
                        style="dim"))],
                    row.cells[0])
        if target is None and row is not None:
            # views without a drill target (statistics, groupings) still explain
            # the row rather than leaving the pane blank
            return [detail_pane.Line(Text(row.text, style="dim"))], self.view.title
        title = f"{self.view.title} · {row.cells[0]}" if row is not None else self.view.title
        return (detail_pane.render(target, row.host if row else None, self.shots,
                                   full=full, scanned=self._scans_index()),
                title)

    def _refresh_detail(self) -> None:
        """Show the full record for the highlighted row - the table only has
        room for a few columns, and script and vulnerability detail has none."""
        try:
            pane = self.query_one("#detail-body", Static)
        except NoMatches:
            return
        row = self._current_row()
        target = row.target if row is not None else None
        if ((self._raw is not None or self._raw_pending is not None)
                and id(target) != self._detail_target):
            # The raw output on screen is about the row that was left. Showing
            # it against a different one would be the pane describing a record
            # the list is no longer on.
            self._raw = None
            self._raw_pending = None
            self._raw_token += 1
        # Measured *before* the content changes, because the height it is
        # measured against is about to change with it.
        self._following = self._pinned_to_end()
        lines, _title = self._detail_content(row)
        if self._raw is not None or self._raw_pending is not None:
            # The pane is showing one entry of this record; a redraw of the
            # record underneath must not take it away.
            self._render_raw()
            return
        # Clamped rather than reset: the same record is re-rendered under the
        # cursor whenever a batch of scans is folded in, and a reader who had
        # moved down it should not be sent back to the top by an arriving file.
        self._lines = lines
        self._line = max(0, min(self._line, len(lines) - 1)) if lines else 0
        pane.update(self._with_cursor(lines))
        if self._reader is not None:
            # The reader shows everything the pane shows, and may show more -
            # both come from this one call, so neither can drift into being a
            # second description of the record. This is also what keeps a
            # running scan streaming into an open reader, and a mode change
            # (`o`) or a freeze toggle (`p`) reflected in it, with no separate
            # "is the reader open on this row" bookkeeping.
            deep, _ = self._detail_content(row, full=True)
            self._reader.update(deep)
        # Scrolling is decided by *what changed*, not by what kind of row this
        # is. A new record starts at the top; the same record being re-rendered
        # must not move, or a live run's log throws the reader back to the top
        # on every line it prints and manual scrolling becomes impossible.
        moved = id(target) != self._detail_target
        if moved:
            # A different row is a different record: its cursor starts at the
            # top, as the pane's scroll position does.
            self._line = 0
            pane.update(self._with_cursor(lines))
        self._detail_target = id(target)
        # Follow only while the reader is at the end of the log. Position *is*
        # the mode: scrolling up to read something stops the tail from yanking
        # the view away, and scrolling back to the end resumes it, so the two
        # can never disagree about what the user wants. A mode that had to be
        # toggled would be one more thing to get out of step with intent.
        following = (isinstance(target, Run) and target.running
                     and self._report_mode == "raw" and not self._log_frozen
                     and self._following)
        if isinstance(target, timeline.Scan):
            self._apply_detail_visibility()
            return
        try:
            pane_scroll = self.query_one("#detail", VerticalScroll)
        except NoMatches:
            self._apply_detail_visibility()
            return
        if following:
            # Follow the newest line, which is why the scroll comes after the
            # update rather than the usual scroll-to-top.
            pane_scroll.scroll_end(animate=False)
        elif moved:
            pane_scroll.scroll_home(animate=False)
        self._apply_detail_visibility()

    def _with_cursor(self, lines: list[detail_pane.Line]) -> RenderableType:
        """The record, with the line the cursor is on marked out.

        Reverse video on the line itself rather than a gutter marker: the
        record's own lines already carry colour and weight for what they mean,
        and a second column of glyphs would compete with them. The copy is what
        keeps the styling out of the record - `detail.render` builds one
        description and this decorates a view of it.
        """
        if not lines:
            return detail_pane.as_group(lines)
        index = max(0, min(self._line, len(lines) - 1))
        shown: list[detail_pane.Line] = list(lines)
        current = shown[index]
        if isinstance(current.text, Text):
            if current.text.plain.strip():
                marked = current.text.copy()
                # The base style, composed with whatever the line already
                # carries, rather than a span over it: a heading keeps its
                # colour and weight and gains the reverse, and "is this line
                # the cursor's" stays a property of the line.
                marked.style = f"{marked.style} reverse".strip()
            else:
                # A blank line has nothing to reverse; give the eye something
                # to find instead of a gap that looks like no cursor at all.
                marked = Text(" " * 3, style="reverse")
            shown[index] = detail_pane.Line(marked, current.opens)
        return detail_pane.as_group(shown)

    def _openable(self) -> list[int]:
        """The indices of the record's lines that `o` can act on."""
        return [i for i, line in enumerate(self._lines) if line.opens is not None]

    def _opens_here(self) -> object | None:
        """What the line under the cursor opens, if it opens anything."""
        if 0 <= self._line < len(self._lines):
            return self._lines[self._line].opens
        return None

    def action_line(self, delta: int) -> None:
        """Move the pane's cursor one line - or scroll, when it cannot move.

        Every line is a stop, as in a text editor, and the record scrolls to
        keep the cursor in view. A scan's report and a capture's log are one
        renderable as far as the pane is concerned, so the cursor has a single
        stop there; falling back to scrolling a line is what keeps those
        readable, and the end of a long record whose last line wraps below the
        fold too.
        """
        if not self._lines:
            return
        at = max(0, min(len(self._lines) - 1, self._line + delta))
        if at == self._line:
            self.action_scroll_detail(delta)
            return
        self._line = at
        self._show_line()

    def _show_line(self) -> None:
        """Redraw with the cursor where it is, and scroll it into view."""
        try:
            pane = self.query_one("#detail-body", Static)
            region = self.query_one("#detail", VerticalScroll)
        except NoMatches:
            return
        pane.update(self._with_cursor(self._lines))
        # One line is one record line, which may wrap to several rows, so the
        # scroll target is measured rather than assumed to be the index.
        height = max(1, region.size.height)
        top = region.scroll_offset.y
        row = self._row_of(self._line)
        if row < top:
            region.scroll_to(y=row, animate=False)
        elif row >= top + height:
            region.scroll_to(y=max(0, row - height + 1), animate=False)
        self._refresh_status()

    def _row_of(self, index: int) -> int:
        """How far down the pane the given record line starts.

        Counted from the lines above it, since a `Text` that wraps occupies
        more than one row. Cheap enough at a record's size, and it is the only
        way the cursor and the scrolling can agree about where a line is.
        """
        width = 0
        try:
            width = self.query_one("#detail", VerticalScroll).size.width - 2
        except NoMatches:
            pass
        rows = 0
        for line in self._lines[:index]:
            rows += _rows_of(line.text, width)
        return rows

    # --- nmap's own text, for the line the cursor is on --------------------

    def _siblings(self, request: rawlog.Request) -> list[rawlog.Entry]:
        """Every scan that recorded this request's subject, in scan order."""
        return self._scans_index().entries(request.host, request.service)

    def _open_raw(self, request: rawlog.Request) -> None:
        """Show what one scan wrote about the record's subject.

        Inline unless the file is big enough that reading and cutting it would
        be felt between keystrokes; see `_RAW_INLINE_MAX`.
        """
        self._raw_from = self._line
        path = request.entry.path
        cached = self._files_read.get(path) if path is not None else None
        if path is not None and cached is None and self._too_big(path):
            self._raw_token += 1
            self._raw_pending = request
            self._render_raw()
            self._read_raw(request, self._raw_token)
            return
        self._raw_pending = None
        source = None
        if path is not None:
            source = cached if cached is not None else self._file_text(path)
        self._raw = (request, rawlog.read(request, source=source))
        self._render_raw()
        self._refresh_status()

    @staticmethod
    def _too_big(path: Path) -> bool:
        try:
            return path.stat().st_size > _RAW_INLINE_MAX
        except OSError:
            return False

    @work(thread=True, exclusive=True, group="rawlog")
    def _read_raw(self, request: rawlog.Request, token: int) -> None:
        """Read and cut a large output file off the event loop."""
        path = request.entry.path
        text = None
        if path is not None:
            try:
                with bulk.bulk(), bulk.responsive():
                    text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = None
        if self._raw_token != token:
            return                                  # Esc, or another entry
        excerpt = rawlog.read(request, source=text)
        self.call_from_thread(self._on_raw_read, token, request, excerpt, text)

    def _on_raw_read(self, token: int, request: rawlog.Request,
                     excerpt: rawlog.Excerpt, text: str | None) -> None:
        if self._raw_token != token:
            return
        if text is not None and request.entry.path is not None:
            self._keep(request.entry.path, text)
        self._raw_pending = None
        self._raw = (request, excerpt)
        self._render_raw()
        self._refresh_status()

    def _file_text(self, path: Path) -> str | None:
        """A scan's output, read at most once per path while it is wanted.

        Read here rather than when the record is drawn: the cursor moves
        between records continuously and this is the only moment the file is
        actually needed. `None` when it cannot be read - `rawlog` says so as
        content, which is what the reader has to be told.
        """
        if path in self._files_read:
            return self._files_read[path]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        self._keep(path, text)
        return text

    def _keep(self, path: Path, text: str) -> None:
        """Hold a file's text, dropping the oldest once a few are held."""
        if len(self._files_read) >= _FILES_KEPT:
            self._files_read.pop(next(iter(self._files_read)))
        self._files_read[path] = text

    def _render_raw(self) -> None:
        """Put the raw state on screen, cursor at its top."""
        try:
            pane = self.query_one("#detail-body", Static)
            region = self.query_one("#detail", VerticalScroll)
        except NoMatches:
            return
        if self._raw is not None:
            self._lines = detail_pane.raw_record(*self._raw, at=self._position())
        elif self._raw_pending is not None:
            self._lines = detail_pane.raw_pending(self._raw_pending)
        else:
            return
        self._line = 0
        pane.update(self._with_cursor(self._lines))
        region.scroll_home(animate=False)
        self._apply_detail_visibility()

    def _position(self) -> tuple[int, int]:
        """Which of the subject's scans is showing, out of how many."""
        if self._raw is None:
            return (1, 1)
        entries = self._siblings(self._raw[0])
        here = next((i for i, e in enumerate(entries)
                     if e.scan is self._raw[0].entry.scan), 0)
        return (here + 1, len(entries))

    def _close_raw(self) -> bool:
        """Back to the record, at the entry that was opened. False if not open."""
        if self._raw is None and self._raw_pending is None:
            return False
        self._raw_token += 1                        # abandon a read in flight
        self._raw = None
        self._raw_pending = None
        self._refresh_detail()
        self._line = self._raw_from
        self._show_line()
        return True

    def _pinned_to_end(self) -> bool:
        """Whether the detail pane is scrolled to the end of its content.

        A line of tolerance: a pane whose content ends mid-row would otherwise
        never quite reach its own maximum, and a log that stops following
        because of a rounding error is indistinguishable from a bug.
        """
        try:
            pane = self.query_one("#detail", VerticalScroll)
        except NoMatches:
            return True
        return pane.scroll_offset.y >= pane.max_scroll_y - 1

    def _reader_payload(self, row: vdefs.Row | None) -> tuple[str, reader_mod.Content, bool]:
        """What the reader needs to show one row: title, record, follow-tail.

        Always the record, as lines, so the reader has a cursor and links on
        it. A scan's text the pane happens to be showing is handed over
        separately (`action_open_detail`), as the level above this one.
        """
        lines, title = self._detail_content(row, full=True)
        target = row.target if row is not None else None
        # Match the pane's own rule for the same case (`_refresh_detail`'s
        # scroll_end): only a running scan's raw log opens at the newest line.
        follow = (isinstance(target, ScanRun) and target.running
                 and self._report_mode == "raw" and not self._log_frozen)
        return title, lines, follow

    def _raw_page(self, request: rawlog.Request) -> reader_mod.RawPage:
        """One scan's text about one subject, for the reader.

        Read synchronously: the reader asked for it with a key and has nothing
        else to show meanwhile, and the file is cached for the pane as well.
        """
        path = request.entry.path
        source = self._file_text(path) if path is not None else None
        excerpt = rawlog.read(request, source=source)
        entries = self._siblings(request)
        here = next((i for i, e in enumerate(entries) if e.scan is request.entry.scan), 0)
        lines = detail_pane.raw_record(request, excerpt, at=(here + 1, len(entries)))
        return (request, f"{request.entry.label} · {request.subject}",
                detail_pane.as_group(lines))

    def _raw_sibling(self, request: rawlog.Request,
                     delta: int) -> reader_mod.RawPage | None:
        """The previous/next scan's text about the same subject; `None` at the ends."""
        entries = self._siblings(request)
        here = next((i for i, e in enumerate(entries) if e.scan is request.entry.scan), -1)
        at = here + delta
        if here < 0 or not (0 <= at < len(entries)):
            return None
        return self._raw_page(rawlog.Request(entries[at], request.host, request.service))

    def _step_detail(self, delta: int) -> tuple[str, reader_mod.Content, bool] | None:
        """`←`/`→` in the reader: move the list, hand back the row landed on.

        Moving the real cursor rather than tracking a second one in the reader
        is what keeps the two in step: the pane underneath updates as usual,
        and leaving the reader lands on the entry last read instead of the one
        it was opened from. `None` at either end - `action_move` clamps too,
        and neither skips section headings, so the reader visits exactly the
        rows the list would.
        """
        table = self.query_one(DataTable)
        limit = min(table.row_count, len(self._rows))
        target_row = (table.cursor_row or 0) + delta
        if not (0 <= target_row < limit):
            return None
        table.move_cursor(row=target_row)
        return self._reader_payload(self._rows[target_row])

    @work(exclusive=True, group="modal")
    async def action_open_detail(self) -> None:
        """`d`: the selected row's record, full-screen and searchable."""
        row = self._current_row()
        if row is None and not self._rows:
            self.notify("nothing to show", severity="warning")
            return
        title, content, follow = self._reader_payload(row)
        # Whatever the pane is showing is what the reader opens on: a scan's
        # text opens as that, with the record behind it for `Esc`.
        showing = self._raw[0] if self._raw is not None else self._raw_pending
        raw = self._raw_page(showing) if showing is not None else None
        reader = DetailReader(title, content, on_freeze=self.action_freeze_log,
                              on_step=self._step_detail, follow=follow,
                              on_open=self._raw_page, on_sibling=self._raw_sibling,
                              raw=raw)
        self._reader = reader
        try:
            await self.push_screen_wait(reader)
        finally:
            self._reader = None

    def _on_tick(self) -> None:
        """Both things that depend on the terminal's size, on one timer."""
        if self._busy is not None:
            self._spin += 1
            self._show_busy()
        if self._reading is not None and not self._reading.finished:
            # The spinner turns, and the quiet window ends here rather than on
            # the next file - a read that stalls on one large scan still has to
            # start saying so.
            self._spin += 1
            self._refresh_status()
            self._refresh_empty(self._rows)
        self._apply_detail_visibility()
        self._check_width()

    def _check_width(self) -> None:
        """Re-budget the columns when the terminal is resized."""
        try:
            table = self.query_one(DataTable)
        except NoMatches:
            return
        width = table.scrollable_content_region.width or table.size.width
        if width and width != self._last_width:
            self._last_width = width
            self._refresh_view(preserve=True)

    def _apply_detail_visibility(self) -> None:
        try:
            pane = self.query_one("#detail", VerticalScroll)
        except NoMatches:
            return
        # Nothing selected means nothing to report: with an empty list the
        # message gets the screen rather than sharing it with a blank pane.
        pane.display = (self._show_detail and bool(self._rows)
                        and self.size.height >= self.MIN_HEIGHT_FOR_DETAIL)


    def action_toggle_detail(self) -> None:
        self._show_detail = not self._show_detail
        self._apply_detail_visibility()
        self._refresh_status()

    def action_scroll_detail(self, direction: int) -> None:
        """Scroll the pane one line, for a record the cursor cannot move in.

        Paging through a long one is what `d` is for.
        """
        try:
            self.query_one("#detail", VerticalScroll).scroll_relative(
                y=direction, animate=False)
        except NoMatches:
            return

    def action_page(self, direction: int) -> None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return
        step = max(1, table.size.height - 2)
        table.move_cursor(row=max(0, min(table.row_count - 1,
                                         (table.cursor_row or 0) + direction * step)))

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        """Keep the priority bindings from piercing a modal.

        `home`/`g` and `end`/`G` are `priority=True` so they beat DataTable's
        own home/end - but priority is checked before the *screen*, so they
        also fired straight past every modal: `G` in the reader, the help or
        the scan dialog silently jumped the list underneath to its last row.
        Returning `None` here declines the binding rather than swallowing the
        key, so it goes on to the modal that should have had it all along.
        """
        if action.startswith("jump") and len(self.screen_stack) > 1:
            return None
        return True

    def action_jump(self, where: int) -> None:
        table = self.query_one(DataTable)
        if table.row_count:
            table.move_cursor(row=(table.row_count - 1) if where else 0)

    # --- export ------------------------------------------------------------

    @work(exclusive=True, group="modal")
    async def action_export(self) -> None:
        await self._do_export()

    @staticmethod
    def _visible_records(rows: list[vdefs.Row]) -> list[exporter.Record]:
        """What the current view is showing, so an export follows the filter.

        Every row says what it stands for, so this is a concatenation rather
        than the unwrap-by-type walk it used to be - and a statistics view no
        longer has to fall back to "every host in the scan set".
        """
        out: dict[tuple, exporter.Record] = {}
        for row in rows:
            for record in row.records:
                out.setdefault(record.identity, record)
        return list(out.values())

    def _export_source(self) -> tuple[list[exporter.Record], str]:
        """Marks when there are any, the rows on screen when there are not.

        Both are named out loud - in the status line while marking, and in the
        first modal before anything is written - because an export whose source
        has to be inferred is the one way this pair of sources goes wrong.
        """
        if self._marked:
            records = list(self._marked.values())
            return records, f"{len(records)} marked record(s)"
        records = self._visible_records(self._rows)
        return records, f"the {len(records)} record(s) on screen"

    async def _pick_format(self) -> str | None:
        return await self.push_screen_wait(ChoiceScreen(
            "Write it as:",
            [(key, label) for key, (label, _) in exporter.FORMATS.items()]))

    async def _do_export(self) -> None:
        from pathlib import Path

        records, source = self._export_source()
        if not records:
            self.notify("nothing to export", severity="warning")
            return
        choices = [(key, label) for key, (label, _, _) in exporter.EXPORTS.items()]
        choices.append(("custom", "custom… (pick the fields)"))
        disabled: set[str] = set()
        if self.nmap.available:
            choices.append(("scan", "scan these hosts with nmap…"))
        # Shown whether or not it can be run: a hidden feature is an
        # undiscoverable one, while a disabled one with its reason teaches what
        # is missing. The count is shown before committing because a few
        # hundred URLs is a capture measured in minutes.
        urls = len(self._capture_urls(records))
        if self.gowitness.available:
            # Where it will write, before it writes: with several directories
            # the first is only a default, and it should not be a surprise.
            where = _short(gw_capture.capture_dir(self.scan_dir).root)
            choices.append(("capture",
                            f"capture {urls} url(s) with gowitness… → {where}"))
        else:
            disabled.add("capture")
            choices.append(("capture",
                            f"capture screenshots — {self.gowitness.reason}"))
        which = await self.push_screen_wait(
            ChoiceScreen(f"Export {source}:", choices, disabled=disabled))
        if which is None:
            return
        if which == "capture":
            self._start_capture(records)
            return
        if which == "scan":
            addresses = list(dict.fromkeys(r.host.address for r in records))
            self._start_scan_flow(addresses)
            return

        if which == "custom":
            fields = await self.push_screen_wait(MultiChoiceScreen(
                "Fields to export:",
                [(name, name) for name in exporter.FIELD_NAMES],
                preselected=("address", "port_label", "service")))
            if not fields:
                return
            fmt = await self._pick_format()
            if fmt is None:
                return
            text = exporter.render(records, fields, fmt)
        else:
            _label, recipe, column = exporter.EXPORTS[which]
            items = recipe(records)
            if column is None:
                # The port list is one comma-separated line whatever happens;
                # offering a format here would be a lie about what is written.
                fmt = "text"
                self.notify("the port list is always one line; format not applied")
            else:
                fmt = await self._pick_format()
                if fmt is None:
                    return
            text = exporter.render_items(items, column or "ports", fmt)

        dest = await self.push_screen_wait(ChoiceScreen(
            "Send it to:", [("clipboard", "clipboard"), ("file", "file")]))
        if dest is None:
            return
        if dest == "clipboard":
            try:
                actions.copy_to_clipboard(text)
                self.notify(f"copied {len(text.splitlines())} line(s)")
            except actions.ActionError as exc:
                self.notify(str(exc), severity="error")
            return
        path = await self.push_screen_wait(
            PromptScreen("Write to file:", f"export{exporter.FORMATS[fmt][1]}"))
        if not path:
            return
        try:
            Path(path).expanduser().write_text(text + "\n", encoding="utf-8")
            self.notify(f"wrote {path}")
        except OSError as exc:
            self.notify(f"write failed: {exc}", severity="error")


def _short(path: Path) -> str:
    """A directory as the user would type it: relative to where seek was started
    when it is below it, absolute otherwise."""
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix() or "."
    except (OSError, ValueError):
        return str(path)


def _rows_of(renderable: RenderableType, width: int) -> int:
    """How many terminal rows one record line occupies at this width.

    A record line is one thing a renderer emitted; a long one wraps. The cursor
    stops on the line, but the pane scrolls in rows, so the two need this to
    agree about where a line begins.
    """
    if width <= 0 or not isinstance(renderable, Text):
        return 1
    text = renderable.plain
    if not text:
        return 1
    return max(1, sum(max(1, -(-cell_len(part) // width))
                      for part in text.split("\n")))


def _fit_hints(items: list[tuple[str, str]], width: int) -> tuple[list[tuple[str, str]], bool]:
    """Choose which hints fit, rather than letting the line be cut mid-word.

    Clipping dropped whatever came last, which on a 100-column terminal meant
    marking, exporting and `?` - the least guessable keys, and the door to the
    rest of them. So the two navigation hints, `?` and `Esc` are kept whatever
    happens, the others fill the space in order, and a `…` admits when some are
    missing.
    """
    if not items:
        return [], False
    must = {0, 1} | {i for i, (key, _) in enumerate(items) if key in ("?", "Esc")}
    chosen = {i for i in must if i < len(items)}

    def width_of(indices: set[int]) -> int:
        parts = [cell_len(f"{items[i][0]} {items[i][1]}") for i in indices]
        return sum(parts) + 3 * max(0, len(parts) - 1)

    for index in range(len(items)):
        if index in chosen:
            continue
        if width_of(chosen | {index}) + 4 <= width:   # 4 leaves room for the `…`
            chosen.add(index)
    return [items[i] for i in sorted(chosen)], len(chosen) < len(items)


def _drop_empty_sections(rows: list[vdefs.Row]) -> list[vdefs.Row]:
    """Remove a heading the filter has left with nothing under it.

    Headings carry no filter text of their own - matching them would mean
    matching the word "Ports" - so they survive the filter unconditionally and
    are dropped here instead, once it is known whether their section still has
    any lines.
    """
    live = {r.section for r in rows if not r.heading}
    return [r for r in rows if not r.heading or r.section in live]


# Shared with the web interface, which sorts the same rows the same way.
_key_at = vdefs.key_at


def _open_browser(url: str) -> None:
    """Hand a URL to the system's opener, detached - from a worker thread."""
    with contextlib.suppress(OSError):
        subprocess.Popen(actions.opener_argv(url), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)


def run_viewer(scans: ScanSet | Pending, config: Config | None = None,
               sources: list[Path] | None = None,
               scan_dir: Path | None = None) -> int:
    """Open the viewer on a finished model, or on files still to be read."""
    result = NmapApp(scans, config, sources=sources, scan_dir=scan_dir).run()
    return result if isinstance(result, int) else 0
