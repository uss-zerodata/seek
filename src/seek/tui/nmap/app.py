"""The scan viewer: one table, one filter, one breadcrumb.

Reuses the search session's conventions deliberately - the same fuzzy query
grammar in the filter, the same staged `Esc`, the same hint bar and status line -
so the two modes do not need separate mental models. Nothing here is persisted:
the files named on the command line are the whole truth for the run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

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
from seek.nmap import export as exporter
from seek.nmap import filtering, timeline
from seek.nmap import presets as presets_mod
from seek.nmap import views as proj
from seek.nmap.diff import ScanDiff, diff
from seek.nmap.models import ScanSet
from seek.nmap.runner import Runner, ScanRun, State, elevation_help
from seek.tui.cells import cell_len, clip_cells
from seek.tui.menu import ChoiceScreen, MultiChoiceScreen, PromptScreen
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap import scans as scan_views
from seek.tui.nmap import views as vdefs
from seek.tui.nmap.commands import ScanCommands
from seek.tui.nmap.help import NmapHelpScreen
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


@dataclass(slots=True)
class _Mark:
    """Where the cursor was, and how the list was ordered, when a drill-down was
    opened - so `Esc` comes back to the row it was opened from.

    The row is remembered by identity first and by position only as a fallback:
    a filter typed inside the drill-down, or cleared on the way out, changes
    which index the row you came from now sits at.
    """

    target: object = None
    index: int = 0
    sort_col: int = 0
    sort_desc: bool = False

    def locate(self, rows: list[vdefs.Row]) -> int:
        if self.target is not None:
            for i, row in enumerate(rows):
                if row.target is self.target:
                    return i
        return self.index


class ScanTable(DataTable):
    """The list, with ←/→ reassigned.

    `DataTable` uses them to move between columns, which does nothing useful in
    row-cursor mode - so they scroll the report below instead, leaving ↑/↓ to
    move the selection. Binding them here rather than on the app keeps them out
    of the filter box, where they still edit text.
    """

    BINDINGS = [
        Binding("left", "detail(-1)", "Scroll detail up", show=False),
        Binding("right", "detail(1)", "Scroll detail down", show=False),
    ]

    def action_detail(self, direction: int) -> None:
        self.app.action_scroll_detail(direction)


_HINTS = {
    "hosts": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "services"), ("v", "swap"),
              ("1-9", "sort"), ("r", "reverse"), ("/", "filter"), ("u", "reachable"),
              ("s", "stats"), ("b", "group"), ("m", "mark"), ("n", "scan"), ("x", "export"),
              ("?", "help"), ("^P", "commands")],
    "services": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "hosts"), ("v", "swap"),
                 ("1-9", "sort"), ("r", "reverse"), ("/", "filter"), ("s", "stats"),
                 ("b", "group"), ("m", "mark"), ("n", "scan"), ("x", "export"), ("?", "help"),
                 ("^P", "commands")],
    "host-detail": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "same service everywhere"),
                    ("1-9", "sort"), ("r", "reverse"),
                    ("/", "filter"), ("d", "detail"), ("m", "mark"), ("x", "export"),
                    ("?", "help"), ("^P", "commands")],
    "group-hosts": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "host"), ("1-9", "sort"),
                    ("r", "reverse"), ("/", "filter"), ("m", "mark"), ("x", "export"),
                    ("?", "help"), ("^P", "commands")],
    "service-detail": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "host"),
                       ("1-9", "sort"), ("/", "filter"), ("m", "mark"), ("x", "export"),
                       ("?", "help"), ("^P", "commands")],
    "grouping": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "hosts"),
                 ("b", "next grouping"), ("1-9", "sort"), ("/", "filter"),
                 ("m", "mark"), ("x", "export"), ("?", "help"), ("^P", "commands")],
    "names": [("↑↓", "select"), ("←→", "scroll detail"), ("↵", "hosts"),
              ("1-9", "sort"), ("r", "reverse"), ("/", "filter"), ("m", "mark"),
              ("n", "scan"), ("x", "export"), ("?", "help"), ("^P", "commands")],
    "scans": [("↑↓", "select"), ("o", "report view"), ("p", "freeze log"),
              ("c", "cancel"), ("n", "new scan"), ("1-9", "sort"), ("/", "filter"),
              ("x", "export"), ("?", "help"), ("^P", "commands")],
    "stats": [("↑↓", "select"), ("↵", "open the figure"), ("1-9", "sort"),
              ("r", "reverse"), ("/", "filter"), ("s", "back"), ("m", "mark"),
              ("x", "export"), ("?", "help"), ("^P", "commands")],
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
        Binding("escape", "back", "Back", show=False),
        Binding("slash", "filter", "Filter", show=False),
        Binding("enter", "drill", "Open", show=False),
        Binding("v", "swap", "Next overview", show=False),
        Binding("V", "swap_back", "Previous overview", show=False),
        Binding("r", "reverse", "Reverse sort", show=False),
        Binding("s", "stats", "Statistics", show=False),
        Binding("b", "group", "Group by", show=False),
        Binding("u", "reachable", "Reachable only", show=False),
        Binding("d", "toggle_detail", "Detail pane", show=False),
        # J/K scroll the report below, pairing with j/k moving the list above.
        Binding("K", "scroll_detail(-1)", "Detail up", show=False),
        Binding("J", "scroll_detail(1)", "Detail down", show=False),
        Binding("n", "new_scan", "New scan", show=False),
        Binding("o", "report_mode", "Report view", show=False),
        Binding("p", "freeze_log", "Freeze the log", show=False),
        Binding("c", "cancel_scan", "Cancel the scan", show=False),
        Binding("m", "mark", "Mark", show=False),
        Binding("M", "clear_marks", "Clear marks", show=False),
        Binding("x", "export", "Export", show=False),
        Binding("question_mark", "help", "Help", show=False),
        Binding("q", "quit_now", "Quit", show=False),
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

    def __init__(self, scans: ScanSet, config: Config | None = None,
                 sources: list[Path] | None = None,
                 scan_dir: Path | None = None) -> None:
        super().__init__()
        self.scans = scans
        self.config = config or Config()
        # Where a scan writes, and what to re-read when one finishes. Both are
        # the launch directory unless the config says otherwise.
        self.sources: list[Path] = list(sources or [])
        self.scan_dir = Path(self.config.scan_output_dir or scan_dir or Path.cwd())
        self.nmap = presets_mod.probe(self.config.nmap_path)
        self.runner = Runner()
        self._diffs: dict[int, ScanDiff] = {}
        # The file history is expensive to build (it re-parses), so cache it and
        # rebuild only when the model changes - which `self.scans` identity marks,
        # since a finished scan is absorbed by replacing it.
        self._history: list[timeline.Scan] = []
        self._history_for: object = None
        self._report_mode = "condensed"
        self._log_frozen = False
        self.stack: list[vdefs.View] = [vdefs.hosts_view()]
        # One mark per level pushed onto `stack`, so unwinding restores both the
        # cursor and the sort the level below was left in.
        self._marks: list[_Mark] = []
        self._pending_mark: _Mark | None = None
        self._rows: list[vdefs.Row] = []
        self._sort_col = 0
        self._sort_desc = False
        self._group_keys = ("service", "product", "port")
        self._group_at = 0
        self._only_reachable = False
        self._show_detail = True
        self._active_tab = "hosts"
        self._widths: list[int] = []
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
        warn = self.query_one("#warn", Static)
        warn.display = self.scans.overstated
        if self.scans.overstated:
            asserted, real = len(self.scans.asserted_up), len(self.scans.reachable)
            self.query_one("#warn", Static).update(Text(
                f"⚠  scan asserted {asserted} hosts up (-Pn) but only {real} show any "
                f"evidence — listing by evidence", style="bold bright_yellow"))
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
        if not self.scans.hosts and self.nmap.available:
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
        natural = [cell_len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row.cells[:len(natural)]):
                natural[i] = max(natural[i], cell_len(str(cell)))
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

    def _refresh_view(self, preserve: bool = False, restore: _Mark | None = None) -> None:  # noqa: E501
        # Built once and used for both halves. `_column_widths` and
        # `_reload_rows` each used to call `View.rows`, so every sort, tab
        # switch and resize recomputed the whole projection twice - for the
        # service and grouping overviews, twice over every host in the set.
        # Widths come from the *unfiltered* rows on purpose: columns that
        # re-budgeted as the filter narrowed would shift under the cursor.
        all_rows = self.view.rows(self.scans)
        table = self.query_one(DataTable)
        # Read before the clear: `DataTable.clear` resets the cursor to (0, 0),
        # so `preserve` used to read back a zero it had just written and a
        # resize dropped the selection to the top of the list.
        keep = table.cursor_row or 0
        table.clear(columns=True)
        self._widths = self._column_widths(all_rows)
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
        self._fill(self._narrow(all_rows), preserve=preserve, restore=restore, keep=keep)

    def _reload_rows(self, preserve: bool = False) -> None:
        # A mark left by `Esc` clearing the filter is spent on the next rebuild,
        # whichever path gets there - the debounce timer or the flush.
        restore, self._pending_mark = self._pending_mark, None
        keep = self.query_one(DataTable).cursor_row or 0
        self._fill(self._narrow(self.view.rows(self.scans)),
                   preserve=preserve, restore=restore, keep=keep)

    def _narrow(self, rows: list[vdefs.Row]) -> list[vdefs.Row]:
        """Apply the filter box and the current sort to ``rows``."""
        text = self.query_one("#filter", Input).value.strip()
        self._spec = filtering.parse_filter(text) if text else filtering.FilterSpec()
        self._unfiltered = sum(1 for r in rows if not r.heading)
        if not self._spec.is_empty:
            rows = [r for r in rows
                    if r.heading or filtering.matches(self._spec, r.text, r.addresses)]
            rows = _drop_empty_sections(rows)
        col = min(self._sort_col, max(0, len(self.view.columns) - 1))
        # Two stable passes rather than one compound key: `reverse` belongs to
        # the column only. Reversing a single (rank, heading, value) key would
        # turn the sections upside down and push every heading to the bottom of
        # its own lines.
        rows.sort(key=lambda r: _key_at(r, col), reverse=self._sort_desc)
        rows.sort(key=lambda r: (r.section_rank, 0 if r.heading else 1))
        return rows

    def _fill(self, rows: list[vdefs.Row], preserve: bool = False,
              restore: _Mark | None = None, keep: int = 0) -> None:
        query = self._spec.query
        self._rows = rows
        table = self.query_one(DataTable)
        table.clear()
        for row in rows:
            table.add_row(
                Text(self._mark_glyph(row), style=_MARK_STYLE),
                *(self._cell(c, query, self._width_at(n), row.style)
                  for n, c in enumerate(row.cells)))
        if rows:
            # Re-laying the columns (a resize) must not move the selection, and
            # neither must coming back out of a drill-down; only a genuine
            # change of the row set resets it to the top.
            if restore is not None:
                index = restore.locate(rows)
            else:
                index = keep if preserve else 0
            table.move_cursor(row=max(0, min(len(rows) - 1, index)))
        self._refresh_empty(rows)
        self._refresh_status()
        self._refresh_detail()

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
        if query:
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
        elif self._only_reachable and self._active_tab == "hosts":
            headline = "No host shows evidence of being reachable"
            hint = "u lists every host the scan named"
        elif len(self.stack) > 1:
            headline = f"{self.view.title} has nothing to show"
            hint = "Esc goes back · ? for help"
        else:
            headline = "This scan recorded no hosts"
            hint = "the files named on the command line are the whole truth · ? for help"
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
        found = match_spans(query, shown)
        if found is not None:
            style = self.config.theme.get("match", "bold bright_yellow")
            for pos in found[1]:
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

    def _refresh_status(self) -> None:
        left = Text(f"{len(self.scans.hosts)} host(s) across "
                    f"{len(self.scans.sources)} scan(s)", style="dim")
        shown = sum(1 for r in self._rows if not r.heading)
        right = Text(f"{shown} row{'s' if shown != 1 else ''}", style="bold")
        if self._marked:
            right.append(f"  ·  {len(self._marked)} marked", style=_MARK_STYLE)
        if self.runner.runs:
            right.append(f"  ·  {len(self.runner.runs)} run(s)", style="dim")
        # Symbol and words, never colour alone: whether a scan can be started at
        # all is worth knowing before reaching for the key that starts one.
        right.append("  ·  ")
        right.append(self.nmap.label(),
                     style="bold" if self.nmap.available else "dim")
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

        line = Text.assemble(left, "  ", right)
        try:
            self.query_one("#status", Static).update(line)
        except NoMatches:
            return
        in_filter = self.focused is self.query_one("#filter", Input)
        items = list(FILTER_HINTS if in_filter else _HINTS.get(self.view.kind, []))
        if not in_filter:
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
        """A number picks the column and always sorts ascending.

        Toggling direction by pressing the same number again was the thing
        testers could not form a model of - `r` reverses, and that is the only
        thing that does.
        """
        if index >= len(self.view.columns):
            return
        self._sort_col = index
        self._sort_desc = False
        self._refresh_view()

    def action_stats(self) -> None:
        self._toggle_stats()

    def action_group(self) -> None:
        self._cycle_grouping()

    def action_reachable(self) -> None:
        self._toggle_reachable()

    def _toggle_stats(self) -> None:
        self._activate("hosts" if self._active_tab == "stats" else "stats")

    def _cycle_grouping(self) -> None:
        if self._active_tab in _GROUP_TABS:
            index = (_GROUP_TABS.index(self._active_tab) + 1) % len(_GROUP_TABS)
            self._activate(_GROUP_TABS[index])
        else:
            self._activate(_GROUP_TABS[0])

    def _toggle_reachable(self) -> None:
        """A filter on the host list, not an overview of its own."""
        if self._active_tab != "hosts":
            self._activate("hosts")
        self._only_reachable = not self._only_reachable
        self.stack[-1] = vdefs.hosts_view(self._only_reachable)
        self._reset_sort()

    def _mark_current(self) -> _Mark:
        """Where the cursor is now, so a later `Esc` can put it back."""
        table = self.query_one(DataTable)
        index = table.cursor_row or 0
        row = self._rows[index] if 0 <= index < len(self._rows) else None
        return _Mark(target=row.target if row is not None else None, index=index,
                     sort_col=self._sort_col, sort_desc=self._sort_desc)

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
        return vdefs.hosts_view(self._only_reachable)

    def _scan_history(self) -> list[timeline.Scan]:
        """The file history, rebuilt only when the model actually changes."""
        if self._history_for is not self.scans:
            self._history = timeline.build(self.scans.files)
            self._history_for = self.scans
        return self._history

    def _scans_view(self) -> vdefs.View:
        def build(_scans) -> list[vdefs.Row]:
            history = self._scan_history()
            done = {str(s.path) for s in history if s.path}
            # A finished run is already in the history as its file; only runs
            # with no file yet (running, failed, cancelled) get their own row.
            live = [r for r in self.runner.runs
                    if r.state is not State.DONE or str(r.xml_path) not in done]
            return scan_views.history_rows(history, live)

        return vdefs.View(
            title="Scans", columns=scan_views.SCANS_COLUMNS, build=build,
            kind="scans", tab="scans", default_sort=scan_views.SCANS_DEFAULT_SORT,
        )

    def _activate(self, tab_id: str) -> None:
        """Switch overview. A tab replaces the stack: drill-downs belong to the
        overview they were opened from, not to a different one."""
        self._active_tab = tab_id
        self.stack = [self._view_for_tab(tab_id)]
        self._marks.clear()
        tabs = self.query_one(Tabs)
        if tabs.active != tab_id:
            tabs.active = tab_id
        self._reset_sort()
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
            view = vdefs.host_detail(target)
        elif hasattr(target, "port"):
            view = self._service_view(target)
        else:
            return
        self._marks.append(self._mark_current())
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
        """Cycle the selected run's report: condensed → diff → raw."""
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
        self._activate("scans")
        self._select_target(run)        # focus the live run, not the oldest scan
        self.notify(f"started {run.preset}")
        await self.runner.run(run, self._on_scan_line, self._on_scan_done)

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
        """Re-read every source plus the new file.

        Not an incremental merge: one loading path means a scan started here and
        one run outside are folded in by exactly the same rules.
        """
        from seek.nmap.merge import load
        from seek.nmap.views import prepare

        before = self.scans.hosts
        # A directory source already covers the new file - naming it as well
        # would parse it twice and double its provenance.
        covered = any(p.is_dir() and run.xml_path.parent == p for p in self.sources)
        if not covered:
            self.sources.append(run.xml_path)
        try:
            self.scans = prepare(load(list(self.sources)))
        except Exception as exc:                      # noqa: BLE001 - report, never crash
            self.notify(f"{run.xml_path.name} could not be read: {exc}",
                        severity="error")
            if not covered:
                self.sources.pop()
            return
        self._diffs[id(run)] = diff(before, self.scans.hosts)
        self._resolve_marks()
        self.notify(f"{run.preset}: {self._diffs[id(run)].summary()}")

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

    def action_quit_now(self) -> None:
        self._request_quit()

    async def action_quit(self) -> None:
        """Textual's own quit - `ctrl+c` and the system palette - guarded too.

        Overridden rather than left alone: a guard one keypress can walk around
        is not a guard.
        """
        self._request_quit()

    @work(exclusive=True, group="quit")
    async def _request_quit(self) -> None:
        """Leaving while a scan runs ends it, so ask first.

        A scan writes its output only when it finishes, so quitting mid-run
        throws the work away - which is worth one keypress of confirmation, and
        `Esc` is the answer that keeps scanning.
        """
        running = self.runner.busy()
        if running is None:
            self.exit(0)
            return
        answer = await self.push_screen_wait(ChoiceScreen(
            f"{running.preset} has been running for "
            f"{scan_views.elapsed(running.elapsed)}. Quitting ends it, and a "
            f"scan that does not finish writes no file.",
            [("stay", "Keep scanning"), ("quit", "End the scan and quit")]))
        if answer == "quit":
            self.exit(0)

    def on_unmount(self) -> None:
        """Never leave a scan running behind a closed viewer.

        The child is started in its own session so that cancelling reaches
        everything nmap spawns - which also means quitting without this would
        leave it scanning the target with nobody watching.
        """
        running = self.runner.busy()
        if running is not None:
            self.runner.cancel()

    def action_reverse(self) -> None:
        self._sort_desc = not self._sort_desc
        self._refresh_view()

    def action_back(self) -> None:
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

    def _refresh_detail(self) -> None:
        """Show the full record for the highlighted row - the table only has
        room for a few columns, and script and vulnerability detail has none."""
        try:
            pane = self.query_one("#detail-body", Static)
        except NoMatches:
            return
        row = self._current_row()
        target = row.target if row is not None else None
        if isinstance(target, timeline.Scan):
            pane.update(scan_views.scan_report(target, self._report_mode))
            self._apply_detail_visibility()
            return
        if isinstance(target, ScanRun):
            pane.update(scan_views.report(target, self._report_mode,
                                          self._diffs.get(id(target)),
                                          self._log_frozen))
            self._apply_detail_visibility()
            if self._report_mode == "raw" and target.running and not self._log_frozen:
                # Follow the newest line, which is why the scroll comes after
                # the update rather than the usual scroll-to-top.
                try:
                    self.query_one("#detail", VerticalScroll).scroll_end(animate=False)
                except NoMatches:
                    pass
            return
        if row is not None and row.heading:
            pane.update(Text(f"{row.cells[0]}\n\n"
                             "Select a line under this heading to open what it counts.",
                             style="dim"))
        elif target is None and row is not None:
            # views without a drill target (statistics, groupings) still explain
            # the row rather than leaving the pane blank
            pane.update(Text(row.text, style="dim"))
        else:
            pane.update(detail_pane.render(target, row.host if row else None))
        try:  # a new record starts at the top of its report
            self.query_one("#detail", VerticalScroll).scroll_home(animate=False)
        except NoMatches:
            pass
        self._apply_detail_visibility()

    def _on_tick(self) -> None:
        """Both things that depend on the terminal's size, on one timer."""
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
        try:
            self.query_one("#detail", VerticalScroll).scroll_relative(
                y=direction * 3, animate=False)
        except NoMatches:
            return

    def action_page(self, direction: int) -> None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return
        step = max(1, table.size.height - 2)
        table.move_cursor(row=max(0, min(table.row_count - 1,
                                         (table.cursor_row or 0) + direction * step)))

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
        if self.nmap.available:
            choices.append(("scan", "scan these hosts with nmap…"))
        which = await self.push_screen_wait(ChoiceScreen(f"Export {source}:", choices))
        if which is None:
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


def _key_at(row: vdefs.Row, col: int) -> tuple:
    """Sort on the column's own key.

    Keys are pre-normalised by the view (an address becomes its octets, a count
    stays an int), so they must be compared *as they are* - stringifying them is
    what made `10.10.10.11` sort before `10.10.10.2`. Numbers, tuples and strings
    are kept in separate buckets so a mixed column still has a total order.
    """
    if col < len(row.sort_key):
        value = row.sort_key[col]
    else:
        value = row.cells[col] if col < len(row.cells) else ""
    if isinstance(value, bool):
        return (0, (int(value),), "")
    if isinstance(value, int | float):
        return (0, (value,), "")
    if isinstance(value, tuple):
        # an address key: (0, (10, 10, 10, 2), "") - compare the octets
        flat = value[1] if len(value) > 1 and isinstance(value[1], tuple) else value
        if flat and all(isinstance(x, int | float) for x in flat):
            return (0, tuple(flat), "")
        return (1, (), " ".join(str(x) for x in value))
    return (1, (), str(value).lower())


def run_viewer(scans: ScanSet, config: Config | None = None,
               sources: list[Path] | None = None,
               scan_dir: Path | None = None) -> int:
    result = NmapApp(scans, config, sources=sources, scan_dir=scan_dir).run()
    return result if isinstance(result, int) else 0
