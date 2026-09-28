"""Key reference for the scan viewer.

Rendered as a real two-column grid, not space-padded text: a description that
runs long wraps *within its own column* instead of falling back to the left
margin, and the key, the description and the section titles each carry their own
weight so the page can be scanned rather than read.
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

# Each group: a title, then (key, description) rows. A row with an empty key is
# a continuation of the one above it - a second line of the same idea, which the
# grid keeps aligned under the description column.
_GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("Move around", [
        ("↑ ↓ · j k", "select a row; the detail below follows it"),
        ("J K", "move the detail pane's cursor a line at a time"),
        ("← →", "jump it to the next or previous line that opens something"),
        ("o", "open what the cursor is on: the scan's own text for this"),
        ("", "host or port, scoped to it; Esc goes back to the record"),
        ("", "inside it ← → step between the scans that saw the same thing"),
        ("PgUp PgDn", "page the list"),
        ("Home End · g G", "jump to the first / last row"),
        ("↵", "open the selected row — keep pressing to keep digging"),
        ("", "host → its services → that service everywhere → a host"),
        ("", "a statistics figure opens the hosts, ports or services it counts"),
        ("Esc", "leave the filter, then clear it, then back one level, then quit"),
        ("q", "quit (asks first while a scan is running)"),
        ("Ctrl+P", "command palette — every action, searchable by name"),
    ]),
    ("Change the view", [
        ("v · V", "next / previous overview tab"),
        ("s", "statistics: coverage, services and ports, each one openable"),
        ("b", "group by service, then product, then port"),
        ("u", "only hosts with evidence of being reachable;"),
        ("", "on a host's port list, only its open ports"),
        ("d", "open the selected row's detail full-screen and searchable"),
        ("", "/ searches it; n N jump between matches; ← → read the previous"),
        ("", "or next entry without leaving; a running scan's raw output"),
        ("", "keeps streaming in while it is open"),
        ("D", "show or hide the inline detail pane"),
    ]),
    ("Filter and sort", [
        ("/", "filter; matched characters are highlighted in the list"),
        ("1 … 9", "sort by that column (ascending) — or click its heading"),
        ("r", "reverse the sort direction"),
        ("10.0.0.0/24", "a CIDR term filters by address range"),
        ("10.0.0.5", "a bare address means that host alone"),
        ("!10.0.0.0/8", "a negated range subtracts from the rest"),
    ]),
    ("Collect and take away", [
        ("m", "mark the row (a bucket row marks every host in it)"),
        ("M", "clear every mark; marks survive filtering, sorting and tabs"),
        ("x", "export the marked rows, or the rows on screen when none are"),
        ("", "hosts, ports, host:port, URLs, or your own fields"),
        ("", "as plain text, CSV or JSON"),
        ("", "— or hand the URLs to gowitness and capture them"),
    ]),
    ("Capture (gowitness)", [
        ("x", "the export dialog runs a capture over this view's URLs"),
        ("", "results land on the host and service records themselves;"),
        ("", "d opens the same record with every header and console line"),
        ("i", "open a capture's screenshot in the system image viewer"),
        ("W", "serve the report and open it at the selected result"),
    ]),
    ("Scan", [
        ("n", "new scan: scope, preset, command, then a review before it runs"),
        ("o", "cycle a scan's report: overview, what it added, raw output"),
        ("", "(on a host or service record, o opens the raw log instead)"),
        ("p", "freeze the log to read it — the scan keeps running"),
        ("c", "cancel the running scan"),
        ("", "the Scans tab is a history: every scan file present, oldest first,"),
        ("", "each diffed against the state before it — imported scans included"),
    ]),
]

_SYNTAX: list[tuple[str, str]] = [
    ("foo bar", "match foo AND bar"),
    ("'foo", "exact substring"),
    ("^foo  ·  foo$", "starts with · ends with"),
    ("!foo", "exclude"),
    ("Foo", "an uppercase letter makes the term case-sensitive"),
]

# The same restraint as the rest of the viewer: weight and one accent, in ANSI
# names that adapt to the terminal's own palette rather than a fixed hex theme.
# Titles carry weight, keys the header accent, descriptions the default colour,
# and everything secondary is dim.
_KEY_STYLE = "bold cyan"
_TITLE_STYLE = "bold"
_DESC_STYLE = ""
_MUTED = "dim"


def _grid(rows: list[tuple[str, str]]) -> Table:
    """One section as a two-column grid; the description column wraps itself."""
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="left", no_wrap=True, width=16)
    table.add_column(justify="left", ratio=1)
    for key, desc in rows:
        table.add_row(
            Text(key, style=_KEY_STYLE),
            Text(desc, style=_DESC_STYLE if key else _MUTED),
        )  # a continuation row (no key) reads as the dim second line it is
    return table


def help_body() -> RenderableType:
    parts: list[RenderableType] = []
    for title, rows in _GROUPS:
        parts.append(Text(title, style=_TITLE_STYLE))
        parts.append(_grid(rows))
        parts.append(Text(""))
    parts.append(Text("Filter syntax", style=_TITLE_STYLE))
    parts.append(_grid(_SYNTAX))
    return Group(*parts)


class NmapHelpScreen(ModalScreen[None]):
    BINDINGS = [("escape,question_mark,q", "close", "Close")]
    DEFAULT_CSS = """
    NmapHelpScreen { align: center middle; }
    NmapHelpScreen > VerticalScroll {
        width: 82; height: auto; max-height: 90%;
        background: $panel; border: round $primary; padding: 1 3;
    }
    NmapHelpScreen #title { text-style: bold; padding: 0 0 1 0; }
    NmapHelpScreen #keys { color: $text-muted; padding: 1 0 0 0; }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            title = Text("seek nmap", style="bold")
            title.append("   keys and filter syntax", style=_MUTED)
            yield Static(title, id="title")
            yield Static(help_body())
            yield Static("↑↓ scroll · Esc, q or ? to close", id="keys")

    def action_close(self) -> None:
        self.dismiss(None)
