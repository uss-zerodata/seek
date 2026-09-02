"""Key reference for the scan viewer."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

_GROUPS = [
    ("Move", [
        ("↑ ↓  /  j k", "select a row — the detail below follows it"),
        ("← →", "scroll the detail of the selected row"),
        ("PgUp PgDn", "page the list"),
        ("Home End  /  g G", "first / last row"),
        ("↵", "open the selected row — keep pressing it to keep digging:"),
        ("", "host → its services → that service on every host → a host …"),
        ("", "a statistics figure opens the hosts, services or ports it counts"),
        ("Esc", "leave the filter → clear it → back one level → quit"),
        ("", "back lands on the row you opened, in the order you left it"),
        ("q", "quit — asks first while a scan is running"),
        ("Ctrl+P", "command palette — every action here, searchable by name"),
    ]),
    ("Look at", [
        ("v  /  V", "next / previous overview tab"),
        ("", "the marked tab follows a drill-down onto another overview"),
        ("d", "show / hide the detail pane"),
        ("s", "statistics — coverage, services and ports, each figure openable"),
        ("", "Names lists every DNS name found, resolved or from a certificate"),
        ("b", "group by service, then product, then port"),
        ("u", "only hosts with evidence of being reachable"),
    ]),
    ("Narrow and order", [
        ("/", "filter — matched characters are highlighted in the list"),
        ("10.0.0.0/24", "a CIDR term filters by address range"),
        ("10.0.0.5", "a complete address means that host alone"),
        ("10.0.0.0/8 192.168.0.0/16", "several ranges mean either of them"),
        ("!10.0.0.0/8", "a negated range subtracts from the rest"),
        ("1 … 9", "sort by that column (always ascending) — or click its heading"),
        ("r", "reverse the sort direction"),
        ("", "the statistics tab sorts inside each section, headings stay put"),
    ]),
    ("Collect", [
        ("m", "mark the selected row — a bucket row marks every host in it"),
        ("", "marks survive filtering, sorting, drilling and tabs"),
        ("M", "clear every mark"),
    ]),
    ("Scan", [
        ("n", "new scan — scope, preset, command, then a review before it runs"),
        ("o", "cycle the run's report: overview, what it added, raw output"),
        ("p", "freeze the log for reading — the scan keeps running"),
        ("c", "cancel the running scan for real"),
        ("", "output goes to the launch directory as -oA (xml, nmap, gnmap)"),
        ("", "presets live in the config file; root is derived from the flags"),
    ]),
    ("Take away", [
        ("x", "export — the marked records, or the rows on screen when none are"),
        ("", "hosts, ports, host:port, URLs, or pick your own fields"),
        ("", "as plain text, CSV (with a header) or JSON"),
    ]),
]

_SYNTAX = [
    ("foo bar", "match foo AND bar"),
    ("'foo", "exact substring"),
    ("^foo", "starts with"),
    ("foo$", "ends with"),
    ("!foo", "exclude"),
    ("Foo", "an uppercase letter makes it case-sensitive"),
]


def help_text() -> str:
    rows: list[str] = ["seek nmap — keys", ""]
    for title, entries in _GROUPS:
        rows.append(title)
        rows += [f"  {key:<20} {desc}" for key, desc in entries]
        rows.append("")
    rows.append("Filter syntax  (the same as a search session)")
    rows += [f"  {pat:<20} {desc}" for pat, desc in _SYNTAX]
    return "\n".join(rows)


class NmapHelpScreen(ModalScreen[None]):
    BINDINGS = [("escape,question_mark,q", "close", "Close")]
    DEFAULT_CSS = """
    NmapHelpScreen { align: center middle; }
    NmapHelpScreen > VerticalScroll {
        width: 78; height: auto; max-height: 90%;
        background: $panel; border: round $primary; padding: 1 2;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static(help_text())

    def action_close(self) -> None:
        self.dismiss(None)
