"""Every viewer action, exposed through the command palette.

The keys are bare and terminal-safe, but that also makes them easy to forget.
The palette lists the same actions by name, so nothing is reachable only by
knowing a keystroke - including the sort columns, which depend on whichever
overview is showing and so are built when the palette is opened.
"""

from __future__ import annotations

from collections.abc import Callable

from textual.command import DiscoveryHit, Hit, Hits, Provider

# (title, subtitle, method name on the app, optional argument)
_STATIC: list[tuple[str, str, str, object]] = [
    ("Hosts", "Overview of every host", "_activate", "hosts"),
    ("Services", "Services grouped across hosts", "_activate", "services"),
    ("Statistics", "Coverage, services and ports — each figure opens", "_activate", "stats"),
    ("Group by service", "Hosts and ports per service name", "_activate", "group-service"),
    ("Group by product", "Hosts and ports per product", "_activate", "group-product"),
    ("Group by port", "Hosts per port", "_activate", "group-port"),
    ("Next overview", "Move one tab right (v)", "_cycle_tab", 1),
    ("Previous overview", "Move one tab left (V)", "_cycle_tab", -1),
    ("Only reachable hosts", "Hide hosts with no evidence (u)", "_toggle_reachable", None),
    ("Open selected row", "Drill into the selection (Enter)", "action_drill", None),
    ("Back", "Leave this view (Esc)", "action_back", None),
    ("First row", "Jump to the top (Home)", "action_jump", 0),
    ("Last row", "Jump to the bottom (End)", "action_jump", 1),
    ("Page down", "Move a screen down", "action_page", 1),
    ("Page up", "Move a screen up", "action_page", -1),
    ("Scroll detail down", "Scroll the report (→)", "action_scroll_detail", 1),
    ("Scroll detail up", "Scroll the report (←)", "action_scroll_detail", -1),
    ("Open detail full-screen", "Searchable; ← → step entries; streams a scan (d)",
     "action_open_detail", None),
    ("Show or hide the detail pane", "Toggle the inline report pane (D)",
     "action_toggle_detail", None),
    ("Reverse sort", "Flip the current order (r)", "action_reverse", None),
    ("Filter", "Narrow the list; CIDR terms filter by range (/)", "action_filter", None),
    ("New scan", "Scope, preset, command, review, run (n)", "action_new_scan", None),
    ("Cancel the running scan", "Ends the process (c)", "action_cancel_scan", None),
    ("Freeze the log", "Stops the view, not the scan (p)", "action_freeze_log", None),
    ("Report view", "Overview, diff or raw output (o)", "action_report_mode", None),
    ("Mark selected row", "Collect it for export (m)", "action_mark", None),
    ("Clear marks", "Drop every mark (M)", "action_clear_marks", None),
    ("Export", "The marks, or this view — fields and format are yours (x)",
     "action_export", None),
    ("Help", "Key reference (?)", "action_help", None),
    ("Quit", "Leave the viewer (q)", "action_quit_now", None),
]


def _bind(app, method: str, argument: object) -> Callable[[], None]:
    target = getattr(app, method)
    if argument is None:
        return lambda: target()
    return lambda: target(argument)


def _commands(app) -> list[tuple[str, str, Callable[[], None]]]:
    out = [(title, subtitle, _bind(app, method, argument))
           for title, subtitle, method, argument in _STATIC]
    # Sorting depends on the columns of whatever overview is showing.
    for index, column in enumerate(app.view.columns):
        out.append((
            f"Sort by {column}",
            f"Order this list by its {column.lower()} column ({index + 1})",
            _bind(app, "action_sort", index),
        ))
    return out


class ScanCommands(Provider):
    """Makes every viewer action reachable by name."""

    async def discover(self) -> Hits:
        for title, subtitle, run in _commands(self.app):
            yield DiscoveryHit(title, run, help=subtitle)

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        for title, subtitle, run in _commands(self.app):
            score = matcher.match(title)
            if score > 0:
                yield Hit(score, matcher.highlight(title), run, help=subtitle)
