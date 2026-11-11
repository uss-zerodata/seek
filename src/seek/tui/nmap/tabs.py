"""The overviews, as tabs - one definition for the terminal and the browser."""

from __future__ import annotations

from seek.nmap.progress import Report
from seek.nmap.session import Session
from seek.tui.nmap import scans as scan_views
from seek.tui.nmap import views as vdefs

TABS: list[tuple[str, str]] = [
    ("hosts", "Hosts"),
    ("services", "Services"),
    ("stats", "Statistics"),
    ("group-service", "By service"),
    ("group-product", "By product"),
    ("group-port", "By port"),
    ("group-tag", "By tag"),
    ("inventory", "Inventory"),
    ("findings", "Findings"),
    ("names", "Names"),
    ("scans", "Scans"),
]
GROUP_TABS = ("group-service", "group-product", "group-port", "group-tag")


def scans_view(session: Session) -> vdefs.View:
    """Every scan file in time order, and every run the session has started."""
    def build(_scans, report: Report | None = None) -> list[vdefs.Row]:
        # A running scan's file is partial: the run stands for it until it ends.
        running = {str(p) for p in session.running_paths()}
        history = [s for s in session.scan_history(report)
                   if not s.path or str(s.path) not in running]
        done = {str(s.path) for s in history if s.path}
        # An ended run is in the history as its file - whatever it finished;
        # a run with no file (running, or nothing written) gets its own row.
        live = [r for r in session.runner.runs
                if r.running or str(r.xml_path) not in done]
        # A capture leaves no scan file, so every one of them keeps its row.
        live += list(session.captures.runs)
        return scan_views.history_rows(history, live)

    return vdefs.View(
        title="Scans", columns=scan_views.SCANS_COLUMNS, build=build,
        kind="scans", tab="scans", default_sort=scan_views.SCANS_DEFAULT_SORT,
        # A live run's elapsed time and its log move without the model
        # changing, so these rows are rebuilt every refresh. The expensive half
        # - the file history - is cached by the session.
        cacheable=False, reports=True,
    )


def tab_view(tab: str, session: Session, only_up: bool = False,
             only_ports: bool = False) -> vdefs.View:
    if tab == "scans":
        return scans_view(session)
    if tab == "inventory":
        return vdefs.inventory_view(session)
    if tab == "findings":
        return vdefs.findings_view(session)
    if tab == "names":
        return vdefs.names_view()
    if tab == "services":
        return vdefs.services_view()
    if tab == "stats":
        return vdefs.statistics_view()
    if tab in GROUP_TABS:
        return vdefs.grouping_view(tab.removeprefix("group-"), session)
    return vdefs.hosts_view(only_up, only_ports, session)
