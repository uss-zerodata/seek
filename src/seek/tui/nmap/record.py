"""What a row's record is - one answer for the terminal's pane, its reader and the web.

The pane, the reader (`d`) and the browser all show exactly this, so none of
them can say something different about a row. Lines rather than one renderable
because the pane is navigated by a cursor; a record that is one block - a
scan's report, a heading - is one line of it.
"""

from __future__ import annotations

from rich.text import Text

from seek.gowitness import capture as gw_capture
from seek.nmap import timeline
from seek.nmap.runner import ScanRun
from seek.nmap.session import Session
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap import scans as scan_views
from seek.tui.nmap import views as vdefs


def record_lines(row: vdefs.Row | None, view_title: str, session: Session,
                 report_mode: str = "condensed", frozen: bool = False,
                 following: bool = True, full: bool = False
                 ) -> tuple[list[detail_pane.Line], str]:
    """The lines and a title for a row's record."""
    target = row.target if row is not None else None
    if isinstance(target, timeline.Scan):
        return ([detail_pane.Line(scan_views.scan_report(target, report_mode))],
                f"Scan · {target.label}")
    if isinstance(target, gw_capture.CaptureRun):
        # Checked before ScanRun and separately from it: a capture is a `Run`,
        # not a `ScanRun`, and the record renderer knows nothing about runs.
        return ([detail_pane.Line(
                    scan_views.report(target, report_mode, None, frozen, following,
                                      full))],
                f"Capture · {target.scope}")
    if isinstance(target, ScanRun):
        return ([detail_pane.Line(
                    scan_views.report(target, report_mode, session.diffs.get(id(target)),
                                      frozen, following, full))],
                f"Scan · {target.preset}")
    if row is not None and row.heading:
        return ([detail_pane.Line(Text(
                    f"{row.cells[0]}\n\n"
                    "Select a line under this heading to open what it counts.",
                    style="dim"))],
                row.cells[0])
    if target is None and row is not None:
        # Views without a drill target (statistics, groupings) still explain
        # the row rather than leaving the pane blank.
        return [detail_pane.Line(Text(row.text, style="dim"))], view_title
    title = f"{view_title} · {row.cells[0]}" if row is not None else view_title
    return (detail_pane.render(target, row.host if row else None, session.shots,
                               full=full, scanned=session.scanned(),
                               inventory=session.inventory_ready(),
                               lookup=session.lookup_ready()),
            title)
