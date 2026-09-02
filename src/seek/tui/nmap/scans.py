"""The Scans tab: every scan present, as a history over time.

One list, one report pane - the same shape as every other tab. It holds two
kinds of entry, shown alike (a scan is a scan):

- a **scan file** on disk, whether this session ran it or not, placed in the
  history by its recorded start time and diffed against everything before it;
- a **live run** started here that has no file yet - still running, or failed
  before it could write one - carrying its streaming log.

A run that finishes becomes a file and rejoins the history there, so nothing is
listed twice. Each entry reads three ways (`o`): an overview, what it added
since the scan before it, and the raw output.
"""

from __future__ import annotations

from datetime import datetime

from rich.console import Group, RenderableType
from rich.text import Text

from seek.gowitness.capture import CaptureRun
from seek.nmap import timeline
from seek.nmap.diff import ScanDiff
from seek.nmap.runner import ScanRun, State
from seek.runner import Run
from seek.tui.nmap.views import Row

# (columns, default sort) for the Scans tab; the View is built by the app so its
# `build` can recompute live runs every refresh while the file history is cached.
SCANS_COLUMNS = ("Scan", "Scope", "State", "When", "Result")
SCANS_DEFAULT_SORT = (3, False)   # by time, oldest first: a history reads down

_STATE_GLYPH = {
    State.RUNNING: "●",
    State.DONE: "✓",
    State.FAILED: "✗",
    State.CANCELLED: "⊘",
}

# The report modes, in the order `o` cycles them.
MODES = ("condensed", "diff", "raw")
_MODE_LABEL = {
    "condensed": "overview",
    "diff": "what this scan added",
    "raw": "raw output",
}

_KEY = "dim"
_HEAD = "bold cyan"
# Live runs sort after every dated file: they are happening now.
_NOW = 10**12


def elapsed(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes:02d}:{secs:02d}"


def _when(start: int | None) -> str:
    if start is None:
        return "—"
    return datetime.fromtimestamp(start).strftime("%m-%d %H:%M")


def history_rows(history: list[timeline.Scan], live: list[Run]) -> list[Row]:
    """Rows for the file history plus any live run without a file yet.

    Pure and recomputed each refresh: `history` is cached by the caller (it
    re-parses), while `live` reflects the runners' current state each call.
    """
    out: list[Row] = []
    for scan in history:
        out.append(Row(
            cells=(f"✓ {scan.label}", _scope(scan), "done",
                   _when(scan.start), scan.result()),
            text=f"{scan.label} {scan.result()}",
            target=scan,
            sort_key=(scan.start or 0, scan.label, "done", "", scan.result()),
        ))
    for run in live:
        result = run.progress() if run.running else run.result
        out.append(Row(
            cells=(f"{_STATE_GLYPH[run.state]} {run.label}", run.scope,
                   str(run.state), elapsed(run.elapsed), result),
            text=f"{run.label} {run.scope} {run.state} {result}",
            target=run,
            sort_key=(_NOW, run.label, str(run.state), run.elapsed, result),
        ))
    return out


def _scope(scan: timeline.Scan) -> str:
    return f"{scan.host_count} host(s)"


# --- reports ----------------------------------------------------------------


def _mode_header(mode: str, trailer: str = "", note: str = "",
                 note_style: str = _KEY) -> Text:
    header = Text()
    header.append(_MODE_LABEL.get(mode, mode), style=_HEAD)
    if note:
        header.append(" · ", style=_KEY)
        header.append(note, style=note_style)
    if trailer:
        header.append(f"   {trailer}", style=_KEY)
    return header


def scan_report(scan: timeline.Scan, mode: str) -> RenderableType:
    """A file-backed scan in the history, read the way `mode` asks for."""
    header = _mode_header(mode, trailer=scan.label)
    if mode == "raw":
        text = timeline.raw_text(scan)
        return Group(header, Text(), *[Text(f"  {ln}") for ln in text.splitlines()])
    if mode == "diff":
        return Group(header, Text(), *_diff_lines(scan.added, baseline=scan.baseline))
    lines = [
        _pair("when", _when(scan.start)),
        _pair("hosts", scan.host_count, style="bold"),
        _pair("open ports", scan.open_ports),
    ]
    if scan.args:
        lines.append(_pair("command", scan.args))
    lines += [Text(), _pair("added", scan.result(), style="bold")]
    lines += _diff_highlights(scan.added)
    return Group(header, Text(), *lines)


def report(run: Run, mode: str, changes: ScanDiff | None,
           frozen: bool = False) -> RenderableType:
    """A live in-app run, read the way `mode` asks for."""
    if isinstance(run, CaptureRun):
        return capture_report(run, mode, frozen)
    note = ""
    style = _KEY
    if mode == "raw" and run.running:
        # A frozen log must never be mistaken for a paused scan.
        note = "frozen — the scan is still running" if frozen else "following"
        style = "bold bright_yellow" if frozen else _KEY
    header = _mode_header(mode, trailer=run.label, note=note, note_style=style)

    if mode == "raw":
        return Group(header, *_log_lines(run))
    if mode == "diff":
        return Group(header, Text(),
                     *_diff_lines(changes, running=run.running))
    return Group(header, Text(), *_condensed_lines(run, changes))


def capture_report(run: CaptureRun, mode: str, frozen: bool = False) -> RenderableType:
    """A capture, read three ways - the same three a scan reads.

    "diff" here is what this capture found rather than what changed about the
    network: a capture is a reading of one moment, and the useful comparison is
    between what answered and what did not.
    """
    note = ""
    style = _KEY
    if mode == "raw" and run.running:
        note = "frozen — the capture is still running" if frozen else "following"
        style = "bold bright_yellow" if frozen else _KEY
    # A capture's three modes are not a scan's: there is no "added since the
    # last scan" here, so the diff view is what did not answer instead.
    label = {"condensed": "overview", "diff": "what did not answer",
             "raw": "raw output"}.get(mode, mode)
    header = Text()
    header.append(label, style=_HEAD)
    if note:
        header.append(" · ", style=_KEY)
        header.append(note, style=style)
    header.append(f"   capture · {run.backend}", style=_KEY)
    if mode == "raw":
        return Group(header, *_log_lines(run))
    if mode == "diff":
        return Group(header, Text(), *_capture_failures(run))
    return Group(header, Text(), *_capture_overview(run))


def _capture_overview(run: CaptureRun) -> list[Text]:
    lines = [
        _pair("targets", str(run.total)),
        _pair("captured", str(run.captured)),
        _pair("failed", str(run.failed)),
        _pair("backend", run.backend or "—"),
        _pair("output", str(run.paths.root)),
    ]
    if run.running:
        lines.append(_pair("progress", run.progress()))
    return lines


def _capture_failures(run: CaptureRun) -> list[Text]:
    """What did not answer. gowitness records this nowhere on disk, so this is
    the only place it can be read."""
    if not run.failures:
        text = "nothing failed" if not run.running else "nothing has failed yet"
        return [Text(f"  {text}", style=_KEY)]
    out = [Text(f"  {len(run.failures)} target(s) could not be captured",
                style="bold")]
    for url, why in run.failures.items():
        line = Text("    ")
        line.append("✗ ", style="red")
        line.append(f"{url}  ")
        line.append(why, style=_KEY)
        out.append(line)
    return out


def _pair(label: str, value: str) -> Text:
    text = Text("  ")
    text.append(f"{label:<10}", style=_KEY)
    text.append(value)
    return text


def _log_lines(run: Run) -> list[Text]:
    lines: list[Text] = []
    if run.dropped:
        lines.append(Text(f"  … {run.dropped} earlier line(s) dropped", style=_KEY))
    if not run.log:
        lines.append(Text("  no output yet", style=_KEY))
    lines += [Text(f"  {line}") for line in run.log]
    return lines


def _pair(label: str, value: object, style: str = "") -> Text:
    text = Text()
    text.append(f"  {label:<11}", style=_KEY)
    text.append(str(value), style=style)
    return text


def _condensed_lines(run: ScanRun, changes: ScanDiff | None) -> list[Text]:
    lines = [
        _pair("state", run.state, style="bold"),
        _pair("scope", ", ".join(run.targets[:6])
              + (" …" if len(run.targets) > 6 else "")),
        _pair("elapsed", elapsed(run.elapsed)),
        _pair("command", run.command()),
    ]
    if run.state is State.DONE:
        lines.append(_pair("wrote", f"{run.out_base}.{{xml,nmap,gnmap}}"))
    if run.result:
        lines.append(_pair("result", run.result))
    if changes is not None:
        lines += [Text(), _pair("found", changes.summary(), style="bold")]
        lines += _diff_highlights(changes)
    return lines


def _diff_highlights(changes: ScanDiff) -> list[Text]:
    lines: list[Text] = []
    for host in changes.new_hosts[:8]:
        lines.append(Text(f"    + {host.address}   "
                          f"{len(host.open_services)} open port(s)"))
    if len(changes.new_hosts) > 8:
        lines.append(Text(f"    … {len(changes.new_hosts) - 8} more", style=_KEY))
    return lines


def _diff_lines(changes: ScanDiff | None, running: bool = False,
                baseline: bool = False) -> list[Text]:
    if baseline:
        return [Text("  baseline — the first scan, nothing earlier to compare",
                     style=_KEY)]
    if changes is None:
        state = "still running" if running else "no comparison for this scan"
        return [Text(f"  {state}", style=_KEY)]
    if changes.empty:
        return [Text("  nothing new — this scan confirmed what was already known",
                     style=_KEY)]
    lines: list[Text] = []
    for host in changes.new_hosts:
        line = Text("    + ", style="bold green")
        line.append(f"{host.address:<16}")
        line.append("new host   ", style=_KEY)
        line.append(f"{len(host.open_services)} open port(s)")
        lines.append(line)
    for port in changes.new_ports:
        line = Text("    + ", style="bold green")
        line.append(f"{port.address:<16}")
        line.append(f"{port.label:<10}")
        line.append("new port   ", style=_KEY)
        line.append(port.detail)
        lines.append(line)
    for change in changes.changed:
        line = Text("    ~ ", style="bold yellow")
        line.append(f"{change.address:<16}")
        line.append(f"{change.label:<10}")
        line.append(f"{change.before} → {change.after}")
        lines.append(line)
    return lines
