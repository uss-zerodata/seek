"""The Scans tab: the runs of this session, and what each one said.

The run list is a `View` like any other - same table, same sorting, same report
pane below - so nothing here invents a layout. What is new is the report: a run
is read three ways, and which way is named in the pane's first line.
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.text import Text

from seek.nmap.diff import ScanDiff
from seek.nmap.runner import ScanRun, State
from seek.tui.nmap.views import Row, View

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
    "diff": "what this run added",
    "raw": "raw output",
}

_KEY = "dim"
_HEAD = "bold cyan"


def elapsed(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes:02d}:{secs:02d}"


def scans_view(runs: list[ScanRun], diffs: dict[int, ScanDiff]) -> View:
    """The runs of this session, newest last, as a table like any other."""

    def build(_scans) -> list[Row]:
        out = []
        for index, run in enumerate(runs):
            result = run.progress() if run.running else run.result
            summary = diffs.get(id(run))
            if summary is not None and run.state is State.DONE:
                result = summary.summary()
            out.append(Row(
                cells=(f"{_STATE_GLYPH[run.state]} {run.preset}", run.scope,
                       str(run.state), elapsed(run.elapsed), result),
                text=f"{run.preset} {run.scope} {run.state} {result}",
                target=run,
                sort_key=(index, run.scope, str(run.state), run.elapsed, result),
            ))
        return out

    return View(
        title="Scans",
        columns=("Scan", "Scope", "State", "Elapsed", "Result"),
        build=build, kind="scans", tab="scans",
    )


def report(run: ScanRun, mode: str, changes: ScanDiff | None,
           frozen: bool = False) -> RenderableType:
    """One run, read the way `mode` asks for. The mode is always named."""
    header = Text()
    header.append(_MODE_LABEL.get(mode, mode), style=_HEAD)
    if mode == "raw" and run.running:
        # The one thing a frozen log must never be mistaken for is a paused
        # scan, so the header says which of the two this is, in words.
        header.append(" · ", style=_KEY)
        header.append("frozen — the scan is still running" if frozen else "following",
                      style="bold bright_yellow" if frozen else _KEY)
    header.append(f"   {run.preset}", style=_KEY)

    if mode == "raw":
        return Group(header, *_log_lines(run))
    if mode == "diff":
        return Group(header, Text(), *_diff_lines(run, changes))
    return Group(header, Text(), *_condensed_lines(run, changes))


def _log_lines(run: ScanRun) -> list[Text]:
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
        for host in changes.new_hosts[:8]:
            lines.append(Text(f"    + {host.address}   "
                              f"{len(host.open_services)} open port(s)"))
        if len(changes.new_hosts) > 8:
            lines.append(Text(f"    … {len(changes.new_hosts) - 8} more",
                              style=_KEY))
    return lines


def _diff_lines(run: ScanRun, changes: ScanDiff | None) -> list[Text]:
    if changes is None:
        state = "still running" if run.running else "no comparison for this run"
        return [Text(f"  {state}", style=_KEY)]
    if changes.empty:
        return [Text("  nothing new — this run confirmed what was already known",
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
