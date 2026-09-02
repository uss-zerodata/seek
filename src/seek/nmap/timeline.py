"""The scans as a history, each diffed against everything before it.

Every nmap run leaves its own file, stamped with the moment it started. Read in
time order they are a history unfolding: the first establishes a baseline, and
each later one is worth reading as *what changed* since the last - a host that
appeared, a port that opened, a service that was finally identified.

That is exactly the diff the Scans tab already draws for a run started in the
app; this extends it to every scan file present, whether the app ran it or not.

Pure: files in, ordered entries out. Two things it must not do, and does not:

- **It re-parses each file** rather than trusting the retained per-file hosts.
  `merge` folds later scans *into* the earliest object that carries an address,
  so those retained lists are no longer "what that one scan saw". A pristine
  re-parse is the only honest basis for a per-scan diff. Parsing is ~11 ms/MB
  and this runs only when the Scans tab is opened.
- **It orders by the recorded start time**, not file order or filename, so an
  externally-run scan slots into the history where it actually happened.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path

from seek.nmap.diff import ScanDiff, diff
from seek.nmap.merge import _merge_host
from seek.nmap.models import Host, ScanFile
from seek.nmap.parse import NmapParseError, parse_file


@dataclass(slots=True)
class Scan:
    """One scan in the history: what it found, and what it added."""

    label: str
    path: Path | None
    start: int | None
    hosts: list[Host]
    added: ScanDiff
    baseline: bool = False          # the first scan - nothing to diff against
    args: str = ""
    run: object = None              # the in-app ScanRun, when this was run here

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def open_ports(self) -> int:
        return sum(len(h.open_services) for h in self.hosts)

    def result(self) -> str:
        """The one-line outcome for the run list."""
        if self.baseline:
            return f"baseline · {self.host_count} host(s)"
        return self.added.summary()


def _stem(path: Path) -> str:
    """A readable label from the filename, without seek's own prefix noise."""
    name = path.stem
    return name


def build(files: list[ScanFile]) -> list[Scan]:
    """The scan history, oldest first, each diffed against the merged prior.

    `files` supplies the paths, start times and command lines; the hosts are
    re-parsed here so the diff reflects what each scan alone recorded.
    """
    ordered = sorted(files, key=lambda f: (f.start is None, f.start or 0, f.name))
    reparsed: list[tuple[ScanFile, list[Host]]] = []
    for sf in ordered:
        try:
            reparsed.append((sf, parse_file(sf.path).hosts))
        except NmapParseError:
            continue                # unreadable now: leave it out rather than crash

    # An accumulator of *our own* Host objects, so merging one scan never
    # mutates another's pristine list. `before` is a deep snapshot taken ahead
    # of the merge - `merge` mutates in place, so a live reference would read
    # back as `after` and every diff would come up empty.
    out: list[Scan] = []
    acc: dict[str, Host] = {}
    for sf, hosts in reparsed:
        before = [copy.deepcopy(h) for h in acc.values()]
        for host in hosts:
            if not host.address:
                continue
            existing = acc.get(host.address)
            if existing is None:
                acc[host.address] = copy.deepcopy(host)
            else:
                _merge_host(existing, copy.deepcopy(host))
        after = list(acc.values())
        out.append(Scan(
            label=_stem(sf.path),
            path=sf.path,
            start=sf.start,
            hosts=hosts,
            added=diff(before, after),
            baseline=not before,
            args=sf.args,
        ))
    return out


# --- the raw view -----------------------------------------------------------


def raw_text(scan: Scan) -> str:
    """nmap's own text for a scan: the sibling .nmap if present, else built.

    `-oA` writes `.nmap` beside the `.xml`, and that is the real output; when it
    is missing (a lone `.xml`, or a scan handed over as XML only) the XML is the
    source of truth for everything else in the app, so a readable report is
    reconstructed from it rather than showing nothing.
    """
    if scan.path is not None:
        sibling = scan.path.with_suffix(".nmap")
        try:
            if sibling.exists():
                return sibling.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    return synthesize(scan)


def synthesize(scan: Scan) -> str:
    """A nmap-style report reconstructed from the parsed hosts."""
    lines: list[str] = []
    if scan.args:
        lines.append(f"# {scan.args}")
        lines.append("")
    for host in scan.hosts:
        name = f" ({host.hostname})" if host.hostname else ""
        lines.append(f"Nmap scan report for {host.address}{name}")
        state = host.state or "unknown"
        lines.append(f"Host is {state}"
                     + (f" ({host.reason})" if host.reason else ""))
        opens = host.open_services
        if opens:
            lines.append("PORT      STATE SERVICE        VERSION")
            for svc in opens:
                port = f"{svc.port}/{svc.protocol}"
                version = " ".join(x for x in (svc.product, svc.version) if x)
                lines.append(f"{port:<9} {svc.state or 'open':<5} "
                             f"{(svc.name or ''):<14} {version}".rstrip())
        else:
            lines.append("No open ports recorded")
        lines.append("")
    if not scan.hosts:
        lines.append("No hosts recorded in this scan.")
    return "\n".join(lines).rstrip() + "\n"
