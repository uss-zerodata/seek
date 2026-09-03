"""The scans as a history, each diffed against everything before it.

Every nmap run leaves its own file, stamped with the moment it started. Read in
time order they are a history unfolding: the first establishes a baseline, and
each later one is worth reading as *what changed* since the last - a host that
appeared, a port that opened, a service that was finally identified.

That is exactly the diff the Scans tab already draws for a run started in the
app; this extends it to every scan file present, whether the app ran it or not.

Pure: files in, ordered entries out. Three things it must get right:

- **The per-scan hosts are the parsed ones**, which is honest because `merge`
  builds the consolidated model out of copies - a scan's own record is never
  written into by a later one. This used to re-parse every file to be sure of
  that, which meant reading the whole engagement from disk a second time.
- **It compares against a snapshot, not a copy of the model.** Only the hosts
  a scan mentions can differ after it is folded in, so each scan is diffed
  against what was known about *those* hosts. Snapshotting the entire
  accumulated model per scan was quadratic - 50 s on a dozen large files, all
  of it in `deepcopy`.
- **It orders by the recorded start time**, not file order or filename, so an
  externally-run scan slots into the history where it actually happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from seek.nmap.diff import ScanDiff, diff_from, snapshot
from seek.nmap.merge import _merge_host
from seek.nmap.models import Host, ScanFile
from seek.nmap.progress import SCANS, Report


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


def build(files: list[ScanFile], report: Report | None = None) -> list[Scan]:
    """The scan history, oldest first, each diffed against the merged prior.

    `report` is called with the scans folded in, out of the scans there are,
    as each one goes in - the shared shape, so the same renderer draws this as
    draws a read or a projection. The work is one pass over the files and
    cannot be resumed, so it reports rather than yields.
    """
    ordered = sorted(files, key=lambda f: (f.start is None, f.start or 0, f.name))
    out: list[Scan] = []
    # Our own copies, so folding one scan in never writes into another's
    # records. The accumulator is the merged state as of this point in the
    # history - which is what each new scan has to be compared against.
    acc: dict[str, Host] = {}
    seen: dict[str, int] = {}                       # address -> when it first appeared
    for done, sf in enumerate(ordered, start=1):
        scanned = list(dict.fromkeys(h.address for h in sf.hosts if h.address))
        baseline = not acc
        # Taken before the merge, and only for the hosts this scan mentions:
        # every other host is in both states unchanged and cannot contribute.
        before = snapshot(acc[address] for address in scanned if address in acc)
        for host in sf.hosts:
            if not host.address:
                continue
            existing = acc.get(host.address)
            if existing is None:
                seen[host.address] = len(acc)
                acc[host.address] = host.copy()
            else:
                _merge_host(existing, host)
        # Read back in the order the model holds them - first seen, first
        # listed - so what a scan added reads down the page the way the host
        # list does, rather than in whatever order one file happened to use.
        scanned.sort(key=seen.__getitem__)
        out.append(Scan(
            label=_stem(sf.path),
            path=sf.path,
            start=sf.start,
            hosts=sf.hosts,
            added=diff_from(before, [acc[address] for address in scanned]),
            baseline=baseline,
            args=sf.args,
        ))
        if report is not None:
            report(done, len(ordered), SCANS)
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
