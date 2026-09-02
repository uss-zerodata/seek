"""One nmap scan: what it writes, how it reports progress, how it fails.

The supervision - process group, streaming, cancellation, settling - is not
here: it is in `seek.runner`, shared with every other tool the app runs. What
*is* here is everything that is true of nmap and of nothing else:

- where the scan writes its files (`-oA`, so `.xml` beside `.nmap`);
- the progress lines nmap prints when asked, and only when asked;
- what a successful scan's one-line result says;
- how a refused `sudo -n` is recognised and explained.

`State`, `Runner`, `LOG_LIMIT` and `GRACE_SECONDS` are re-exported so that code
reading about a scan can keep importing them from here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from seek.runner import GRACE_SECONDS, LOG_LIMIT, Run, Runner, State

__all__ = ["GRACE_SECONDS", "LOG_LIMIT", "Runner", "ScanRun", "State",
           "elevation_help"]


# nmap prints these when asked (`--stats-every`), and at higher verbosity on its
# own. Parsed when they appear; never asked for behind the user's back.
_STATS = re.compile(r"About\s+([\d.]+)%\s+done", re.I)
_STATS_ALT = re.compile(r"(\d+)\s+hosts?\s+completed\s+\((\d+)\s+up\)", re.I)


@dataclass
class ScanRun(Run):
    """One scan: what was asked for, what it said, and what became of it."""

    preset: str = ""
    targets: list[str] = field(default_factory=list)
    out_base: Path = Path()
    elevated: bool = False
    percent: float | None = None
    hosts_up: int | None = None

    @property
    def label(self) -> str:
        return self.preset

    @property
    def scope(self) -> str:
        if len(self.targets) == 1:
            return self.targets[0]
        return f"{len(self.targets)} targets"

    @property
    def xml_path(self) -> Path:
        return self.out_base.with_suffix(".xml")

    def read_progress(self, line: str) -> None:
        match = _STATS.search(line)
        if match:
            self.percent = float(match.group(1))
        match = _STATS_ALT.search(line)
        if match:
            self.hosts_up = int(match.group(2))

    def progress(self) -> str:
        bits = []
        if self.percent is not None:
            bits.append(f"{self.percent:.0f}%")
        if self.hosts_up is not None:
            bits.append(f"{self.hosts_up} up")
        return " · ".join(bits) or "running"

    def summarise(self) -> str:
        for line in reversed(self.log):
            if "IP addresses" in line or "hosts up" in line:
                return line.strip()[:120]
        return "finished"

    def failure(self, code: int, tail: list[str]) -> str:
        if self.elevated and _elevation_refused(tail):
            return "sudo -n refused — no password was asked for"
        return super().failure(code, tail)


_REFUSAL = ("a password is required", "no tty present", "sudo: a terminal is required",
            "may not run", "not allowed")


def _elevation_refused(lines: list[str]) -> bool:
    lowered = " ".join(lines[-5:]).lower()
    return any(hint in lowered for hint in _REFUSAL)


def elevation_help(program: str = "nmap") -> str:
    """What to do when `sudo -n` is refused - said once, in one place."""
    return (
        "sudo -n never prompts, and sudo would have asked for a password. "
        f"Either run seek as root, warm the timestamp with `sudo -v` in another "
        f"terminal, or give {program} the capability it needs with setcap "
        "(cap_net_raw,cap_net_admin,cap_net_bind_service+eip) and run it unelevated."
    )
