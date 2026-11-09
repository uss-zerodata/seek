"""One nmap scan: what it writes, how it reports progress, how it fails.

The supervision - process group, streaming, cancellation, settling - is not
here: it is in `seek.runner`, shared with every other tool the app runs. What
*is* here is everything that is true of nmap and of nothing else:

- where the scan writes its files (`-oA`, so `.xml` beside `.nmap`);
- the progress lines nmap prints when asked, and only when asked;
- what a successful scan's one-line result says;
- whether sudo would run a scan without asking, and how a refused `sudo -n`
  is recognised and explained.

`State`, `Runner`, `LOG_LIMIT` and `GRACE_SECONDS` are re-exported so that code
reading about a scan can keep importing them from here.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from seek.runner import GRACE_SECONDS, LOG_LIMIT, Run, Runner, State

__all__ = ["GRACE_SECONDS", "LOG_LIMIT", "Runner", "ScanRun", "State",
           "elevation_help", "sudo_ready"]


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

    def fraction(self) -> float | None:
        return None if self.percent is None else self.percent / 100

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
            "you must have a tty", "may not run", "not allowed")


def _elevation_refused(lines: list[str]) -> bool:
    lowered = " ".join(lines[-5:]).lower()
    return any(hint in lowered for hint in _REFUSAL)


def elevation_help(program: str = "nmap", terminal: bool = False) -> str:
    """What to do when sudo would ask for a password where nothing can ask -
    said once, in one place.

    Not "run `sudo -v` in another terminal": sudo keeps its authorisation per
    terminal by default, so one made elsewhere never applies here.
    """
    path = shutil.which(program) or program
    first = ("sudo did not authorise this scan. "
             if terminal else
             "sudo wants a password and this scan cannot ask for one. Start it from "
             "the terminal viewer, which lets sudo ask; ")
    return (
        f"{first}{'Run' if terminal else 'or run'} seek as root; or let nmap open raw "
        f"sockets itself - `sudo setcap cap_net_raw,cap_net_admin,"
        f"cap_net_bind_service+eip {path}` - and seek runs it with --privileged, "
        "without sudo."
    )


async def sudo_ready(argv: list[str]) -> str | None:
    """`None` when sudo would run this elevated argv's program without asking;
    otherwise sudo's own reason.

    Asked by running `sudo -n <program> --version`: a harmless run of the very
    program, which answers exactly "would sudo run it now". `sudo -n -l` does
    not - with a password rule and any unrelated NOPASSWD rule, it says yes and
    the scan is then refused. Asked in the viewer's session, like the scan
    itself, so an authorisation made in this terminal counts.
    """
    command = argv[2:] if argv[:2] == ["sudo", "-n"] else argv
    try:
        process = await asyncio.create_subprocess_exec(
            "sudo", "-n", command[0], "--version", stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            process_group=0)
    except FileNotFoundError:
        return "sudo is not installed"
    except OSError as exc:
        return f"sudo could not be run: {exc.strerror or exc}"
    _out, err = await process.communicate()
    if process.returncode == 0:
        return None
    lines = err.decode("utf-8", "replace").strip().splitlines()
    return lines[-1] if lines else f"sudo -n {command[0]} exited {process.returncode}"
