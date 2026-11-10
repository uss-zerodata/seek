"""One nmap scan: what it writes, how it reports progress, how it fails.

The supervision - process group, streaming, cancellation, settling - is not
here: it is in `seek.runner`, shared with every other tool the app runs. What
*is* here is everything that is true of nmap and of nothing else:

- where the scan writes its files (`-oA`, so `.xml` beside `.nmap`);
- how far the whole scan is, from the lines nmap prints at `-v` (its
  `--stats-every` lines never come: nmap prints them only for an interactive
  terminal, and seek runs it with stdin closed);
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

from seek.nmap import options as options_mod
from seek.runner import GRACE_SECONDS, LOG_LIMIT, Run, Runner, State

__all__ = ["GRACE_SECONDS", "LOG_LIMIT", "Runner", "ScanRun", "State",
           "elevation_help", "sudo_ready"]


# What nmap prints at -v, as 7.94 prints it under seek (stdin closed):
#   Initiating Connect Scan at 08:18
#   Scanning 3 hosts [2 ports/host]          (or "Scanning <host> [2 ports]")
#   Connect Scan Timing: About 45.00% done; ETC: 08:30 (0:10:00 remaining)
#   Nmap scan report for 10.0.0.5 [host down]
_PHASE = re.compile(r"^Initiating (.+?)(?:\.? at \d\d?:\d\d| against |$)")
_GROUP = re.compile(r"^Scanning (?:(\d+) hosts|\S+(?: \([^)]*\))?) \[\d+ ports?")
_PERCENT = re.compile(r"About\s+([\d.]+)%\s+done", re.I)
_REPORT = "Nmap scan report for "
_VERBOSE = re.compile(r"^-[vd]+\d*$")
_COUNTED = re.compile(r"Nmap done: (\d+) IP address")


def count_argv(argv: list[str], programs: set[str]) -> list[str] | None:
    """`nmap -sL -n` over the scan's own target options - nmap's count of what
    the scan covers, with no packet sent. `None` when it cannot be counted:
    random targets (`-iR`), no target, or a program that is not nmap."""
    i = 0
    if argv and Path(argv[0]).name == "sudo":
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            i += 1
    if i >= len(argv) or argv[i] not in programs:
        return None
    groups, targets = options_mod.split(argv[i + 1:])
    keep: list[str] = []
    for group in groups:
        head = group[0].split("=", 1)[0]
        if head.startswith("-iR"):
            return None
        if head.startswith("-iL") or head in ("--exclude", "--excludefile", "-6"):
            keep += group
    if not targets and not any(g.startswith("-iL") for g in keep):
        return None
    return [argv[i], "-sL", "-n", *keep, *targets]


def counted(last_line: str) -> int | None:
    match = _COUNTED.search(last_line)
    return int(match.group(1)) or None if match else None


def _left(seconds: float) -> str:
    minutes = int(seconds // 60)
    if minutes >= 60:
        return f"{minutes // 60}h {minutes % 60:02d}m"
    return f"{minutes}m" if minutes else f"{max(int(seconds), 1)}s"


@dataclass
class ScanRun(Run):
    """One scan: what was asked for, what it said, and what became of it."""

    preset: str = ""
    targets: list[str] = field(default_factory=list)
    out_base: Path = Path()
    elevated: bool = False
    # How far the whole scan is (see `fraction`). `total` is nmap's own count
    # of the targets, set once `nmap -sL` has answered.
    total: int | None = None
    finished: int = 0                   # report lines: hosts done, up or down
    reported_up: int = 0
    phase: str = ""
    percent: float | None = None        # the current phase, current group
    group: int = 0                      # up hosts of the group not yet reported
    best: float = 0.0                   # the figure never goes back

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

    @property
    def verbose(self) -> bool:
        """Only at -v does nmap report the hosts it found down - without them
        a count of hosts finished stalls on any sparse network."""
        return any(_VERBOSE.match(token) for token in self.argv)

    def read_progress(self, line: str) -> None:
        if line.startswith(_REPORT):
            self.finished += 1
            if "[host down]" not in line:
                self.reported_up += 1
                self.group = max(self.group - 1, 0)
            return
        if match := _PHASE.match(line):
            self.phase, self.percent = match.group(1), None
        elif match := _GROUP.match(line):
            # Host discovery runs ahead in batches of its own; the hosts it
            # finds down are counted as they are reported.
            if "Ping" not in self.phase:
                self.group = int(match.group(1) or 1)
        elif match := _PERCENT.search(line):
            self.percent = float(match.group(1))

    def fraction(self) -> float | None:
        """Of the whole scan: hosts finished plus the group under way, over the
        total. Never back, never 100 % before nmap ends; `None` without -v
        (down hosts go unreported) or without a total."""
        if not self.verbose or not self.total:
            return None
        if self.state is not State.RUNNING:
            return 1.0 if self.state is State.DONE else self.best
        part = self.group * (self.percent or 0) / 100
        self.best = max(self.best, min((self.finished + part) / self.total, 0.99))
        return self.best

    def progress(self) -> str:
        phase = (f"{self.phase.lower()} {self.percent:.0f}%"
                 if self.phase and self.percent is not None else self.phase.lower())
        whole = self.fraction()
        if whole is not None:
            bits = [f"≈ {whole * 100:.0f}%", f"{self.finished}/{self.total} hosts"]
            if whole >= 0.02 and self.running:
                bits.append(f"≈ {_left(self.elapsed * (1 - whole) / whole)} left")
        elif not self.verbose:
            bits = [f"{self.reported_up} up hosts reported", "-v gives progress"]
        else:
            bits = [f"{self.finished} hosts"]
        if phase:
            bits.insert(1 if whole is not None else 0, phase)
        return " · ".join(bits) if self.finished or phase or whole else "running"

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
