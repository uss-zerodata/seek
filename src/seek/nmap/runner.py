"""Running one scan, and watching it.

A run is a process, its output, and what became of it. This module owns all
three and nothing else: no Textual, no screen, no model. The viewer supplies an
argument vector and two callbacks; a future feature that runs a different tool
supplies the same and gets the same supervision.

Two rules the rest of the app depends on:

- **Never a shell.** `create_subprocess_exec` takes an argument vector. The
  command the user edited was already split and checked by `presets`; nothing
  here re-joins it into a string.
- **Freezing is not pausing.** There is no pause here, by design: nmap's timers
  run against the wall clock, so suspending the process can make hosts time out
  on resume and quietly corrupt the result. The viewer freezes its *view*; this
  module only ever runs or cancels.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import signal
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

LOG_LIMIT = 20_000
"""Lines kept per run. `-p- -v` on a /24 produces far more than a screen's
worth, and an unbounded buffer in a long-lived TUI is a leak with a nice name."""

GRACE_SECONDS = 3.0
"""How long a cancelled scan gets to end on `SIGTERM` before `SIGKILL`."""


class State(StrEnum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


# nmap prints these when asked (`--stats-every`), and at higher verbosity on its
# own. Parsed when they appear; never asked for behind the user's back.
_STATS = re.compile(r"About\s+([\d.]+)%\s+done", re.I)
_STATS_ALT = re.compile(r"(\d+)\s+hosts?\s+completed\s+\((\d+)\s+up\)", re.I)


@dataclass(slots=True)
class ScanRun:
    """One scan: what was asked for, what it said, and what became of it."""

    preset: str
    argv: list[str]
    targets: list[str]
    out_base: Path
    elevated: bool = False
    state: State = State.RUNNING
    started: float = field(default_factory=time.monotonic)
    ended: float | None = None
    exit_code: int | None = None
    result: str = ""                     # the one-line outcome, for the run list
    percent: float | None = None
    hosts_up: int | None = None
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LIMIT))
    dropped: int = 0                     # lines the bound pushed out

    @property
    def running(self) -> bool:
        return self.state is State.RUNNING

    @property
    def elapsed(self) -> float:
        return (self.ended or time.monotonic()) - self.started

    @property
    def scope(self) -> str:
        if len(self.targets) == 1:
            return self.targets[0]
        return f"{len(self.targets)} targets"

    @property
    def xml_path(self) -> Path:
        return self.out_base.with_suffix(".xml")

    def command(self) -> str:
        """The argv as one readable line - for the log header and the palette."""
        return " ".join(self.argv)

    def append(self, line: str) -> None:
        if len(self.log) == self.log.maxlen:
            self.dropped += 1
        self.log.append(line)
        self._read_progress(line)

    def _read_progress(self, line: str) -> None:
        match = _STATS.search(line)
        if match:
            self.percent = float(match.group(1))
        match = _STATS_ALT.search(line)
        if match:
            self.hosts_up = int(match.group(2))

    def progress(self) -> str:
        """What to show in the run list while it is running."""
        bits = []
        if self.percent is not None:
            bits.append(f"{self.percent:.0f}%")
        if self.hosts_up is not None:
            bits.append(f"{self.hosts_up} up")
        return " · ".join(bits) or "running"


class Runner:
    """Supervises at most one scan at a time.

    One at a time is a deliberate limit, not an implementation shortcut: two
    concurrent scans would compete for the same network path and make each
    other's timing data meaningless, quite apart from the output-file
    collisions.
    """

    def __init__(self) -> None:
        self.runs: list[ScanRun] = []
        self._process: asyncio.subprocess.Process | None = None
        self._current: ScanRun | None = None
        self._cancelling = False

    @property
    def current(self) -> ScanRun | None:
        return self._current if self._current and self._current.running else None

    def busy(self) -> ScanRun | None:
        return self.current

    async def run(self, run: ScanRun, on_line: Callable[[str], None],
                  on_done: Callable[[ScanRun], None]) -> ScanRun:
        """Start `run`, stream its output, and settle its state.

        `on_line` is called for each line as it arrives, `on_done` once, after
        the state is final.
        """
        self.runs.append(run)
        self._current = run
        self._cancelling = False
        try:
            process = await asyncio.create_subprocess_exec(
                *run.argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                # Its own process group, so cancelling reaches the children
                # nmap spawns rather than only the sudo wrapper.
                start_new_session=True,
            )
        except FileNotFoundError:
            return self._settle(run, State.FAILED, None,
                                f"{run.argv[0]} not found", on_done)
        except OSError as exc:
            return self._settle(run, State.FAILED, None,
                                f"could not start: {exc.strerror or exc}", on_done)

        self._process = process
        assert process.stdout is not None
        async for raw in process.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            run.append(line)
            on_line(line)
        code = await process.wait()
        self._process = None
        return self._settle(run, *self._classify(run, code), on_done)

    def _classify(self, run: ScanRun, code: int) -> tuple[State, int, str]:
        if self._cancelling:
            return State.CANCELLED, code, "cancelled — no file was written"
        if code == 0:
            return State.DONE, code, self._summarise(run)
        tail = [line for line in run.log if line.strip()]
        last = tail[-1] if tail else f"exit {code}"
        if run.elevated and _elevation_refused(tail):
            return State.FAILED, code, "sudo -n refused — no password was asked for"
        return State.FAILED, code, last[:120]

    @staticmethod
    def _summarise(run: ScanRun) -> str:
        for line in reversed(run.log):
            if "IP addresses" in line or "hosts up" in line:
                return line.strip()[:120]
        return "finished"

    def _settle(self, run: ScanRun, state: State, code: int | None, result: str,
                on_done: Callable[[ScanRun], None]) -> ScanRun:
        run.state = state
        run.ended = time.monotonic()
        run.exit_code = code
        run.result = result
        self._current = None
        on_done(run)
        return run

    def cancel(self) -> bool:
        """End the running scan. `SIGKILL` follows if `SIGTERM` is ignored."""
        process = self._process
        run = self._current
        if process is None or run is None or not run.running:
            return False
        self._cancelling = True
        run.append("")
        run.append("[seek] cancelling — sending SIGTERM")
        self._signal(process, signal.SIGTERM)
        try:
            asyncio.get_event_loop().call_later(GRACE_SECONDS, self._kill, process)
        except RuntimeError:
            # The loop is already closing - this is the app shutting down, and
            # SIGTERM has been delivered either way.
            self._kill(process)
        return True

    def _kill(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is None:
            self._signal(process, signal.SIGKILL)

    @staticmethod
    def _signal(process: asyncio.subprocess.Process, sig: signal.Signals) -> None:
        """Signal the whole group: nmap under sudo is two processes."""
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(os.getpgid(process.pid), sig)


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
