"""Running one external tool, and watching it.

A run is a process, its output, and what became of it. This module owns all
three and nothing else: no Textual, no screen, no model, and nothing that knows
which tool is being run. The caller supplies an argument vector and two
callbacks; every tool gets the same supervision.

Two rules the rest of the app depends on:

- **Never a shell.** `create_subprocess_exec` takes an argument vector. The
  command was already split and checked by whoever built it; nothing here
  re-joins it into a string.
- **Freezing is not pausing.** There is no pause here, by design: a scanner's
  timers run against the wall clock, so suspending the process can make hosts
  time out on resume and quietly corrupt the result. The viewer freezes its
  *view*; this module only ever runs or cancels.

**What is tool-specific lives on the `Run`, not here.** How to read progress out
of a line, how to summarise a success, and how to explain a failure differ per
tool and are overridden by subclasses (`nmap.runner.ScanRun`,
`gowitness.capture.CaptureRun`). Supervision - the process group, the bounded
log, SIGTERM then SIGKILL - is identical for every tool, and is the part that
must not drift between them.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

LOG_LIMIT = 20_000
# The longest output line read whole. asyncio's own default is 64 KiB, and one
# longer line (script output, `-d`) raised out of the read loop.
LINE_LIMIT = 16 * 1024 * 1024
"""Lines kept per run. `-p- -v` on a /24 produces far more than a screen's
worth, and an unbounded buffer in a long-lived TUI is a leak with a nice name."""

GRACE_SECONDS = 3.0
"""How long a cancelled run gets to end on `SIGTERM` before `SIGKILL`."""


class State(StrEnum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Run:
    """One run of one tool: what was asked for, what it said, what became of it.

    Subclass per tool to add where its output goes and how to read it. The
    fields here are the ones the runner and the run list need from every tool.
    """

    argv: list[str]
    state: State = State.RUNNING
    started: float = field(default_factory=time.monotonic)
    ended: float | None = None
    exit_code: int | None = None
    result: str = ""                     # the one-line outcome, for the run list
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LIMIT))
    dropped: int = 0                     # lines the bound pushed out
    # Where to say that it ended (ntfy-compatible; "" is off), and whether to
    # say it at 25/50/75 % too. `milestone` is the last percentage said.
    notify_url: str = ""
    notify_progress: bool = False
    milestone: int = 0
    # The log as the interface last drew it, per depth - kept on the run so it
    # dies with it (a cache keyed by `id(run)` can hand a new run a dead one's).
    rendered: dict = field(default_factory=dict, repr=False, compare=False)

    @property
    def running(self) -> bool:
        return self.state is State.RUNNING

    @property
    def elapsed(self) -> float:
        return (self.ended or time.monotonic()) - self.started

    @property
    def label(self) -> str:
        """What the run list calls this run - a preset name, or the tool."""
        return self.argv[0] if self.argv else "run"

    @property
    def scope(self) -> str:
        """What the run was over, in one phrase."""
        return ""

    def command(self) -> str:
        """The argv as one readable line - for the log header and the palette."""
        return " ".join(self.argv)

    def append(self, line: str) -> None:
        if len(self.log) == self.log.maxlen:
            self.dropped += 1
        self.log.append(line)
        self.read_progress(line)

    # --- what each tool answers differently ------------------------------

    def read_progress(self, line: str) -> None:
        """Pick progress out of one output line. Tools that print none say so
        by not overriding this."""

    def progress(self) -> str:
        """What to show in the run list while it is running."""
        return "running"

    def fraction(self) -> float | None:
        """How far along, 0..1, or `None` when the tool has not said."""
        return None

    @property
    def notify_name(self) -> str:
        """What a notification calls this run - a name the user chose, never
        anything about the targets."""
        return self.label

    def summarise(self) -> str:
        """The one-line result of a successful run."""
        return "finished"

    def failure(self, code: int, tail: list[str]) -> str:
        """The one-line result of a failed run. `tail` is its non-blank output."""
        return (tail[-1] if tail else f"exit {code}")[:120]


class Runner:
    """Supervises at most one run at a time.

    One at a time is a deliberate limit, not an implementation shortcut: two
    concurrent scans would compete for the same network path and make each
    other's timing data meaningless, quite apart from the output-file
    collisions. Tools that do not contend get their own `Runner` rather than
    sharing this one, which is what lets a capture run during a scan while
    neither tool can run twice.
    """

    def __init__(self) -> None:
        self.runs: list[Run] = []
        self._process: asyncio.subprocess.Process | None = None
        self._current: Run | None = None
        self._cancelling = False

    @property
    def current(self) -> Run | None:
        return self._current if self._current and self._current.running else None

    def busy(self) -> Run | None:
        return self.current

    def claim(self, run: Run) -> None:
        """Make `run` the current one *now*, before its task first runs.

        `run()` used to do this on its first step, one loop turn after the
        caller had checked `busy()` - two starts in one turn (a double click,
        the browser and the terminal together) both passed, both scans ran,
        and only the second could be cancelled.
        """
        self.runs.append(run)
        self._current = run
        self._cancelling = False

    async def run(self, run: Run, on_line: Callable[[str], None],
                  on_done: Callable[[Run], None],
                  on_start: Callable[[Run], None] | None = None) -> Run:
        """Start `run`, stream its output, and settle its state.

        `on_line` is called for each line as it arrives, `on_done` once, after
        the state is final, and `on_start` once the run is listed but before it
        has produced anything.

        `on_start` exists because "listed" and "has said something" are minutes
        apart for a tool that pulls a container image before it begins: without
        it the caller can only refresh its view when the first line arrives, and
        until then the run it just started is nowhere to be seen.
        """
        if self._current is not run:
            self.claim(run)
        if on_start is not None:
            on_start(run)
        try:
            process = await asyncio.create_subprocess_exec(
                *run.argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                # Its own process group, so cancelling reaches the children the
                # tool spawns rather than only the sudo or docker wrapper - but
                # the viewer's *session*: a new session has no terminal, and
                # sudo keeps its authorisation per terminal, so `sudo -n` never
                # saw one made here. stdin is closed because a background group
                # that reads the terminal is stopped (nmap reads keys from it).
                process_group=0,
                limit=LINE_LIMIT,
            )
        except FileNotFoundError:
            return self._settle(run, State.FAILED, None,
                                f"{run.argv[0]} not found", on_done)
        except OSError as exc:
            return self._settle(run, State.FAILED, None,
                                f"could not start: {exc.strerror or exc}", on_done)

        self._process = process
        assert process.stdout is not None
        while True:
            try:
                raw = await process.stdout.readline()
            except ValueError:
                # Longer than LINE_LIMIT. asyncio drops what it buffered of it
                # and raises; carrying on is what keeps the pipe drained - a
                # loop that died here left the tool blocked writing and the run
                # "running" for ever.
                note = f"[seek] a line longer than {LINE_LIMIT // 1024 // 1024} MiB was cut"
                run.append(note)
                on_line(note)
                continue
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\n")
            run.append(line)
            on_line(line)
        code = await process.wait()
        self._process = None
        return self._settle(run, *self._classify(run, code), on_done)

    def _classify(self, run: Run, code: int) -> tuple[State, int, str]:
        if self._cancelling:
            return State.CANCELLED, code, "cancelled — what it wrote so far is kept"
        if code == 0:
            return State.DONE, code, run.summarise()
        tail = [line for line in run.log if line.strip()]
        return State.FAILED, code, run.failure(code, tail)

    def _settle(self, run: Run, state: State, code: int | None, result: str,
                on_done: Callable[[Run], None]) -> Run:
        run.state = state
        run.ended = time.monotonic()
        run.exit_code = code
        run.result = result
        self._current = None
        on_done(run)
        return run

    def cancel(self) -> bool:
        """End the running process. `SIGKILL` follows if `SIGTERM` is ignored."""
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
        """Signal the whole group: a tool under sudo or docker is two processes."""
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(os.getpgid(process.pid), sig)
