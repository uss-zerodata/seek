"""How far an update is, in one line: which step of how many, a bar, what it
is doing, and how long it will take.

Each source reports `(source, done, total, activity)`: `done`/`total` measure
its *whole* job - for a download-and-index step the bytes downloaded plus the
bytes of the archive read back while indexing - so one bar covers the step
from start to finish instead of filling twice or sitting at zero while it
indexes. The time left is the step's own rate so far, projected over what is
left of it.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable

BAR_WIDTH = 20
_FULL, _EMPTY = "█", "░"


def bar(fraction: float, width: int = BAR_WIDTH) -> str:
    filled = max(0, min(width, round(fraction * width)))
    return _FULL * filled + _EMPTY * (width - filled)


def duration(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds:02d} s" if minutes < 10 else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min"


def megabytes(n: int) -> str:
    """A size as people read one: kB below a megabyte, MB above."""
    return f"{n / 1e6:.1f} MB" if n >= 1_000_000 else f"{n / 1e3:.0f} kB"


class Tracker:
    """Collects progress reports; `line()` says where the update is."""

    def __init__(self, sources: Iterable[str], clock: Callable[[], float] = time.monotonic):
        self.sources = list(sources)
        self.clock = clock
        self.source = ""
        self.done = 0
        self.total = 0
        self.activity = ""
        self._step_started = clock()
        self.started = self._step_started

    def __call__(self, source: str, done: int, total: int, activity: str) -> None:
        if source != self.source:
            self.source = source
            self._step_started = self.clock()
        self.done, self.total, self.activity = done, total, activity

    @property
    def fraction(self) -> float | None:
        return min(1.0, self.done / self.total) if self.total else None

    def remaining(self) -> float | None:
        """Seconds left in this step, once there is enough to project from."""
        fraction = self.fraction
        elapsed = self.clock() - self._step_started
        if fraction is None or fraction < 0.01 or fraction >= 1 or elapsed < 2:
            return None
        return elapsed * (1 - fraction) / fraction

    def line(self) -> str:
        if not self.source:
            return "starting"
        step = (f"{self.sources.index(self.source) + 1}/{len(self.sources)} "
                if self.source in self.sources else "")
        head = f"{step}{self.source}"
        fraction = self.fraction
        if fraction is None:
            return f"{head} · {self.activity}"
        left = self.remaining()
        tail = f" · ~{duration(left)} left" if left is not None else ""
        return f"{head} {bar(fraction)} {fraction * 100:3.0f}% · {self.activity}{tail}"

    def short(self) -> str:
        """For a status line that shares its row: step, bar, percent, time left."""
        if not self.source:
            return "starting"
        step = (f"{self.sources.index(self.source) + 1}/{len(self.sources)} "
                if self.source in self.sources else "")
        fraction = self.fraction
        if fraction is None:
            return f"{step}{self.source}"
        left = self.remaining()
        tail = f" ~{duration(left)}" if left is not None else ""
        return f"{step}{self.source} {bar(fraction, 10)} {fraction * 100:.0f}%{tail}"

    def elapsed(self) -> str:
        return duration(self.clock() - self.started)
