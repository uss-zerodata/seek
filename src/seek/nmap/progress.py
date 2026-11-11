"""One shape for every step that keeps the user waiting.

Reading files, folding them together, building the scan history and projecting
an overview are four different jobs with one thing in common: each of them can
say how far it has got, and the interface has to be able to draw any of them
without knowing which it is drawing. So they all report the same three things -
how much is done, how much there is, and what is being counted.

The unit travels with the numbers because a bare `3/12` is not a report: the
spec asks a determinate bar to name what it counts, and carrying the word here
is what lets one renderer serve every step without a table mapping producers to
nouns.

A total of zero means "this cannot count itself yet". That is the honest state
of a directory walk, which knows how many scans it has found but not how many
it will find; the interface shows such a step as running rather than as a bar
pinned at nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from typing import TypeVar

# (work done, work in total, the unit those two count). Called from whatever
# thread owns the work, so a receiver that touches the interface has to hop.
Report = Callable[[int, int, str], None]

FILES = "files"
SCANS = "scans"
HOSTS = "hosts"
TAGS = "tags"

# Reported once per this many items. Small enough that a bar moves visibly on
# a projection that takes a second, large enough that a slow receiver cannot
# come to dominate a loop that is otherwise a few microseconds an item.
EVERY = 256

T = TypeVar("T")


def counted(items: Iterable[T], report: Report | None, unit: str = HOSTS,
            every: int = EVERY) -> Iterator[T]:
    """Yield from `items`, reporting progress against their number.

    Wrapping the loop rather than counting inside it keeps the reporting out
    of the projections themselves - they stay a `for host in ...` over the
    model - and guarantees the two properties the interface relies on: the
    figure only ever grows, and the last report is always `done == total`, so
    a bar cannot be left at 98% by a loop that ended early.

    `items` has to have a length: a step that cannot say how many there are
    should report a zero total itself rather than pretend.
    """
    if report is None:
        yield from items
        return
    total = len(items)                              # type: ignore[arg-type]
    report(0, total, unit)
    done = 0
    for item in items:
        yield item
        done += 1
        if done % every == 0:
            report(done, total, unit)
    report(total, total, unit)
