"""Memory-management policy for the phases that keep the user waiting.

Reading an engagement builds millions of tracked container objects, and every
generational collection walks all of them. Measured on 120 files over 24 200
hosts: the work itself is seconds, but a single collection landing in the
middle of it stopped the interface for 1.6 s - which is what "sluggish" was.

Three tools, all of them CPython's, none of them clever:

- :func:`bulk` suspends cycle collection for the length of one phase.
- :func:`freeze` moves the built model into the permanent generation, so later
  collections stop walking it at all. Deferring collection only postpones the
  pause; freezing removes it.
- :func:`responsive` shortens the interval at which a working thread hands the
  interpreter back, so the event loop gets its turn between keystrokes rather
  than at the default 5 ms boundary.

**The policy lives at the callers, not in the domain functions.** `load`,
`merge`, `timeline.build` and the projections are pure, they are imported
directly by tests and by the export path, and a library call that turns the
host program's collector off is a surprise that outlives the call if anything
goes wrong. The caller knows it has started a long phase; the callee does not.
In this application that means exactly two owners - the reading worker and the
projection worker - and nowhere else.

Safe here for one reason worth stating: the model has no reference cycles
(Host → Service → ScriptResult, no back-references), so its objects are freed
by reference counting whether or not the collector ever looks at them. Nothing
below leaks memory; it only decides when the collector is allowed to walk.
"""

from __future__ import annotations

import gc
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager

# Handed back to the event loop this often while a background phase runs. Two
# hundredths of the default: measured at 5 ms, the median wait for a keystroke
# was the switch interval itself and nothing else.
SWITCH_INTERVAL = 0.001

_lock = threading.Lock()
_running = 0                                        # phases holding the interval
_restore = sys.getswitchinterval()


@contextmanager
def bulk() -> Iterator[None]:
    """Run a long phase with cycle collection suspended, and freeze on the way out.

    Restores the collector in `finally` and only if it was on to begin with:
    a phase that raises must leave collection exactly as it found it, and a
    caller that had disabled it for its own reasons must not find it enabled
    afterwards.

    The freeze is not an extra: suspending collection alone only *defers* the
    stall to the first allocation after the phase, when a generation holding
    everything the phase built is finally walked. Measured on the statistics
    projection over 24 200 hosts - worst event-loop pause 354 ms with the
    collector merely suspended and re-enabled, 4 ms with what survived frozen
    first, and the phase itself a fifth faster into the bargain. What is
    frozen is what the phase built and the caller is about to use; the rest
    was freed by reference counting as it went, because none of it is cyclic.
    """
    enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        gc.freeze()
        if enabled:
            gc.enable()


def freeze() -> None:
    """Move everything currently tracked into the permanent generation.

    Called once a model has been published, which is the only moment at which
    "everything now alive is long-lived" is true. From then on a collection
    walks what the run allocates next, not the twenty-four thousand hosts it
    is walking through.
    """
    gc.freeze()


def unfreeze() -> None:
    """Let the permanent generation be collected again.

    The other half of :func:`freeze`, and the reason the pair belongs to one
    place: a model that is being replaced must leave the permanent generation
    with it, or a re-read pins every superseded model in memory for the life
    of the run.
    """
    gc.unfreeze()


@contextmanager
def responsive() -> Iterator[None]:
    """Hand the interpreter back sooner while a background phase runs.

    A thread does not give parallelism for this work - it is pure Python and
    holds the interpreter - so what a worker owes the event loop is frequent
    turns. Counted rather than nested: several phases can run at once, and the
    interval is restored when the last of them finishes.
    """
    global _running, _restore
    with _lock:
        if _running == 0:
            _restore = sys.getswitchinterval()
            sys.setswitchinterval(SWITCH_INTERVAL)
        _running += 1
    try:
        yield
    finally:
        with _lock:
            _running -= 1
            if _running == 0:
                sys.setswitchinterval(_restore)


def frozen_count() -> int:
    """How many objects are in the permanent generation. For tests."""
    return gc.get_freeze_count()
