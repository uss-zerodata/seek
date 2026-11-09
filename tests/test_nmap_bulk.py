"""The collector policy: it has to be exactly as reversible as it claims.

Suspending collection and pinning a model in the permanent generation are both
process-wide, so the only thing that makes them safe is that they are undone -
including when the phase they were taken out for blows up. That is what these
cover; the speed they buy is measured in `benchmarks/bench_nmap.py`, not here.
"""

from __future__ import annotations

import gc
import sys

import pytest

from seek.nmap import bulk
from seek.nmap.models import Host, ScanSet, Service
from seek.tui.nmap.app import NmapApp


def _model(hosts: int = 4000) -> ScanSet:
    """A model big enough that pinning one would be visible in the count."""
    return ScanSet(
        hosts=[Host(address=f"10.0.{i // 254}.{i % 254}",
                    services=[Service(protocol="tcp", port=80, state="open"),
                              Service(protocol="tcp", port=443, state="open")])
               for i in range(hosts)],
        sources=["one.xml"],
    )


def test_a_phase_that_raises_leaves_collection_as_it_found_it():
    """`finally`, not a happy path: a leaked policy outlives the run."""
    assert gc.isenabled(), "the suite runs with the collector on"
    with pytest.raises(RuntimeError):
        with bulk.bulk():
            assert not gc.isenabled(), "suspended for the length of the phase"
            raise RuntimeError("the phase failed")
    assert gc.isenabled(), "and restored on the way out"


def test_bulk_does_not_enable_a_collector_it_found_disabled():
    """Restoring the previous state, not asserting a preferred one."""
    gc.disable()
    try:
        with bulk.bulk():
            pass
        assert not gc.isenabled()
    finally:
        gc.enable()


def test_the_switch_interval_is_restored_by_the_last_phase_to_finish():
    """Counted, not nested: two phases can be running at once."""
    before = sys.getswitchinterval()
    with bulk.responsive():
        assert sys.getswitchinterval() == bulk.SWITCH_INTERVAL
        with bulk.responsive():
            assert sys.getswitchinterval() == bulk.SWITCH_INTERVAL
        assert sys.getswitchinterval() == bulk.SWITCH_INTERVAL, \
            "the inner phase finishing does not free the outer one"
    assert sys.getswitchinterval() == before


def test_the_switch_interval_is_restored_when_a_phase_raises():
    before = sys.getswitchinterval()
    with pytest.raises(RuntimeError):
        with bulk.responsive():
            raise RuntimeError("the phase failed")
    assert sys.getswitchinterval() == before


def test_a_re_read_does_not_leave_the_superseded_model_pinned():
    """The permanent generation must not grow by a model per re-read.

    The two models are the same size, so the frozen count after the second
    publication has to be no higher than after the first. Two things together
    are what make that true, and this fails if either stops holding: the
    publication unfreezes before it replaces, and the model has no reference
    cycles - so the superseded one is freed by reference counting the moment
    the viewer drops it, whether or not the collector ever looks at it. A
    back-reference added to `Host` or `Service` would break the second half
    and pin every model the run ever built, which is what this is here to
    catch.
    """
    app = NmapApp(_model())
    try:
        gc.collect()
        after_first = gc.get_freeze_count()
        app._publish(_model())
        gc.collect()
        after_second = gc.get_freeze_count()
        # A little slack for what the publication itself allocates; the failure
        # this guards against is a whole model, three orders of magnitude up.
        assert after_second <= after_first + 500, (
            f"{after_second - after_first} objects more frozen after a re-read")
    finally:
        bulk.unfreeze()
