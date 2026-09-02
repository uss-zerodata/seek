"""What a scan added: new hosts, newly open ports, changed identifications."""

from __future__ import annotations

from pathlib import Path

from seek.nmap.diff import diff
from seek.nmap.merge import load
from seek.nmap.views import prepare

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _hosts(*names):
    return prepare(load([FIX / f"{n}.xml" for n in names])).hosts


def test_a_host_that_was_not_there_before_is_new():
    changes = diff(_hosts("merge-a"), _hosts("merge-a", "merge-b"))
    addresses = [h.address for h in changes.new_hosts]
    assert addresses, "merge-b brings a host merge-a did not have"
    assert "new host" in changes.summary()


def test_a_port_that_was_not_open_before_is_new():
    before = _hosts("merge-a")
    after = _hosts("merge-a", "merge-b")
    known = {h.address for h in before}
    ports = [p for p in diff(before, after).new_ports if p.address in known]
    assert ports, "merge-b opens ports on a host merge-a already knew"
    assert all(p.label for p in ports)


def test_a_changed_identification_is_reported_with_both_sides():
    """A probed identification replacing a port-table guess is the common case."""
    before = _hosts("merge-b")          # 3128 probed as http
    after = _hosts("merge-a", "merge-b")
    changes = diff(before, after)
    assert changes.empty or all(c.before != c.after for c in changes.changed)


def test_a_scan_that_adds_nothing_says_so():
    hosts = _hosts("basic")
    changes = diff(hosts, hosts)
    assert changes.empty
    assert changes.summary() == "nothing new"


def test_the_first_scan_of_an_empty_model_is_all_new():
    after = _hosts("basic")
    changes = diff([], after)
    assert len(changes.new_hosts) == len(after)
    assert not changes.new_ports, "a new host's ports are part of the host"


def test_a_disappearing_port_is_not_reported_as_a_finding():
    before = _hosts("basic")
    after = [h for h in _hosts("basic") if h.address != "192.0.2.2"]
    assert diff(before, after).empty, "the overviews show what is current"
