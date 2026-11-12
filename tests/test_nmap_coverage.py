"""Which ports a host was probed on: `<scaninfo>`, timed-out and down hosts, per file."""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap.coverage import Coverage, contains, merge_ranges, parse_ranges
from seek.nmap.merge import read
from seek.nmap.parse import parse_file

FIXTURES = Path(__file__).parent / "fixtures" / "coverage"


def _hosts(*names: str):
    scans = read([FIXTURES / n for n in names])
    return scans, {h.address: h for h in scans.hosts}, Coverage(scans.files)


def test_port_lists_are_parsed_sorted_and_merged():
    assert parse_ranges("8080,1-1000,999-1002,22") == ((1, 1002), (8080, 8080))
    assert parse_ranges("") == ()
    assert merge_ranges([(5, 6), (1, 4)]) == ((1, 6),), "touching ranges join"
    assert contains(((1, 1000), (8443, 8443)), 8443) and not contains(((1, 1000),), 1001)


@pytest.mark.parametrize("text", ["1-abc", "80-22", "70000", "-5"])
def test_a_list_that_is_not_ports_is_refused(text):
    with pytest.raises(ValueError):
        parse_ranges(text)


def test_the_file_records_what_it_probed_and_who_was_not_probed():
    f = parse_file(FIXTURES / "ports.xml")
    assert f.coverage == {"tcp": ((1, 1000),), "udp": ((161, 161),)}
    assert f.timed_out == {"192.0.2.61"}
    assert f.not_scanned == {"192.0.2.62"}


def test_two_scans_with_different_port_lists_add_up():
    _scans, hosts, cov = _hosts("ports.xml", "other.xml")
    host = cov.of(hosts["192.0.2.60"])
    assert host.covers(22, "tcp") and host.covers(8443, "tcp")
    assert not host.covers(9100, "tcp")


def test_a_host_that_timed_out_was_not_probed():
    _scans, hosts, cov = _hosts("ports.xml")
    assert not cov.of(hosts["192.0.2.61"]).covers(80, "tcp")


def test_a_down_host_was_not_probed():
    _scans, hosts, cov = _hosts("ports.xml")
    assert not cov.of(hosts["192.0.2.62"]).covers(22, "tcp")


def test_a_ping_sweep_covers_nothing_and_still_loads():
    scans, hosts, cov = _hosts("sweep.xml")
    assert not scans.failures and "192.0.2.63" in hosts
    assert not cov.of(hosts["192.0.2.63"]).covers(80)


def test_a_protocol_is_covered_on_its_own():
    _scans, hosts, cov = _hosts("ports.xml")
    host = cov.of(hosts["192.0.2.60"])
    assert host.covers(53, "tcp") and not host.covers(53, "udp")
    assert host.covers(161, "udp") and host.covers(161), "any protocol"


def test_an_unreadable_list_makes_its_protocol_unknown_not_empty():
    scans, hosts, cov = _hosts("unreadable.xml")
    assert not scans.failures, "the file still loads"
    host = cov.of(hosts["192.0.2.64"])
    assert host.unknown == {"tcp"}
    assert host.covers(53, "udp") and not host.covers(80, "tcp")
    assert "ip" not in scans.files[0].coverage, "-sO lists protocols, not ports"


def test_a_truncated_scan_keeps_its_coverage():
    scans, hosts, cov = _hosts("truncated.xml")
    assert not scans.files[0].complete
    assert cov.of(hosts["192.0.2.65"]).covers(22, "tcp")


def test_hosts_sharing_sources_share_one_answer():
    _scans, hosts, cov = _hosts("ports.xml", "other.xml")
    a = cov.of(hosts["192.0.2.60"])
    assert cov.of(hosts["192.0.2.60"]) is a


def test_subtract_leaves_the_ports_not_in_the_second_list():
    from seek.nmap.coverage import subtract
    assert subtract(((1, 10), (20, 30)), ((3, 4), (8, 22))) == ((1, 2), (5, 7), (23, 30))
    assert subtract(((22, 23),), ()) == ((22, 23),)
    assert subtract(((22, 23),), ((1, 100),)) == ()
