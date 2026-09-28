"""The one rule that decides whether a host is up.

An open port, however the host was scanned, or a real host-discovery answer.
A `-Pn` assumption on its own is nothing - not even with closed or filtered
ports, an OS guess or script output behind it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap.export import Record, export_up_hosts
from seek.nmap.merge import load
from seek.nmap.views import statistics

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _hosts(*names):
    return {h.address: h for h in load([FIX / f"{n}.xml" for n in names]).hosts}


# --- the rule ---------------------------------------------------------------


@pytest.mark.parametrize(("address", "up"), [
    ("203.0.113.1", True),    # -Pn, open port
    ("203.0.113.2", False),   # -Pn, closed + filtered, OS guess, script output
    ("203.0.113.3", False),   # -Pn, nothing at all
])
def test_under_pn_only_an_open_port_counts(address, up):
    host = _hosts("up-rule-pn")[address]
    assert host.state_asserted
    assert host.up is up


def test_closed_filtered_os_and_scripts_are_not_enough():
    host = _hosts("up-rule-pn")["203.0.113.2"]
    assert host.services and host.os and host.scripts, "the fixture has all of them"
    assert not host.open_services
    assert not host.up


def test_discovery_alone_is_enough():
    host = _hosts("up-rule-discovery")["203.0.113.4"]
    assert host.reason == "echo-reply" and not host.services
    assert host.up


def test_a_recorded_down_is_not_up():
    assert not _hosts("up-rule-discovery")["203.0.113.5"].up


def test_pn_asserted_still_reports_two_of_ten():
    scans = load([FIX / "pn-asserted.xml"])
    assert len(scans.hosts) == 10
    assert [h.address for h in scans.up] == ["198.51.100.3", "198.51.100.7"]
    assert scans.overstated


def test_statistics_count_by_the_rule():
    hosts = list(_hosts("up-rule-pn", "up-rule-discovery").values())
    st = statistics(hosts)
    # .1 open, .6 open (recorded down by discovery), .4 discovery
    assert st.up == 3


# --- merging ----------------------------------------------------------------


@pytest.mark.parametrize("order", [
    ("up-rule-discovery", "up-rule-discovery-late"),
    ("up-rule-discovery-late", "up-rule-discovery"),
])
def test_observed_up_beats_observed_down_in_either_order(order):
    hosts = _hosts(*order)
    for address in ("203.0.113.4", "203.0.113.5"):
        assert hosts[address].state == "up", address
        assert hosts[address].reason == "echo-reply"
        assert hosts[address].up


@pytest.mark.parametrize("order", [
    ("up-rule-discovery", "up-rule-pn"),
    ("up-rule-pn", "up-rule-discovery"),
])
def test_an_open_port_makes_a_recorded_down_host_up(order):
    host = _hosts(*order)["203.0.113.6"]
    assert host.state == "down", "the recorded state stays what nmap wrote"
    assert host.up, "the open port from the -Pn scan decides it"


def test_an_asserted_up_does_not_replace_a_recorded_down(tmp_path):
    pn = tmp_path / "pn.xml"
    pn.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -Pn -oX pn.xml '
        '203.0.113.5" start="1756001300" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="user-set" reason_ttl="0"/>'
        '<address addr="203.0.113.5" addrtype="ipv4"/></host>\n</nmaprun>\n')
    for paths in ([FIX / "up-rule-discovery.xml", pn], [pn, FIX / "up-rule-discovery.xml"]):
        host = {h.address: h for h in load(paths).hosts}["203.0.113.5"]
        assert host.state == "down" and host.reason == "no-response"
        assert not host.up


# --- the host record --------------------------------------------------------


def _record_text(host) -> str:
    from rich.console import Console

    from seek.tui.nmap import detail

    console = Console(width=120, record=True)
    console.print(detail.as_group(detail.host_detail(host)))
    return console.export_text()


@pytest.mark.parametrize(("address", "says"), [
    ("203.0.113.1", "up — an open port (asserted by -Pn)"),
    ("203.0.113.2", "unconfirmed — asserted up by -Pn, no open port"),
    ("203.0.113.4", "up  (echo-reply)"),
    ("203.0.113.5", "down"),
    ("203.0.113.6", "up — an open port (recorded down)"),
])
def test_the_record_names_the_part_of_the_rule_that_applies(address, says):
    assert says in _record_text(_hosts("up-rule-pn", "up-rule-discovery")[address])


def test_an_open_filtered_udp_port_under_pn_renders_as_unconfirmed(tmp_path):
    """The crash from real scans: `-Pn`, one `open|filtered` UDP port."""
    scan = tmp_path / "udp.xml"
    scan.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -Pn -sU -p 53 -oX udp.xml '
        '203.0.113.8" start="1756000000" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="user-set" reason_ttl="0"/>'
        '<address addr="203.0.113.8" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response" '
        'reason_ttl="0"/><service name="domain" method="table" conf="3"/></port>'
        '</ports></host>\n</nmaprun>\n')
    host = load([scan]).hosts[0]
    assert not host.up, "open|filtered is not open"
    assert "unconfirmed" in _record_text(host)


# --- export -----------------------------------------------------------------


def test_the_up_hosts_recipe_follows_the_rule():
    hosts = _hosts("up-rule-pn", "up-rule-discovery")
    records = [Record(h) for h in hosts.values()]
    assert set(export_up_hosts(records)) == {"203.0.113.1", "203.0.113.4", "203.0.113.6"}
