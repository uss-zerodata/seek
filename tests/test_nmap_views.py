"""Projections: the up rule, statistics, grouping."""

from __future__ import annotations

from pathlib import Path

from seek.nmap import views
from seek.nmap.merge import load

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _scans(*names):
    return views.prepare(load([FIX / f"{n}.xml" for n in names]))


# --- the up rule (-Pn) ------------------------------------------------------


def test_pn_scan_reports_up_hosts_not_the_asserted_count():
    scans = _scans("pn-asserted")
    assert len(scans.hosts) == 10
    assert len(scans.asserted_up) == 10, "nmap asserted all ten up"
    assert len(scans.up) == 2, "only two have an open port"
    assert [h.address for h in scans.up] == ["198.51.100.3", "198.51.100.7"]


def test_the_discrepancy_is_detectable():
    assert _scans("pn-asserted").overstated is True
    assert _scans("discovery").overstated is False


def test_the_raw_state_and_reason_are_kept():
    h = _scans("pn-asserted").hosts[0]
    assert (h.state, h.reason) == ("up", "user-set")
    assert h.state_asserted is True
    assert h.up is False


def test_real_host_discovery_agrees_with_the_recorded_state():
    scans = _scans("discovery")
    assert len(scans.asserted_up) == 4
    assert len(scans.up) == 4, "a discovery answer is enough"
    assert all(not h.state_asserted for h in scans.up)


def test_a_host_reached_by_discovery_with_no_open_port_is_still_up():
    h = next(h for h in _scans("discovery").hosts if h.address == "203.0.113.1")
    assert h.services == []
    assert h.up is True


def test_a_down_host_with_no_open_port_is_not_up():
    h = next(h for h in _scans("discovery").hosts if h.address == "203.0.113.9")
    assert h.state == "down"
    assert h.up is False


# --- statistics -------------------------------------------------------------


def test_statistics_separate_asserted_from_up():
    st = views.statistics(_scans("pn-asserted").hosts)
    assert (st.targets, st.asserted_up, st.up, st.with_open_ports) == (10, 10, 2, 2)
    assert st.overstated is True


def test_statistics_count_services_and_their_ports():
    st = views.statistics(_scans("basic").hosts)
    names = dict((n, c) for n, c, _ in st.services)
    assert names["http"] == 2
    assert names["ssh"] == 1
    ports = dict((n, p) for n, _, p in st.services)
    assert ports["http"] == ["80/tcp"]
    assert st.distinct_services == len(st.services)
    assert st.open_ports == ["22/tcp", "80/tcp"]


def test_statistics_count_hosts_per_port_and_the_services_on_it():
    """Ports used to exist only as a comma list truncated inside a detail cell."""
    st = views.statistics(_scans("basic").hosts)
    assert st.ports == [("80/tcp", 2, ["http"]), ("22/tcp", 1, ["ssh"])], \
        "busiest port first, and every distinct open port is present"
    assert [p for p, _, _ in st.ports] != sorted(p for p, _, _ in st.ports), \
        "the breakdown is ordered by host count, not by label"


def test_a_port_serving_several_services_names_all_of_them():
    st = views.statistics(_scans("merge-a", "merge-b").hosts)
    named = dict((label, names) for label, _, names in st.ports)
    assert named["3128/tcp"] == ["http"], "the probed name, not the table guess"
    assert set(named) == set(st.open_ports)


def test_the_port_breakdown_follows_the_subset_it_is_given():
    scans = _scans("basic")
    subset = [h for h in scans.hosts if h.address == "192.0.2.2"]
    st = views.statistics(subset)
    assert st.ports == [("80/tcp", 1, ["http"])]


def test_statistics_follow_the_filter():
    scans = _scans("basic")
    subset = [h for h in scans.hosts if h.address == "192.0.2.2"]
    st = views.statistics(subset)
    assert st.targets == 1
    assert [n for n, _, _ in st.services] == ["http"]


# --- service groups ---------------------------------------------------------


def test_identical_services_across_hosts_group_into_one_row():
    groups = views.service_groups(_scans("basic").hosts)
    http = next(g for g in groups if g.port == 80)
    assert http.host_count == 2, "both hosts run nginx 1.22.1 on 80"
    assert http.product == "nginx"


def test_a_version_difference_splits_the_group():
    groups = views.service_groups(_scans("merge-a", "merge-b").hosts)
    assert len([g for g in groups if g.port == 22]) == 1
    ssh = next(g for g in groups if g.port == 22)
    assert ssh.version == "10.0p2"


def test_closed_and_filtered_ports_are_not_in_the_service_overview():
    groups = views.service_groups(_scans("basic").hosts)
    assert all(g.port != 443 for g in groups), "443 is closed"


def test_group_carries_its_vulnerability_count():
    groups = views.service_groups(_scans("vuln").hosts)
    g80 = next(g for g in groups if g.port == 80)
    assert g80.vulnerability_count == 1


# --- grouping views ---------------------------------------------------------


def test_group_by_service_lists_hosts_and_ports():
    grouped = dict(views.group_by(_scans("basic").hosts, "service"))
    assert len(grouped["http"]) == 2
    assert {h.address for h, _ in grouped["http"]} == {"192.0.2.1", "192.0.2.2"}


def test_group_by_product_omits_services_with_no_product():
    hosts = _scans("merge-a").hosts
    grouped = dict(views.group_by(hosts, "product"))
    assert grouped == {}, "merge-a has no detected products at all"


def test_group_by_port_lists_the_hosts_exposing_it():
    grouped = dict(views.group_by(_scans("basic").hosts, "port"))
    assert {h.address for h, _ in grouped["80/tcp"]} == {"192.0.2.1", "192.0.2.2"}


def test_groups_are_ordered_by_size():
    sizes = [len(v) for _, v in views.group_by(_scans("basic").hosts, "service")]
    assert sizes == sorted(sizes, reverse=True)


# --- exports moved to test_nmap_export.py with the code they cover -----------


def test_the_projections_no_longer_carry_the_exporters():
    """`views` projects the model; `export` shapes a selection for another tool."""
    assert not [n for n in dir(views) if n.startswith("export_")]
