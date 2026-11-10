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


# --- sorting ports ------------------------------------------------------------


_EXAMPLE = ["8080/tcp", "80/tcp", "22/tcp", "8080/udp", "443/tcp", "53/udp"]
_SORTED = ["22/tcp", "53/udp", "80/tcp", "443/tcp", "8080/tcp", "8080/udp"]


def _one_host_with(tmp_path, labels):
    ports = "".join(
        f'<port protocol="{label.split("/")[1]}" portid="{label.split("/")[0]}">'
        f'<state state="open" reason="syn-ack" reason_ttl="64"/>'
        f'<service name="svc{i}" method="table" conf="3"/></port>'
        for i, label in enumerate(labels))
    scan = tmp_path / "ports.xml"
    scan.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -oX ports.xml '
        '192.0.2.9" start="1756000000" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="syn-ack" reason_ttl="64"/>'
        f'<address addr="192.0.2.9" addrtype="ipv4"/><ports>{ports}</ports></host>\n'
        '</nmaprun>\n')
    return views.prepare(load([scan]))


def _sorted_by(rows, col, desc=False):
    from seek.tui.nmap.app import _key_at

    return [r.cells[col] for r in sorted(rows, key=lambda r: _key_at(r, col), reverse=desc)]


def test_the_keys_order_by_number_then_protocol():
    assert sorted(_EXAMPLE, key=views.label_key) == _SORTED
    assert views.ports_key(["22/tcp", "80/tcp"]) < views.ports_key(["80/tcp", "443/tcp"])


def test_a_hosts_ports_sort_by_number_not_text(tmp_path):
    from seek.tui.nmap import views as vdefs

    scans = _one_host_with(tmp_path, _EXAMPLE)
    rows = vdefs.host_detail(scans.hosts[0]).rows(scans)
    assert _sorted_by(rows, 0) == _SORTED
    assert _sorted_by(rows, 0, desc=True) == list(reversed(_SORTED))


def test_the_hostname_column_sorts_by_the_name_it_shows():
    from seek.nmap.models import Host, ScanSet, Service
    from seek.tui.nmap import views as vdefs

    by_cert = Host(address="10.0.0.1", services=[
        Service(protocol="tcp", port=443, names=[("zulu.example", "certificate")])])
    by_dns = Host(address="10.0.0.2", hostnames=["alpha.example"])
    nameless = Host(address="10.0.0.3")
    scans = ScanSet(hosts=[by_cert, by_dns, nameless])
    shown = _sorted_by(vdefs.hosts_view().rows(scans), 1)
    assert shown == [vdefs.ABSENT, "alpha.example", "zulu.example"]


def test_the_by_port_grouping_sorts_by_number(tmp_path):
    from seek.tui.nmap import views as vdefs

    scans = _one_host_with(tmp_path, _EXAMPLE)
    rows = vdefs.grouping_view("port").rows(scans)
    assert _sorted_by(rows, 0) == _SORTED


def test_a_groupings_ports_column_is_sorted_at_all(tmp_path):
    """Its sort key used to be an empty string: choosing it left the order as built."""
    from seek.tui.nmap import views as vdefs

    scans = views.prepare(load([FIX / "basic.xml", FIX / "vuln.xml"]))
    rows = vdefs.grouping_view("service").rows(scans)
    got = _sorted_by(rows, 3)
    keys = [views.ports_key(cell.rstrip(" …").split(", ")) for cell in got]
    assert keys == sorted(keys), got


def test_a_hosts_ports_are_held_by_number_not_protocol_first(tmp_path):
    """The model's own order - what the record's service list, the exports and
    an unsorted view all read. Protocol-first put `8080/tcp` before `53/udp`."""
    scans = _one_host_with(tmp_path, _EXAMPLE)
    assert [f"{s.port}/{s.protocol}" for s in scans.hosts[0].services] == _SORTED


def test_a_merged_hosts_ports_are_held_by_number(tmp_path):
    first = _one_host_with(tmp_path, ["8080/tcp", "80/tcp"]).files[0].path
    second = tmp_path / "more"
    second.mkdir()
    extra = _one_host_with(second, ["53/udp", "22/tcp"]).files[0].path
    scans = views.prepare(load([first, extra]))
    assert ([f"{s.port}/{s.protocol}" for s in scans.hosts[0].services]
            == ["22/tcp", "53/udp", "80/tcp", "8080/tcp"])


def test_the_record_lists_a_hosts_services_by_number(tmp_path):
    from seek.tui.nmap import detail

    scans = _one_host_with(tmp_path, _EXAMPLE)
    text = "\n".join(str(line.text) for line in detail.render(scans.hosts[0]))
    at = [text.index(f"{label} ") for label in _SORTED]
    assert at == sorted(at), text


def test_service_groups_come_out_by_number(tmp_path):
    scans = _one_host_with(tmp_path, _EXAMPLE)
    assert [f"{g.port}/{g.protocol}" for g in views.service_groups(scans.hosts)] == _SORTED


def test_the_names_ports_column_is_sorted_at_all():
    from seek.tui.nmap import views as vdefs

    scans = views.prepare(load([FIX / "basic.xml", FIX / "vuln.xml"]))
    rows = vdefs.names_view().rows(scans)
    got = _sorted_by(rows, 3)
    keys = [views.ports_key(cell.rstrip(" …").split(", ")) for cell in got]
    assert keys == sorted(keys), got


def test_the_cached_order_is_the_sort_and_never_the_cache_itself(tmp_path):
    from seek.config import Config
    from seek.nmap.session import Session
    from seek.nmap.views import prepare
    from seek.tui.nmap import views as vdefs
    from seek.tui.nmap.tabs import tab_view

    paths = sorted((Path(__file__).parent / "fixtures" / "nmap").glob("*.xml"))
    sess = Session(Config(nmap_path="/nonexistent/nmap"), paths, tmp_path, databases=[],
                   scans=prepare(load(paths)))
    view = tab_view("hosts", sess)
    rows = view.rows(sess.scans)
    assert len(rows) > 5
    for col in range(len(view.columns)):
        for desc in (False, True):
            expected = sorted(rows, key=lambda r, c=col: vdefs.key_at(r, c), reverse=desc)
            expected.sort(key=lambda r: (r.section_rank, 0 if r.heading else 1))
            got = view.ordered(rows, col, desc)
            assert got == expected, (col, desc)
            assert got is not view.ordered(rows, col, desc), "a copy, never the cache"
    assert view.ordered(list(rows), 0, False) is None, "only the view's own rows are cached"
