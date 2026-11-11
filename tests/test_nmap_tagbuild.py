"""The rule builder: shared facts, exclusions, the preview and the draft."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from seek.gowitness.results import Capture
from seek.nmap import tagbuild as tb
from seek.nmap import tagging
from seek.nmap import tagrules as tr
from seek.nmap.export import Record
from seek.nmap.models import Host, ScanFile, Service

SCAN = "scan.xml"


def _svc(port, name=None, product=None) -> Service:
    return Service("tcp", port, "open", name=name, product=product, sources=[SCAN])


def _host(address, *services) -> Host:
    return Host(address=address, state="up", reason="syn-ack", services=list(services),
                sources=[SCAN])


def _printer(address, serial, *extra):
    return _host(address, _svc(80, "http", "Zebra httpd"), _svc(515, "printer"),
                 _svc(9100, "jetdirect"), *extra)


def _world(others=500, other_extra=lambda n: [_svc(22, "ssh")], files=None, other_title=True):
    """Five printers, and `others` look-alikes with the same ports and title."""
    hosts, caps = [], {}
    for n in range(5):
        address = f"192.0.2.{n + 1}"
        hosts.append(_printer(address, n))
        caps[(address, "tcp", 80)] = [Capture(f"http://{address}",
                                              title=f"D2J2019{n:05d} - READY")]
    for n in range(others):
        address = f"198.51.{n // 250}.{n % 250 + 1}"
        hosts.append(_printer(address, n, *other_extra(n)))
        if other_title:
            caps[(address, "tcp", 80)] = [Capture(f"http://{address}", title="Printer Home Page")]
    files = files if files is not None else [ScanFile(Path(SCAN), label=SCAN,
                                                      coverage={"tcp": ((1, 65535),)})]
    index = tagging.prepare(hosts, files, caps)
    return hosts, files, index


def _builder(hosts, files, index, picked=5, tags=None):
    return tb.start(index, files, tags, [Record(h) for h in hosts[:picked]])


# --- 7.1 shared facts --------------------------------------------------------------


def test_five_printers_share_their_ports_with_counts_of_the_others():
    b = _builder(*_world())
    shared = tb.shared(b)
    by_label = {p.fact.label: p for p in shared.facts}
    for label in ("80/tcp open", "515/tcp open", "9100/tcp open"):
        assert by_label[label].selected == 5 and by_label[label].others == 500
    assert "80/tcp product 'Zebra httpd'" in by_label


def test_the_rarest_fact_comes_first():
    hosts, files, index = _world(others=20, other_extra=lambda n: [])
    hosts[0].services.append(_svc(631, "ipp"))       # rare: the selection's alone...
    for h in hosts[1:5]:
        h.services.append(_svc(631, "ipp"))
    index = tagging.prepare(hosts, files, {})
    shared = tb.shared(_builder(hosts, files, index))
    assert shared.facts[0].fact.label == "631/tcp open" and shared.facts[0].others == 0


def test_a_shared_product_is_a_literal_and_a_service_is_anchored():
    product = tb.Fact(tb.Kind.PRODUCT, "tcp", 8080, "Jetty(i-jetty g2p5_0.08)")
    assert product.condition() == {"port": "8080/tcp",
                                   "product": {"literal": "Jetty(i-jetty g2p5_0.08)"}}
    service = tb.Fact(tb.Kind.SERVICE, "tcp", 80, "http").condition()
    assert tr.condition(service).fields[0][1].search("http")
    assert not tr.condition(service).fields[0][1].search("https")


def test_differing_titles_offer_their_common_end():
    shared = tb.shared(_builder(*_world(others=0)))
    partial = {p.fact.label for p in shared.partial}
    assert "80/tcp title ends with '- READY'" in partial
    end = next(p for p in shared.partial if p.fact.partial == "end")
    assert end.selected == 5


# --- 7.2 exclusions ----------------------------------------------------------------


def _chosen():
    return [tb.Fact(tb.Kind.OPEN, "tcp", 80), tb.Fact(tb.Kind.OPEN, "tcp", 515),
            tb.Fact(tb.Kind.OPEN, "tcp", 9100)]


def test_one_fact_separates_the_five_from_the_five_hundred():
    b = _builder(*_world())
    ex = tb.exclusions(b, _chosen())
    assert (ex.matched, ex.unwanted) == (505, 500)
    best = ex.single[0]
    assert best.fact.label == "22/tcp open" and best.excludes == 500
    assert ex.combination is None
    shown = tb.preview(b, _chosen(), [best.fact])
    assert shown.selected == 5 and len(shown.matched) == 5 and not shown.confirm


def test_no_single_fact_separates_them_so_a_combination_is_offered():
    def extra(n):
        return [_svc(22, "ssh")] if n % 2 else [_svc(23, "telnet")]
    ex = tb.exclusions(_builder(*_world(others=40, other_extra=extra, other_title=False)),
                       _chosen())
    assert ex.single[0].excludes == 20
    combo = ex.combination
    assert {f.label for f in combo.facts} == {"22/tcp open", "23/tcp open"}
    assert (combo.excludes, combo.remaining) == (40, 0)


def test_an_exclusion_that_rests_on_an_unscanned_port_says_so():
    files = [ScanFile(Path(SCAN), label=SCAN, coverage={"tcp": ((80, 80), (515, 515),
                                                                 (9100, 9100), (22, 22))}),
             ScanFile(Path("narrow.xml"), label="narrow.xml",
                      coverage={"tcp": ((80, 80), (515, 515), (9100, 9100))})]
    hosts, _files, index = _world(others=10, files=files)
    hosts[0].sources = ["narrow.xml"]           # the first printer: 22 never probed
    index = tagging.prepare(hosts, files, {})
    ex = tb.exclusions(_builder(hosts, files, index), _chosen())
    best = ex.single[0]
    assert best.fact.label == "22/tcp open" and best.assumed_on == ("192.0.2.1",)
    shown = tb.preview(_builder(hosts, files, index), _chosen(), [best.fact])
    assert shown.assumed == ("192.0.2.1",) and shown.selected == 5


# --- 7.3 preview, drafts, edge cases --------------------------------------------


def test_a_rule_that_excludes_the_selection_needs_a_confirmation():
    b = _builder(*_world(others=5))
    shown = tb.preview(b, _chosen(), [tb.Fact(tb.Kind.OPEN, "tcp", 9100)])
    assert shown.selected == 0 and "none of the selected" in shown.confirm


def test_the_draft_is_the_rule_the_preview_counted():
    hosts, files, index = _world(others=30)
    b = _builder(hosts, files, index)
    negative = [tb.Fact(tb.Kind.OPEN, "tcp", 22)]
    raw = tb.draft("zebra", _chosen(), negative)
    rule = tr.condition({"all": raw["when"]})
    built = tagging.evaluate(index, rule)
    assert tb.preview(b, _chosen(), negative).matched == b.addresses(built.certain)
    assert raw["grant"] == "host" and raw["when"][-1] == {"not": {"port": "22/tcp"}}


def test_one_host_is_warned_about():
    hosts, files, index = _world(others=3)
    shared = tb.shared(_builder(hosts, files, index, picked=1))
    assert any("one host is selected" in n for n in shared.notes)


def test_hosts_sharing_nothing_say_so():
    hosts = [_host("192.0.2.1", _svc(22, "ssh")), _host("192.0.2.2", _svc(80, "http"))]
    index = tagging.prepare(hosts, [], {})
    shared = tb.shared(tb.start(index, [], None, [Record(h) for h in hosts]))
    assert not shared.facts and any("share no fact" in n for n in shared.notes)


def test_a_vanished_host_is_dropped_with_a_note():
    hosts, files, index = _world(others=3)
    gone = _host("203.0.113.9", _svc(80))
    b = tb.start(index, files, None, [Record(hosts[0]), Record(gone)])
    assert b.selected_hosts == [0] and any("no longer in the scans" in n for n in b.notes)


def test_selected_services_tie_port_facts_to_their_ports():
    hosts, files, index = _world(others=3)
    records = [Record(h, next(s for s in h.services if s.port == 515)) for h in hosts[:5]]
    shared = tb.shared(tb.start(index, files, None, records))
    ports = {p.fact.port for p in shared.facts if p.fact.port is not None}
    assert ports == {515}


def test_a_tag_is_a_fact_too():
    hosts, files, index = _world(others=3)
    _doc, defs = tr.load("tags:\n  zebra:\n    rules: [{when: [{port: 9100}]}]\n", "r")
    from seek.nmap import tagfiles
    order, _ = tr.order(defs.tags)
    tags = tagging.build(hosts, files, tagfiles.Loaded(tags=defs.tags, order=order),
                         prepared=index)
    shared = tb.shared(_builder(hosts, files, index, tags=tags))
    assert any(p.fact.kind is tb.Kind.TAG and p.fact.value == "zebra" for p in shared.facts)


# --- 7.4 time ----------------------------------------------------------------------


@pytest.mark.slow
def test_each_step_is_quick_at_engagement_scale():
    hosts, files, index = _world(others=24_000)
    b = _builder(hosts, files, index)
    for step in (lambda: tb.shared(b), lambda: tb.exclusions(b, _chosen()),
                 lambda: tb.preview(b, _chosen(), [tb.Fact(tb.Kind.OPEN, "tcp", 22)])):
        t = time.perf_counter()
        step()
        assert time.perf_counter() - t < 0.3
