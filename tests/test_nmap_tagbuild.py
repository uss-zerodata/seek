"""The rule builder: facts, the draft and its assessment, proposals, opening a rule."""

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
REQ, EXC, IGN = tb.State.REQUIRE, tb.State.EXCLUDE, tb.State.IGNORE


def _svc(port, name=None, product=None) -> Service:
    return Service("tcp", port, "open", name=name, product=product, sources=[SCAN])


def _host(address, *services) -> Host:
    return Host(address=address, state="up", reason="syn-ack", services=list(services),
                sources=[SCAN])


def _printer(address, *extra, product="Zebra httpd", web=80):
    return _host(address, _svc(web, "http", product), _svc(515, "printer"),
                 _svc(9100, "jetdirect"), *extra)


def _files(coverage=None):
    return [ScanFile(Path(SCAN), label=SCAN, coverage=coverage or {"tcp": ((1, 65535),)})]


def _world(others=500, other_extra=lambda n: [_svc(22, "ssh")], files=None, other_title=True):
    """Five printers, and `others` look-alikes with the same ports and title."""
    hosts, caps = [], {}
    for n in range(5):
        address = f"192.0.2.{n + 1}"
        hosts.append(_printer(address))
        caps[(address, "tcp", 80)] = [Capture(f"http://{address}",
                                              title=f"D2J2019{n:05d} - READY")]
    for n in range(others):
        address = f"198.51.{n // 250}.{n % 250 + 1}"
        hosts.append(_printer(address, *other_extra(n)))
        if other_title:
            caps[(address, "tcp", 80)] = [Capture(f"http://{address}", title="Printer Home Page")]
    files = files if files is not None else _files()
    return hosts, files, tagging.prepare(hosts, files, caps)


def _builder(hosts, files, index, picked=5, tags=None):
    return tb.start(index, files, tags, [Record(h) for h in hosts[:picked]])


def _open(port):
    return tb.Fact(tb.Kind.OPEN, "tcp", ((port, port),))


def _chosen(draft):
    for port in (80, 515, 9100):
        draft = draft.with_state(_open(port), REQ)
    return draft


def _rows(a):
    return {r.fact.label: r for r in a.rows}


# --- 2.1 facts -----------------------------------------------------------------


def test_a_proposed_value_equals_it_and_keeps_its_special_characters():
    product = tb.Fact(tb.Kind.PRODUCT, "tcp", ((8080, 8080),), "Jetty(i-jetty g2p5_0.08)")
    assert product.condition() == {"port": "8080/tcp",
                                   "product": {"equals": "Jetty(i-jetty g2p5_0.08)"}}
    test = tr.condition(product.condition()).fields[0][1]
    assert test.search("jetty(i-jetty g2p5_0.08)")
    assert not test.search("Jetty(i-jetty g2p5_0.08) extra")


@pytest.mark.parametrize("mode, case, value, yes, no", [
    (tb.Mode.EQUALS, False, "Zebra httpd", "zebra HTTPD", "Zebra httpd 2"),
    (tb.Mode.CONTAINS, False, "zebra", "ZTC Zebra ZD420", "Ricoh"),
    (tb.Mode.START, False, "Zebra", "zebra ZT410", "ZTC Zebra"),
    (tb.Mode.END, True, "- READY", "D2J - READY", "D2J - ready"),
    (tb.Mode.REGEX, False, r"Z[TD]\d+", "ZD420", "ZX1"),
])
def test_each_mode_matches_as_it_says(mode, case, value, yes, no):
    fact = tb.fact_from("product", protocol="tcp", ports="80", value=value, mode=mode, case=case)
    test = tr.condition(fact.condition()).fields[0][1]
    assert test.search(yes) and not test.search(no)


def test_a_port_scope_is_one_port_a_list_or_any():
    listed = tb.fact_from("open", ports="80,8080/tcp")
    assert listed.condition() == {"port": "80,8080/tcp"} and listed.label == "80,8080/tcp open"
    anywhere = tb.fact_from("product", protocol="tcp", ports="", value="zebra",
                            mode="contains")
    assert anywhere.condition() == {"protocol": "tcp", "product": {"literal": "zebra"}}
    assert anywhere.label == "any tcp port product contains 'zebra'"


@pytest.mark.parametrize("kwargs, fragment", [
    ({"kind": "product", "ports": "80", "value": "Zebra(", "mode": "regex"}, "not a valid"),
    ({"kind": "product", "ports": "9000-8000", "value": "x"}, "reversed"),
    ({"kind": "open", "ports": ""}, "needs a port"),
    ({"kind": "title", "ports": "80", "value": ""}, "needs a value"),
])
def test_an_invalid_edit_says_why(kwargs, fragment):
    kind = kwargs.pop("kind")
    with pytest.raises(tr.RuleError, match=fragment):
        tb.fact_from(kind, **kwargs)


# --- 2.2 the draft and its assessment -------------------------------------------


def test_the_assessment_counts_what_the_rule_saves():
    hosts, files, index = _world(others=30)
    b = _builder(hosts, files, index)
    draft = _chosen(b.draft()).with_state(_open(22), EXC)
    a = tb.assess(b, draft)
    raw = tb.draft_rule(draft, "zebra")
    built = tagging.evaluate(index, tr.condition({"all": raw["when"]}))
    assert a.matched == len(built.certain | built.assumed.keys()) == 5
    assert list(a.rule) == raw["when"] and raw["when"][-1] == {"not": {"port": "22/tcp"}}


def test_same_port_joins_facts_of_one_scope_into_one_condition():
    product = tb.fact_from("product", ports="", value="zebra", mode="contains")
    title = tb.fact_from("title", ports="", value="READY", mode="end")
    hosts = [_host("192.0.2.1", _svc(80, "http", "Zebra httpd")),
             _host("192.0.2.2", _svc(80, "http", "Zebra httpd"), _svc(8080, "http"))]
    caps = {("192.0.2.1", "tcp", 80): [Capture("http://192.0.2.1", title="x - READY")],
            ("192.0.2.2", "tcp", 8080): [Capture("http://192.0.2.2:8080", title="x - READY")]}
    index = tagging.prepare(hosts, _files(), caps)
    b = tb.start(index, _files(), None, [Record(hosts[0])])
    draft = b.draft().with_state(product, REQ).with_state(title, REQ)
    same = tb.assess(b, draft)
    assert len(same.rule) == 1 and same.matched == 1, "the split host is not counted"
    apart = tb.assess(b, tb.Draft(draft.selection, draft.facts, same_port=False))
    assert len(apart.rule) == 2 and apart.matched == 2


def test_excluding_one_host_by_address():
    hosts, files, index = _world(others=1, other_extra=lambda n: [])
    b = _builder(hosts, files, index)
    draft = _chosen(b.draft())
    a = tb.assess(b, draft)
    assert a.other_count == 1 and a.others[0].address == "198.51.0.1"
    draft = draft.with_state(tb.Fact(tb.Kind.ADDRESS, value="198.51.0.1"), EXC)
    a = tb.assess(b, draft)
    assert (a.matched, a.other_count) == (5, 0)
    assert {"not": {"address": "198.51.0.1"}} in a.rule


def test_a_forgotten_printer_is_added_to_the_selection():
    hosts, files, index = _world(others=2, other_extra=lambda n: [], other_title=False)
    b = _builder(hosts, files, index)
    draft = _chosen(b.draft()).add("198.51.0.1")
    a = tb.assess(b, draft)
    assert (a.of_selection, a.selected_matched, a.other_count) == (6, 6, 1)
    assert _rows(a)["80/tcp open"].selected == 6


def test_one_fact_separates_the_five_from_the_five_hundred():
    hosts, files, index = _world()
    a = tb.assess(_builder(hosts, files, index), _chosen(_builder(hosts, files, index).draft()))
    assert (a.matched, a.other_count) == (505, 500)
    best = a.exclusions[0]
    assert best.fact.label == "22/tcp open" and best.excludes == 500
    assert a.combination is None


def test_no_single_fact_separates_them_so_a_combination_is_offered():
    def extra(n):
        return [_svc(22, "ssh")] if n % 2 else [_svc(23, "telnet")]
    hosts, files, index = _world(others=40, other_extra=extra, other_title=False)
    b = _builder(hosts, files, index)
    a = tb.assess(b, _chosen(b.draft()))
    assert a.exclusions[0].excludes == 20
    assert {f.label for f in a.combination.facts} == {"22/tcp open", "23/tcp open"}
    assert (a.combination.excludes, a.combination.remaining) == (40, 0)


def test_nothing_to_exclude_when_only_the_selection_matches():
    hosts, files, index = _world(others=3)
    b = _builder(hosts, files, index)
    a = tb.assess(b, _chosen(b.draft()).with_state(_open(22), EXC))
    assert a.other_count == 0 and not a.exclusions and a.combination is None


def test_an_exclusion_that_rests_on_an_unscanned_port_says_so():
    files = [ScanFile(Path(SCAN), label=SCAN, coverage={"tcp": ((80, 80), (515, 515),
                                                                 (9100, 9100), (22, 22))}),
             ScanFile(Path("narrow.xml"), label="narrow.xml",
                      coverage={"tcp": ((80, 80), (515, 515), (9100, 9100))})]
    hosts, _files_, index = _world(others=10, files=files)
    hosts[0].sources = ["narrow.xml"]           # the first printer: 22 never probed
    index = tagging.prepare(hosts, files, {})
    b = _builder(hosts, files, index)
    a = tb.assess(b, _chosen(b.draft()))
    best = a.exclusions[0]
    assert best.fact.label == "22/tcp open" and best.assumed_on == ("192.0.2.1",)
    a = tb.assess(b, _chosen(b.draft()).with_state(best.fact, EXC))
    assert a.assumed == ("192.0.2.1",) and a.selected_matched == 5


def test_a_rule_that_excludes_the_selection_needs_a_confirmation():
    hosts, files, index = _world(others=5)
    b = _builder(hosts, files, index)
    a = tb.assess(b, _chosen(b.draft()).with_state(_open(9100), EXC))
    assert a.selected_matched == 0 and "none of the selected" in a.confirm


def test_changing_ones_mind_keeps_the_other_choices():
    hosts, files, index = _world(others=5)
    b = _builder(hosts, files, index)
    draft = b.draft().with_state(_open(80), REQ).with_state(_open(22), EXC)
    draft = draft.with_state(_open(80), IGN)
    a = tb.assess(b, draft)
    assert a.rule == ({"not": {"port": "22/tcp"}},)
    assert _rows(a)["22/tcp open"].state is EXC


def test_an_empty_draft_matches_nothing_and_lists_the_selection():
    hosts, files, index = _world(others=3)
    b = _builder(hosts, files, index)
    a = tb.assess(b, b.draft())
    assert a.matched == 0 and len(a.selection) == 5 and not a.rule


def test_matches_show_their_ports_and_title():
    hosts, files, index = _world(others=1)
    b = _builder(hosts, files, index)
    a = tb.assess(b, _chosen(b.draft()))
    (other,) = a.others
    assert other.ports == "80,515,9100,22" and other.title == "Printer Home Page"


# --- 2.3 proposals -----------------------------------------------------------------


def test_five_printers_share_their_ports_with_counts_of_the_others():
    hosts, files, index = _world()
    rows = _rows(tb.assess(_builder(hosts, files, index), _builder(hosts, files, index).draft()))
    for label in ("80/tcp open", "515/tcp open", "9100/tcp open"):
        assert (rows[label].selected, rows[label].others) == (5, 500)
    assert "80/tcp product = 'Zebra httpd'" in rows


def test_the_rarest_fact_comes_first():
    hosts, files, index = _world(others=20, other_extra=lambda n: [])
    for h in hosts[:5]:
        h.services.append(_svc(631, "ipp"))
    index = tagging.prepare(hosts, files, {})
    offered = tb.proposals(_builder(hosts, files, index), list(range(5)))
    assert offered[0].fact.label == "631/tcp open" and offered[0].others == 0


def test_a_host_marked_by_mistake_leaves_the_rest_shared():
    hosts, files, index = _world(others=3)
    web = _host("203.0.113.9", _svc(80, "http", "nginx"))
    hosts.append(web)
    index = tagging.prepare(hosts, files, {})
    b = tb.start(index, files, None, [Record(h) for h in hosts[:5]] + [Record(web)])
    a = tb.assess(b, b.draft().with_state(_open(9100), REQ))
    assert _rows(a)["9100/tcp open"].selected == 5
    assert [m.address for m in a.selection if not m.matched] == ["203.0.113.9"]


def test_printers_on_two_ports_share_the_value_as_a_list():
    hosts = ([_printer(f"192.0.2.{n}") for n in range(1, 4)]
             + [_printer(f"192.0.2.{n}", web=8080) for n in range(4, 6)])
    index = tagging.prepare(hosts, _files(), {})
    rows = _rows(tb.assess(tb.start(index, _files(), None, [Record(h) for h in hosts]),
                           tb.Draft(tuple(h.address for h in hosts))))
    row = rows["80,8080/tcp product = 'Zebra httpd'"]
    assert row.selected == 5


def test_two_models_share_a_word():
    hosts = [_printer("192.0.2.1", product="Zebra ZT410"),
             _printer("192.0.2.2", product="ZTC Zebra ZD420")]
    index = tagging.prepare(hosts, _files(), {})
    rows = _rows(tb.assess(tb.start(index, _files(), None, [Record(h) for h in hosts]),
                           tb.Draft(("192.0.2.1", "192.0.2.2"))))
    assert rows["80/tcp product contains 'Zebra'"].selected == 2


def test_differing_titles_offer_their_common_end():
    hosts, files, index = _world(others=0)
    rows = _rows(tb.assess(_builder(hosts, files, index), _builder(hosts, files, index).draft()))
    assert rows["80/tcp title ends with '- READY'"].selected == 5


def test_one_host_is_warned_about():
    hosts, files, index = _world(others=3)
    a = tb.assess(_builder(hosts, files, index, picked=1),
                  _builder(hosts, files, index, picked=1).draft())
    assert any("one host is selected" in n for n in a.notes)


def test_hosts_sharing_nothing_say_so():
    hosts = [_host("192.0.2.1", _svc(22, "ssh")), _host("192.0.2.2", _svc(80, "http"))]
    index = tagging.prepare(hosts, [], {})
    b = tb.start(index, [], None, [Record(h) for h in hosts])
    assert any("share no fact" in n for n in tb.assess(b, b.draft()).notes)


def test_a_vanished_host_is_dropped_with_a_note():
    hosts, files, index = _world(others=3)
    b = tb.start(index, files, None, [Record(hosts[0]), Record(_host("203.0.113.9"))])
    assert b.initial == ("192.0.2.1",) and any("no longer in the scans" in n for n in b.notes)


def test_selected_services_tie_port_facts_to_their_ports():
    hosts, files, index = _world(others=3)
    records = [Record(h, next(s for s in h.services if s.port == 515)) for h in hosts[:5]]
    offered = tb.proposals(tb.start(index, files, None, records), list(range(5)))
    assert {p.fact.ports for p in offered if p.fact.has_ports} == {((515, 515),)}


def test_a_tag_is_a_fact_too():
    hosts, files, index = _world(others=3)
    _doc, defs = tr.load("tags:\n  zebra:\n    rules: [{when: [{port: 9100}]}]\n", "r")
    from seek.nmap import tagfiles
    order, _ = tr.order(defs.tags)
    tags = tagging.build(hosts, files, tagfiles.Loaded(tags=defs.tags, order=order),
                         prepared=index)
    offered = tb.proposals(_builder(hosts, files, index, tags=tags), list(range(5)))
    assert any(p.fact.kind is tb.Kind.TAG and p.fact.value == "zebra" for p in offered)


# --- 2.4 refine ----------------------------------------------------------------------


def test_an_edit_that_drops_a_host_says_which():
    hosts = [_printer(f"192.0.2.{n}") for n in range(1, 5)] + [
        _printer("192.0.2.5", product="Zebra ZD420")]
    index = tagging.prepare(hosts, _files(), {})
    b = tb.start(index, _files(), None, [Record(h) for h in hosts])
    narrowed = tb.fact_from("product", protocol="tcp", ports="80", value="Zebra httpd")
    got = tb.refine(b, b.draft(), narrowed)
    assert (got.selected, got.of_selection, got.dropped) == (4, 5, ("192.0.2.5",))
    widened = tb.fact_from("product", ports="", value="zebra", mode="contains")
    assert tb.refine(b, b.draft(), widened).dropped == ()


def test_toggling_equals_follows_the_mode():
    hosts = [_printer("192.0.2.1"), _printer("192.0.2.2", product="Zebra httpd 2")]
    index = tagging.prepare(hosts, _files(), {})
    b = tb.start(index, _files(), None, [Record(hosts[0])])
    equals = tb.fact_from("product", protocol="tcp", ports="80", value="Zebra httpd")
    contains = tb.fact_from("product", protocol="tcp", ports="80", value="Zebra httpd",
                            mode="contains")
    assert tb.refine(b, b.draft(), equals).others == 0
    assert tb.refine(b, b.draft(), contains).others == 1
    draft = b.draft().with_state(equals, REQ).replace_fact(equals, contains)
    assert tb.draft_rule(draft, "r")["when"] == [{"port": "80/tcp",
                                                   "product": {"literal": "Zebra httpd"}}]


# --- 2.5 opening a saved rule ----------------------------------------------------


def _rule(when, grant="host"):
    text = f"tags:\n  zebra:\n    rules:\n      - {{name: r, grant: {grant}, when: {when}}}\n"
    _doc, defs = tr.load(text, "seek-rules.yaml")
    return defs.tags["zebra"].rules[0]


def test_a_built_rule_opens_as_the_facts_it_was_built_from():
    product = tb.fact_from("product", ports="80,8080/tcp", value="zebra", mode="contains")
    draft = tb.Draft(("192.0.2.1",), ((product, REQ), (_open(515), REQ), (_open(22), EXC)))
    raw = tb.draft_rule(draft, "r")
    import json
    opened = tb.from_rule(_rule(json.dumps(raw["when"])))
    assert opened.facts == draft.facts and opened.same_port
    assert tb.draft_when(tb.Draft((), opened.facts, opened.same_port)) == raw["when"]


def test_what_the_builder_cannot_show_is_kept_as_written():
    opened = tb.from_rule(_rule('[{port: 80, script: http-title}, {hostname: printer}]'))
    assert [f.kind for f, _s in opened.facts] == [tb.Kind.FIXED, tb.Kind.FIXED]
    assert tb.draft_when(tb.Draft((), opened.facts)) == [
        {"port": 80, "script": "http-title"}, {"hostname": "printer"}]


def test_separate_conditions_on_one_scope_stay_separate():
    opened = tb.from_rule(_rule("[{product: a}, {title: b}]"))
    assert not opened.same_port
    assert len(tb.draft_when(tb.Draft((), opened.facts, opened.same_port))) == 2


@pytest.mark.parametrize("when, fragment", [
    ("{any: [{port: 80}, {port: 81}]}", "any:"),
    ("[{port: 80}, {any: [{port: 81}]}]", "nested"),
    ("[{port: 80, product: a, title: c}, {port: 80, title: b}]", "edit it in the file"),
])
def test_a_rule_beyond_the_builder_says_why(when, fragment):
    reason = tb.from_rule(_rule(when))
    assert isinstance(reason, str) and fragment in reason and "seek-rules.yaml" in reason


def test_a_colleague_rule_is_not_opened():
    text = ("rules:\n  - name: r\n    pattern: {nmap_port: {port: 80}}\n    host_tags: [web]\n")
    rule = tr.load(text, "seek-rules.yaml")[1].tags["web"].rules[0]
    assert "categorize_systems" in tb.from_rule(rule)


# --- 2.6 time ------------------------------------------------------------------------


@pytest.mark.slow
def test_each_change_is_quick_at_engagement_scale():
    hosts, files, index = _world(others=24_000)
    b = _builder(hosts, files, index)
    tb.assess(b, b.draft())                       # the proposals, once per selection
    draft = _chosen(b.draft())
    for step in (lambda: tb.assess(b, draft),
                 lambda: tb.assess(b, draft.with_state(_open(22), EXC)),
                 lambda: tb.refine(b, draft, tb.fact_from("product", ports="", value="zeb",
                                                          mode="contains"))):
        t = time.perf_counter()
        step()
        assert time.perf_counter() - t < 0.3


def test_the_selected_ports_widen_to_their_hosts():
    hosts, files, index = _world(others=3)
    records = [Record(h, next(s for s in h.services if s.port == 515)) for h in hosts[:5]]
    b = tb.start(index, files, None, records)
    ports = {p.fact.ports for p in tb.proposals(b, list(range(5))) if p.fact.has_ports}
    assert ports == {((515, 515),)} and b.limit_text == "ports 515/tcp"
    whole = b.limited(None)
    ports = {p.fact.ports for p in tb.proposals(whole, list(range(5))) if p.fact.has_ports}
    assert ((80, 80),) in ports and whole.limit_text == "whole hosts"
    assert whole._holders is b._holders, "the counts are shared"
