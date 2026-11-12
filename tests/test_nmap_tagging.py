"""Tag rules run over hosts: matching, negation and assumptions, service tags, bodies."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from seek.gowitness.results import Capture
from seek.nmap import tagfiles as tf
from seek.nmap import tagging
from seek.nmap import tagrules as tr
from seek.nmap.models import Host, ScanFile, ScriptResult, Service

FIXTURES = Path(__file__).parent / "fixtures" / "tagging"
SCAN = "scan.xml"


def svc(port, name=None, product=None, proto="tcp", state="open", scripts=(), **kw) -> Service:
    return Service(protocol=proto, port=port, state=state, name=name, product=product,
                   scripts=list(scripts), sources=[SCAN], **kw)


def host(address, *services, hostnames=(), os=None, sources=(SCAN,)) -> Host:
    return Host(address=address, state="up", reason="syn-ack", hostnames=list(hostnames),
                os=os, services=list(services), sources=list(sources))


def scanfile(tcp=((1, 1000),), udp=(), label=SCAN, **kw) -> ScanFile:
    coverage = {"tcp": tuple(tcp)} if tcp else {}
    if udp:
        coverage["udp"] = tuple(udp)
    return ScanFile(path=Path(label), label=label, coverage=coverage, **kw)


def loaded(text: str, entries=()) -> tf.Loaded:
    _doc, defs = tr.load(text, "seek-rules.yaml")
    assert not [p for p in defs.problems if p.level is tr.Level.ERROR], defs.problems
    order, disabled = tr.order(defs.tags)
    return tf.Loaded(tags=defs.tags, order=order, disabled=disabled, problems=defs.problems,
                     entries={Path("seek-tags.yaml"): tuple(entries)} if entries else {})


def run(text, hosts, files=None, captures=None, entries=(), bodies=None) -> tagging.TagSet:
    files = [scanfile()] if files is None else files
    return tagging.build(hosts, files, loaded(text, entries), captures or {}, bodies)


def rule(tag: str, *conds: str, grant: str = "host") -> str:
    when = "".join(f"\n          - {c}" for c in conds)
    return f"tags:\n  {tag}:\n    rules:\n      - grant: {grant}\n        when:{when}\n"


# --- rules, conditions --------------------------------------------------------------


def test_any_rule_grants_the_tag_and_all_conditions_must_hold():
    text = ("tags:\n  printer:\n    rules:\n"
            "      - when: [{port: 515}, {port: 9100}]\n"
            "      - when: [{port: 80, title: Web Image Monitor}]\n")
    by_ports = host("192.0.2.1", svc(515), svc(9100))
    one_port = host("192.0.2.2", svc(515))
    by_title = host("192.0.2.3", svc(80, "http"))
    caps = {("192.0.2.3", "tcp", 80): [Capture("http://192.0.2.3", title="Web Image Monitor")]}
    tags = run(text, [by_ports, one_port, by_title], captures=caps)
    assert set(tags.hosts) == {"192.0.2.1", "192.0.2.3"}


def test_fields_of_one_condition_describe_one_port():
    text = rule("x", "{service: http, product: nginx}")
    split = host("192.0.2.1", svc(80, "http", "Apache httpd"), svc(8443, "ssl", "nginx"))
    same = host("192.0.2.2", svc(80, "http", "nginx"))
    assert set(run(text, [split, same]).hosts) == {"192.0.2.2"}


def test_a_port_must_be_open_unless_a_state_is_given():
    closed = host("192.0.2.1", svc(22, "ssh", state="closed"))
    assert not run(rule("x", "{port: 22}"), [closed]).hosts
    assert run(rule("x", "{port: 22, state: closed}"), [closed]).hosts


def test_script_output_and_certificate_issuer_are_tested():
    cert = ScriptResult("ssl-cert", "Subject: commonName=x\nIssuer: organizationName=RICOH",
                        {"subject": {"commonName": "x"},
                         "issuer": {"organizationName": "RICOH COMPANY,LTD."}})
    header = ScriptResult("http-server-header", "openresty")
    h = host("192.0.2.1", svc(7443, "ssl", scripts=[cert]), svc(80, "http", scripts=[header]))
    assert run(rule("x", "{port: 7443, cert_issuer: RICOH COMPANY}"), [h]).hosts
    assert run(rule("x", "{script: {id: http-server-header, output: openresty}}"), [h]).hosts
    assert not run(rule("x", "{port: 80, cert_issuer: RICOH}"), [h]).hosts


def test_capture_fields_title_header_technology_redirect_network():
    cap = Capture("https://192.0.2.1", title="Login", final_url="https://192.0.2.1/login.html",
                  headers=[("Server", "lighttpd")], technologies=["jQuery"],
                  network=[("https://192.0.2.1/doc/page/login.asp", "200")],
                  tls_issuer="HIKVISION", tls_subject="CN=cam")
    h = host("192.0.2.1", svc(443, "https"))
    caps = {("192.0.2.1", "tcp", 443): [cap]}
    for cond in ("{title: login}", "{header: 'server: lighttpd'}", "{technology: jquery}",
                 "{redirect: '/login\\.html$'}", "{network_log: 'login\\.asp'}",
                 "{cert_issuer: hikvision}", "{cert_subject: 'CN=cam'}"):
        assert run(rule("x", cond), [h], captures=caps).hosts, cond


def test_host_conditions_network_name_os_and_another_tag():
    named = Service("tcp", 443, "open", name="https", sources=[SCAN],
                    names=[("fw.sdlan.example.net", "certificate")])
    h = host("10.20.1.5", named, os="Linux 5.X")
    other = host("10.30.1.5", svc(443, "https"))
    assert set(run(rule("x", "{address: 10.20.0.0/16}"), [h, other]).hosts) == {"10.20.1.5"}
    assert run(rule("x", "{hostname: '\\.sdlan\\.example\\.net$'}"), [h]).hosts
    assert run(rule("x", "{os: linux}"), [h]).hosts
    text = ("tags:\n  printer:\n    rules: [{when: [{port: 9100}]}]\n"
            "  ricoh:\n    rules: [{when: [{tag: printer}, {port: 80, title: Monitor}]}]\n")
    p = host("192.0.2.5", svc(9100), svc(80, "http"))
    caps = {("192.0.2.5", "tcp", 80): [Capture("http://192.0.2.5", title="Web Image Monitor")]}
    assert set(run(text, [p], captures=caps).of_host("192.0.2.5")) == {"printer", "ricoh"}


# --- negation and assumptions -----------------------------------------------------


EXCLUDE_SSH = rule("printer-x", "{port: 80, title: Printer Home Page}", "{not: {port: 22/tcp}}")


def _printer(address, *extra):
    return host(address, svc(80, "http"), *extra)


def _home(address):
    return {(address, "tcp", 80): [Capture(f"http://{address}", title="Printer Home Page")]}


def test_an_exclusion_removes_hosts_with_the_port_open():
    with_ssh = _printer("192.0.2.1", svc(22, "ssh"))
    tags = run(EXCLUDE_SSH, [with_ssh], captures=_home("192.0.2.1"))
    assert not tags.hosts


def test_negation_is_none_of_the_ports_not_per_port():
    h = host("192.0.2.1", svc(22, "ssh"), svc(80, "http"))
    assert not run(rule("x", "{not: {service: ssh}}"), [h]).hosts


def test_a_port_scanned_and_not_open_is_certain():
    tags = run(EXCLUDE_SSH, [_printer("192.0.2.1")], captures=_home("192.0.2.1"))
    grant = tags.of_host("192.0.2.1")["printer-x"]
    assert not grant.uncertain


def test_a_port_nobody_scanned_is_an_assumption_that_names_it():
    files = [scanfile(tcp=((80, 80), (515, 515), (9100, 9100)))]
    tags = run(EXCLUDE_SSH, [_printer("192.0.2.1")], files, _home("192.0.2.1"))
    grant = tags.of_host("192.0.2.1")["printer-x"]
    assert grant.uncertain and grant.evidence == ("22/tcp not scanned",)
    assert tags.counts["printer-x"].uncertain == 1


def test_one_port_of_a_list_meets_the_condition():
    text = rule("x", '{port: "80,8000-8999/tcp", product: Zebra}')
    on_8080 = host("192.0.2.1", svc(8080, "http", "Zebra httpd"))
    on_443 = host("192.0.2.2", svc(443, "https", "Zebra httpd"))
    assert set(run(text, [on_8080, on_443]).hosts) == {"192.0.2.1"}


def test_the_fields_of_a_list_still_describe_one_port():
    text = rule("x", '{port: [80, 8080], service: http, product: Zebra}')
    split = host("192.0.2.1", svc(80, "http", "Apache httpd"), svc(8080, "ssl", "Zebra httpd"))
    same = host("192.0.2.2", svc(8080, "http", "Zebra httpd"))
    assert set(run(text, [split, same]).hosts) == {"192.0.2.2"}


def test_a_wide_range_finds_what_any_port_finds():
    text = rule("x", '{port: "1-65535", product: Zebra}')
    hosts = [host("192.0.2.1", svc(9100, None, "Zebra")), host("192.0.2.2", svc(22, "ssh"))]
    assert set(run(text, hosts).hosts) == {"192.0.2.1"}


def test_a_negated_list_names_the_ports_not_scanned():
    text = rule("x", "{port: 80}", '{not: {port: "22,23/tcp"}}')
    h = host("192.0.2.1", svc(80, "http"), svc(22, "ssh", state="closed"))
    tags = run(text, [h], [scanfile(tcp=((80, 80),))])
    assert tags.of_host("192.0.2.1")["x"].evidence == ("23/tcp not scanned",)
    scanned = run(text, [h], [scanfile(tcp=((1, 1000),))])
    assert not scanned.of_host("192.0.2.1")["x"].uncertain


def test_a_long_list_of_unscanned_ports_is_shortened():
    text = rule("x", "{port: 80}", '{not: {port: "1,3,5,7,9,11,13/tcp"}}')
    tags = run(text, [host("192.0.2.1", svc(80))], [scanfile(tcp=((80, 80),))])
    assert tags.of_host("192.0.2.1")["x"].evidence == ("1,3,5,7,9/tcp and 2 more not scanned",)


def test_a_recorded_closed_port_is_evidence_even_without_a_port_list():
    h = _printer("192.0.2.1", svc(22, "ssh", state="closed"))
    tags = run(EXCLUDE_SSH, [h], [scanfile(tcp=())], _home("192.0.2.1"))
    assert not tags.of_host("192.0.2.1")["printer-x"].uncertain


def test_a_host_that_timed_out_is_an_assumption():
    files = [scanfile(timed_out={"192.0.2.1"})]
    tags = run(EXCLUDE_SSH, [_printer("192.0.2.1")], files, _home("192.0.2.1"))
    assert tags.of_host("192.0.2.1")["printer-x"].uncertain


def test_a_certain_rule_wins_over_an_assumed_one():
    text = ("tags:\n  x:\n    rules:\n"
            "      - when: [{port: 80}, {not: {port: 22/tcp}}]\n"
            "      - when: [{port: 80}]\n")
    tags = run(text, [_printer("192.0.2.1")], [scanfile(tcp=((80, 80),))])
    assert not tags.of_host("192.0.2.1")["x"].uncertain


def test_an_assumption_reaches_the_tags_that_ask_for_it():
    text = (rule("zebra", "{port: 80}", "{not: {port: 22/tcp}}") +
            "  zebra-zd420:\n    rules: [{when: [{tag: zebra}]}]\n")
    tags = run(text, [_printer("192.0.2.1")], [scanfile(tcp=((80, 80),))])
    child = tags.of_host("192.0.2.1")["zebra-zd420"]
    assert child.evidence == ("22/tcp not scanned",)


def test_a_host_never_carries_a_tag_and_its_negation():
    text = (rule("a", "{port: 80}", "{not: {port: 22/tcp}}") +
            "  not-a:\n    rules: [{when: [{port: 80}, {not: {tag: a}}]}]\n")
    tags = run(text, [_printer("192.0.2.1")], [scanfile(tcp=((80, 80),))])
    assert set(tags.of_host("192.0.2.1")) == {"a"}


def test_a_negated_capture_test_without_a_capture_is_an_assumption():
    text = rule("x", "{port: 80}", "{not: {port: 80, title: Login}}")
    grant = run(text, [_printer("192.0.2.1")]).of_host("192.0.2.1")["x"]
    assert grant.evidence == ("no capture of 80/tcp",)


# --- missing data in a positive test ----------------------------------------------


def test_no_capture_means_no_match():
    assert not run(rule("x", "{port: 80, title: Monitor}"), [_printer("192.0.2.1")]).hosts


def _body_db(path: Path, rows: dict[int, str | None], html: bool = True) -> Path:
    con = sqlite3.connect(path)
    cols = "id integer, url text" + (", html text" if html else "")
    con.execute(f"create table results ({cols})")
    for rid, body in rows.items():
        con.execute("insert into results values (?, ?" + (", ?)" if html else ")"),
                    (rid, f"http://x/{rid}", *([body] if html else [])))
    con.commit()
    con.close()
    return path


def _zebra(address, db, rid):
    return {(address, "tcp", 80): [Capture(f"http://{address}", row_id=rid, database=db)]}


def test_a_body_test_reads_the_capture_database(tmp_path):
    db = _body_db(tmp_path / "g.sqlite3", {1: "<h1>Zebra Technologies<br>ZD420</h1>", 2: "x"})
    a, b = _printer("192.0.2.1"), _printer("192.0.2.2")
    caps = {**_zebra("192.0.2.1", db, 1), **_zebra("192.0.2.2", db, 2)}
    tags = run(rule("zebra", "{port: 80, body: {literal: ZD420}}"), [a, b], captures=caps,
               bodies=tagging.BodySource())
    assert set(tags.hosts) == {"192.0.2.1"}


def test_bodies_that_are_not_there_are_not_evaluated_and_counted(tmp_path):
    db = _body_db(tmp_path / "g.sqlite3", {1: None}, html=False)
    tags = run(rule("zebra", "{port: 80, body: ZD420}"), [_printer("192.0.2.1")],
               captures=_zebra("192.0.2.1", db, 1), bodies=tagging.BodySource())
    assert not tags.hosts
    (p,) = [p for p in tags.problems if p.tag == "zebra"]
    assert "1 service(s) could not be evaluated" in p.message and "no page body" in p.message


def test_a_locked_database_is_reported_not_raised(tmp_path, monkeypatch):
    db = _body_db(tmp_path / "g.sqlite3", {1: "ZD420"})

    def locked(*_a, **_k):
        raise tagging.gw_results.BodiesUnavailable("g.sqlite3: database is locked")
        yield  # pragma: no cover
    monkeypatch.setattr(tagging.gw_results, "read_bodies", locked)
    tags = run(rule("zebra", "{port: 80, body: ZD420}"), [_printer("192.0.2.1")],
               captures=_zebra("192.0.2.1", db, 1), bodies=tagging.BodySource())
    assert not tags.hosts and any("database is locked" in p.message for p in tags.problems)


def test_body_verdicts_are_cached_and_only_candidates_are_read(tmp_path, monkeypatch):
    db = _body_db(tmp_path / "g.sqlite3", {1: "ZD420", 2: "ZD420"})
    asked: list[list[int]] = []
    real = tagging.gw_results.read_bodies

    def spy(path, ids, cap):
        asked.append(sorted(ids))
        yield from real(path, ids, cap)
    monkeypatch.setattr(tagging.gw_results, "read_bodies", spy)
    source = tagging.BodySource()
    text = rule("zebra", "{port: 80, body: ZD420}", "{port: 9100}")
    hosts = [_printer("192.0.2.1", svc(9100)), _printer("192.0.2.2")]
    caps = {**_zebra("192.0.2.1", db, 1), **_zebra("192.0.2.2", db, 2)}
    assert set(run(text, hosts, captures=caps, bodies=source).hosts) == {"192.0.2.1"}
    assert set(run(text, hosts, captures=caps, bodies=source).hosts) == {"192.0.2.1"}
    assert len(asked) == 1, "the second build read nothing"


def test_a_body_is_cut_at_the_cap(tmp_path):
    db = _body_db(tmp_path / "g.sqlite3", {1: "x" * 50 + "ZD420"})
    tags = run(rule("zebra", "{port: 80, body: ZD420}"), [_printer("192.0.2.1")],
               captures=_zebra("192.0.2.1", db, 1), bodies=tagging.BodySource(cap=40))
    assert not tags.hosts


# --- service tags, manual entries, dependencies ----------------------------------


def test_service_tags_go_to_the_ports_of_positive_conditions():
    text = rule("ricoh-web-ui", "{port: 80, title: Web Image Monitor}", "{port: 515}",
                "{not: {port: 22/tcp}}", grant="service")
    h = host("192.0.2.1", svc(80, "http"), svc(515, "printer"), svc(9100))
    caps = {("192.0.2.1", "tcp", 80): [Capture("http://192.0.2.1", title="Web Image Monitor")]}
    tags = run(text, [h], captures=caps)
    assert not tags.hosts
    assert set(tags.services) == {("192.0.2.1", "tcp", 80), ("192.0.2.1", "tcp", 515)}


def test_manual_entries_tag_hosts_and_services_and_count_the_unloaded():
    entries = [tf.Entry("explored", "192.0.2.1"), tf.Entry("high-value", "192.0.2.1", "tcp", 443),
               tf.Entry("explored", "203.0.113.9")]
    tags = run("", [host("192.0.2.1", svc(443), svc(80))], entries=entries)
    assert set(tags.of_host("192.0.2.1")) == {"explored"}
    assert tags.names("192.0.2.1", "tcp", 443) == {"explored", "high-value"}
    assert tags.names("192.0.2.1", "tcp", 80) == {"explored"}
    assert tags.unmatched_entries == 1


def test_a_manual_tag_satisfies_a_rule_that_asks_for_it():
    text = "tags:\n  ricoh:\n    rules: [{when: [{tag: printer}, {port: 80}]}]\n"
    tags = run(text, [_printer("192.0.2.1")], entries=[tf.Entry("printer", "192.0.2.1")])
    assert {"printer", "ricoh"} <= set(tags.of_host("192.0.2.1"))


def test_a_rule_and_a_manual_entry_share_one_grant_with_both_sources():
    tags = run(rule("explored", "{port: 80}"), [_printer("192.0.2.1")],
               entries=[tf.Entry("explored", "192.0.2.1")])
    grant = tags.of_host("192.0.2.1")["explored"]
    assert len(grant.sources) == 2 and any(s.startswith("manual") for s in grant.sources)


def test_a_port_free_rule_is_noted_as_slow():
    tags = run(rule("x", "{title: Monitor}"), [])
    assert tags.notes["x"] == ("slow: no port",)


def test_an_unreadable_port_list_is_named_once():
    files = [scanfile(coverage_unknown={"tcp"})]
    tags = run("", [], files)
    assert any("tcp port list of scan.xml" in p.message for p in tags.problems)


# --- the colleague's rules -------------------------------------------------------


def _colleague_world():
    ricoh = host("192.0.2.10", svc(80, "http"), svc(515, "printer"), svc(9100, "jetdirect"),
                 svc(54080, "ipp"))
    catalyst = host("192.0.2.20", svc(80, "http", "OpenResty web app server"),
                    svc(443, "https", "OpenResty web app server"), svc(830, "tcpwrapped"))
    axis = host("192.0.2.30", svc(80, "http"), svc(443, "https"), svc(554, "rtsp"),
                svc(49152, "upnp"))
    caps = {("192.0.2.10", "tcp", 80): [Capture("http://192.0.2.10", title="Web Image Monitor")]}
    return [ricoh, catalyst, axis], caps


def test_the_colleague_s_rules_give_the_same_host_tags():
    hosts, caps = _colleague_world()
    text = (FIXTURES / "categorize_rules.yaml").read_text()
    tags = tagging.build(hosts, [scanfile()], loaded(text), caps)
    assert set(tags.of_host("192.0.2.10")) == {"printer", "ricoh"}
    assert set(tags.of_host("192.0.2.20")) == {"switch", "cisco", "catalyst"}
    assert set(tags.of_host("192.0.2.30")) == {"cctv", "axis"}


def test_service_tags_of_an_all_pattern_go_to_every_matched_port():
    """`categorize_systems` intersects the matched services of an `all`, so this
    rule tags no port there; seek tags both ports it matched (design D2)."""
    hosts, caps = _colleague_world()
    text = (FIXTURES / "categorize_rules.yaml").read_text()
    tags = tagging.build(hosts, [scanfile()], loaded(text), caps)
    ui = {k for k, v in tags.services.items() if "ricoh-web-ui" in v}
    assert ui == {("192.0.2.10", "tcp", 80), ("192.0.2.10", "tcp", 515)}


@pytest.mark.parametrize("address", ["192.0.2.10", "192.0.2.20"])
def test_tags_carry_their_definitions_issues(address):
    hosts, caps = _colleague_world()
    text = (FIXTURES / "categorize_rules.yaml").read_text() + (
        "tags:\n  printer:\n    issues: [{title: Raw printing, severity: low}]\n")
    tags = tagging.build(hosts, [scanfile()], loaded(text), caps)
    issues = tags.issues(tags.of_host(address))
    assert bool(issues) == (address == "192.0.2.10")
