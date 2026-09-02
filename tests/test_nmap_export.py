"""The exporter: records, the field catalogue, the three formats, the recipes.

Everything here is pure - no viewer, no screen - which is the point of the
module: the same selection can later be handed to a tool runner.
"""

from __future__ import annotations

import json
from pathlib import Path

from seek.nmap import export, views
from seek.nmap import names as name_mod
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import views as vdefs

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _hosts(*names):
    return prepare(load([FIX / f"{n}.xml" for n in names])).hosts


def _records(*names):
    return export.records_for(_hosts(*names))


def _service(address: str, port: int, *names):
    host = next(h for h in _hosts(*names) if h.address == address)
    return export.Record(host, next(s for s in host.services if s.port == port))


# --- records ----------------------------------------------------------------


def test_a_host_and_one_of_its_services_are_different_records():
    host = export.Record(_hosts("basic")[0])
    svc = _service("192.0.2.1", 443, "basic")
    assert host.identity == ("192.0.2.1",)
    assert svc.identity == ("192.0.2.1", "tcp", 443)
    assert host.identity != svc.identity, "marking either one is a real choice"


def test_a_host_record_covers_its_open_services():
    host = export.Record(_hosts("basic")[0])
    assert [s.port for s in host.services] == [22, 80], "the closed 443 is not covered"
    assert [s.port for s in _service("192.0.2.1", 443, "basic").services] == [443], \
        "a service record covers itself, open or not"


# --- the recipes, unchanged in output ---------------------------------------


def test_the_named_recipes_produce_what_they_always_did():
    records = _records("basic")
    assert export.export_hosts(records) == ["192.0.2.1", "192.0.2.2"]
    assert export.export_all_hosts(records) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
    assert export.export_ports(records) == ["22,80"]
    assert export.export_host_ports(records) == [
        "192.0.2.1:22", "192.0.2.1:80", "192.0.2.2:80"]


# --- the names a host is known by -------------------------------------------


def test_the_names_are_the_resolved_ones_and_the_certificates():
    """A reverse lookup fills `hostnames`; a TLS service claims more in its cert."""
    record = _records("scripts")[0]
    assert export.names_for(record) == ["scripted.example", "example.test"]


def test_certificate_names_come_from_the_output_and_the_tables():
    """`ssl-cert` puts the subject in the text but the SANs only in its tables."""
    host = _hosts("scripts")[0]
    svc = next(s for s in host.services if s.port == 443)
    assert name_mod.service_names(svc) == [("example.test", "certificate")]


def test_a_wildcard_certificate_name_is_not_a_target():
    from seek.nmap.models import ScriptResult, Service

    svc = Service(protocol="tcp", port=443, state="open", name="https", scripts=[
        ScriptResult(id="ssl-cert",
                     output="Subject: commonName=*.example.test",
                     data={"extensions": [{"value": "DNS:*.example.test, "
                                                    "DNS:www.example.test"}]}),
    ])
    assert name_mod.service_names(svc) == [("www.example.test", "certificate")], \
        "nothing resolves a wildcard"


def test_a_certificate_naming_an_address_is_not_a_name():
    from seek.nmap.models import ScriptResult, Service

    svc = Service(protocol="tcp", port=443, state="open", name="https", scripts=[
        ScriptResult(id="ssl-cert", output="Subject: commonName=10.0.0.5"),
    ])
    assert name_mod.service_names(svc) == []


def test_a_service_with_no_certificate_contributes_no_names():
    host = _hosts("basic")[0]
    svc = next(s for s in host.services if s.port == 22)
    assert name_mod.service_names(svc) == []


def test_urls_cover_the_address_and_every_name():
    """The reference builds an IP list and a domain list, then combines them."""
    urls = export.export_urls(_records("scripts"))
    assert urls == ["https://192.0.2.10", "https://scripted.example",
                    "https://example.test"]


def test_a_name_carries_the_port_of_the_service_it_was_found_on():
    from seek.nmap.models import Host, ScriptResult, Service

    host = Host(address="10.0.0.5", hostnames=["web.example.test"], state="up",
                reason="syn-ack", services=[
                    Service(protocol="tcp", port=8443, state="open", name="https",
                            tunnel="ssl", scripts=[
                                ScriptResult(id="ssl-cert",
                                             output="commonName=alt.example.test")]),
                ])
    name_mod.attach(host)              # what `views.prepare` does at load time
    assert export.export_urls([export.Record(host)]) == [
        "https://10.0.0.5:8443", "https://web.example.test:8443",
        "https://alt.example.test:8443"]


def test_the_names_field_can_be_exported_like_any_other():
    row = export.rows(_records("scripts"), ["address", "names"])
    assert row == [("192.0.2.10", "scripted.example,example.test")]


def test_urls_use_the_right_scheme_and_keep_odd_ports():
    assert "https://192.0.2.10" in export.export_urls(_records("scripts"))
    assert export.export_urls(_records("vuln")) == [
        "http://192.0.2.30", "https://192.0.2.30", "http://192.0.2.30:8080"]


def test_a_recipe_naming_hosts_names_each_host_once():
    """Three marked services on one host are still one host."""
    records = [_service("192.0.2.1", 22, "basic"), _service("192.0.2.1", 80, "basic")]
    assert export.export_all_hosts(records) == ["192.0.2.1"]
    assert export.export_host_ports(records) == ["192.0.2.1:22", "192.0.2.1:80"]


def test_a_marked_service_exports_as_itself():
    """The old host-based recipes collapsed this to the address."""
    records = [_service("192.0.2.1", 80, "basic")]
    assert export.export_ports(records) == ["80"], "not every port on the host"
    assert export.export_host_ports(records) == ["192.0.2.1:80"]


def test_the_port_list_declares_that_a_format_does_not_apply():
    assert export.EXPORTS["ports"][2] is None
    assert all(col for _, _, col in
               (v for k, v in export.EXPORTS.items() if k != "ports"))


# --- fields -----------------------------------------------------------------


def test_fields_are_written_in_catalogue_order_whatever_the_pick_order():
    records = [_service("192.0.2.1", 80, "basic")]
    picked = export.rows(records, ["service", "address", "port"])
    assert picked == [("192.0.2.1", "80", "http")]
    assert export.ordered_fields({"port", "address"}) == ["address", "port"]


def test_a_host_record_leaves_the_service_fields_empty():
    row = export.rows([export.Record(_hosts("basic")[0])],
                      ["address", "port", "service", "url"])
    assert row == [("192.0.2.1", "", "", "")], "no service, not a failure"


def test_host_facts_and_service_facts_are_both_available():
    row = export.rows([_service("192.0.2.1", 22, "basic")], export.FIELD_NAMES)[0]
    named = dict(zip(export.FIELD_NAMES, row, strict=True))
    assert named["address"] == "192.0.2.1"
    assert named["hostname"] == "alpha.example"
    assert named["os"] == "Linux 5.X"
    assert named["reachable"] == "yes"
    assert named["port_label"] == "22/tcp"
    assert named["service"] == "ssh"
    assert named["product"] == "OpenSSH"
    assert named["version"] == "9.2p1"


def test_identical_rows_are_written_once():
    """Asked for the address alone, five services on one host are one host."""
    records = [_service("192.0.2.1", 22, "basic"), _service("192.0.2.1", 80, "basic")]
    assert export.rows(records, ["address"]) == [("192.0.2.1",)]
    assert export.render(records, ["address"], "text") == "192.0.2.1"
    assert json.loads(export.render(records, ["address"], "json")) == [{"address": "192.0.2.1"}]


# --- formats ----------------------------------------------------------------


def test_text_writes_one_record_per_line():
    text = export.render(_records("basic"), ["address", "os"], "text")
    assert text.splitlines() == ["192.0.2.1 Linux 5.X", "192.0.2.2", "192.0.2.3"]


def test_csv_carries_a_header_and_quotes_what_needs_it():
    records = [_service("192.0.2.1", 22, "basic")]
    out = export.render(records, ["address", "extrainfo", "sources"], "csv")
    lines = out.splitlines()
    assert lines[0] == "address,sources,extrainfo", "catalogue order, not pick order"
    assert lines[1] == "192.0.2.1,basic.xml,Debian 2"

    host = _hosts("merge-a", "merge-b")[0]
    multi = export.render([export.Record(host)], ["address", "sources"], "csv")
    assert '"merge-a.xml,merge-b.xml"' in multi, "a value with a comma is quoted"


def test_json_is_a_list_of_objects_keyed_by_field():
    out = export.render(_records("basic"), ["address", "reachable"], "json")
    parsed = json.loads(out)
    assert parsed[0] == {"address": "192.0.2.1", "reachable": "yes"}
    assert [o["reachable"] for o in parsed] == ["yes", "yes", "no"]


def test_a_recipe_can_be_written_in_any_format():
    items = export.export_hosts(_records("basic"))
    assert export.render_items(items, "address", "text") == "192.0.2.1\n192.0.2.2"
    assert export.render_items(items, "address", "csv").splitlines()[0] == "address"
    assert json.loads(export.render_items(items, "address", "json")) == [
        {"address": "192.0.2.1"}, {"address": "192.0.2.2"}]


def test_an_unknown_format_is_refused():
    try:
        export.render(_records("basic"), ["address"], "yaml")
    except ValueError as exc:
        assert "yaml" in str(exc)
    else:  # pragma: no cover - the point of the test
        raise AssertionError("an unknown format must not pass silently")


# --- every row says what it stands for --------------------------------------


def _views():
    scans = prepare(load([FIX / "basic.xml"]))
    host = scans.hosts[0]
    group = views.service_groups(scans.hosts)[0]
    bucket = vdefs.Grouping(key="service", label="http",
                            members=[(h, s) for h in scans.hosts
                                     for s in h.open_services if s.name == "http"])
    return scans, [
        vdefs.hosts_view(), vdefs.host_list("Some", scans.hosts),
        vdefs.services_view(), vdefs.host_detail(host),
        vdefs.service_detail(group), vdefs.grouping_view("service"),
        vdefs.grouping_detail(bucket), vdefs.statistics_view(),
    ]


def test_every_row_of_every_view_stands_for_records():
    scans, views_ = _views()
    for view in views_:
        for row in view.rows(scans):
            assert row.records or row.heading, \
                f"{view.title}: {row.cells[0]!r} stands for nothing"


def test_a_bucket_row_carries_every_pair_in_it():
    scans = prepare(load([FIX / "basic.xml"]))
    row = next(r for r in vdefs.grouping_view("service").rows(scans)
               if r.cells[0] == "http")
    assert [r.identity for r in row.records] == [
        ("192.0.2.1", "tcp", 80), ("192.0.2.2", "tcp", 80)]


def test_a_statistics_coverage_line_carries_the_hosts_it_counts():
    scans = prepare(load([FIX / "basic.xml"]))
    row = next(r for r in vdefs.statistics_view().rows(scans)
               if r.cells[0] == "With open ports")
    assert [r.identity for r in row.records] == [("192.0.2.1",), ("192.0.2.2",)]


def test_the_names_are_attached_at_load_not_re_derived_per_view():
    """`prepare` runs the recogniser once; the views read the field."""
    host = _hosts("scripts")[0]
    svc = next(s for s in host.services if s.port == 443)
    assert svc.names == [("example.test", "certificate")], "prepare attached them"
    assert svc.cert_names == ["example.test"], "and the certificate ones are nameable"


# --- the names a multi-site host gives away ---------------------------------


def test_a_multi_site_host_gives_up_its_vhosts():
    """An address cannot be asked which names point at it - the server can."""
    host = _hosts("vhosts")[0]
    found = dict(name_mod.host_names(host))
    assert list(found) == [
        "gamma.example",          # the one PTR the address owner published
        "shop.example.test",      # where port 80 redirects, and the cert subject
        "blog.example.test",      # subject-alternative names: the vhost list
        "www.example.test",
        "api.example.test",       # a certificate-transparency lookup
        "staging.example.test",
        "gamma.corp.example",     # what RDP announces about itself
        "corp.example",
    ]
    assert found["gamma.example"] == "resolved"
    assert found["blog.example.test"] == "certificate on 443/tcp"
    assert found["api.example.test"] == "certificate transparency on 443/tcp"
    assert found["gamma.corp.example"] == "host identity on 3389/tcp"


def test_a_name_seen_twice_keeps_both_pieces_of_evidence():
    host = _hosts("vhosts")[0]
    found = dict(name_mod.host_names(host))
    assert found["shop.example.test"] == "redirect on 80/tcp, certificate on 443/tcp"


def test_an_advisory_link_is_not_a_name_the_server_answers_to():
    """`http-vuln-*` scripts cite URLs; those hosts are not this host."""
    assert name_mod.host_names(_hosts("vuln")[0]) == []


def test_the_sources_behind_a_hosts_names_can_be_summarised():
    assert name_mod.sources_of(_hosts("vhosts")[0]) == [
        "certificate", "certificate transparency", "host identity", "redirect",
        "resolved"]


def test_every_vhost_becomes_a_url_on_the_port_that_revealed_it():
    urls = export.export_urls(_records("vhosts"))
    assert "https://blog.example.test" in urls
    assert "https://www.example.test" in urls
    assert "http://shop.example.test" in urls, "port 80 as well as 443"
    assert "https://192.0.2.50" in urls, "and the address that was scanned"
    # A name RDP announced is still worth trying against this host's web server:
    # whether it is served there is exactly what a vhost check answers, and the
    # provenance is on screen for the reader to judge.
    assert "https://gamma.corp.example" in urls
