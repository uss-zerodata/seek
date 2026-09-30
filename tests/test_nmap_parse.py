"""Parsing nmap XML: shape is strict, content is lax, failures are typed."""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap.parse import NmapParseError, parse_file

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _hosts(name: str):
    return {h.address: h for h in parse_file(FIX / f"{name}.xml").hosts}


# --- basic shape ------------------------------------------------------------


def test_parses_hosts_services_and_os():
    h = _hosts("basic")["192.0.2.1"]
    assert h.hostname == "alpha.example"
    assert h.os == "Linux 5.X"
    assert h.osclass == "Linux"
    assert [(s.port, s.protocol, s.state) for s in h.services] == [
        (22, "tcp", "open"), (80, "tcp", "open"), (443, "tcp", "closed")
    ]
    ssh = h.services[0]
    assert (ssh.name, ssh.product, ssh.version, ssh.extrainfo) == (
        "ssh", "OpenSSH", "9.2p1", "Debian 2"
    )


def test_missing_facts_are_none_not_errors():
    h = _hosts("basic")["192.0.2.2"]
    assert h.hostname is None
    assert h.hostnames == []
    assert h.os is None and h.osclass is None
    filtered = next(s for s in h.services if s.port == 22)
    assert filtered.state == "filtered"
    assert filtered.name is None and filtered.product is None


def test_down_host_is_parsed_with_no_services():
    h = _hosts("basic")["192.0.2.3"]
    assert h.state == "down"
    assert h.services == []
    assert h.up is False


def test_open_services_helper_excludes_closed_and_filtered():
    h = _hosts("basic")["192.0.2.1"]
    assert [s.port for s in h.open_services] == [22, 80]


def test_empty_run_yields_no_hosts():
    assert parse_file(FIX / "empty-run.xml").hosts == []


# --- scripts ----------------------------------------------------------------


def test_structured_script_table_round_trips():
    svc = _hosts("scripts")["192.0.2.10"].services[0]
    cert = next(s for s in svc.scripts if s.id == "ssl-cert")
    assert cert.data["subject"]["commonName"] == "example.test"
    assert cert.data["subject"]["organizationName"] == "Example Org"
    ext = cert.data["extensions"]
    assert ext[0]["name"] == "X509v3 Subject Alternative Name"


def test_free_text_only_script_keeps_its_output():
    svc = _hosts("scripts")["192.0.2.10"].services[0]
    methods = next(s for s in svc.scripts if s.id == "http-methods")
    assert methods.output == "Supported Methods: GET HEAD POST"
    assert methods.data is None


def test_output_is_kept_even_when_tables_are_present():
    svc = _hosts("scripts")["192.0.2.10"].services[0]
    title = next(s for s in svc.scripts if s.id == "http-title")
    assert title.output == "Example Site"
    assert title.data == {"title": "Example Site"}


def test_hostscript_attaches_to_the_host_not_a_service():
    h = _hosts("scripts")["192.0.2.10"]
    assert [s.id for s in h.scripts] == ["smb2-time"]
    assert all(s.id != "smb2-time" for svc in h.services for s in svc.scripts)


def test_unkeyed_table_children_become_a_list():
    svc = next(s for s in _hosts("vuln")["192.0.2.30"].services if s.port == 80)
    cve = next(s for s in svc.scripts if s.id == "http-vuln-cve2011-3192")
    assert cve.data["CVE-2011-3192"]["ids"] == ["BID:49303", "CVE:CVE-2011-3192"]
    assert cve.data["CVE-2011-3192"]["refs"][0].startswith("https://")


# --- failures ---------------------------------------------------------------


def test_truncated_file_raises_a_typed_error():
    with pytest.raises(NmapParseError, match="malformed XML"):
        parse_file(FIX / "truncated.xml")


def test_non_nmap_xml_raises_a_typed_error():
    with pytest.raises(NmapParseError, match="not an nmap scan"):
        parse_file(FIX / "not-nmap.xml")


def test_missing_file_raises_a_typed_error():
    with pytest.raises(NmapParseError):
        parse_file(FIX / "does-not-exist.xml")


# --- recognition ------------------------------------------------------------


def test_source_is_recorded_on_hosts_and_services():
    sf = parse_file(FIX / "basic.xml")
    assert sf.hosts[0].sources == ["basic.xml"]
    assert sf.hosts[0].services[0].sources == ["basic.xml"]


def test_disabled_ping_is_detected_from_args():
    assert parse_file(FIX / "pn-asserted.xml").disabled_ping is True
    assert parse_file(FIX / "discovery.xml").disabled_ping is False


# --- CPEs and OS matches -------------------------------------------------------


def _inv_host(addr: str):
    return next(h for h in parse_file(FIX / "inventory.xml").hosts if h.address == addr)


def test_service_cpes_are_read_as_written():
    svc = next(s for s in _inv_host("198.51.100.10").services if s.port == 22)
    assert svc.cpes == ["cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:linux:linux_kernel"]


def test_a_service_without_cpe_has_none():
    svc = next(s for s in _inv_host("198.51.100.10").services if s.port == 21)
    assert svc.cpes == []


def test_every_os_match_is_kept_with_its_cpes():
    host = _inv_host("198.51.100.10")
    assert host.os == "Linux 4.15 - 5.8", "the best match's name, as before"
    assert [(m.name, m.accuracy) for m in host.os_matches] == [
        ("Linux 4.15 - 5.8", 96), ("Linux 2.6.32", 90)]
    assert host.os_matches[0].cpes == ["cpe:/o:linux:linux_kernel:4",
                                       "cpe:/o:linux:linux_kernel:5"]
