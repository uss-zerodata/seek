"""The software inventory: recognisers, reconciliation, and the whole-model build."""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap import inventory as inv_mod
from seek.nmap.inventory import Observation, parse_product_tokens, reconcile, refines
from seek.nmap.merge import load
from seek.nmap.models import Host, ScriptResult, Service

FIX = Path(__file__).parent / "fixtures" / "nmap"
WEB, PORTAL = "198.51.100.10", "198.51.100.20"


@pytest.fixture(scope="module")
def inv():
    return inv_mod.build(load([FIX / "inventory.xml"]).hosts)


def _svc(inv, addr, port, proto="tcp"):
    return {c.key: c for c in inv.by_service.get((addr, proto, port), [])}


# --- nmap -----------------------------------------------------------------------


def test_a_probed_service_with_a_cpe(inv):
    samba = _svc(inv, WEB, 445)["samba"]
    assert samba.version == "4.6.2"
    assert samba.cpe22 == ["cpe:/a:samba:samba:4.6.2"]
    assert samba.cpe_origin == "nmap"


def test_a_cpe_without_a_version_gets_the_version_found_elsewhere(inv):
    nginx = _svc(inv, WEB, 80)["nginx"]
    assert nginx.cpe22 == ["cpe:/a:igor_sysoev:nginx"], "nmap's URI kept as written"
    assert nginx.cpe23 == ["cpe:2.3:a:igor_sysoev:nginx:1.16.1:*:*:*:*:*:*:*"]


def test_a_port_table_guess_is_not_a_product(inv):
    assert (WEB, "tcp", 3128) not in inv.by_service


def test_a_closed_port_has_no_components(inv):
    assert (WEB, "tcp", 81) not in inv.by_service


def test_os_matches_carry_their_cpes_without_one_version(inv):
    linux = {c.key: c for c in inv.by_host[WEB]}["linux"]
    assert linux.kind == "o"
    assert linux.version is None
    assert linux.cpe22 == ["cpe:/o:linux:linux_kernel:4", "cpe:/o:linux:linux_kernel:5"]
    assert any("Linux 4.15 - 5.8" in o.detail for o in linux.observations)


def test_the_operating_system_belongs_to_the_host(inv):
    for comps in inv.by_service.values():
        assert all(c.kind == "a" for c in comps)
    assert {c.key for c in inv.by_host[PORTAL]} == {"windows"}


# --- scripts ----------------------------------------------------------------------


def test_a_server_header_script():
    obs = inv_mod.from_script(ScriptResult("http-server-header", "pve-api-daemon/3.0",
                                           ["pve-api-daemon/3.0"]))
    assert [(o.product, o.version, o.source) for o in obs] == [
        ("pve-api-daemon", "3.0", "http-server-header")]


def test_a_header_several_products_share():
    assert parse_product_tokens("Python/3.8 websockets/8.1") == [
        ("Python", "3.8"), ("websockets", "8.1")]
    assert parse_product_tokens("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f") == [
        ("Apache", "2.4.41"), ("OpenSSL", "1.1.1f")]


def test_a_banner_from_an_unrecognised_service():
    host = Host("192.0.2.9", services=[Service(
        "tcp", 2222, "open", name="unknown", method="probed",
        scripts=[ScriptResult("fingerprint-strings",
                              "\n  NULL: \n    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                              {"NULL": "\n    SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"})])])
    ssh = _svc(inv_mod.build([host]), "192.0.2.9", 2222)["openssh"]
    assert ssh.version == "8.9p1"
    assert "Ubuntu-3ubuntu0.6" in ssh.observations[0].detail


def test_greetings_of_known_daemons(inv):
    assert _svc(inv, WEB, 21)["vsftpd"].version == "3.0.3"
    postfix = _svc(inv, WEB, 25)["postfix"]
    assert postfix.version is None and not postfix.versioned


def test_an_unknown_greeting_says_nothing():
    assert inv_mod.from_script(ScriptResult("banner", "220 Welcome to the Apache FTP")) == []


def test_header_lines_are_read_but_not_the_body(inv):
    keys = set(_svc(inv, WEB, 8080))
    assert {"python", "websockets", "express"} <= keys
    assert "apache-httpd" not in keys, "'Powered by Apache/2.4.1' was page text"


def test_advisory_text_is_not_software(inv):
    keys = set(_svc(inv, WEB, 8443))
    assert keys == {"apache-tomcat"}, "the Struts advisory named no component"


def test_vulners_keys_are_observations(inv):
    tomcat = _svc(inv, WEB, 8443)["apache-tomcat"]
    assert tomcat.sources == ["nmap", "vulners"]


def test_smb_lan_manager_joins_the_smb_service(inv):
    samba = _svc(inv, WEB, 445)["samba"]
    assert "smb-os-discovery" in samba.sources
    assert not samba.conflicting


def test_generator(inv):
    assert _svc(inv, WEB, 80)["wordpress"].version == "6.2.2"


# --- reconciliation ------------------------------------------------------------


def _o(product, version, rank, source="s"):
    return Observation(product, version, source, "", rank)


def test_two_sources_agree():
    c = reconcile("nginx", [_o("nginx", "1.16.1", 0, "nmap"),
                            _o("Nginx", "1.16.1", 3, "gowitness")])
    assert (c.version, c.conflicting, c.sources) == ("1.16.1", False, ["nmap", "gowitness"])


def test_a_version_fills_in_a_gap(inv):
    nginx = _svc(inv, WEB, 80)["nginx"]
    assert nginx.version == "1.16.1"
    assert [o.source for o in nginx.observations] == ["nmap", "http-server-header"]


def test_two_sources_disagree(inv):
    ssh = _svc(inv, WEB, 22)["openssh"]
    assert ssh.version == "8.2p1", "the probe is the more trusted source"
    assert ssh.conflicting
    assert ssh.versions == [("8.2p1", "nmap"), ("8.9p1", "banner")]


def test_a_refinement_is_not_a_conflict():
    c = reconcile("php", [_o("PHP", "7.4", 1), _o("PHP", "7.4.33", 3)])
    assert (c.version, c.conflicting) == ("7.4.33", False)


def test_a_conflict_is_not_narrowed_by_the_rival():
    c = reconcile("x", [_o("x", "1.2", 0), _o("x", "1.3.4", 1), _o("x", "1.2.7", 2)])
    assert (c.version, c.conflicting) == ("1.2.7", True)


@pytest.mark.parametrize(("specific", "general", "expected"), [
    ("8.9p1", "8.9", True), ("1.16.1", "1.16", True), ("1.16", "1.1", False),
    ("2.4", "2.4", True), ("2.4", "2.4.1", False)])
def test_refines(specific, general, expected):
    assert refines(specific, general) is expected


def test_different_products_on_one_port_stay_apart():
    host = Host("192.0.2.9", services=[Service(
        "tcp", 443, "open", name="https", product="Traefik", method="probed",
        scripts=[ScriptResult("http-server-header", "nginx", ["nginx"])])])
    comps = _svc(inv_mod.build([host]), "192.0.2.9", 443)
    assert set(comps) == {"traefik", "nginx"}
    assert not any(c.conflicting for c in comps.values())


def test_an_unmapped_product_has_no_cpe(inv):
    ws = _svc(inv, WEB, 8080)["websockets"]
    assert ws.cpes == [] and ws.cpe_origin is None


def test_an_alias_cpe_carries_the_version(inv):
    py = _svc(inv, WEB, 8080)["python"]
    assert py.cpe_origin == "alias"
    assert py.cpe23 == ["cpe:2.3:a:python:python:3.8:*:*:*:*:*:*:*"]


def test_nmaps_cpe_wins_over_the_alias_table(inv):
    # The table names nginx `f5:nginx`; nmap said `igor_sysoev:nginx`.
    assert _svc(inv, WEB, 80)["nginx"].cpe22 == ["cpe:/a:igor_sysoev:nginx"]


def test_entries_group_by_product_and_version():
    hosts = load([FIX / "inventory.xml"]).hosts
    found = {(e.key, e.version): e for e in inv_mod.entries(inv_mod.build(hosts), hosts)}
    nginx = found[("nginx", "1.16.1")]
    assert (len(nginx.hosts), nginx.service_count) == (1, 1)
    assert ("postfix", None) in found, "unversioned products are rows of their own"
    linux = found[("linux", None)]
    assert linux.places[0][1] is None, "a host-level component has no service"
    assert found[("openssh", "8.2p1")].conflicting


def test_progress_is_reported():
    seen = []
    inv_mod.build(load([FIX / "inventory.xml"]).hosts,
                  report=lambda done, total, unit: seen.append((done, total)))
    assert seen[-1] == (2, 2)


# --- captures ------------------------------------------------------------------

_PAGE = ('<html><head><title>Portal</title>'
         '<meta content="Joomla! 4.2 - Open Source" name="Generator"></head></html>')


def _gowitness_db(path: Path) -> Path:
    """A capture database in gowitness's shape, with only what these tests read."""
    import sqlite3

    con = sqlite3.connect(path)
    con.executescript("""
        create table results (id integer primary key, url text, final_url text,
            response_code integer, response_reason text, protocol text, title text,
            html text, filename text, failed numeric, failed_reason text);
        create table technologies (id integer primary key, result_id integer, value text);
        create table headers (id integer primary key, result_id integer, key text,
            value text);
    """)
    results = [
        # 80 on the web host: versioned and unversioned detections, a runtime header
        (1, "http://198.51.100.10/", 200, "", 0, ""),
        # the portal's 443 by host name, with a generator tag in the page
        (2, "https://portal.example.test/", 200, _PAGE, 0, ""),
        # a failed capture of the portal's port 80 says nothing
        (3, "http://198.51.100.20/", None, "", 1, "net::ERR_CONNECTION_RESET"),
        # a URL no service in the model answers on
        (4, "http://203.0.113.99:9000/", 200, "", 0, ""),
    ]
    for rid, url, code, html, failed, why in results:
        con.execute("insert into results (id, url, final_url, response_code, html, filename,"
                    " failed, failed_reason) values (?, ?, ?, ?, ?, '', ?, ?)",
                    (rid, url, url, code, html, failed, why))
    for rid, value in [(1, "Nginx:1.16.1"), (1, "PHP"), (1, "HSTS"), (1, "jQuery:2.1.3"),
                       (3, "IIS")]:
        con.execute("insert into technologies (result_id, value) values (?, ?)", (rid, value))
    for rid, key, value in [(1, "x-powered-by", "PHP/7.4.33"), (1, "Server", "nginx/1.16.1"),
                            (2, "X-AspNet-Version", "4.0.30319")]:
        con.execute("insert into headers (result_id, key, value) values (?, ?, ?)",
                    (rid, key, value))
    con.commit()
    con.close()
    return path


@pytest.fixture
def session(tmp_path):
    from seek.config import Config
    from seek.nmap.session import Session
    from seek.nmap.views import prepare

    paths = [FIX / "inventory.xml"]
    db = _gowitness_db(tmp_path / "gowitness.sqlite3")
    s = Session(Config(nmap_path="/nonexistent/nmap"), paths, tmp_path, databases=[db],
                scans=prepare(load(paths)))
    from seek.gowitness.results import read_database
    s.shots.add(read_database(db)[0])
    return s


def test_a_versioned_technology_detection(session):
    comps = _svc(session.inventory(), WEB, 80)
    nginx = comps["nginx"]
    assert nginx.version == "1.16.1"
    assert "gowitness" in nginx.sources
    assert comps["jquery"].version == "2.1.3"


def test_a_header_names_the_runtime(session):
    php = _svc(session.inventory(), WEB, 80)["php"]
    assert php.version == "7.4.33", "the header's version beats an unversioned detection"
    assert not php.conflicting


def test_protocols_are_not_software(session):
    assert "hsts" not in _svc(session.inventory(), WEB, 80)


def test_a_capture_by_host_name_and_its_generator(session):
    comps = _svc(session.inventory(), PORTAL, 443)
    assert comps["aspnet"].version == "4.0.30319"
    assert "joomla!" in comps and comps["joomla!"].version == "4.2"
    assert any("meta generator" in o.detail for o in comps["joomla!"].observations)


def test_a_failed_capture_contributes_nothing(session):
    assert (PORTAL, "tcp", 80) not in session.inventory().by_service


def test_an_unplaced_capture_is_counted(session):
    assert session.inventory().unplaced == 1


def test_the_inventory_is_cached_until_the_captures_change(session):
    first = session.inventory()
    assert session.inventory() is first
    session.shots.add([])
    assert session.inventory() is not first


def test_meta_generator_reads_attributes_in_any_order():
    from seek.gowitness.results import meta_generator
    assert meta_generator('<meta name="generator" content="Hugo 0.120.4">') == "Hugo 0.120.4"
    assert meta_generator("<META CONTENT='WordPress 6.4' NAME=generator>") == "WordPress 6.4"
    assert meta_generator('<meta name="description" content="x">') == ""


# --- shapes nmap writes that the real scans showed ----------------------------------


def _one(svc: Service) -> dict:
    return _svc(inv_mod.build([Host("192.0.2.9", services=[svc])]), "192.0.2.9", svc.port)


def test_a_distribution_suffix_is_not_part_of_the_version():
    comps = _one(Service("tcp", 22, "open", name="ssh", product="OpenSSH",
                         version="10.0p2 Debian 7", method="probed",
                         cpes=["cpe:/a:openbsd:openssh:10.0p2"]))
    ssh = comps["openssh"]
    assert ssh.version == "10.0p2"
    assert "Debian 7" in ssh.observations[0].detail


def test_a_version_range_is_left_alone():
    comps = _one(Service("tcp", 139, "open", product="Samba smbd", version="3.X - 4.X",
                         method="probed"))
    assert comps["samba"].version == "3.X - 4.X"


def test_a_server_header_reported_as_the_product_is_split():
    comps = _one(Service("tcp", 8765, "open", name="http",
                         product="Python/3.8 websockets/8.1", method="probed"))
    assert {k: c.version for k, c in comps.items()} == {"python": "3.8", "websockets": "8.1"}


def test_nmaps_proxmox_cpe_meets_the_detectors_name():
    from seek.nmap import cpe
    assert cpe.lookup("cpe:/a:proxmox:proxmox_virtual_environment:3.0").key == \
        cpe.product_key("Proxmox VE")
