"""Findings and support status, for the inventory fixture against the feed fixtures."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import vulndb_fixtures as fx

from seek.config import Config
from seek.nmap import inventory as inv_mod
from seek.nmap.merge import load
from seek.nmap.models import Host, Service
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.vulndb import eol, match, update
from seek.vulndb.store import Cycle, Store

FIX = Path(__file__).parent / "fixtures" / "nmap"
TODAY = date(2026, 10, 1)
WEB = "198.51.100.10"


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    root = tmp_path_factory.mktemp("vulndb")
    feeds = fx.build(root / "www")
    path = root / "vulndb.sqlite3"
    with fx.serve(feeds) as urls:
        results = update.run(path, urls=urls, today=TODAY, now=1_790_000_000.0)
    assert not any(r.error for r in results), results
    return path


def _lookup(db, services, host_addr="192.0.2.9", **host_kw):
    host = Host(host_addr, services=services, **host_kw)
    inv = inv_mod.build([host])
    return match.build(inv, [host], Store(db), TODAY), inv, host


def _one(db, svc: Service, extra=()) -> match.Assessment:
    lk, inv, host = _lookup(db, [svc, *extra])
    comps = inv.of_service(host, svc)
    assert comps, "the service has a component"
    return lk.of(comps[0], (host.address, svc.protocol, svc.port))


def _probed(product, version, port=80, cpes=(), scripts=()):
    return Service("tcp", port, "open", name="http", product=product, version=version,
                   method="probed", cpes=list(cpes), scripts=list(scripts))


def ids(a: match.Assessment) -> list[str]:
    return [f.id for f in a.findings]


# --- matching --------------------------------------------------------------------


def test_a_version_inside_a_range_under_either_vendor_name(db):
    a = _one(db, _probed("nginx", "1.16.1", cpes=["cpe:/a:igor_sysoev:nginx:1.16.1"]))
    assert ids(a) == ["CVE-2099-0001", "CVE-2099-0005"], "f5 and igor_sysoev records"
    assert a.findings[0].score == 7.7 and a.findings[0].sources == ("nvd",)


def test_a_version_past_the_fix(db):
    assert ids(_one(db, _probed("nginx", "1.24.0"))) == []


def test_release_order_not_text_order(db):
    a = _one(db, _probed("Apache httpd", "2.4.41"))
    assert ids(a) == ["CVE-2099-0002"] and a.max_severity == "CRITICAL"
    assert ids(_one(db, _probed("Apache httpd", "2.4.100"))) == []


def test_an_update_field_joins_the_version(db):
    a = _one(db, Service("tcp", 22, "open", product="OpenSSH", version="8.9p1",
                         method="probed"))
    assert ids(a) == ["CVE-2099-0004"]
    assert ids(_one(db, Service("tcp", 22, "open", product="OpenSSH", version="8.9",
                                method="probed"))) == []


def test_a_running_on_platform_does_not_inherit(db):
    lk, inv, host = _lookup(db, [], os_matches=[__import__(
        "seek.nmap.models", fromlist=["OsMatch"]).OsMatch(
        "Linux 5.4", 95, ["cpe:/o:linux:linux_kernel:5.4"])])
    [linux] = inv.of_host(host)
    assert lk.of(linux).findings == []


def test_an_undecidable_version_is_neither_affected_nor_safe(db):
    a = _one(db, Service("tcp", 445, "open", product="Samba smbd", version="3.X - 4.X",
                         method="probed"))
    assert a.findings == []
    assert [f.id for f in a.undecided] == ["CVE-2099-0008"]


def test_an_unversioned_component_only_counts(db):
    a = _one(db, _probed("nginx", None))
    assert a.findings == [] and a.undecided == []
    assert a.product_cves == 2, "0001 and 0005 (the rejected one is not stored)"
    assert a.support.status == "unknown" and a.support.reason == "version unknown"


def test_osv_and_nvd_meet_on_the_cve_alias(db):
    svc = _probed("jQuery", "2.1.3")
    lk, inv, host = _lookup(db, [svc])
    a = lk.of(inv.of_service(host, svc)[0])
    by_id = {f.id: f for f in a.findings}
    assert by_id["CVE-2099-0007"].sources == ("nvd", "osv")
    assert "GHSA-test-jq02" in by_id, "an advisory without a CVE keeps its own id"
    assert by_id["GHSA-test-jq02"].severity == "HIGH"


# --- the scan's own findings ------------------------------------------------------


def test_both_agree_and_only_the_scan_knows(db):
    from seek.nmap.models import ScriptResult
    vulners = ScriptResult("vulners", "cpe:/a:samba:samba:4.6.2", {
        "cpe:/a:samba:samba:4.6.2": [
            {"id": "CVE-2099-0008", "cvss": "7.5", "type": "cve"},
            {"id": "CVE-2099-9999", "cvss": "9.1", "type": "cve"}]})
    svc = Service("tcp", 445, "open", product="Samba smbd", version="4.6.2",
                  method="probed", cpes=["cpe:/a:samba:samba:4.6.2"], scripts=[vulners])
    a = _one(db, svc)
    by_id = {f.id: f for f in a.findings}
    assert by_id["CVE-2099-0008"].sources == ("nvd", "vulners")
    assert by_id["CVE-2099-9999"].sources == ("vulners",)
    assert by_id["CVE-2099-9999"].severity == "CRITICAL", "banded from the script's CVSS"
    assert ids(a)[0] == "CVE-2099-9999", "most severe first"


def test_the_whole_fixture(db):
    hosts = prepare(load([FIX / "inventory.xml"])).hosts
    inv = inv_mod.build(hosts)
    lk = match.build(inv, hosts, Store(db), TODAY)
    web = next(h for h in hosts if h.address == WEB)
    tomcat = next(s for s in web.services if s.port == 8443)
    [c] = inv.of_service(web, tomcat)
    a = lk.of(c, (WEB, "tcp", 8443))
    assert [f.sources for f in a.findings if f.id == "CVE-2020-1938"] == [("vulners",)]
    assert a.support.status == "behind" and a.support.latest == "9.0.96"


def test_a_missing_database(tmp_path):
    host = Host("192.0.2.9", services=[_probed("nginx", "1.16.1")])
    inv = inv_mod.build([host])
    lk = match.build(inv, [host], Store(tmp_path / "none.db"), TODAY)
    assert lk.db_missing
    [c] = inv.of_service(host, host.services[0])
    assert lk.of(c).findings == []


# --- support ---------------------------------------------------------------------


def test_support_states(db):
    assert _one(db, _probed("PHP", "7.4.33")).support.label() == "EOL 2022-11-28"
    behind = _one(db, _probed("Apache httpd", "2.4.41")).support
    assert (behind.status, behind.latest, behind.cycle) == ("behind", "2.4.62", "2.4")
    assert _one(db, _probed("nginx", "1.26.2")).support.status == "current"
    untracked = _one(db, _probed("websockets", "8.1")).support
    assert untracked.status == "unknown" and "not tracked" in untracked.reason


def test_ending_soon_and_today_is_the_sessions_date():
    cycles = [Cycle("php", "8.3", "", "2026-12-01", "8.3.12", "", "")]
    s = eol.support("php", "8.3.12", cycles, date(2026, 10, 1))
    assert (s.status, s.ending_soon) == ("current", True)
    s = eol.support("php", "8.3.12", cycles, date(2026, 12, 2))
    assert s.status == "eol"


def test_the_most_specific_cycle_wins():
    cycles = [Cycle("x", "1", "", "false", "1.9", "", ""),
              Cycle("x", "1.24", "", "false", "1.24.3", "", "")]
    assert eol.choose_cycle("1.24.0", cycles).cycle == "1.24"
    assert eol.choose_cycle("1.2.0", cycles).cycle == "1"
    assert eol.choose_cycle("2.0", cycles) is None


# --- the session ---------------------------------------------------------------------


def test_the_session_caches_until_the_database_changes(db, tmp_path):
    paths = [FIX / "inventory.xml"]
    s = Session(Config(nmap_path="/nonexistent", vulndb_path=str(db)), paths, tmp_path,
                databases=[], scans=prepare(load(paths)))
    first = s.lookup()
    assert s.lookup() is first and not first.db_missing
    s.reload_vulndb()
    assert s.lookup() is not first


def test_a_database_that_appears_is_picked_up(db, tmp_path):
    import shutil
    target = tmp_path / "later.db"
    paths = [FIX / "inventory.xml"]
    s = Session(Config(nmap_path="/nonexistent", vulndb_path=str(target)), paths, tmp_path,
                databases=[], scans=prepare(load(paths)))
    assert s.lookup().db_missing
    shutil.copy(db, target)
    assert not s.lookup().db_missing, "a copied database is used as it is"


def test_operating_systems_are_not_matched_against_cves(db):
    from seek.nmap.models import OsMatch
    lk, inv, host = _lookup(db, [], os_matches=[OsMatch("Linux 4.X", 95,
                                                        ["cpe:/o:linux:linux_kernel:4"])])
    [linux] = inv.of_host(host)
    a = lk.of(linux)
    assert a.findings == [] and a.undecided == [] and not a.looked_up
    assert "fingerprint" in a.not_matched
