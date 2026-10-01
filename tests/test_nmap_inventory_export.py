"""The inventory as an export and as an API document - one shape, versioned."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seek.config import Config
from seek.nmap import export as exporter
from seek.nmap.export import Record
from seek.nmap.merge import load
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.web.app import create_app
from seek.web.source import CachedSource

FIX = Path(__file__).parent / "fixtures" / "nmap"
PATHS = [FIX / "inventory.xml"]
WEB = "198.51.100.10"

# Version 2 of the document (1 plus `support` and `findings` per entry, and
# `vulndb_date`). A change here that is not an addition is a new version: bump
# `export.INVENTORY_VERSION` together with this list.
V2_ENTRY_FIELDS = ["address", "names", "port", "protocol", "service", "product", "version",
                   "kind", "cpe22", "cpe23", "cpe_origin", "confidence", "conflicting",
                   "observations", "support", "findings"]
V2_OBSERVATION_FIELDS = ["source", "product", "version", "detail"]
V2_CSV_FIELDS = [*V2_ENTRY_FIELDS, "max_severity", "finding_ids"]


@pytest.fixture
def sess(tmp_path) -> Session:
    return Session(Config(nmap_path="/nonexistent/nmap"), PATHS, tmp_path, databases=[],
                   scans=prepare(load(PATHS)))


def _host(sess, address=WEB):
    return next(h for h in sess.scans.hosts if h.address == address)


def _json(sess, records) -> dict:
    text, fmt = exporter.produce(records, "inventory", "json", inventory=sess.inventory())
    assert fmt == "json"
    return json.loads(text)


def test_the_document_names_its_schema_and_version(sess):
    doc = _json(sess, exporter.records_for(sess.scans.hosts))
    assert (doc["schema"], doc["version"]) == ("seek.inventory", 2)
    assert doc["vulndb_date"] is None, "no database: not looked up, not 'none found'"
    assert doc["generated_from"] == ["inventory.xml"]
    assert doc["unplaced_captures"] == 0


def test_version_2_fields_are_pinned(sess):
    doc = _json(sess, exporter.records_for(sess.scans.hosts))
    assert exporter.INVENTORY_VERSION == 2
    for entry in doc["entries"]:
        assert list(entry) == V2_ENTRY_FIELDS
        for o in entry["observations"]:
            assert list(o) == V2_OBSERVATION_FIELDS


def test_every_component_of_the_listed_hosts(sess):
    doc = _json(sess, exporter.records_for(sess.scans.hosts))
    places = {(e["address"], e["port"], e["product"], e["version"]) for e in doc["entries"]}
    assert (WEB, 80, "nginx", "1.16.1") in places
    assert (WEB, None, "Linux", None) in places, "host-level components go with the host"
    ssh = next(e for e in doc["entries"] if e["product"] == "OpenSSH")
    assert ssh["conflicting"] is True
    assert ssh["cpe23"] == ["cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"]
    assert [o["version"] for o in ssh["observations"]] == ["8.2p1", "8.9p1"]
    assert ssh["names"] == ["web.example.test"]


def test_marked_services_export_only_their_own_components(sess):
    host = _host(sess)
    picked = [Record(host, s) for s in host.services if s.port in (21, 22, 80)]
    doc = _json(sess, picked)
    assert {e["port"] for e in doc["entries"]} == {21, 22, 80}
    assert all(e["port"] is not None for e in doc["entries"]), "no host-level entries"


def test_csv_has_one_row_per_component_and_the_v1_header(sess):
    text, _ = exporter.produce(exporter.records_for(sess.scans.hosts), "inventory", "csv",
                               inventory=sess.inventory())
    rows = list(csv.reader(io.StringIO(text)))
    assert rows[0] == V2_CSV_FIELDS
    doc = _json(sess, exporter.records_for(sess.scans.hosts))
    assert len(rows) - 1 == len(doc["entries"])
    ssh = next(r for r in rows if r[5] == "OpenSSH")
    assert ssh[12] == "yes" and ssh[13] == "nmap=8.2p1; banner=8.9p1"


def test_the_recipe_is_offered_and_needs_the_inventory(sess):
    assert "inventory" in exporter.EXPORTS
    with pytest.raises(ValueError):
        exporter.produce(exporter.records_for(sess.scans.hosts), "inventory", "json")


def test_the_api_serves_the_same_document_as_the_export(sess):
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots),
                                   sess))
    served = client.get("/api/v1/inventory").json()
    assert served == _json(sess, exporter.records_for(sess.scans.hosts))


def test_the_web_export_route_offers_and_produces_it(sess):
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots),
                                   sess))
    options = client.get("/api/v1/export/options", params={"tab": "hosts"}).json()
    assert "inventory" in [r["key"] for r in options["recipes"]]
    text = client.get("/api/v1/export", params={"which": "inventory", "fmt": "json",
                                                "tab": "hosts"}).text
    assert json.loads(text) == _json(sess, exporter.records_for(sess.scans.hosts))


# --- with the vulnerability database (document version 2) -------------------------------


@pytest.fixture(scope="module")
def vdb(tmp_path_factory):
    import vulndb_fixtures as fx
    return fx.database(tmp_path_factory.mktemp("vdb"))


@pytest.fixture
def looked_up(tmp_path, vdb) -> Session:
    return Session(Config(nmap_path="/nonexistent/nmap", vulndb_path=str(vdb)), PATHS,
                   tmp_path, databases=[], scans=prepare(load(PATHS)))


def test_entries_carry_support_and_findings(looked_up):
    text, _ = exporter.produce(exporter.records_for(looked_up.scans.hosts), "inventory",
                               "json", inventory=looked_up.inventory(),
                               lookup=looked_up.lookup())
    doc = json.loads(text)
    assert doc["vulndb_date"] is not None
    nginx = next(e for e in doc["entries"] if e["product"] == "nginx")
    assert nginx["support"]["status"] == "eol" and nginx["support"]["eol_date"] == "2020-04-21"
    assert [f["id"] for f in nginx["findings"]] == ["CVE-2099-0001", "CVE-2099-0005"]
    assert nginx["findings"][0]["sources"] == ["nvd"]
    tomcat = next(e for e in doc["entries"] if e["product"] == "Apache Tomcat")
    assert any(f["id"] == "CVE-2020-1938" and f["sources"] == ["vulners"]
               for f in tomcat["findings"])


def test_csv_carries_the_lookup_columns(looked_up):
    text, _ = exporter.produce(exporter.records_for(looked_up.scans.hosts), "inventory",
                               "csv", inventory=looked_up.inventory(),
                               lookup=looked_up.lookup())
    rows = list(csv.DictReader(io.StringIO(text)))
    nginx = next(r for r in rows if r["product"] == "nginx")
    assert (nginx["support"], nginx["findings"], nginx["max_severity"]) == ("eol", "2", "HIGH")
    assert nginx["finding_ids"] == "CVE-2099-0001 CVE-2099-0005"


def test_the_api_serves_the_v2_document_and_the_findings(looked_up):
    client = TestClient(create_app(CachedSource(lambda: looked_up.scans,
                                                lambda: looked_up.shots), looked_up))
    served = client.get("/api/v1/inventory").json()
    exported = json.loads(exporter.produce(
        exporter.records_for(looked_up.scans.hosts), "inventory", "json",
        inventory=looked_up.inventory(), lookup=looked_up.lookup())[0])
    assert served == exported
    findings = {f["id"]: f for f in client.get("/api/v1/findings").json()}
    assert findings["CVE-2099-0001"]["product"] == "nginx"
    assert findings["CVE-2099-0001"]["places"] == [
        {"address": WEB, "protocol": "tcp", "port": 80}]
    state = client.get("/api/v1/vulndb").json()
    assert state["missing"] is False and state["label"].startswith("◈ vulndb")


def test_the_browser_update_is_refused_while_one_runs(looked_up):
    client = TestClient(create_app(CachedSource(lambda: looked_up.scans,
                                                lambda: looked_up.shots), looked_up))
    assert looked_up._vulndb_lock.acquire()
    try:
        assert client.post("/api/v1/vulndb/update").status_code == 409
    finally:
        looked_up._vulndb_lock.release()
    assert client.post("/api/v1/vulndb/cancel").status_code == 409


# --- sorting the web overviews by their column headings ---------------------------------


def test_a_column_heading_sorts_instead_of_failing(sess):
    """`desc=` (empty) used to be a 422 shown in place of the list."""
    import re

    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots), sess))
    page = client.get("/v/inventory", params={"sort": "2", "desc": ""})
    assert page.status_code == 200 and "<table" in page.text
    from html import unescape
    links = [unescape(h) for h in re.findall(r'class="sort" href="\?([^"]*)"', page.text)]
    assert links and not any(re.search(r"(^|&)desc=(&|$)", h) for h in links), links
    assert any("sort=2&desc=1" in h for h in links), "the sorted column's link reverses it"
    flipped = client.get("/v/inventory", params={"sort": "2", "desc": "1"})
    assert flipped.status_code == 200 and "↓" in flipped.text
