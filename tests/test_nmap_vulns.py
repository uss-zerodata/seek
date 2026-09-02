"""Vulnerability extraction reports what the scan said, and nothing more."""

from __future__ import annotations

from pathlib import Path

from seek.nmap import vulns
from seek.nmap.models import ScriptResult
from seek.nmap.parse import parse_file

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _host():
    h = parse_file(FIX / "vuln.xml").hosts[0]
    vulns.attach(h)
    return h


def _svc(h, port):
    return next(s for s in h.services if s.port == port)


# --- the NSE `vuln` library shape ------------------------------------------


def test_nse_vuln_table_yields_the_full_record():
    v = _svc(_host(), 80).vulnerabilities[0]
    assert v.id == "CVE-2011-3192"          # from the TABLE KEY, not an elem
    assert v.title == "Apache byterange filter DoS"
    assert v.state == "VULNERABLE"
    assert v.ids == ["BID:49303", "CVE:CVE-2011-3192"]
    assert len(v.refs) == 2
    assert v.disclosed == "2011-08-19"
    assert v.source_script == "http-vuln-cve2011-3192"


def test_a_state_is_never_reported_as_a_severity():
    v = _svc(_host(), 80).vulnerabilities[0]
    assert v.state == "VULNERABLE"
    assert v.severity is None, "a state must not be mapped onto a severity"


def test_disclosure_can_be_assembled_from_the_dates_table():
    dates = {"disclosure": {"year": "2020", "month": "01", "day": "02"}}
    data = {"CVE-2020-0001": {"state": "VULNERABLE", "dates": dates}}
    got = vulns.from_script(ScriptResult(id="http-vuln-x", output="", data=data))
    assert got[0].disclosed == "2020-01-02"


def test_not_vulnerable_findings_are_not_reported():
    data = {"CVE-2000-1111": {"state": "NOT VULNERABLE", "title": "checked"}}
    assert vulns.from_script(ScriptResult(id="http-vuln-x", output="", data=data)) == []


# --- vulners ----------------------------------------------------------------


def test_vulners_supplies_a_cvss_severity_and_no_state():
    found = _svc(_host(), 8080).vulnerabilities
    by_id = {v.id: v for v in found}
    assert by_id["CVE-2019-9518"].severity == "7.5"
    assert by_id["CVE-2020-27216"].severity == "4.6"
    assert by_id["CVE-2019-9518"].state is None


# --- free text and negatives -----------------------------------------------


def test_free_text_vulnerability_script_yields_an_id_only():
    v = next(v for v in _svc(_host(), 8080).vulnerabilities if v.id == "CVE-2016-4438")
    assert (v.severity, v.state, v.title) == (None, None, None)
    assert v.source_script == "http-vuln-legacy"


def test_a_script_merely_mentioning_a_cve_is_not_a_finding():
    ids = [v.id for v in _svc(_host(), 8080).vulnerabilities]
    assert "CVE-2018-1000861" not in ids, "banner-note only quotes a changelog"


def test_scripts_that_found_nothing_yield_no_records():
    for sid in ("http-csrf", "http-dombased-xss"):
        assert vulns.from_script(
            ScriptResult(id=sid, output="Couldn't find any vulnerabilities.", data=None)
        ) == []


def test_a_scan_with_no_vulnerability_scripts_yields_zero():
    h = parse_file(FIX / "scripts.xml").hosts[0]
    vulns.attach(h)
    assert all(s.vulnerabilities == [] for s in h.services)
    assert vulns.host_vulnerabilities(h) == []


# --- de-duplication ---------------------------------------------------------


def test_the_same_finding_on_two_ports_is_counted_once_per_host():
    h = _host()
    assert [v.id for v in _svc(h, 80).vulnerabilities] == ["CVE-2011-3192"]
    assert [v.id for v in _svc(h, 443).vulnerabilities] == ["CVE-2011-3192"]
    distinct = vulns.host_vulnerabilities(h)
    assert [v.id for v in distinct].count("CVE-2011-3192") == 1
    assert len(distinct) == 4
