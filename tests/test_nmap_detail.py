"""The detail pane's report: the whole record, nothing elided."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import detail as detail_pane

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _report(target, host=None) -> str:
    """The full report for a row, independent of how tall the pane happens to be."""
    console = Console(width=120, file=open("/dev/null", "w"), record=True)
    console.print(detail_pane.render(target, host))
    return console.export_text()


def test_script_output_is_shown_in_full_not_just_its_first_line():
    """The README offers "the full text of script results".

    The pane used to show the first non-blank line of the first five scripts,
    five flattened data lines each, cut at 104 characters. Script output is
    often the only place a finding is actually described, and the pane scrolls
    (`←`/`→`, `J`/`K`), so length is not a reason to cut it short.
    """
    scans = prepare(load([FIX / "scripts.xml"]))
    host = next(h for h in scans.hosts if any(s.scripts for s in h.services))
    svc = next(s for s in host.services if len(s.scripts) > 1)

    report = _report(svc, host)
    for script in svc.scripts:
        assert script.id in report, f"{script.id} was dropped from the report"
        for line in (script.output or "").splitlines():
            if line.strip():
                assert line.strip()[:60] in report, f"output of {script.id} was cut"


def test_a_script_without_table_data_shows_no_stray_none():
    """`_flatten(None)` rendered `str(None)` as a literal "None" line."""
    scans = prepare(load([FIX / "scripts.xml"]))
    for host in scans.hosts:
        for svc in host.services:
            report = _report(svc, host)
            assert not any(line.strip() == "None" for line in report.splitlines())


def test_every_vulnerability_reference_is_listed():
    """References used to be cut at three."""
    scans = prepare(load([FIX / "vuln.xml"]))
    for host in scans.hosts:
        for svc in host.services:
            for vuln in svc.vulnerabilities:
                report = _report(svc, host)
                for ref in vuln.refs:
                    assert ref in report, f"{ref} was dropped"


def test_a_host_with_many_services_lists_them_all():
    """The service list used to stop at ten with a "… N more" line."""
    from seek.nmap.models import Host, Service

    host = Host(address="192.0.2.1", state="up", reason="syn-ack")
    host.services = [
        Service(protocol="tcp", port=1000 + i, state="open", name=f"svc{i}")
        for i in range(25)
    ]
    report = _report(host)
    for svc in host.services:
        assert f"{svc.port}/tcp" in report
    assert "more" not in report
