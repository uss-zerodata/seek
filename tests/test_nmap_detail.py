"""The detail pane's report: the whole record, nothing elided."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from seek.nmap import rawlog
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import detail as detail_pane

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _text_of(lines) -> str:
    """The rendered text of a record's lines."""
    console = Console(width=120, file=open("/dev/null", "w"), record=True)
    console.print(detail_pane.as_group(lines))
    return console.export_text()


def _report(target, host=None) -> str:
    """The full report for a row, independent of how tall the pane happens to be."""
    console = Console(width=120, file=open("/dev/null", "w"), record=True)
    console.print(detail_pane.as_group(detail_pane.render(target, host)))
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


# --- the record is lines, and the reader is those lines joined ----------------


def test_a_record_is_lines_and_the_reader_shows_them_joined():
    """One builder, two views. The pane navigates the lines; the reader reads
    them as one block. If these could differ, the two would be two descriptions
    of the same record, which is the thing `render` exists to prevent."""
    from rich.console import Group

    scans = prepare(load([FIX / "scripts.xml"]))
    host = scans.hosts[0]
    lines = detail_pane.render(host, scanned=rawlog.Scanned(scans.files))
    assert lines and all(isinstance(x, detail_pane.Line) for x in lines)

    joined = detail_pane.as_group(lines)
    assert isinstance(joined, Group)
    assert list(joined.renderables) == [x.text for x in lines]


def test_a_host_record_offers_the_scans_that_saw_it():
    scans = prepare(load([FIX / "basic.xml", FIX / "scripts.xml"]))
    host = next(h for h in scans.hosts if h.address == "192.0.2.1")
    lines = detail_pane.render(host, scanned=rawlog.Scanned(scans.files))
    openable = [x for x in lines if x.opens is not None]
    assert [x.opens.entry.label for x in openable] == ["basic"]
    assert all(x.opens.host is host and x.opens.service is None for x in openable)
    assert "Scans" in _text_of(lines)


def test_a_service_record_offers_the_scans_that_saw_that_port():
    scans = prepare(load([FIX / "basic.xml"]))
    host = next(h for h in scans.hosts if h.address == "192.0.2.1")
    svc = next(s for s in host.services if s.port == 22)
    lines = detail_pane.render(svc, host, scanned=rawlog.Scanned(scans.files))
    openable = [x for x in lines if x.opens is not None]
    assert openable, "a service's record has to offer its scans too"
    assert all(x.opens.service is svc for x in openable)


def test_a_record_built_without_the_scan_files_names_its_scans_as_before():
    """A caller that has a record but not the set it came from loses nothing."""
    scans = prepare(load([FIX / "basic.xml"]))
    host = next(h for h in scans.hosts if h.address == "192.0.2.1")
    lines = detail_pane.render(host)
    assert not any(x.opens for x in lines), "nothing to open without the files"
    assert "basic.xml" in _text_of(lines), "but the scans are still named"


def test_a_bucket_record_has_nothing_to_open():
    """It describes a service across many hosts; there is no one block for it."""
    from seek.nmap.views import service_groups

    scans = prepare(load([FIX / "basic.xml"]))
    group = service_groups(scans.hosts)[0]
    lines = detail_pane.render(group)
    assert lines and not any(x.opens for x in lines)


def test_an_entry_says_when_the_scan_left_no_output_file():
    scans = prepare(load([FIX / "xml-only.xml"]))
    host = scans.hosts[0]
    lines = detail_pane.render(host, scanned=rawlog.Scanned(scans.files))
    assert "no output file" in _text_of(lines)


# --- tags in the record -------------------------------------------------------------


def _tagged():
    from seek.nmap import tagfiles, tagging, tagrules

    scans = prepare(load([FIX / "basic.xml"]))
    _d, defs = tagrules.load(
        "tags:\n  web-only:\n    description: A web page and nothing else\n"
        "    issues: [{title: Exposed admin page, severity: medium}]\n"
        "    rules: [{when: [{port: 80}, {not: {port: 8080/tcp}}]}]\n", "eng/seek-rules.yaml")
    order, _ = tagrules.order(defs.tags)
    entries = (tagfiles.Entry("explored", "192.0.2.2"),
               tagfiles.Entry("web-ui", "192.0.2.2", "tcp", 80))
    loaded = tagfiles.Loaded(tags=defs.tags, order=order,
                             entries={Path("eng/seek-tags.yaml"): entries})
    host = next(h for h in scans.hosts if h.address == "192.0.2.2")
    return scans, host, tagging.build(scans.hosts, scans.files, loaded)


def _text(lines) -> str:
    console = Console(width=120, color_system=None)
    with console.capture() as cap:
        console.print(detail_pane.as_group(lines))
    return cap.get()


def test_a_host_record_lists_its_tags_sources_assumptions_and_issues():
    _scans, host, tags = _tagged()
    text = _text(detail_pane.render(host, tags=tags))
    assert "Tags (3)" in text
    assert "explored  manual (eng/seek-tags.yaml)" in text
    assert "web-only ?" in text and "assumes   8080/tcp not scanned" in text
    assert "medium   Exposed admin page" in text
    assert "web-ui  on 80/tcp" in text


def test_a_service_record_lists_its_own_tags_and_its_host_s():
    _scans, host, tags = _tagged()
    svc = next(s for s in host.services if s.port == 80)
    text = _text(detail_pane.render(svc, host, tags=tags))
    assert "web-ui  manual" in text and "explored  from the host" in text


def test_a_record_without_tags_has_no_tags_block():
    _scans, host, _tags = _tagged()
    assert "Tags" not in _text(detail_pane.render(host))


def test_a_tag_bucket_says_what_the_tag_is_costs_and_assumes():
    from seek.nmap import views as proj
    from seek.tui.nmap.views import Grouping

    scans, _host, tags = _tagged()
    members = dict(proj.group_by(scans.hosts, "tag", tags=tags))["web-only"]
    text = _text(detail_pane.render(Grouping("tag", "web-only", list(members)), tags=tags))
    assert "A web page and nothing else" in text
    assert "uncertain" in text and "Issues (1)" in text and "Exposed admin page" in text
