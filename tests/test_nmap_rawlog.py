"""Cutting nmap's own text down to one host or one port.

Pure: text in, lines out. The value of this is entirely in the boundaries -
where a host's block starts and stops, which lines belong to a port and which
to the port after it - so that is what these are about. The fixtures reproduce
the shapes nmap really writes, including the three that get it wrong when the
matching is naive.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap import rawlog
from seek.nmap.merge import load
from seek.nmap.views import prepare

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _text(name: str) -> str:
    return (FIX / f"{name}.nmap").read_text(encoding="utf-8")


def _model(*names: str):
    return prepare(load([FIX / f"{n}.xml" for n in names]))


def _host(scans, address: str):
    return next(h for h in scans.hosts if h.address == address)


# --- host blocks -------------------------------------------------------------


def test_a_host_block_runs_to_the_next_report_line():
    block = rawlog.host_block(_text("basic"), "192.0.2.1")
    assert block[0] == "Nmap scan report for alpha.example (192.0.2.1)"
    assert "22/tcp  open   ssh     OpenSSH 9.2p1" in block
    assert not any("192.0.2.2" in line for line in block), \
        "the next host's block was swept in"


def test_the_last_host_block_stops_at_the_footer():
    """There is no report line after it, so something else has to close it."""
    block = rawlog.host_block(_text("basic"), "192.0.2.2")
    assert block[0] == "Nmap scan report for 192.0.2.2"
    assert block[-1].endswith("nginx 1.22.1")
    assert not any(line.startswith("#") for line in block)
    assert not any("Service detection performed" in line for line in block)


def test_blocks_are_found_without_blank_lines_between_them():
    """A `-sn` run writes one report and one status line per host, no spacing."""
    block = rawlog.host_block(_text("discovery"), "203.0.113.2")
    assert block == ["Nmap scan report for 203.0.113.2",
                     "Host is up, received syn-ack (0.0018s latency)."]


def test_the_text_nmap_only_writes_in_its_report_is_kept():
    """`Not shown:` and the reason a port answered have no field in the XML."""
    block = rawlog.host_block(_text("basic"), "192.0.2.1")
    assert any(line.startswith("Not shown: 997 filtered") for line in block)
    assert any(line.startswith("Scanned at") for line in block)


def test_a_host_the_scan_did_not_write_about_yields_nothing():
    """A down host gets no report of its own in ordinary output."""
    assert rawlog.host_block(_text("basic"), "192.0.2.3") == []


def test_a_hostname_and_address_report_line_is_matched_by_address():
    block = rawlog.host_block(_text("scripts"), "192.0.2.10")
    assert block[0] == "Nmap scan report for scripted.example (192.0.2.10)"


def test_an_address_that_is_a_prefix_of_another_is_not_confused_with_it():
    """`10.10.10.1` must not open the block belonging to `10.10.10.10`."""
    text = _text("rawlog")
    short = rawlog.host_block(text, "10.10.10.1")
    long = rawlog.host_block(text, "10.10.10.10")
    assert short[0] == "Nmap scan report for 10.10.10.1"
    assert long[0] == "Nmap scan report for gw.example (10.10.10.10)"
    assert not any("gw.example" in line for line in short)
    assert not any("nginx" in line for line in long), "the wrong host's ports"


def test_the_host_block_keeps_what_follows_its_ports():
    block = rawlog.host_block(_text("scripts"), "192.0.2.10")
    assert any(line == "Host script results:" for line in block)
    assert any(line.startswith("Service Info:") for line in block)


# --- port blocks -------------------------------------------------------------


def test_a_port_block_carries_the_host_lines_that_name_its_host():
    """A bare port line does not say whose port it is."""
    block = rawlog.port_block(_text("basic"), "192.0.2.1", 22, "tcp")
    assert block[0] == "Nmap scan report for alpha.example (192.0.2.1)"
    assert any(line.startswith("PORT ") for line in block), "and the column header"
    assert any(line.startswith("22/tcp") for line in block)


def test_a_port_block_stops_at_the_next_port():
    block = rawlog.port_block(_text("basic"), "192.0.2.1", 22, "tcp")
    assert not any(line.startswith("80/tcp") for line in block)
    assert not any(line.startswith("443/tcp") for line in block)


def test_a_ports_script_output_travels_with_it():
    block = rawlog.port_block(_text("scripts"), "192.0.2.10", 443, "tcp")
    assert any(line.startswith("| ssl-cert:") for line in block)
    assert any(line.startswith("|_http-methods:") for line in block)
    assert any("Subject Alternative Name" in line for line in block), \
        "a continuation line that is not itself a script header"


def test_a_port_number_inside_another_ports_output_is_not_a_port_line():
    """`the daemon also answers on 80/tcp` is prose, not the start of a block."""
    block = rawlog.port_block(_text("rawlog"), "10.10.10.10", 22, "tcp")
    assert any("also answers on 80/tcp" in line for line in block), \
        "the ssh script's own text belongs to port 22"
    assert not any(line.startswith("80/tcp") for line in block), \
        "but the real port 80 line does not"
    assert not any("Apache" in line for line in block)


def test_a_port_block_from_the_right_host():
    """Both hosts expose 80/tcp; each block has to be its own."""
    text = _text("rawlog")
    first = rawlog.port_block(text, "10.10.10.1", 80, "tcp")
    second = rawlog.port_block(text, "10.10.10.10", 80, "tcp")
    assert any("nginx 1.24.0" in line for line in first)
    assert any("Apache httpd 2.4.57" in line for line in second)
    assert not any("Apache" in line for line in first)


def test_a_port_the_scan_did_not_write_about_yields_nothing():
    assert rawlog.port_block(_text("basic"), "192.0.2.1", 9999, "tcp") == []


# --- entries -----------------------------------------------------------------


def test_entries_are_the_scans_that_recorded_the_subject():
    scans = _model("basic", "scripts", "xml-only")
    entries = rawlog.Scanned(scans.files).entries(_host(scans, "192.0.2.1"))
    assert [e.label for e in entries] == ["basic"]
    assert entries[0].written, "basic.xml has a .nmap beside it"
    assert entries[0].summary() == "2 port(s) open"


def test_entries_are_in_scan_order():
    """The order the scans ran, which is the order the record reads in."""
    scans = _model("scripts", "basic")           # given in the other order
    scans.files.sort(key=lambda f: f.name)       # and stored in another again
    host = _host(scans, "192.0.2.1")
    entries = rawlog.Scanned(scans.files).entries(host)
    assert [e.scan.start for e in entries] == sorted(e.scan.start for e in entries)


def test_a_scan_with_no_output_file_is_still_an_entry():
    scans = _model("xml-only")
    entry = rawlog.Scanned(scans.files).entries(_host(scans, "198.51.100.7"))[0]
    assert not entry.written and entry.path is None


def test_entries_for_a_service_are_the_scans_that_saw_that_port():
    scans = _model("basic", "scripts")
    host = _host(scans, "192.0.2.1")
    ssh = next(s for s in host.services if s.port == 22)
    assert [e.label for e in rawlog.Scanned(scans.files).entries(host, ssh)] == ["basic"]


def test_listing_entries_never_opens_a_file(monkeypatch):
    """The cursor moves between records continuously; a `.nmap` can be huge."""
    scans = _model("basic", "scripts")

    def refuse(*args, **kwargs):
        raise AssertionError("a file was read while listing entries")

    monkeypatch.setattr(Path, "read_text", refuse)
    for host in scans.hosts:
        rawlog.Scanned(scans.files).entries(host)


# --- reading an entry --------------------------------------------------------


def test_reading_an_entry_returns_the_scoped_block():
    scans = _model("basic")
    host = _host(scans, "192.0.2.1")
    entry = rawlog.Scanned(scans.files).entries(host)[0]
    excerpt = rawlog.read(rawlog.Request(entry, host))
    assert not excerpt.reconstructed and not excerpt.problem
    assert excerpt.lines[0].endswith("(192.0.2.1)")


def test_a_scan_with_no_output_file_is_reconstructed_and_says_so():
    scans = _model("xml-only")
    host = _host(scans, "198.51.100.7")
    excerpt = rawlog.read(rawlog.Request(rawlog.Scanned(scans.files).entries(host)[0], host))
    assert excerpt.reconstructed, "the caller has to be able to label it"
    assert excerpt.lines[0] == "Nmap scan report for lone.example (198.51.100.7)"
    assert any(line.startswith("25/tcp") for line in excerpt.lines)
    assert any(line.startswith("587/tcp") for line in excerpt.lines)


def test_a_reconstructed_port_shows_only_that_port():
    scans = _model("xml-only")
    host = _host(scans, "198.51.100.7")
    svc = next(s for s in host.services if s.port == 587)
    entry = rawlog.Scanned(scans.files).entries(host, svc)[0]
    excerpt = rawlog.read(rawlog.Request(entry, host, svc))
    assert any(line.startswith("587/tcp") for line in excerpt.lines)
    assert not any(line.startswith("25/tcp") for line in excerpt.lines)


def test_a_subject_the_file_does_not_mention_is_reported_not_empty():
    scans = _model("basic")
    host = _host(scans, "192.0.2.3")
    excerpt = rawlog.read(rawlog.Request(rawlog.Scanned(scans.files).entries(host)[0], host))
    assert excerpt.lines == []
    assert "says nothing about 192.0.2.3" in excerpt.problem


def test_a_file_that_cannot_be_read_is_reported_not_raised(tmp_path):
    scans = _model("basic")
    host = _host(scans, "192.0.2.1")
    entry = rawlog.Scanned(scans.files).entries(host)[0]
    entry.path = tmp_path / "gone.nmap"
    excerpt = rawlog.read(rawlog.Request(entry, host))
    assert excerpt.lines == [] and "could not be read" in excerpt.problem


def test_a_caller_can_supply_the_text_it_has_already_read():
    """So the viewer can cache files without this module owning a cache."""
    scans = _model("basic")
    host = _host(scans, "192.0.2.1")
    entry = rawlog.Scanned(scans.files).entries(host)[0]
    supplied = rawlog.read(rawlog.Request(entry, host), source=_text("basic"))
    assert supplied.lines == rawlog.read(rawlog.Request(entry, host)).lines


def test_reading_raw_text_leaves_the_model_untouched():
    """The XML is the source of the model; this is text to read, nothing more."""
    scans = _model("basic", "scripts", "xml-only")

    def snapshot():
        return [(h.address, h.state, h.reason, tuple(h.hostnames),
                 tuple((s.protocol, s.port, s.state, s.name, s.product, s.version,
                        len(s.scripts), len(s.vulnerabilities), tuple(s.names))
                       for s in h.services))
                for h in scans.hosts]

    before = snapshot()
    for host in scans.hosts:
        for entry in rawlog.Scanned(scans.files).entries(host):
            rawlog.read(rawlog.Request(entry, host))
            for svc in host.services:
                for one in rawlog.Scanned(scans.files).entries(host, svc):
                    rawlog.read(rawlog.Request(one, host, svc))
    assert snapshot() == before


def test_a_service_that_is_not_on_the_host_is_refused():
    """A service is identified by its protocol and port *on a host*."""
    scans = _model("basic", "xml-only")
    host = _host(scans, "192.0.2.1")
    elsewhere = next(s for s in _host(scans, "198.51.100.7").services
                     if s.port == 587)
    assert elsewhere.key not in {s.key for s in host.services}
    entry = rawlog.Scanned(scans.files).entries(host)[0]
    assert "not on this host" in rawlog.read(rawlog.Request(entry, host, elsewhere)).problem


@pytest.mark.parametrize("name", ["basic", "discovery", "scripts", "rawlog"])
def test_every_fixture_shape_yields_a_block_for_every_host_it_reports(name):
    """Whatever the fixture's shape, each host it wrote about is findable."""
    text = _text(name)
    reported = [line for line in text.splitlines()
                if line.startswith("Nmap scan report for ")]
    assert reported, f"{name}.nmap reports no host"
    scans = _model(name)
    for host in scans.hosts:
        block = rawlog.host_block(text, host.address)
        if not block:
            continue                                # a down host gets no report
        assert block[0].startswith("Nmap scan report for ")
        assert host.address in block[0]
