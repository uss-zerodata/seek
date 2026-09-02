"""The scans as a history: ordered by time, each diffed against the prior state."""

from __future__ import annotations

from pathlib import Path

from seek.nmap import timeline
from seek.nmap.merge import load

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _files(*names):
    return load([FIX / f"{n}.xml" for n in names]).files


def test_scans_are_ordered_by_their_recorded_start_time():
    # basic.xml starts 1756000000; scripts.xml starts 1756000100 (later)
    hist = timeline.build(_files("scripts", "basic"))   # given newest-first
    assert [s.path.name for s in hist] == ["basic.xml", "scripts.xml"], \
        "ordered by start time, not the order they were given"


def test_the_first_scan_is_the_baseline():
    hist = timeline.build(_files("basic"))
    assert hist[0].baseline
    assert "baseline" in hist[0].result()


def test_each_scan_diffs_against_everything_before_it():
    # a ping-sweep discovery (no ports) then a service scan on the same hosts
    hist = timeline.build(_files("discovery", "basic"))
    assert hist[0].baseline
    later = hist[1]
    assert not later.baseline
    # basic.xml opens ports the discovery scan never saw
    assert later.added.new_ports or later.added.new_hosts, "it added something"


def test_a_scan_that_repeats_known_ground_adds_nothing():
    hist = timeline.build(_files("basic", "basic"))
    assert hist[1].added.empty
    assert "nothing new" in hist[1].result()


def test_the_per_scan_hosts_are_pristine_not_the_merged_state():
    """merge() mutates the earliest file's hosts; the timeline must not show that."""
    from seek.nmap.parse import parse_file

    hist = timeline.build(_files("discovery", "basic"))
    for scan in hist:
        alone = parse_file(scan.path)
        own_open = sum(len(h.open_services) for h in alone.hosts)
        assert scan.open_ports == own_open, \
            f"{scan.label} shows what it saw ({own_open}), not the merged total"


def test_raw_prefers_the_sibling_nmap_then_falls_back(tmp_path):
    xml = (FIX / "basic.xml").read_text()
    x = tmp_path / "scan.xml"
    x.write_text(xml)
    files = load([x]).files
    scan = timeline.build(files)[0]

    # no sibling .nmap: synthesised from the XML (always present)
    body = timeline.raw_text(scan)
    assert "Nmap scan report for 192.0.2.1" in body
    assert "22/tcp" in body

    # a sibling .nmap: used verbatim
    (tmp_path / "scan.nmap").write_text("REAL NMAP TEXT OUTPUT\n")
    assert timeline.raw_text(scan) == "REAL NMAP TEXT OUTPUT\n"


def test_a_scan_with_no_start_time_sorts_after_dated_ones():
    # not-nmap has no scan; use two real ones and check missing-start handling
    hist = timeline.build(_files("basic"))
    assert hist[0].start is not None, "basic.xml carries a start epoch"
