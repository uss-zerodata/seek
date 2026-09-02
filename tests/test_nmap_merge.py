"""Consolidating several scans, and staying stateless while doing it."""

from __future__ import annotations

import shutil
from pathlib import Path

from seek.nmap.merge import collect_paths, load
from seek.nmap.models import Service

FIX = Path(__file__).parent / "fixtures" / "nmap"
A, B = FIX / "merge-a.xml", FIX / "merge-b.xml"


def _host(scans, addr):
    return next(h for h in scans.hosts if h.address == addr)


def _svc(host, port) -> Service:
    return next(s for s in host.services if s.port == port)


# --- consolidation ----------------------------------------------------------


def test_two_files_merge_into_one_host_with_both_services():
    scans = load([A, B])
    assert [h.address for h in scans.hosts] == ["192.0.2.40", "192.0.2.41", "192.0.2.42"]
    ports = [s.port for s in _host(scans, "192.0.2.40").services]
    assert ports == [22, 53, 80, 3128], "union of both files, sorted"


def test_a_later_file_fills_in_missing_facts():
    h = _host(load([A, B]), "192.0.2.40")
    assert h.hostname == "forty.example"   # absent from A
    assert h.os == "Linux 6.X"             # absent from A
    assert _svc(h, 22).product == "OpenSSH"  # A had the port but no product


def test_the_same_host_and_port_is_not_duplicated():
    h = _host(load([A, B]), "192.0.2.40")
    assert len([s for s in h.services if s.port == 22]) == 1


def test_probed_identification_beats_a_table_guess_in_either_order():
    for order in ([A, B], [B, A]):
        svc = _svc(_host(load(order), "192.0.2.40"), 3128)
        assert svc.product == "Proxmox VE REST API", f"order {order} lost the probe"
        assert svc.method == "probed"


def test_merge_is_deterministic_in_file_order():
    first, second = load([A, B]), load([A, B])
    key = lambda s: [(h.address, [(x.port, x.product) for x in h.services]) for h in s.hosts]  # noqa: E731
    assert key(first) == key(second)


def test_one_bad_file_among_several_still_yields_a_usable_set():
    scans = load([A, FIX / "truncated.xml", B])
    assert len(scans.hosts) == 3
    assert [name for name, _ in scans.failures] == ["truncated.xml"]


def test_non_nmap_file_is_reported_and_skipped():
    scans = load([A, FIX / "not-nmap.xml"])
    assert len(scans.hosts) == 2
    assert scans.failures and "not an nmap scan" in scans.failures[0][1]


# --- provenance -------------------------------------------------------------


def test_provenance_names_the_source_files():
    h = _host(load([A, B]), "192.0.2.40")
    assert h.sources == ["merge-a.xml", "merge-b.xml"]
    assert _svc(h, 22).sources == ["merge-a.xml", "merge-b.xml"]
    assert _svc(h, 53).sources == ["merge-a.xml"], "only A saw port 53"
    assert _svc(h, 3128).sources == ["merge-b.xml"], "only B saw port 3128"


def test_hosts_seen_in_one_file_only_are_attributed_to_it():
    scans = load([A, B])
    assert _host(scans, "192.0.2.41").sources == ["merge-a.xml"]
    assert _host(scans, "192.0.2.42").sources == ["merge-b.xml"]


# --- directory input --------------------------------------------------------


def test_a_directory_expands_to_the_scans_inside_it(tmp_path):
    for f in (A, B):
        shutil.copy(f, tmp_path / f.name)
    (tmp_path / "notes.txt").write_text("ignored\n")
    assert [p.name for p in collect_paths([tmp_path])] == ["merge-a.xml", "merge-b.xml"]
    assert len(load([tmp_path]).hosts) == 3


def test_a_single_file_still_routes_through_the_merge_path():
    scans = load([A])
    assert scans.sources == ["merge-a.xml"]
    assert len(scans.hosts) == 2


# --- statelessness ----------------------------------------------------------


def test_a_run_creates_no_files(tmp_path):
    for f in (A, B):
        shutil.copy(f, tmp_path / f.name)
    before = {p.name for p in tmp_path.iterdir()}
    load([tmp_path])
    assert {p.name for p in tmp_path.iterdir()} == before


def test_repeat_runs_over_the_same_inputs_are_identical():
    key = lambda s: [(h.address, h.hostname, h.os, sorted(x.port for x in h.services))  # noqa: E731
                     for h in s.hosts]
    assert key(load([A, B])) == key(load([A, B]))


def test_omitting_a_file_removes_its_contribution():
    with_b = load([A, B])
    without_b = load([A])
    assert "192.0.2.42" in [h.address for h in with_b.hosts]
    assert "192.0.2.42" not in [h.address for h in without_b.hosts]
    assert _host(without_b, "192.0.2.40").os is None, "B's OS must not persist"
    assert _host(without_b, "192.0.2.40").hostname is None
