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


def test_merging_leaves_each_file_saying_what_that_scan_saw():
    """The set is built from copies: the Scans tab reads these back per file."""
    scans = load([A, B])
    a, b = scans.files
    shared = "192.0.2.40"
    in_a = next(h for h in a.hosts if h.address == shared)
    in_b = next(h for h in b.hosts if h.address == shared)
    merged = _host(scans, shared)
    assert {s.port for s in merged.services} > {s.port for s in in_a.services}, \
        "the merged host carries both scans"
    assert {s.port for s in in_a.services} != {s.port for s in in_b.services}, \
        "and neither file was rewritten to match the other"
    assert not any(s is m for s in in_a.services for m in merged.services), \
        "no record is shared between a file and the merged model"


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


def test_a_directory_is_searched_all_the_way_down(tmp_path):
    """An engagement directory has phases in subdirectories, not a flat list."""
    deep = tmp_path / "10.0.0.0-24" / "02-services"
    deep.mkdir(parents=True)
    shutil.copy(A, tmp_path / A.name)
    shutil.copy(B, deep / B.name)
    assert [p.name for p in collect_paths([tmp_path])] == ["merge-b.xml", "merge-a.xml"]
    assert len(load([tmp_path]).hosts) == 3


def test_the_walk_skips_dot_directories_and_files_that_are_not_scans(tmp_path):
    """Discovery must not turn every `.xml` on the disk into a skipped-file line."""
    shutil.copy(A, tmp_path / A.name)
    shutil.copy(FIX / "not-nmap.xml", tmp_path / "pom.xml")
    hidden = tmp_path / ".cache"
    hidden.mkdir()
    shutil.copy(B, hidden / B.name)
    assert [p.name for p in collect_paths([tmp_path])] == ["merge-a.xml"]
    assert load([tmp_path]).failures == []


def test_a_named_file_is_still_read_and_reported_rather_than_sniffed_away():
    """Sniffing is for what the walk turns up; a named file was asked for."""
    scans = load([FIX / "not-nmap.xml"])
    assert scans.failures and "not an nmap scan" in scans.failures[0][1]


def test_a_walk_does_not_re_add_a_file_that_was_named(tmp_path):
    """`seek nmap . scans/a.xml` must not double a host's provenance."""
    shutil.copy(A, tmp_path / A.name)
    assert collect_paths([tmp_path, tmp_path / A.name]) == [tmp_path / A.name]
    assert collect_paths([tmp_path / A.name, tmp_path]) == [tmp_path / A.name]
    assert _host(load([tmp_path, tmp_path / A.name]), "192.0.2.41").sources == \
        ["merge-a.xml"]


def test_a_scan_whose_root_element_is_far_into_the_file_is_still_found(tmp_path):
    """`-oA` writes the whole command - every target - in a comment first.

    A reverse-lookup scan of a /24 puts `<nmaprun>` some 7 kB in; a /16 puts it
    much further. Recognition has to rest on the doctype, which is always on
    the second line.
    """
    body = A.read_text()
    head, root = body.split("<nmaprun", 1)
    padded = tmp_path / "wide-scope.xml"
    padded.write_text(f"{head}<!DOCTYPE nmaprun>\n"
                      f"<!-- {'10.10.10.1 ' * 2000} -->\n<nmaprun{root}")
    assert collect_paths([tmp_path]) == [padded]
    assert load([tmp_path]).hosts, "and it parses, not merely gets listed"


def test_the_search_reports_its_progress(tmp_path):
    """A long walk must be able to say it is still going.

    Two phases, one shape: the walk counts what it has found against a total
    of zero, because it cannot know how many scans it will find until it has
    found them; then the read counts files against the number the walk turned
    up. Both name the unit, so one renderer can draw either.
    """
    deep = tmp_path / "a" / "b"
    deep.mkdir(parents=True)
    shutil.copy(A, tmp_path / A.name)
    shutil.copy(B, deep / B.name)

    seen = []
    load([tmp_path], lambda done, total, unit: seen.append((done, total, unit)))

    assert seen, "the callback is called while the tree is walked"
    assert {unit for _, _, unit in seen} == {"files"}, "and says what it counts"
    walking = [s for s in seen if s[1] == 0]
    reading = [s for s in seen if s[1]]
    assert [s[0] for s in walking] == sorted(s[0] for s in walking), \
        "the count of scans found only grows"
    assert walking[-1][0] == 2, "it ends with everything found"
    assert [s[:2] for s in reading] == [(1, 2), (2, 2)], \
        "then the files are read, out of a total that is known by then"


def test_progress_is_optional_and_costs_the_caller_nothing():
    assert len(load([A, B]).hosts) == 3


def test_a_file_named_twice_by_hand_is_still_read_twice():
    """An explicit list is taken literally - the timeline reads a re-run this way."""
    assert collect_paths([A, A]) == [A, A]


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


# --- several directories ----------------------------------------------------


def _two_dirs(tmp_path):
    """`x/scan.xml` and `y/scan.xml`: the names tools write in every directory."""
    for name, src in (("x", A), ("y", B)):
        (tmp_path / name).mkdir()
        shutil.copy(src, tmp_path / name / "scan.xml")
    return tmp_path / "x", tmp_path / "y"


def test_same_named_scans_in_two_directories_stay_two_sources(tmp_path):
    x, y = _two_dirs(tmp_path)
    scans = load([x, y])
    assert scans.sources == ["x/scan.xml", "y/scan.xml"]
    host = _host(scans, "192.0.2.40")               # in both files
    assert host.sources == ["x/scan.xml", "y/scan.xml"], "seen in both, not once"
    assert _svc(host, 22).sources == ["x/scan.xml", "y/scan.xml"]


def test_every_scan_is_qualified_once_there_are_several_directories(tmp_path):
    x, y = _two_dirs(tmp_path)
    (y / "sub").mkdir()
    shutil.copy(A, y / "sub" / "other.xml")         # collides with nothing
    assert "y/sub/other.xml" in load([x, y]).sources


def test_one_directory_or_files_keep_bare_names(tmp_path):
    x, _ = _two_dirs(tmp_path)
    assert load([x]).sources == ["scan.xml"]
    assert load([A, B]).sources == ["merge-a.xml", "merge-b.xml"]
    assert load([x, x]).sources == ["scan.xml"], "one directory named twice is one"


def test_failures_are_named_by_directory_too(tmp_path):
    for name in ("x", "y"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "scan.xml").write_text('<?xml version="1.0"?>\n<nmaprun scanner="nmap"')
    failed = [name for name, _ in load([tmp_path / "x", tmp_path / "y"]).failures]
    assert failed == ["x/scan.xml", "y/scan.xml"]


def test_the_scan_file_carries_its_label(tmp_path):
    x, y = _two_dirs(tmp_path)
    assert [f.name for f in load([x, y]).files] == ["x/scan.xml", "y/scan.xml"]


def _merged_service(first: Service, second: Service) -> Service:
    from seek.nmap.merge import _merge_service
    _merge_service(first, second)
    return first


def test_cpes_travel_with_a_probe_that_replaces_a_guess():
    guess = Service("tcp", 80, "open", name="http", method="table",
                    cpes=["cpe:/a:guess:guess"])
    probe = Service("tcp", 80, "open", name="http", product="nginx", method="probed",
                    cpes=["cpe:/a:igor_sysoev:nginx:1.16.1"])
    assert _merged_service(guess, probe).cpes == ["cpe:/a:igor_sysoev:nginx:1.16.1"]


def test_cpes_union_between_equals():
    a = Service("tcp", 22, "open", method="probed", cpes=["cpe:/a:openbsd:openssh:8.2p1"])
    b = Service("tcp", 22, "open", method="probed",
                cpes=["cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:linux:linux_kernel"])
    assert _merged_service(a, b).cpes == ["cpe:/a:openbsd:openssh:8.2p1",
                                          "cpe:/o:linux:linux_kernel"]
