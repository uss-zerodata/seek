"""How far a whole nmap scan is - from the lines nmap 7.94 prints at -v.

The line shapes below are copied from real runs: on loopback, and on hosts that
never answer (a network namespace with a dummy interface).
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from seek import notify
from seek.config import Config
from seek.nmap.models import ScanSet
from seek.nmap.runner import ScanRun, State, count_argv, counted
from seek.nmap.session import Session

_GROUP_OF_3 = [
    "Initiating Connect Scan at 08:18",
    "Scanning 3 hosts [2 ports/host]",
]
_DISCOVERY = [
    "Initiating Ping Scan at 08:50",
    "Scanning 5 hosts [4 ports/host]",
    "Completed Ping Scan at 08:50, 5.02s elapsed (5 total hosts)",
]


def _run(*args: str, total: int | None = 12) -> ScanRun:
    run = ScanRun(preset="p", argv=["nmap", *args, "-oA", "/x/o", "10.0.0.0/28"],
                  targets=["10.0.0.0/28"], out_base=Path("/x/o"))
    run.total = total
    return run


def _feed(run: ScanRun, lines: list[str]) -> ScanRun:
    for line in lines:
        run.append(line)
    return run


def test_groups_add_up_to_the_whole_scan():
    run = _feed(_run("-v"), _GROUP_OF_3)
    assert run.fraction() == 0
    _feed(run, ["Connect Scan Timing: About 50.00% done; ETC: 08:30 (0:01:00 remaining)"])
    assert run.fraction() == pytest.approx(1.5 / 12), "half of a group of three"
    _feed(run, [f"Nmap scan report for 10.0.0.{i}" for i in (1, 2, 3)])
    assert run.fraction() == pytest.approx(3 / 12)
    _feed(run, _GROUP_OF_3 + ["Nmap scan report for localhost (127.0.0.4)"])
    assert run.finished == 4 and run.group == 2
    assert "4/12 hosts" in run.progress() and "connect scan" in run.progress()


def test_down_hosts_count_as_finished():
    run = _feed(_run("-v"), _DISCOVERY + [
        f"Nmap scan report for 10.99.0.{i} [host down]" for i in range(2, 7)])
    assert run.finished == 5 and run.reported_up == 0
    assert run.group == 0, "a discovery batch is not a port-scan group"
    assert run.fraction() == pytest.approx(5 / 12)


def test_a_new_phase_never_takes_it_back():
    run = _feed(_run("-v"), _GROUP_OF_3 + [
        "Connect Scan Timing: About 90.00% done; ETC: 08:30 (0:00:10 remaining)"])
    high = run.fraction()
    _feed(run, ["Initiating Service scan at 08:20",
                "Service scan Timing: About 5.00% done; ETC: 08:40 (0:10:00 remaining)"])
    assert run.phase == "Service scan" and run.fraction() == high


def test_never_all_done_before_nmap_ends():
    run = _feed(_run("-v", total=2), _GROUP_OF_3 + [
        "Nmap scan report for 10.0.0.1", "Nmap scan report for 10.0.0.2"])
    assert run.fraction() == 0.99
    run.state = State.DONE
    assert run.fraction() == 1.0


def test_without_v_no_figure_is_claimed():
    run = _feed(_run(), ["Nmap scan report for 10.0.0.1"])
    assert run.fraction() is None
    assert run.progress() == "1 up hosts reported · -v gives progress"


def test_without_a_total_counts_only():
    run = _feed(_run("-vv", total=None), _GROUP_OF_3 + ["Nmap scan report for 10.0.0.1"])
    assert run.fraction() is None
    assert run.progress().startswith("connect scan · 1 hosts")


def test_milestones_follow_the_whole_scan():
    run = _feed(_run("-v", total=120), _GROUP_OF_3 + [
        "Connect Scan Timing: About 80.00% done; ETC: 08:30 (0:00:10 remaining)"])
    assert notify.crossed(run.fraction(), 0) == 0, "the first group's 80 % is 2 % of it all"


# --- the count -----------------------------------------------------------------------


@pytest.mark.parametrize("argv, expected", [
    (["nmap", "-sT", "-v", "-p", "22", "-oA", "o", "10.0.0.0/24", "--exclude", "10.0.0.1"],
     ["nmap", "-sL", "-n", "--exclude", "10.0.0.1", "10.0.0.0/24"]),
    (["sudo", "-n", "/usr/bin/nmap", "-sS", "-iL", "hosts.txt", "-oA", "o"],
     ["/usr/bin/nmap", "-sL", "-n", "-iL", "hosts.txt"]),
    (["nmap", "-6", "-sT", "-oA", "o", "2001:db8::1"],
     ["nmap", "-sL", "-n", "-6", "2001:db8::1"]),
    (["nmap", "-sT", "-iR", "100", "-oA", "o"], None),
    ([sys.executable, "-c", "print(1)"], None),
])
def test_what_is_counted(argv, expected):
    assert count_argv(argv, {"nmap", "/usr/bin/nmap"}) == expected


def test_the_count_is_nmaps_last_line():
    assert counted("Nmap done: 255 IP addresses (0 hosts up) scanned in 0.01 seconds") == 255
    assert counted("Nmap done: 0 IP addresses (0 hosts up) scanned in 0.01 seconds") is None
    assert counted("") is None


def _stub(tmp_path: Path, body: str) -> str:
    path = tmp_path / "nmap-stub"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return str(path)


async def _started(tmp_path: Path, nmap: str, *args: str) -> tuple[Session, ScanRun]:
    session = Session(Config(nmap_path=nmap), [tmp_path], tmp_path, databases=[],
                      scans=ScanSet())
    run = ScanRun(preset="p", argv=[nmap, "-v", *args, "-oA", str(tmp_path / "o"), "10.0.0.0/24"],
                  targets=["10.0.0.0/24"], out_base=tmp_path / "o")
    session.start_scan(run)
    return session, run


async def test_the_scan_counts_its_targets_with_nmap(tmp_path):
    nmap = _stub(tmp_path, 'case "$*" in *-sL*) i=0; while [ $i -lt 3 ]; do echo "Nmap scan '
                           'report for 10.0.0.$i"; i=$((i+1)); done; '
                           'echo "Nmap done: 255 IP addresses (0 hosts up) in 0.01 s";; '
                           '*) sleep 1;; esac')
    session, run = await _started(tmp_path, nmap)
    for _ in range(50):
        if run.total:
            break
        await asyncio.sleep(0.05)
    assert run.total == 255
    session.cancel_all()


async def test_a_count_that_fails_leaves_no_total(tmp_path, monkeypatch):
    from seek.nmap import session as session_mod

    monkeypatch.setattr(session_mod, "COUNT_TIMEOUT", 0.3)
    nmap = _stub(tmp_path, "sleep 5\n")
    session, run = await _started(tmp_path, nmap)
    await asyncio.sleep(0.8)
    assert run.total is None and run.running, "the scan does not wait for it"
    session.cancel_all()


async def test_random_targets_are_not_counted(tmp_path):
    nmap = _stub(tmp_path, 'echo "Nmap done: 9 IP addresses"; sleep 1\n')
    session, run = await _started(tmp_path, nmap, "-iR", "100")
    await asyncio.sleep(0.5)
    assert run.total is None
    session.cancel_all()
