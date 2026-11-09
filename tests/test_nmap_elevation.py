"""Getting root for a scan: the route, the sudo check, and the terminal prompt.

The xattr bytes are verbatim from `setcap` on Debian 13. Password sudo itself is
checked by hand in a container (see the scan-elevation change): no test here
can type a password into a real sudo.
"""

from __future__ import annotations

import os
import sys
from contextlib import nullcontext
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from seek.config import Config
from seek.nmap import presets
from seek.nmap import runner as run_mod
from seek.nmap.merge import load
from seek.nmap.presets import Probe, raw_capable
from seek.nmap.runner import Runner, ScanRun, State
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.web.app import create_app
from seek.web.source import CachedSource

FIX = Path(__file__).parent / "fixtures" / "nmap"
# setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip
FULL = bytes.fromhex("0100000200340000003400000000000000000000")
# setcap cap_net_raw+p - permitted but not effective, and no cap_net_admin
PARTIAL = bytes.fromhex("0000000200200000000000000000000000000000")


def _xattr(monkeypatch, value: bytes | None) -> None:
    def getxattr(_path, _name):
        if value is None:
            raise OSError(61, "No data available")
        return value
    monkeypatch.setattr(os, "getxattr", getxattr, raising=False)


@pytest.mark.parametrize("value, expected", [(FULL, True), (PARTIAL, False),
                                             (None, False), (b"\x01", False)])
def test_capabilities_are_read_from_the_file(monkeypatch, value, expected):
    _xattr(monkeypatch, value)
    assert raw_capable("/usr/bin/nmap") is expected


def test_capabilities_this_process_may_not_hold_do_not_count(monkeypatch):
    """Exec fails with EPERM when a file capability is outside the bounding set."""
    _xattr(monkeypatch, FULL)
    monkeypatch.setattr(presets, "_bounding", lambda: ~(1 << 12))   # no NET_ADMIN
    assert raw_capable("/usr/bin/nmap") is False


def _session(tmp_path, *, capable=False, euid=1000, monkeypatch) -> Session:
    monkeypatch.setattr(os, "geteuid", lambda: euid)
    sess = Session(Config(nmap_path="nmap"), [], tmp_path, databases=[],
                   scans=prepare(load([FIX / "basic.xml"])))
    sess.nmap = Probe(path="/usr/bin/nmap", version="7.94", capable=capable)
    return sess


def _plan(sess, args="-sS -p 22"):
    return sess.plan_scan("p", f"nmap {args} 192.0.2.1",
                          sess.scan_dir / "out")


def test_unprivileged_without_capabilities_goes_through_sudo(tmp_path, monkeypatch):
    plan = _plan(_session(tmp_path, monkeypatch=monkeypatch))
    assert plan.via == "sudo" and plan.elevated
    assert plan.argv[:3] == ["sudo", "-n", "/usr/bin/nmap"], "the path seek found"
    assert "--privileged" not in plan.argv


def test_capabilities_replace_sudo_with_privileged(tmp_path, monkeypatch):
    plan = _plan(_session(tmp_path, capable=True, monkeypatch=monkeypatch))
    assert plan.via == "capabilities" and not plan.elevated
    assert plan.argv[0] == "nmap" and "sudo" not in plan.argv
    assert plan.argv.count("--privileged") == 1
    assert plan.copy_remote.startswith("sudo nmap -sS"), "the other machine has no setcap"
    assert "--privileged" not in plan.copy_remote


def test_a_given_privileged_flag_is_not_doubled(tmp_path, monkeypatch):
    plan = _plan(_session(tmp_path, capable=True, monkeypatch=monkeypatch),
                 "-sS --privileged")
    assert plan.argv.count("--privileged") == 1


def test_root_runs_directly(tmp_path, monkeypatch):
    plan = _plan(_session(tmp_path, euid=0, monkeypatch=monkeypatch))
    assert plan.via == "" and plan.argv[0] == "nmap"


def test_an_unprivileged_scan_takes_no_route(tmp_path, monkeypatch):
    plan = _plan(_session(tmp_path, monkeypatch=monkeypatch), "-sT")
    assert plan.via == "" and plan.argv[0] == "nmap"


# --- asking sudo first -------------------------------------------------------------------


def _fake_sudo(tmp_path, monkeypatch, body: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    log = tmp_path / "sudo.log"
    sudo = bin_dir / "sudo"
    sudo.write_text(f'#!/bin/sh\nprintf "%s \\n" "$*" >> {log}\n{body}')
    sudo.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return log


async def test_sudo_ready_runs_the_program_harmlessly(tmp_path, monkeypatch):
    log = _fake_sudo(tmp_path, monkeypatch, "exit 0\n")
    assert await run_mod.sudo_ready(["sudo", "-n", "/opt/nmap", "-sS", "x"]) is None
    assert log.read_text().split() == ["-n", "/opt/nmap", "--version"]


async def test_sudo_ready_gives_sudos_reason(tmp_path, monkeypatch):
    _fake_sudo(tmp_path, monkeypatch, "echo 'sudo: a password is required' >&2\nexit 1\n")
    assert await run_mod.sudo_ready(["sudo", "-n", "nmap"]) == "sudo: a password is required"


async def test_sudo_ready_without_sudo(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert await run_mod.sudo_ready(["sudo", "-n", "nmap"]) == "sudo is not installed"


async def test_a_tool_runs_in_the_viewers_session_with_stdin_closed(tmp_path):
    """A new session has no terminal, and sudo's authorisation is per terminal."""
    probe = ("import os, sys; print(os.getsid(0)); "
             "print(os.getpgid(0) == os.getpid()); print(repr(sys.stdin.read()))")
    run = ScanRun(preset="t", argv=[sys.executable, "-c", probe], targets=["x"],
                  out_base=tmp_path / "o")
    await Runner().run(run, lambda _line: None, lambda _run: None)
    assert run.state is State.DONE, run.result
    assert list(run.log) == [str(os.getsid(0)), "True", "''"]


# --- the terminal viewer lets sudo ask --------------------------------------------------


def _app(tmp_path, monkeypatch, answers: list[str | None]):
    from seek.tui.nmap import app as app_mod

    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    asked = []

    async def sudo_ready(argv):
        asked.append(argv)
        return answers.pop(0)

    prompted = []
    from seek.tui.nmap import flows
    monkeypatch.setattr(flows, "sudo_ready", sudo_ready)
    monkeypatch.setattr(flows, "_sudo_validate",
                        lambda _why: prompted.append(["sudo", "-v"]))
    app = app_mod.NmapApp(prepare(load([FIX / "basic.xml"])),
                          Config(nmap_path="nmap", scan_output_dir=str(tmp_path)),
                          sources=[FIX / "basic.xml"], scan_dir=tmp_path)
    app.suspend = lambda: nullcontext()
    started = []
    app._run_scan = started.append
    return app, prompted, started


def _elevated_run(tmp_path) -> ScanRun:
    return ScanRun(preset="SYN", argv=["sudo", "-n", "nmap", "-sS", "-oA", "o", "x"],
                   targets=["x"], out_base=tmp_path / "o", elevated=True)


async def test_ready_sudo_starts_without_asking(tmp_path, monkeypatch):
    app, prompted, _started = _app(tmp_path, monkeypatch, [None])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert await app._authorise(_elevated_run(tmp_path))
        assert prompted == []


async def test_sudo_asks_on_the_terminal_then_the_scan_starts(tmp_path, monkeypatch):
    app, prompted, _started = _app(tmp_path, monkeypatch,
                                   ["sudo: a password is required", None])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert await app._authorise(_elevated_run(tmp_path))
        assert prompted == [["sudo", "-v"]], "sudo itself asks; seek reads nothing"


async def test_a_refused_password_starts_nothing(tmp_path, monkeypatch):
    app, prompted, _started = _app(tmp_path, monkeypatch,
                                   ["sudo: a password is required",
                                    "sudo: a password is required"])
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert not await app._authorise(_elevated_run(tmp_path))
        assert prompted == [["sudo", "-v"]]


async def test_no_way_to_step_aside_explains_instead(tmp_path, monkeypatch):
    from textual.app import SuspendNotSupported

    app, prompted, _started = _app(tmp_path, monkeypatch, ["sudo: a password is required"])

    def cannot():
        raise SuspendNotSupported("headless")

    app.suspend = cannot
    async with app.run_test() as pilot:
        await pilot.pause(0.2)
        assert not await app._authorise(_elevated_run(tmp_path))
        assert prompted == []


# --- the browser cannot let sudo ask ---------------------------------------------------


def test_the_browser_refuses_a_scan_sudo_would_not_run(tmp_path, monkeypatch):
    from seek.web.api.v1 import runs

    sess = _session(tmp_path, monkeypatch=monkeypatch)

    async def sudo_ready(_argv):
        return "sudo: a password is required"

    monkeypatch.setattr(runs, "sudo_ready", sudo_ready)
    sess.config.nmap_presets = {"SYN": "-sS -p 22"}
    client = TestClient(create_app(CachedSource(lambda: sess.scans, lambda: sess.shots), sess))
    response = client.post("/api/v1/scans", json={"preset": "SYN", "targets": ["192.0.2.1"]})
    assert response.status_code == 409
    assert "terminal viewer" in response.json()["detail"]
    assert sess.runner.runs == [], "refused before anything ran"
    assert presets.needs_root(["-sS"])


def test_unelevated_scans_keep_the_configured_name(tmp_path, monkeypatch):
    plan = _plan(_session(tmp_path, euid=0, monkeypatch=monkeypatch))
    assert plan.argv[0] == "nmap"


# --- the targets are the command's -----------------------------------------------------


def test_targets_taken_out_of_the_command_are_not_scanned(tmp_path, monkeypatch):
    """The scope used to come back when the edit left no target matching it."""
    sess = _session(tmp_path, euid=0, monkeypatch=monkeypatch)
    plan = sess.plan_scan("p", "nmap -sT -iL only-these.txt", tmp_path / "o")
    assert plan.targets == [] and "192.0.2.1" not in plan.argv
    assert plan.argv[:5] == ["nmap", "-sT", "-iL", "only-these.txt", "-oA"]


def test_a_target_added_in_the_editor_is_counted(tmp_path, monkeypatch):
    sess = _session(tmp_path, euid=0, monkeypatch=monkeypatch)
    plan = sess.plan_scan("p", "nmap -sT 192.0.2.1 192.0.2.99", tmp_path / "o")
    assert plan.targets == ["192.0.2.1", "192.0.2.99"]


def test_a_command_with_no_target_is_refused(tmp_path, monkeypatch):
    sess = _session(tmp_path, euid=0, monkeypatch=monkeypatch)
    with pytest.raises(presets.CommandError, match="no target left"):
        sess.plan_scan("p", "nmap -sT --script vuln -p 80", tmp_path / "o")


def test_option_values_are_not_counted_as_targets(tmp_path, monkeypatch):
    sess = _session(tmp_path, euid=0, monkeypatch=monkeypatch)
    plan = sess.plan_scan("p", "nmap -sT --exclude 192.0.2.5 -p 80 192.0.2.0/24",
                          tmp_path / "o")
    assert plan.targets == ["192.0.2.0/24"]
