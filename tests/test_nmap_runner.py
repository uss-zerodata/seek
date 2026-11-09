"""Supervising a scan: streaming, cancelling, and what became of it.

**No test here runs nmap.** Every one points the runner at a stub script that
prints canned output and exits, which is why the runner takes its program from
configuration rather than hardcoding a name.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from seek.nmap import runner as run_mod
from seek.nmap.runner import Runner, ScanRun, State

pytestmark = pytest.mark.asyncio


def _script(tmp_path: Path, body: str, name: str = "fake-nmap") -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def _run(tmp_path: Path, argv: list[str], **kwargs) -> ScanRun:
    return ScanRun(preset="test", argv=argv, targets=["10.0.0.1"],
                   out_base=tmp_path / "base", **kwargs)


async def _drive(runner: Runner, run: ScanRun) -> tuple[ScanRun, list[str]]:
    lines: list[str] = []
    done: list[ScanRun] = []
    await runner.run(run, lines.append, done.append)
    assert done == [run], "on_done fires exactly once, after the state is final"
    return run, lines


# --- streaming --------------------------------------------------------------


async def test_output_arrives_line_by_line_while_the_scan_runs(tmp_path):
    script = _script(tmp_path, "echo one\necho two\necho three\n")
    run, lines = await _drive(Runner(), _run(tmp_path, [str(script)]))
    assert lines == ["one", "two", "three"], "streamed, not collected at the end"
    assert list(run.log) == lines
    assert run.state is State.DONE and run.exit_code == 0


async def test_stderr_is_part_of_the_log(tmp_path):
    script = _script(tmp_path, "echo out\necho problem >&2\n")
    run, _ = await _drive(Runner(), _run(tmp_path, [str(script)]))
    assert "problem" in list(run.log)


async def test_a_log_longer_than_the_bound_keeps_the_newest_and_counts_the_rest(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(run_mod, "LOG_LIMIT", 10)
    run = ScanRun(preset="p", argv=["x"], targets=["t"], out_base=tmp_path / "b")
    run.log = run.log.__class__(maxlen=10)
    for i in range(25):
        run.append(f"line {i}")
    assert len(run.log) == 10 and run.log[-1] == "line 24"
    assert run.dropped == 15, "the bound is visible, not silent"


# --- what became of it ------------------------------------------------------


async def test_a_failing_scan_keeps_nmaps_own_last_word(tmp_path):
    script = _script(tmp_path, "echo 'Failed to resolve nope.invalid'\nexit 1\n")
    run, _ = await _drive(Runner(), _run(tmp_path, [str(script)]))
    assert run.state is State.FAILED and run.exit_code == 1
    assert "Failed to resolve" in run.result


async def test_a_refused_elevation_is_not_reported_as_a_scan_failure(tmp_path):
    script = _script(tmp_path, "echo 'sudo: a password is required' >&2\nexit 1\n")
    run, _ = await _drive(Runner(), _run(tmp_path, [str(script)], elevated=True))
    assert run.state is State.FAILED
    assert "sudo -n refused" in run.result
    assert "no password was asked for" in run.result


async def test_a_missing_program_is_reported_rather_than_raised(tmp_path):
    run, _ = await _drive(Runner(), _run(tmp_path, [str(tmp_path / "nope")]))
    assert run.state is State.FAILED and "not found" in run.result


async def test_a_finished_scan_summarises_itself_from_its_own_output(tmp_path):
    script = _script(
        tmp_path,
        "echo 'Nmap done: 256 IP addresses (3 hosts up) scanned in 31.20 seconds'\n",
    )
    run, _ = await _drive(Runner(), _run(tmp_path, [str(script)]))
    assert run.state is State.DONE and "3 hosts up" in run.result


# --- cancelling -------------------------------------------------------------


async def test_cancelling_ends_the_process_and_keeps_what_it_produced(tmp_path):
    script = _script(tmp_path, "echo started\nsleep 30\n")
    runner = Runner()
    run = _run(tmp_path, [str(script)])
    task = asyncio.create_task(runner.run(run, lambda _l: None, lambda _r: None))
    for _ in range(100):                        # wait for the first line
        await asyncio.sleep(0.02)
        if run.log:
            break
    assert runner.cancel() is True
    await asyncio.wait_for(task, timeout=10)
    assert run.state is State.CANCELLED
    assert "started" in list(run.log), "the output it produced is kept"
    assert "no file was written" in run.result


async def test_cancelling_when_nothing_runs_is_a_no_op(tmp_path):
    assert Runner().cancel() is False


async def test_a_process_that_ignores_sigterm_is_killed(tmp_path, monkeypatch):
    monkeypatch.setattr(run_mod, "GRACE_SECONDS", 0.2)
    script = _script(tmp_path, "trap '' TERM\necho started\nsleep 30\n")
    runner = Runner()
    run = _run(tmp_path, [str(script)])
    task = asyncio.create_task(runner.run(run, lambda _l: None, lambda _r: None))
    for _ in range(100):
        await asyncio.sleep(0.02)
        if run.log:
            break
    runner.cancel()
    await asyncio.wait_for(task, timeout=10)
    assert run.state is State.CANCELLED


# --- the run itself ---------------------------------------------------------


async def test_progress_is_read_from_what_nmap_prints(tmp_path):
    script = _script(
        tmp_path,
        "echo 'Stats: 0:01:42 elapsed; 110 hosts completed (146 up), 146 undergoing'\n"
        "echo 'SYN Stealth Scan Timing: About 43.21% done; ETC: 14:26 (0:02:11 remaining)'\n",
    )
    run, _ = await _drive(Runner(), _run(tmp_path, [str(script)]))
    assert run.percent == pytest.approx(43.21)
    assert run.hosts_up == 146
    assert "43%" in run.progress() and "146 up" in run.progress()


async def test_a_run_without_progress_lines_still_reads_sensibly(tmp_path):
    run = _run(tmp_path, ["x"])
    assert run.progress() == "running"


async def test_the_runner_knows_when_it_is_busy(tmp_path):
    script = _script(tmp_path, "sleep 5\n")
    runner = Runner()
    run = _run(tmp_path, [str(script)])
    assert runner.busy() is None
    task = asyncio.create_task(runner.run(run, lambda _l: None, lambda _r: None))
    await asyncio.sleep(0.2)
    assert runner.busy() is run, "a second scan can be refused, naming this one"
    runner.cancel()
    await asyncio.wait_for(task, timeout=10)
    assert runner.busy() is None


async def test_every_run_of_the_session_is_kept(tmp_path):
    script = _script(tmp_path, "echo hi\n")
    runner = Runner()
    for _ in range(3):
        await runner.run(_run(tmp_path, [str(script)]), lambda _l: None, lambda _r: None)
    assert len(runner.runs) == 3
    assert all(r.state is State.DONE for r in runner.runs)


async def test_the_scope_and_the_xml_path_read_from_the_run(tmp_path):
    run = ScanRun(preset="quick", argv=["nmap"], targets=["10.0.0.1"],
                  out_base=tmp_path / "seek-quick-2026")
    assert run.scope == "10.0.0.1"
    assert run.xml_path.name == "seek-quick-2026.xml"
    run.targets = ["10.0.0.1", "10.0.0.2"]
    assert run.scope == "2 targets"


async def test_elevation_help_names_the_ways_out():
    text = run_mod.elevation_help()
    assert "terminal viewer" in text and "root" in text and "setcap" in text
    assert "--privileged" in text
    assert "another terminal" not in text, "sudo's authorisation is per terminal"
    inside = run_mod.elevation_help(terminal=True)
    assert "terminal viewer" not in inside and "setcap" in inside
