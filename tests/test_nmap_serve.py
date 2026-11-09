"""`seek nmap serve`: the session and the web interface without the viewer."""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.request
from pathlib import Path

import pytest
from typer.testing import CliRunner

from seek.cli import app as cli_app
from seek.config import Config
from seek.nmap.merge import discover, naming
from seek.nmap.runner import ScanRun
from seek.runner import State
from seek.web import serve as serve_mod

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _session(tmp_path, nmap="/nonexistent/nmap"):
    sources = [FIX / "basic.xml", FIX / "vuln.xml"]
    return serve_mod.build(sources, discover(sources), naming(sources), [],
                           Config(nmap_path=nmap, web_port=0), tmp_path)


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response)


@pytest.mark.asyncio
async def test_serving_reads_the_paths_and_answers(tmp_path, capsys):
    session = _session(tmp_path)
    stop = asyncio.Event()
    ready: list[str] = []
    task = asyncio.create_task(serve_mod.serve(session, stop=stop, on_ready=ready.append))
    for _ in range(50):
        if ready:
            break
        await asyncio.sleep(0.1)
    hosts = await asyncio.to_thread(_get, ready[0] + "/api/v1/hosts")
    assert hosts["total"] == 4
    stop.set()
    assert await task == 0
    out = capsys.readouterr()
    assert f"on {ready[0]}" in out.out and "stopped" in out.err


@pytest.mark.asyncio
async def test_stopping_cancels_a_running_scan_and_says_so(tmp_path, capsys):
    script = tmp_path / "fake-nmap"
    script.write_text('#!/bin/sh\ncase "$1" in --version) echo "Nmap 7.94";; '
                      '*) while true; do echo busy; sleep 0.1; done;; esac\n')
    script.chmod(0o755)
    session = _session(tmp_path, str(script))
    stop = asyncio.Event()
    ready: list[str] = []
    task = asyncio.create_task(serve_mod.serve(session, stop=stop, on_ready=ready.append))
    while not ready:
        await asyncio.sleep(0.05)
    run = ScanRun(preset="stub", argv=[str(script), "-sT", "192.0.2.1"],
                  targets=["192.0.2.1"], out_base=tmp_path / "out")
    session.start_scan(run, origin="web")
    await asyncio.sleep(0.4)
    stop.set()
    await task
    assert run.state is State.CANCELLED
    assert "cancelled" in capsys.readouterr().err


def test_a_directory_called_serve_is_not_guessed_at(tmp_path, monkeypatch):
    (tmp_path / "serve").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["seek", "nmap", "serve"])
    result = CliRunner().invoke(cli_app, ["nmap", "serve"])
    assert result.exit_code == 2
    assert "ambiguous" in result.output and "./serve" in result.output
    assert "--serve" in result.output


def test_dot_slash_serve_is_the_directory(tmp_path, monkeypatch):
    from seek import cli

    monkeypatch.setattr(sys, "argv", ["seek", "nmap", "./serve"])
    assert cli._typed_serve() is False
    monkeypatch.setattr(sys, "argv", ["seek", "nmap", "serve", "./scans"])
    assert cli._typed_serve() is True


def _post(url: str, origin: str | None = None):
    request = urllib.request.Request(url, data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json",
                                              **({"Origin": origin} if origin else {})})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


@pytest.mark.asyncio
async def test_the_browsers_stop_ends_serve_like_ctrl_c(tmp_path, capsys):
    session = _session(tmp_path)
    ready: list[str] = []
    task = asyncio.create_task(serve_mod.serve(session, on_ready=ready.append))
    while not ready:
        await asyncio.sleep(0.05)
    assert (await asyncio.to_thread(_get, ready[0] + "/api/v1/web"))["mode"] == "serve"
    status, _ = await asyncio.to_thread(_post, ready[0] + "/api/v1/web/stop",
                                        "https://evil.example")
    assert status == 403 and not task.done(), "another site cannot stop it"
    status, body = await asyncio.to_thread(_post, ready[0] + "/api/v1/web/stop", ready[0])
    assert status == 200 and body == {"stopping": True, "ends": "process"}
    assert await asyncio.wait_for(task, 5) == 0
    assert "stopped" in capsys.readouterr().err


@pytest.mark.asyncio
async def test_an_open_page_is_told_and_does_not_hold_the_stop(tmp_path):
    """The event stream never ends by itself; stopping must not wait for it."""
    import time

    session = _session(tmp_path)
    stop = asyncio.Event()
    ready: list[str] = []
    task = asyncio.create_task(serve_mod.serve(session, stop=stop, on_ready=ready.append))
    while not ready:
        await asyncio.sleep(0.05)
    seen: list[str] = []

    def listen():
        with urllib.request.urlopen(ready[0] + "/api/v1/events", timeout=10) as stream:
            for raw in stream:
                seen.append(raw.decode())
                if raw.startswith(b"event: closing"):
                    return

    reader = asyncio.ensure_future(asyncio.to_thread(listen))
    await asyncio.sleep(0.5)
    began = time.monotonic()
    stop.set()
    await asyncio.wait_for(task, 5)
    await asyncio.wait_for(reader, 5)
    assert time.monotonic() - began < 2, "the stop did not wait out the open stream"
    assert any(line.startswith("event: closing") for line in seen)
