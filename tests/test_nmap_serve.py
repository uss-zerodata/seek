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
