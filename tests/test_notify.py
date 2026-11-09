"""Notifications: what a message may say, when it is sent, and that a failed
delivery changes nothing. A real HTTP receiver on loopback stands in for ntfy."""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from seek import notify
from seek.config import Config, ConfigError, load_config
from seek.gowitness.capture import CaptureRun
from seek.nmap.merge import load
from seek.nmap.runner import ScanRun
from seek.nmap.session import Session
from seek.nmap.views import prepare
from seek.runner import State

FIX = Path(__file__).parent / "fixtures" / "nmap"


@pytest.mark.parametrize("given, called", [
    ("notify.hektor.cc/test", "https://notify.hektor.cc/test"),
    ("http://127.0.0.1:8080/t", "http://127.0.0.1:8080/t"),
    ("  ", ""),
])
def test_a_url_is_normalised(given, called):
    assert notify.normalise(given) == called


@pytest.mark.parametrize("bad", ["ftp://example.test/t", "https://", "mailto:x@y"])
def test_a_url_that_is_not_http_is_refused(bad):
    with pytest.raises(notify.NotifyError):
        notify.normalise(bad)


def test_the_config_normalises_and_refuses(tmp_path):
    good = tmp_path / "good.toml"
    good.write_text('notify_url = "notify.hektor.cc/test"\nnotify_progress = true\n')
    cfg = load_config(good)
    assert cfg.notify_url == "https://notify.hektor.cc/test" and cfg.notify_progress
    bad = tmp_path / "bad.toml"
    bad.write_text('notify_url = "ftp://x/y"\n')
    with pytest.raises(ConfigError, match="notify_url"):
        load_config(bad)


def test_milestones_are_reached_one_at_a_time():
    assert notify.crossed(None, 0) == 0
    assert notify.crossed(0.3, 0) == 25
    assert notify.crossed(0.3, 25) == 0
    seen, reached = [], 0
    while mark := notify.crossed(0.8, reached):
        seen.append(mark)
        reached = mark
    assert seen == [25, 50, 75]


def test_the_message_names_only_what_it_is_given():
    message = notify.ended("Top 1000 TCP", "failed", 3725)
    assert message.title == "seek: Top 1000 TCP"
    assert message.body == "Top 1000 TCP failed after 1h 02m"
    assert message.priority == "high"
    assert notify.ended("q", "done", 61).body == "q finished in 1m 01s"


def test_a_capture_is_named_by_the_tool_not_its_directory():
    run = CaptureRun(argv=["gowitness"], urls=["https://acme.test:443"], where="acme-2026")
    assert run.notify_name == "gowitness capture"
    assert "acme" not in run.notify_name


# --- end to end, against a receiver ---------------------------------------------------


class _Receiver:
    def __init__(self):
        received = self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - http.server's name
                length = int(self.headers["Content-Length"])
                received.append((dict(self.headers), self.rfile.read(length).decode()))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/test"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def receiver():
    r = _Receiver()
    yield r
    r.close()


def _session(tmp_path) -> Session:
    paths = [FIX / "basic.xml"]
    return Session(Config(nmap_path="/nonexistent/nmap"), paths, tmp_path,
                   databases=[], scans=prepare(load(paths)))


# A stand-in for nmap that prints targets, progress and a path, as nmap does.
_NMAP = (
    "print('Nmap scan report for db.acme.test (10.0.0.5)'); "
    "print('Stats: 0:01:00 elapsed; About 30.00% done; ETC: 12:00'); "
    "print('Stats: 0:02:00 elapsed; About 80.00% done; ETC: 12:00'); "
    "print('/home/alice/acme/out.xml')"
)


async def _drain(session: Session) -> None:
    for _ in range(100):
        if not session._tasks:
            return
        await asyncio.sleep(0.02)


async def _scan(tmp_path, url: str, progress: bool) -> tuple[Session, ScanRun]:
    session = _session(tmp_path)
    run = ScanRun(preset="Top 1000 TCP", argv=[sys.executable, "-c", _NMAP],
                  targets=["10.0.0.0/24"], out_base=tmp_path / "acme" / "out",
                  notify_url=url, notify_progress=progress)
    await session.start_scan(run)
    await _drain(session)
    return session, run


async def test_the_end_is_sent_in_ntfy_format_and_says_nothing_else(tmp_path, receiver):
    _session_, run = await _scan(tmp_path, receiver.url, progress=False)
    assert run.state is State.DONE
    assert len(receiver.received) == 1, "progress was off: only the end"
    headers, body = receiver.received[0]
    assert headers["Title"] == "seek: Top 1000 TCP"
    assert headers["Tags"] == "white_check_mark" and headers["Priority"] == "default"
    assert body.startswith("Top 1000 TCP finished in ")
    for secret in ("10.0.0", "acme", "alice", "Nmap scan report", str(tmp_path)):
        assert secret not in body and secret not in str(headers), secret


async def test_progress_sends_each_milestone_once_then_the_end(tmp_path, receiver):
    _session_, run = await _scan(tmp_path, receiver.url, progress=True)
    bodies = [body for _headers, body in receiver.received]
    assert [b.split(" is ")[1].split(" ")[0] for b in bodies[:3]] == ["25%", "50%", "75%"]
    assert bodies[3].startswith("Top 1000 TCP finished") and len(bodies) == 4
    assert run.milestone == 75


async def test_no_url_sends_nothing(tmp_path, receiver):
    _session_, run = await _scan(tmp_path, "", progress=True)
    assert run.state is State.DONE and receiver.received == []


async def test_an_unreachable_webhook_changes_nothing_but_the_log(tmp_path):
    with socket.socket() as s:                  # a port nothing listens on
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    _session_, run = await _scan(tmp_path, f"http://127.0.0.1:{port}/t", progress=False)
    assert run.state is State.DONE, "the scan did what it did"
    assert any(line.startswith("[seek] notification failed:") for line in run.log)
