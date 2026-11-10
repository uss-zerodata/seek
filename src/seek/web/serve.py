"""`seek nmap serve`: the session and the web interface, without the terminal viewer.

Everything the viewer's session does, headless: the same paths are read into
the same model, runs are supervised by the same `Runner`s, and a finished run
is folded in by re-reading every source - the viewer's rule, so a scan started
here and one run outside are treated alike. Ctrl+C cancels what is still
running, says so, and stops the server.
"""

from __future__ import annotations

import asyncio
import signal
import sys
import time
from pathlib import Path

from seek.config import Config
from seek.gowitness.capture import CaptureRun
from seek.nmap import bulk
from seek.nmap.merge import Naming, load
from seek.nmap.models import ScanSet
from seek.nmap.runner import ScanRun, State, elevation_help
from seek.nmap.session import Session
from seek.nmap.views import prepare


def _say(text: str) -> None:
    print(f"seek: {text}", file=sys.stderr, flush=True)


class HeadlessOwner:
    """Folds finished runs into the model when there is no viewer to do it."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._reading: asyncio.Task | None = None
        self._reads = 0                 # only the newest read publishes

    def scan_done(self, run: ScanRun) -> None:
        # A cancelled or failed scan keeps the hosts it finished: read them in.
        if run.xml_path.exists():
            self._reading = asyncio.get_running_loop().create_task(self._reread(run))
        if run.state is State.FAILED and "sudo -n refused" in run.result:
            _say(elevation_help(self.session.config.nmap_path))
        elif run.state is not State.DONE:
            _say(f"{run.preset}: {run.result}")

    def scan_grew(self, run: ScanRun) -> bool:
        """Read in what a running scan has finished - not while another read runs."""
        if self._reading is not None and not self._reading.done():
            return False
        if self.session.file_grew(run):
            self._reading = asyncio.get_running_loop().create_task(
                self._reread(run, live=True))
        return True

    async def _reread(self, run: ScanRun, live: bool = False) -> None:
        session = self.session
        if not any(p.is_dir() and run.xml_path.is_relative_to(p) for p in session.sources) \
                and run.xml_path not in session.sources:
            session.sources.append(run.xml_path)
        hosts = session.scans.hosts
        self._reads += 1
        mine = self._reads

        def read() -> tuple[dict, ScanSet, float]:
            began = time.monotonic()
            with bulk.bulk(), bulk.responsive():
                before = session.baseline(run, hosts)
                scans = prepare(load(list(session.sources), None, session.name))
            return before, scans, time.monotonic() - began

        try:
            before, scans, took = await asyncio.to_thread(read)
        except Exception as exc:                           # noqa: BLE001 - report, never crash
            _say(f"{session.name(run.xml_path)} could not be read: {exc}")
            return
        session.read_took(took)
        session.diffs[id(run)] = session.run_diff(run, before, scans)
        if mine == self._reads:     # a later read has newer files; it publishes
            session.publish(scans, origin="serve")
        if not live:
            session.forget_baseline(run)
            none = any(label == session.name(run.xml_path) for label, _ in scans.failures)
            _say(f"{run.preset}: {session.diffs[id(run)].summary()}"
                 + (" - it ended before nmap finished a host" if none else ""))

    def capture_done(self, run: CaptureRun) -> None:
        self.session.load_captures()
        _say(f"capture: {run.result}")


def build(sources: list[Path], candidates: list[Path], naming: Naming,
          databases: list[Path], config: Config, scan_dir: Path) -> Session:
    session = Session(config, sources, scan_dir, naming=naming, databases=databases)
    with bulk.bulk(), bulk.responsive():
        scans = prepare(load(candidates, None, naming)) if candidates else session.scans
    session.publish(scans, origin="serve")
    session.load_captures()
    session.owner = HeadlessOwner(session)
    return session


async def serve(session: Session, open_browser: bool = False,
                stop: asyncio.Event | None = None, on_ready=None) -> int:
    """Serve until interrupted - or until `stop` is set, which is how tests end it."""
    from seek.web.server import WebError, WebServer
    from seek.web.source import CachedSource

    stop = stop or asyncio.Event()
    # The browser's Stop is Ctrl+C: the same event, the same way out.
    server = WebServer(CachedSource(lambda: session.scans, lambda: session.shots),
                       session.config.web_host, session.config.web_port, session=session,
                       on_stop=stop.set, mode="serve")
    try:
        await server.start()
    except WebError as exc:
        _say(str(exc))
        return 1
    hosts, shots = len(session.scans.hosts), len(session.shots.all())
    print(f"seek: serving {hosts} host(s) and {shots} capture(s) on {server.url}", flush=True)
    print("seek: Ctrl+C stops the server and cancels any scan or capture still running",
          flush=True)
    if on_ready is not None:
        on_ready(server.url)
    if open_browser:
        from seek.tui.nmap.app import _open_browser
        await asyncio.to_thread(_open_browser, server.url)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        await stop.wait()
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)
        for run in session.cancel_all():
            _say(f"cancelled {run.label}")
        for _ in range(50):                         # let a cancelled run settle
            if session.running() is None:
                break
            await asyncio.sleep(0.1)
        await server.aclose()
        _say("stopped")
    return 0
