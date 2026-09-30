"""One engagement, shared by every front end attached to it.

The terminal viewer and the web interface are two views of the same work: the
model read from the sources, the scans and captures run against it, and the
records marked for export. This is where that shared part lives. It imports no
Textual and no FastAPI; a front end attaches by listening to its events and by
calling its methods.

What stays with each front end: which tab is open, the filter, the sort, the
drill-down path and the selected row. Two front ends never move each other.

Folding a finished run back into the model is the job of the model's *owner* -
the terminal viewer's reading pipeline when there is one, a headless reader
under `seek nmap serve` - registered as `Session.owner`. The session tells it a
run ended; it does not presume how an engagement is re-read.

Everything here runs on one event loop: the `Runner`s are asyncio, and the web
server runs as a task on the same loop, so marks and runs are changed from one
thread only and need no locks.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from seek.config import Config
from seek.gowitness import capture as gw_capture
from seek.gowitness import detect as gw_detect
from seek.gowitness import locate as gw_locate
from seek.gowitness import results as gw_results
from seek.gowitness.results import canonical_url
from seek.nmap import merge as merge_mod
from seek.nmap import presets as presets_mod
from seek.nmap import rawlog, timeline
from seek.nmap.export import Record, export_ports, export_urls, records_for, service_urls
from seek.nmap.models import ScanSet
from seek.nmap.runner import ScanRun
from seek.runner import Run, Runner

# How many events a slow listener may fall behind before `line` events are
# dropped for it. A run must never wait for a browser tab.
QUEUE_LIMIT = 2000


@dataclass(slots=True)
class Event:
    """Something every front end may want to show.

    `type` is one of `model` (a new model was published), `run` (a run started
    or ended - `run.state` says which), `line` (a run wrote a line), `marks`.
    `origin` is who caused it, so a front end can tell its own actions from
    another's - the viewer switches to the Scans tab for a run *it* started,
    never for one started in a browser.
    """

    type: str
    origin: str = ""
    run: Run | None = None
    text: str = ""


class Owner(Protocol):
    """Whoever re-reads the engagement when a run has added to it."""

    def scan_done(self, run: ScanRun) -> None: ...
    def capture_done(self, run: gw_capture.CaptureRun) -> None: ...


class Busy(RuntimeError):
    """A tool already has a run; the message names it."""


class ScanError(RuntimeError):
    """A scan cannot be planned; the message is what to tell the user."""


@dataclass(slots=True)
class ScanPlan:
    """A scan as it will run - what the review shows before anything starts."""

    preset: str
    argv: list[str]
    targets: list[str]
    out_base: Path
    elevated: bool
    privilege: str

    def run(self) -> ScanRun:
        return ScanRun(preset=self.preset, argv=self.argv, targets=self.targets,
                       out_base=self.out_base, elevated=self.elevated)


@dataclass
class Subscription:
    """A queue of events for one consumer on the session's loop."""

    queue: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(QUEUE_LIMIT))
    dropped: int = 0

    def put(self, event: Event) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            if event.type == "line":
                self.dropped += 1          # the page refetches the log tail
                return
            with contextlib.suppress(asyncio.QueueEmpty):
                self.queue.get_nowait()     # make room for what matters
            with contextlib.suppress(asyncio.QueueFull):
                self.queue.put_nowait(event)


class Session:
    def __init__(self, config: Config | None = None, sources: list[Path] | None = None,
                 scan_dir: Path | None = None, naming: merge_mod.Naming | None = None,
                 databases: list[Path] | None = None, scans: ScanSet | None = None) -> None:
        self.config = config or Config()
        # Where a scan writes, and what to re-read when one finishes.
        self.sources: list[Path] = list(sources or [])
        # How scans are named for the whole session, so a file never changes
        # its name between the first read and a re-read after a scan.
        self.name: merge_mod.Naming = naming or merge_mod.naming(self.sources)
        self.databases: list[Path] = (list(databases) if databases is not None
                                      else gw_locate.find_databases(self.sources))
        self.shot_index = gw_locate.ShotIndex(p for p in self.sources if p.is_dir())
        self.scan_dir = Path(self.config.scan_output_dir or scan_dir or Path.cwd())
        self.nmap = presets_mod.probe(self.config.nmap_path)
        self.gowitness = gw_detect.probe(self.config.gowitness_mode,
                                         self.config.gowitness_path,
                                         self.config.gowitness_image)
        self.scans: ScanSet = scans if scans is not None else ScanSet()
        self.shots = gw_results.Captures()
        # One slot per tool: serial within a tool, concurrent across tools.
        self.runner = Runner()
        self.captures = Runner()
        # Keyed by record identity, in marking order - which is export order.
        self.marks: dict[tuple, Record] = {}
        self.owner: Owner | None = None
        self._by_service: dict = {}
        self._by_service_key: tuple | None = None
        self._row_texts: dict[int, tuple] = {}
        # What each finished scan added to what was known, by run.
        self.diffs: dict[int, object] = {}
        self._history: list[timeline.Scan] = []
        self._history_for: object = None
        self._scanned: rawlog.Scanned | None = None
        self._scanned_for: object = None
        self._listeners: list[Callable[[Event], None]] = []
        self._tasks: set[asyncio.Task] = set()

    # --- events -------------------------------------------------------------------

    def listen(self, listener: Callable[[Event], None]) -> Callable[[], None]:
        """Call `listener` with every event; returns the way to stop."""
        self._listeners.append(listener)
        return lambda: self._listeners.remove(listener) if listener in self._listeners else None

    def subscribe(self) -> tuple[Subscription, Callable[[], None]]:
        """A bounded queue of events, for a consumer that reads at its own pace."""
        sub = Subscription()
        return sub, self.listen(sub.put)

    def emit(self, event: Event) -> None:
        for listener in list(self._listeners):
            listener(event)

    # --- the model ----------------------------------------------------------------

    def publish(self, scans: ScanSet, origin: str = "") -> None:
        """Replace the model. Marks are re-found in it by what they are."""
        self.scans = scans
        self.resolve_marks()
        self.emit(Event("model", origin))

    def scan_history(self, report=None) -> list[timeline.Scan]:
        """Every scan file in time order, each diffed against the ones before.

        Rebuilt only when the model is replaced - it re-parses every file,
        which is the expensive half of the Scans tab.
        """
        if self._history_for is not self.scans:
            self._history = timeline.build(self.scans.files, report)
            self._history_for = self.scans
        return self._history

    def scanned(self) -> rawlog.Scanned:
        """Which scans recorded which subject, for the model as it stands."""
        if self._scanned_for is not self.scans or self._scanned is None:
            self._scanned = rawlog.Scanned(self.scans.files)
            self._scanned_for = self.scans
        return self._scanned

    # --- what a row can be found by ---------------------------------------------

    def captures_by_service(self) -> dict[tuple[str, str, int], list]:
        """Every capture, by the service it shows - `(address, protocol, port)`.

        Joined the way a record joins them (`export.service_urls`: the address
        and every name the host answers to), rebuilt only when the model or the
        captures change.
        """
        key = (id(self.scans), self.shots.generation)
        if self._by_service_key != key:
            owner: dict[str, tuple[str, str, int]] = {}
            for host in self.scans.hosts:
                for svc in host.services:
                    for url in service_urls(svc, host):
                        owner.setdefault(canonical_url(url),
                                         (host.address, svc.protocol, svc.port))
            index: dict[tuple[str, str, int], list] = {}
            for capture in self.shots.all():
                where = owner.get(canonical_url(capture.url))
                if where is not None:
                    index.setdefault(where, []).append(capture)
            self._by_service, self._by_service_key = index, key
            self._row_texts = {}
        return self._by_service

    def row_text(self, row) -> str:
        """A row's text to filter on: what the list shows, and what its
        screenshots say - page titles, URLs, technologies, HTTP status.

        So `synology` finds the host whose web page is a Synology login, which
        nothing in the scan itself names. Kept per row: rows are cached with the
        model, and this is asked on every keystroke.
        """
        index = self.captures_by_service()
        if not index or not row.records:
            return row.text
        hit = self._row_texts.get(id(row))
        if hit is not None and hit[0] is row:
            return hit[1]
        words: list[str] = []
        seen: set[int] = set()
        for record in row.records:
            services = ([record.service] if record.service is not None
                        else record.host.services)
            for svc in services:
                for capture in index.get((record.host.address, svc.protocol, svc.port), ()):
                    if id(capture) in seen:
                        continue
                    seen.add(id(capture))
                    words += [capture.title, capture.url, capture.final_url,
                              str(capture.status or ""), *capture.technologies]
        text = f"{row.text} {' '.join(w for w in words if w)}" if words else row.text
        self._row_texts[id(row)] = (row, text)
        return text

    def capture_dirs(self) -> list[gw_capture.Paths]:
        """Where captures are: the one output goes to, then every results
        database found below the sources - at any depth and under any name."""
        own = gw_capture.capture_dir(self.scan_dir)
        found = [gw_capture.Paths(db.parent.resolve(), db.name) for db in self.databases]
        out: dict[Path, gw_capture.Paths] = {}
        for paths in [own, *found]:
            out.setdefault(paths.db, paths)
        return list(out.values())

    def load_captures(self, where_of: Callable[[gw_capture.Paths, int], str] | None = None
                      ) -> None:
        """Read every capture database. Absence is the ordinary case, not an error.

        One by one, so each database's own URLs are listed for it; each resolves
        its screenshots from where it is, with one image index shared.
        `where_of` names a database for the run list when there are several.
        """
        dirs = self.capture_dirs()
        for paths in dirs:
            finder = gw_locate.ShotFinder(paths.db, self.shot_index)
            captures, problems = gw_results.read_database(paths.db, finder)
            self.shots.add(captures)
            self.shots.problems.extend(problems)
            where = where_of(paths, len(dirs)) if where_of is not None else ""
            self.register_disk_capture(paths, [c.url for c in captures], where)

    def register_disk_capture(self, paths: gw_capture.Paths, urls: list[str],
                              where: str = "") -> None:
        """List a capture that exists on disk but was not run in this session."""
        if not paths.db.exists() or not urls:
            return
        if any(getattr(run, "paths", None) == paths for run in self.captures.runs):
            return
        self.captures.runs.append(
            gw_capture.from_disk(paths, urls, captured=len(urls), where=where))

    # --- marks --------------------------------------------------------------------

    def toggle(self, records: tuple[Record, ...] | list[Record], origin: str = "") -> bool:
        """Mark these records, or unmark them when every one is marked already.

        Returns whether they are marked now. A row marks its records, so one
        action on a bucket collects everything in it.
        """
        keys = [r.identity for r in records]
        if keys and all(k in self.marks for k in keys):
            for key in keys:
                self.marks.pop(key, None)
            marked = False
        else:
            for record in records:
                self.marks.setdefault(record.identity, record)
            marked = True
        self.emit(Event("marks", origin))
        return marked

    def clear_marks(self, origin: str = "") -> None:
        if self.marks:
            self.marks.clear()
            self.emit(Event("marks", origin))

    def resolve_marks(self) -> None:
        """Marks point at records of the old model; re-find them in the new one."""
        if not self.marks:
            return
        live: dict[tuple, Record] = {}
        by_address = {h.address: h for h in self.scans.hosts}
        for key, record in self.marks.items():
            host = by_address.get(record.host.address)
            if host is None:
                continue
            if record.service is None:
                live[key] = Record(host)
                continue
            match = next((s for s in host.services
                          if (s.protocol, s.port) == (record.service.protocol,
                                                      record.service.port)), None)
            if match is not None:
                live[key] = Record(host, match)
        self.marks = live

    # --- planning a scan: the steps between a preset and a run --------------------

    def draft_command(self, preset: str, targets: list[str]) -> tuple[str, str, Path]:
        """The editable command line for a preset over targets, what it writes,
        and its output base. Refused with the reason the terminal gives."""
        if not self.nmap.available:
            raise ScanError(f"cannot scan: {self.nmap.reason}")
        presets = self.config.nmap_presets
        if preset not in presets:
            raise ScanError(f"no preset {preset!r}")
        if not targets:
            raise ScanError("no targets")
        problem = presets_mod.writable(self.scan_dir)
        if problem is not None:
            raise ScanError(f"cannot write the scan here: {problem}")
        out_base = presets_mod.output_base(self.scan_dir, preset)
        args = presets[preset]
        if presets_mod.PORTS_PLACEHOLDER in args:
            # The reference workflow greps the open ports out of the previous
            # scan's .gnmap and feeds them to -p. The model already knows them.
            known = export_ports(records_for(self.scans.hosts))
            if not known or not known[0]:
                raise ScanError(f"{preset}: no open port is known yet - run a service "
                                "scan first, or type the ports yourself")
            args = args.replace(presets_mod.PORTS_PLACEHOLDER, known[0])
        command = " ".join([self.config.nmap_path, args, *targets])
        return command, f"writes {out_base}.{{xml,nmap,gnmap}}", out_base

    def plan_scan(self, preset: str, command: str, targets: list[str],
                  out_base: Path) -> ScanPlan:
        """What an edited command would run, exactly - or `CommandError` why not.

        The command is parsed, never re-joined: no shell, nmap only, no output
        flags of the user's. Whether it needs root is read from its flags.
        """
        args = presets_mod.parse_command(command, self.config.nmap_path)
        # The targets are whatever survived the edit, in the order given.
        scan_args = [a for a in args if a not in targets]
        chosen = [a for a in args if a in targets] or targets
        elevate = presets_mod.needs_root(scan_args) and os.geteuid() != 0
        argv = presets_mod.build_argv(self.config.nmap_path, scan_args, chosen,
                                      str(out_base), elevate)
        return ScanPlan(preset, argv, chosen, out_base, elevate,
                        presets_mod.privileged_labels(scan_args))

    def plan_capture(self, records) -> gw_capture.CaptureRun:
        """A gowitness capture of the HTTP(S) URLs of these records.

        `export_urls` emits one URL per open HTTP service and per name the host
        answers to, with a scheme and an explicit port - the form that stops
        gowitness deriving its own candidates, so the list written is the list
        probed. Refused rather than started when there is nothing to capture: a
        capture of nothing looks like a capture that found nothing.
        """
        if not self.gowitness.available:
            raise ScanError(f"gowitness unavailable: {self.gowitness.reason}")
        busy = self.captures.busy()
        if busy is not None:
            raise ScanError(f"a capture is already running: {busy.label}")
        urls = export_urls(records)
        if not urls:
            raise ScanError("nothing to capture - no HTTP or HTTPS service in this selection")
        paths = gw_capture.capture_dir(self.scan_dir)
        try:
            gw_capture.write_urls(paths, urls)
        except OSError as exc:
            raise ScanError(f"could not write the URL list: {exc.strerror or exc}") from None
        argv = gw_capture.scan_argv(self.gowitness, paths,
                                    chrome_path=self.config.gowitness_chrome_path,
                                    collect_all=self.config.gowitness_collect_all)
        return gw_capture.CaptureRun(argv=argv, paths=paths, urls=urls,
                                     backend=self.gowitness.backend or "")

    # --- runs ---------------------------------------------------------------------

    def running(self) -> Run | None:
        """The run that quitting would end, if any - either tool."""
        return self.runner.busy() or self.captures.busy()

    def start_scan(self, run: ScanRun, origin: str = "") -> asyncio.Task:
        busy = self.runner.busy()
        if busy is not None:
            raise Busy(f"a scan is already running: {busy.label}")
        return self._start(self.runner, run, origin, self._scan_done)

    def start_capture(self, run: gw_capture.CaptureRun, origin: str = "") -> asyncio.Task:
        busy = self.captures.busy()
        if busy is not None:
            raise Busy(f"a capture is already running: {busy.label}")
        return self._start(self.captures, run, origin, self._capture_done)

    def cancel(self, tool: str) -> Run | None:
        """Cancel the running scan (`nmap`) or capture (`gowitness`)."""
        runner = self.runner if tool == "nmap" else self.captures
        running = runner.busy()
        if running is not None and runner.cancel():
            return running
        return None

    def cancel_all(self) -> list[Run]:
        return [r for r in (self.cancel("nmap"), self.cancel("gowitness")) if r is not None]

    def _start(self, runner: Runner, run: Run, origin: str,
               done: Callable[[Run], None]) -> asyncio.Task:
        def on_line(line: str) -> None:
            self.emit(Event("line", origin, run, line))

        def on_done(finished: Run) -> None:
            done(finished)
            self.emit(Event("run", origin, finished))

        def on_start(started: Run) -> None:
            self.emit(Event("run", origin, started))

        task = asyncio.get_running_loop().create_task(
            runner.run(run, on_line, on_done, on_start=on_start))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _scan_done(self, run: Run) -> None:
        if self.owner is not None:
            self.owner.scan_done(run)

    def _capture_done(self, run: Run) -> None:
        # Read back whatever it managed, whatever became of it, and record what
        # it could not capture - gowitness writes failures nowhere else.
        if self.owner is not None:
            self.owner.capture_done(run)
        else:
            self.load_captures()
        self.shots.add_failures(getattr(run, "failures", {}) or {})
