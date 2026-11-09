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
import http.client
import ipaddress
import os
import queue
import shutil
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from seek import notify
from seek.config import Config
from seek.gowitness import capture as gw_capture
from seek.gowitness import detect as gw_detect
from seek.gowitness import locate as gw_locate
from seek.gowitness import results as gw_results
from seek.gowitness.results import canonical_url
from seek.nmap import builder as builder_mod
from seek.nmap import inventory as inventory_mod
from seek.nmap import merge as merge_mod
from seek.nmap import presets as presets_mod
from seek.nmap import rawlog, remote, timeline
from seek.nmap import recent as recent_mod
from seek.nmap import timing as timing_mod
from seek.nmap.export import Record, export_ports, export_urls, records_for, service_urls
from seek.nmap.models import ScanSet
from seek.nmap.runner import ScanRun
from seek.runner import Run, Runner
from seek.vulndb import match as vulndb_match
from seek.vulndb import store as vulndb_store

# How many events a slow listener may fall behind before `line` events are
# dropped for it. A run must never wait for a browser tab.
QUEUE_LIMIT = 2000


@dataclass(slots=True)
class Event:
    """Something every front end may want to show.

    `type` is one of `model` (a new model was published), `run` (a run started
    or ended - `run.state` says which), `line` (a run wrote a line), `marks`,
    `vulndb` (the vulnerability database was updated; `text` summarises it).
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
    # How a command that needs root gets it: "" (it does not, or seek is root),
    # "capabilities" (nmap's own, with --privileged) or "sudo".
    via: str = ""
    # Why it cannot start *here* - nmap missing, the directory not writable.
    # The plan still exists, because it can be copied to another machine.
    blocked: str | None = None
    copy_local: str | None = None    # None when there is no local nmap to run it
    copy_remote: str = ""
    # The configured defaults; the review may change them for this run.
    notify_url: str = ""
    notify_progress: bool = False

    def run(self) -> ScanRun:
        return ScanRun(preset=self.preset, argv=self.argv, targets=self.targets,
                       out_base=self.out_base, elevated=self.elevated,
                       notify_url=self.notify_url, notify_progress=self.notify_progress)


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


def hosts_by_name(hosts) -> dict[str, object]:
    """Every address and every name a host is known by -> the host."""
    from seek.nmap import names as names_mod

    out: dict[str, object] = {}
    for host in hosts:
        out.setdefault(host.address.lower(), host)
        for name in host.hostnames:
            out.setdefault(name.lower(), host)
        for name, _source in names_mod.host_names(host):
            out.setdefault(name.lower(), host)
    return out


def service_at(url: str, by_name: dict):
    """`(host, service)` for the service a URL's host and port name, whatever
    nmap called the port - the fallback when a capture's URL is not one a
    record builds. Only an *open* TCP port counts: a capture of a port the
    scans saw closed says the scans are stale, not where the page runs.
    Shared by the session and the web model, so both place a capture alike."""
    from urllib.parse import urlsplit

    try:
        split = urlsplit(url)
        port = split.port or {"http": 80, "https": 443}.get(split.scheme.lower())
    except ValueError:
        return None
    host = by_name.get((split.hostname or "").lower())
    if host is None or port is None:
        return None
    svc = next((s for s in host.services
                if s.port == port and s.protocol == "tcp" and s.is_open), None)
    return (host, svc) if svc is not None else None


def _by_host_and_port(url: str, by_name: dict) -> tuple[str, str, int] | None:
    found = service_at(url, by_name)
    if found is None:
        return None
    host, svc = found
    return (host.address, svc.protocol, svc.port)


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
        self._unplaced = 0
        self._unplaced_urls: list[str] = []
        self._inventory: inventory_mod.Inventory | None = None
        self._inventory_for: tuple = (None, None)
        self._store: vulndb_store.Store | None = None
        self._lookup: vulndb_match.Lookup | None = None
        self._lookup_for: tuple = (None, None)
        # One update at a time, from whichever front end asked; what it is doing
        # now, for a status line to show.
        self._vulndb_lock = threading.Lock()
        self.vulndb_progress = ""          # the full line: step, bar, activity, time left
        self.vulndb_progress_short = ""    # the same for a status line
        self.vulndb_cancel: threading.Event | None = None
        self._row_texts: dict[int, tuple] = {}
        # What each finished scan added to what was known, by run.
        self.diffs: dict[int, object] = {}
        self._history: list[timeline.Scan] = []
        self._history_for: object = None
        self._scanned: rawlog.Scanned | None = None
        self._scanned_for: object = None
        self._listeners: list[Callable[[Event], None]] = []
        self._tasks: set[asyncio.Task] = set()
        self._outbox: queue.Queue | None = None          # notifications, for one sender

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
            unplaced: list[str] = []
            by_name: dict[str, object] | None = None
            for capture in self.shots.all():
                where = owner.get(canonical_url(capture.url))
                if where is None:
                    # Not a URL this app would have built: nmap may not have
                    # called the port http (`tcpwrapped`, `unknown`, a TLS
                    # service it could not name) while gowitness found a web
                    # page there. The host and port still say which service it
                    # is - the address, or any name the host is known by.
                    if by_name is None:
                        by_name = self._hosts_by_name()
                    where = _by_host_and_port(capture.url, by_name)
                if where is not None:
                    index.setdefault(where, []).append(capture)
                else:
                    unplaced.append(capture.url)
            self._by_service, self._by_service_key = index, key
            self._unplaced = len(unplaced)
            self._unplaced_urls = unplaced
            self._row_texts = {}
        return self._by_service

    def _hosts_by_name(self) -> dict[str, object]:
        return hosts_by_name(self.scans.hosts)

    @property
    def unplaced_captures(self) -> list[str]:
        """The URLs of captures no scanned service could be found for."""
        self.captures_by_service()
        return list(self._unplaced_urls)

    def inventory(self, report=None) -> inventory_mod.Inventory:
        """The software inventory of the model and the captures as they stand.

        A projection of the session rather than something attached to the
        model: half its evidence is captures, which change without the model
        changing. Rebuilt only when either does.
        """
        scans, generation = self._inventory_for
        if (self._inventory is None or scans is not self.scans
                or generation != self.shots.generation):
            index = self.captures_by_service()
            self._inventory = inventory_mod.build(self.scans.hosts, index,
                                                  self._unplaced, report)
            self._inventory.sources = list(self.scans.sources)
            self._inventory_for = (self.scans, self.shots.generation)
        return self._inventory

    # --- the vulnerability lookup ---------------------------------------------------

    def vulndb(self) -> vulndb_store.Store:
        """The database, opened read-only - reopened when it has appeared or
        been replaced since, so an update run from anywhere is picked up."""
        path = vulndb_store.resolve(self.config.vulndb_path)
        if self._store is None or (self._store.missing and path.exists()):
            if self._store is not None:
                self._store.close()
            self._store = vulndb_store.Store(path)
        return self._store

    def reload_vulndb(self) -> None:
        """After an update: read the file afresh and forget the old answers."""
        if self._store is not None:
            self._store.close()
        self._store = None
        self._lookup = None

    @property
    def vulndb_updating(self) -> bool:
        return self._vulndb_lock.locked()

    def update_vulndb(self, progress=None) -> list:
        """Run the database update - blocking, so call it from a thread. The only
        way this application touches the network, and only when asked. Each
        front end emits the `vulndb` event on its own loop afterwards.

        Raises `Busy` when an update is already running.
        """
        import time

        from seek.vulndb import progress as progress_mod
        from seek.vulndb import update as vulndb_update

        if not self._vulndb_lock.acquire(blocking=False):
            raise Busy("the vulnerability database is already being updated")
        self.vulndb_cancel = threading.Event()
        tracker = progress_mod.Tracker(vulndb_update.SOURCES)
        last = [0.0]

        def report(source: str, done: int, total: int, activity: str) -> None:
            tracker(source, done, total, activity)
            self.vulndb_progress = tracker.line()
            self.vulndb_progress_short = tracker.short()
            # Reports arrive per downloaded chunk; a front end redraws four
            # times a second at most, or the status line is all it does.
            now = time.monotonic()
            if progress is not None and (now - last[0] >= 0.25 or done >= total > 0):
                last[0] = now
                progress(source, done, total, activity)

        try:
            results = vulndb_update.run(vulndb_store.resolve(self.config.vulndb_path),
                                        report, self.vulndb_cancel)
        finally:
            self.vulndb_progress = self.vulndb_progress_short = ""
            self.vulndb_cancel = None
            self._vulndb_lock.release()
        self.reload_vulndb()
        return results

    def cancel_vulndb(self) -> bool:
        if self.vulndb_cancel is None:
            return False
        self.vulndb_cancel.set()
        return True

    def vulndb_label(self) -> str:
        """`◈ vulndb 3d`, `◈ vulndb updating …`, or `◈ no vulndb`."""
        if self.vulndb_updating:
            return f"◈ vulndb {self.vulndb_progress_short or 'starting'}"
        store = self.vulndb()
        if store.missing:
            return "◈ no vulndb"
        age = store.age_days()
        if age is None:
            return "◈ vulndb (never completed)"
        return f"◈ vulndb {age * 24:.0f}h" if age < 1 else f"◈ vulndb {age:.0f}d"

    def vulndb_stale(self) -> bool:
        store = self.vulndb()
        age = store.age_days()
        return store.missing or age is None or age > self.config.vulndb_stale_days

    def lookup(self) -> vulndb_match.Lookup:
        """Findings and support status for the inventory as it stands, rebuilt
        when the inventory or the database changes."""
        inv = self.inventory()
        store = self.vulndb()
        key = (inv, store.generation)
        if self._lookup is None or self._lookup_for[0] is not inv \
                or self._lookup_for[1] != key[1]:
            self._lookup = vulndb_match.build(inv, self.scans.hosts, store)
            self._lookup_for = key
        return self._lookup

    def lookup_ready(self) -> vulndb_match.Lookup | None:
        """The lookup if current, or cheap enough to make now - as `inventory_ready`."""
        inv = self.inventory_ready()
        if inv is None:
            return None
        store = self.vulndb()
        if (self._lookup is not None and self._lookup_for[0] is inv
                and self._lookup_for[1] == store.generation):
            return self._lookup
        if len(self.scans.hosts) <= self.INLINE_INVENTORY_HOSTS:
            return self.lookup()
        return None

    # Below this many hosts a record may build the inventory itself; above it
    # only the projection worker does, and a record shows it once it is there.
    INLINE_INVENTORY_HOSTS = 2000

    def inventory_ready(self) -> inventory_mod.Inventory | None:
        """The inventory if it is current - or cheap enough to make now.

        For a record, which is redrawn on every movement of the list cursor
        and must never be the thing that walks twenty thousand hosts.
        """
        scans, generation = self._inventory_for
        if (self._inventory is not None and scans is self.scans
                and generation == self.shots.generation):
            return self._inventory
        if len(self.scans.hosts) <= self.INLINE_INVENTORY_HOSTS:
            return self.inventory()
        return None

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
        presets = self.config.nmap_presets
        if preset not in presets:
            raise ScanError(f"no preset {preset!r}")
        return self.draft_args(preset, presets[preset], targets)

    def draft_args(self, name: str, args: str, targets: list[str]) -> tuple[str, str, Path]:
        """`draft_command` for any arguments - a preset's, an earlier command's,
        or the builder's. `name` names the output files."""
        if not targets:
            raise ScanError("no targets")
        out_base = presets_mod.output_base(self.scan_dir, name)
        if presets_mod.PORTS_PLACEHOLDER in args:
            # The reference workflow greps the open ports out of the previous
            # scan's .gnmap and feeds them to -p. The model already knows them.
            known = export_ports(records_for(self.scans.hosts))
            if not known or not known[0]:
                raise ScanError(f"{name}: no open port is known yet - run a service "
                                "scan first, or type the ports yourself")
            args = args.replace(presets_mod.PORTS_PLACEHOLDER, known[0])
        command = " ".join([self.config.nmap_path, args, *targets])
        return command, f"writes {out_base}.{{xml,nmap,gnmap}}", out_base

    _facts: dict[tuple, builder_mod.Facts] | None = None

    def builder_facts(self, targets: list[str]) -> builder_mod.Facts:
        """What the builder may know about these targets: the open ports and
        round trips earlier scans recorded, which were up, and whether a raw
        scan is possible here at all.

        Kept per model and target list: the browser's builder asks on every
        click, and walking 24 200 hosts was 75 ms - in a server thread, but
        holding the interpreter the terminal is waiting for."""
        key = tuple(targets)
        if self._facts is None or self._facts_for is not self.scans:
            self._facts, self._facts_for = {}, self.scans
        found = self._facts.get(key)
        if found is None:
            found = self._facts[key] = self._build_facts(targets)
            if len(self._facts) > 16:              # one engagement, a few scopes
                del self._facts[next(iter(self._facts))]
        return found

    _facts_for: object = None

    def _build_facts(self, targets: list[str]) -> builder_mod.Facts:
        nets = []
        for target in targets:
            with contextlib.suppress(ValueError):
                nets.append(ipaddress.ip_network(target, strict=False))
        exact = set(targets)

        def covered(host) -> bool:
            if host.address in exact or exact & set(host.hostnames):
                return True
            with contextlib.suppress(ValueError):
                address = ipaddress.ip_address(host.address)
                return any(address in net for net in nets if net.version == address.version)
            return False

        hosts = [h for h in self.scans.hosts if covered(h)]
        tcp = sorted({s.port for h in hosts for s in h.services
                      if s.is_open and s.protocol == "tcp"})
        udp = sorted({s.port for h in hosts for s in h.services
                      if s.is_open and s.protocol == "udp"})
        privileged = (os.geteuid() == 0 or self.nmap.capable
                      or shutil.which("sudo") is not None)
        return builder_mod.Facts(
            targets=tuple(targets), tcp_ports=",".join(map(str, tcp)),
            udp_ports=",".join(map(str, udp)),
            up=frozenset(h.address for h in hosts if h.up),
            privileged=privileged, rtts=tuple(timing_mod.from_hosts(hosts)))

    def version_gaps(self, records) -> dict[str, list]:
        """The open services of `records` that no source has versioned, by host
        address - in record order, each service once."""
        inv = self.inventory()
        gaps: dict[str, list] = {}
        for record in records:
            for svc in record.services:
                if not svc.is_open or svc.protocol not in ("tcp", "udp"):
                    continue
                if inv.service_versioned(record.host, svc):
                    continue
                listed = gaps.setdefault(record.host.address, [])
                if svc not in listed:
                    listed.append(svc)
        return gaps

    def draft_version_gaps(self, records) -> tuple[str, str, Path, list[str]]:
        """The command that versions what the inventory could not, what it
        costs, its output base and its targets - or `ScanError` why not.

        One nmap command gives every target the same port list, so the scan is
        the union of the gaps; the note says how many pairs that adds, so the
        cost is read before anything runs.
        """
        gaps = self.version_gaps(records)
        if not gaps:
            raise ScanError("every open port here already has a version - nothing to scan")
        tcp = sorted({s.port for ss in gaps.values() for s in ss if s.protocol == "tcp"})
        udp = sorted({s.port for ss in gaps.values() for s in ss if s.protocol == "udp"})
        if udp:
            groups = ([f"T:{','.join(map(str, tcp))}"] if tcp else []) + [
                f"U:{','.join(map(str, udp))}"]
            ports = ",".join(groups)
        else:
            ports = ",".join(map(str, tcp))
        args = presets_mod.VERSION_GAPS_ARGS.replace(presets_mod.PORTS_PLACEHOLDER, ports)
        if udp:
            # A UDP port is only scanned by a UDP scan, and naming one scan
            # type drops the default TCP one - so both are named.
            args += " -sU" + (" -sS" if tcp else "")
        targets = list(gaps)
        wanted = sum(len(ss) for ss in gaps.values())
        extra = len(targets) * (len(tcp) + len(udp)) - wanted
        note = (f"{wanted} unversioned port(s) on {len(targets)} host(s); one port list "
                f"for all of them adds {extra} host/port pair(s) that are versioned "
                "already or not open")
        out_base = presets_mod.output_base(self.scan_dir, presets_mod.VERSION_GAPS_PRESET)
        command = " ".join([self.config.nmap_path, args, *targets])
        return command, note, out_base, targets

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
        needs = presets_mod.needs_root(scan_args) and os.geteuid() != 0
        via = ("capabilities" if self.nmap.capable else "sudo") if needs else ""
        run_args = scan_args
        if via == "capabilities" and "--privileged" not in scan_args:
            # nmap uses its capabilities only when told it is privileged.
            run_args = [*scan_args, "--privileged"]
        elevate = via == "sudo"
        argv = presets_mod.build_argv(self.config.nmap_path, run_args, chosen,
                                      str(out_base), elevate)
        blocked = self.scan_blocked()
        return ScanPlan(preset, argv, chosen, out_base, elevate,
                        presets_mod.privileged_labels(scan_args), via=via, blocked=blocked,
                        notify_url=self.config.notify_url,
                        notify_progress=self.config.notify_progress,
                        copy_local=remote.local_text(argv) if self.nmap.available else None,
                        copy_remote=remote.nmap_snippet(scan_args, chosen, out_base.name))

    def scan_blocked(self) -> str | None:
        """Why a scan cannot start on this machine, or `None`. Planning and
        copying do not depend on it - only starting does."""
        if not self.nmap.available:
            return f"cannot scan: {self.nmap.reason}"
        busy = self.runner.busy()
        if busy is not None:
            return f"a scan is already running: {busy.label} - cancel it first (c)"
        problem = presets_mod.writable(self.scan_dir)
        if problem is not None:
            return f"cannot write the scan here: {problem}"
        return None

    def capture_blocked(self) -> str | None:
        """Why a capture cannot start on this machine, or `None`."""
        if not self.gowitness.available:
            return f"gowitness unavailable: {self.gowitness.reason}"
        busy = self.captures.busy()
        if busy is not None:
            return f"a capture is already running: {busy.label}"
        return None

    def plan_capture(self, records) -> gw_capture.CaptureRun:
        """A gowitness capture of the HTTP(S) URLs of these records.

        `export_urls` emits one URL per open HTTP service and per name the host
        answers to, with a scheme and an explicit port - the form that stops
        gowitness deriving its own candidates, so the list written is the list
        probed. Refused rather than started when there is nothing to capture: a
        capture of nothing looks like a capture that found nothing.
        """
        urls = export_urls(records)
        if not urls:
            raise ScanError("nothing to capture - no HTTP or HTTPS service in this selection")
        paths = gw_capture.capture_dir(self.scan_dir)
        cfg = self.config
        argv = gw_capture.scan_argv(self.gowitness, paths,
                                    chrome_path=cfg.gowitness_chrome_path,
                                    collect_all=cfg.gowitness_collect_all,
                                    settle_ms=cfg.gowitness_settle_ms,
                                    settle_cap_ms=cfg.gowitness_settle_cap_ms)
        return gw_capture.CaptureRun(
            argv=argv, paths=paths, urls=urls, backend=self.gowitness.backend or "",
            blocked=self.capture_blocked(),
            notify_url=cfg.notify_url, notify_progress=cfg.notify_progress,
            copy_local=remote.local_text(argv) if self.gowitness.available else None,
            copy_remote=remote.capture_snippet(urls, collect_all=cfg.gowitness_collect_all,
                                               settle_ms=cfg.gowitness_settle_ms,
                                               settle_cap_ms=cfg.gowitness_settle_cap_ms))

    # --- runs ---------------------------------------------------------------------

    def running(self) -> Run | None:
        """The run that quitting would end, if any - either tool."""
        return self.runner.busy() or self.captures.busy()

    def start_scan(self, run: ScanRun, origin: str = "") -> asyncio.Task:
        busy = self.runner.busy()
        if busy is not None:
            raise Busy(f"a scan is already running: {busy.label}")
        problem = presets_mod.writable(self.scan_dir)
        if problem is not None:
            raise ScanError(f"cannot write the scan here: {problem}")
        task = self._start(self.runner, run, origin, self._scan_done)
        self.command_history().record(run.argv)   # its arguments - never its targets
        return task

    _commands: recent_mod.CommandHistory | None = None

    def command_history(self) -> recent_mod.CommandHistory:
        """The arguments of scans started here, kept across sessions."""
        if self._commands is None:
            self._commands = recent_mod.CommandHistory.default()
        return self._commands

    def earlier_commands(self) -> tuple[list[recent_mod.Earlier], list[recent_mod.Earlier]]:
        """(recent, frequent) for the chooser: this engagement's scans and the
        history together, `{ports}` restored where it was the known ports."""
        known = export_ports(records_for(self.scans.hosts))
        ports = known[0] if known else ""
        files, history = self.scans.files, self.command_history()
        return (recent_mod.recent(files, history, ports),
                recent_mod.frequent(files, history, ports))

    def start_capture(self, run: gw_capture.CaptureRun, origin: str = "") -> asyncio.Task:
        busy = self.captures.busy()
        if busy is not None:
            raise Busy(f"a capture is already running: {busy.label}")
        if not self.gowitness.available:
            raise ScanError(f"gowitness unavailable: {self.gowitness.reason}")
        # Written now, not when planned: a review that is cancelled or only
        # copied writes nothing, and a running capture's list is never replaced.
        try:
            gw_capture.write_urls(run.paths, run.urls)
        except OSError as exc:
            raise ScanError(f"could not write the URL list: {exc.strerror or exc}") from None
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
            if run.notify_url and run.notify_progress:
                while mark := notify.crossed(run.fraction(), run.milestone):
                    run.milestone = mark
                    self._notify(run, origin, notify.milestone(
                        run.notify_name, mark, run.elapsed))

        def on_done(finished: Run) -> None:
            done(finished)
            self.emit(Event("run", origin, finished))
            if finished.notify_url:
                self._notify(finished, origin, notify.ended(
                    finished.notify_name, str(finished.state), finished.elapsed))

        def on_start(started: Run) -> None:
            self.emit(Event("run", origin, started))

        task = asyncio.get_running_loop().create_task(
            runner.run(run, on_line, on_done, on_start=on_start))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _notify(self, run: Run, origin: str, message: notify.Message) -> None:
        """Queue a message for the sender thread; a failure is a line in the
        run's log, never a change to the run - the scan did what it did.

        One daemon thread sends them all, in the order queued, so "finished"
        cannot overtake "75 %". Daemon, not the event loop's thread pool:
        `asyncio.run` waits for that pool when the app ends, so a webhook that
        dropped packets held the terminal for the whole send timeout after
        quitting."""
        if self._outbox is None:
            self._outbox = queue.Queue()
            threading.Thread(target=self._send_notices, name="seek-notify",
                             daemon=True).start()
        self._outbox.put((asyncio.get_running_loop(), run, origin, message))

    def _send_notices(self) -> None:
        assert self._outbox is not None
        while True:
            loop, run, origin, message = self._outbox.get()
            try:
                notify.send(run.notify_url, message)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                reason = getattr(exc, "reason", None) or exc
                line = f"[seek] notification failed: {reason}"
                with contextlib.suppress(RuntimeError):   # the loop has closed
                    loop.call_soon_threadsafe(self._noted, run, origin, line)
            finally:
                self._outbox.task_done()

    def _noted(self, run: Run, origin: str, line: str) -> None:
        run.append(line)
        self.emit(Event("line", origin, run, line))

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
