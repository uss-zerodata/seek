"""Consolidate several scans into one model.

Consolidation is the normal path, not a special case: a single engagement
produces separate discovery, port and service scans that are only useful read
together, so every run goes through here even when one file was given.

Stateless throughout - the files named on the command line are the whole truth
for a run. Nothing is cached, indexed or written.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from seek.nmap.models import Host, ScanFile, ScanSet, Service
from seek.nmap.parse import NmapParseError, parse_file
from seek.nmap.progress import FILES, Report

# nmap writes `<!DOCTYPE nmaprun>` on the second line, and `<nmaprun ...>` after
# a comment that repeats the whole command - targets included, so a scan of a
# /16 pushes the root element tens of kilobytes in. The doctype is what makes
# the check reliable, and the bare word matches either.
_NMAP_MARKER = b"nmaprun"
_SNIFF = 8192


def _is_nmap_xml(path: Path) -> bool:
    """Does this file open like an nmap scan?

    A discovered file has to earn its place: walking a directory tree turns up
    every `.xml` under it, and reporting each pom, plist or feed as a skipped
    scan would bury the real failures. A file named on the command line is not
    sniffed - it was asked for, so if it cannot be parsed the user is told why.
    """
    try:
        with path.open("rb") as fh:
            return _NMAP_MARKER in fh.read(_SNIFF)
    except OSError:
        return False


def _scans_below(root: Path, found: list[Path], report: Report | None) -> list[Path]:
    """Every nmap XML file under `root`, at any depth, in a stable order.

    An engagement directory is rarely flat - scans land in per-phase or
    per-target subdirectories, and the app's own runs write into one - so the
    walk goes all the way down rather than reading the top level only.

    Directories whose name starts with a dot are skipped: `.git` and friends
    hold no scans, and walking them is the one thing that makes an otherwise
    instant start slow. Anything unreadable is passed over - a directory that
    cannot be listed is not an error when the ones beside it can be.
    """
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            # `is_dir()` follows symlinks; `is_symlink()` guards the loop a
            # link back up the tree would otherwise make.
            if entry.is_dir():
                if not entry.is_symlink() and not entry.name.startswith("."):
                    stack.append(entry)
            elif entry.suffix.lower() == ".xml" and _is_nmap_xml(entry):
                found.append(entry)
        # Once per directory, not once per entry: the numbers move at a pace a
        # reader can follow, and a slow `report` cannot dominate the walk.
        #
        # A total of zero, because a walk in progress does not know how many
        # scans it will find - only how many it has. It is the one step here
        # that genuinely cannot count itself, and the shared shape says so
        # rather than drawing a bar against a number it invented.
        if report is not None:
            report(len(found), 0, FILES)
    return sorted(found)


def discover(paths: list[Path], report: Report | None = None) -> list[Path]:
    """Expand directories to the nmap XML files anywhere below them.

    Naming five or more scans by hand every run is exactly the friction that
    pushes people towards an import step, so a directory is accepted in place of
    a list. Order is deterministic: given order, each directory's tree sorted by
    path.

    A file that a directory turns up is dropped if it is already in the list -
    `seek nmap . scans/a.xml` reads `a.xml` once rather than doubling its
    hosts' provenance. A file named twice *by hand* is read twice: an explicit
    list is taken literally, because trimming it would be second-guessing the
    only instruction the user gave.
    """
    out: list[Path] = []
    from_walk: dict[Path, bool] = {}
    # Shared across the roots so the count the walk reports is the run's, not
    # each directory's over again.
    found: list[Path] = []
    for p in paths:
        walked = p.is_dir()
        for path in _scans_below(p, found, report) if walked else [p]:
            try:
                key = path.resolve()
            except OSError:                         # a broken link: judge by name
                key = path.absolute()
            if key in from_walk and (walked or from_walk[key]):
                continue
            from_walk[key] = walked
            out.append(path)
    return out


# What a scan is called, given its path. One function per run, built once from
# the command line, so every file - read at start, or written by a scan later -
# is named the same way.
Naming = Callable[[Path], str]


def bare(path: Path) -> str:
    """The file name alone: one directory, or files named directly."""
    return path.name


def naming(roots: Iterable[Path]) -> Naming:
    """How to name the scans found under `roots`.

    With fewer than two directories a scan is its file name, as it always was.
    With two or more, the file name no longer identifies it - presets and tools
    write the same names everywhere, and two `scan.xml` merged as one source
    recorded a host seen in both as seen once. Every scan is then named by its
    path below the directories' common parent: `x/scan.xml`, `y/sub/scan.xml`.
    All of them rather than only the colliding ones, so a name says where a
    scan came from on its own and does not change when a later scan collides.
    """
    dirs: list[Path] = []
    for root in roots:
        try:
            if Path(root).is_dir():
                dirs.append(Path(root).resolve())
        except OSError:
            continue
    dirs = list(dict.fromkeys(dirs))
    if len(dirs) < 2:
        return bare
    base = Path(os.path.commonpath(dirs))

    def name(path: Path) -> str:
        try:
            return path.resolve().relative_to(base).as_posix()
        except (OSError, ValueError):           # a file named outside them all
            return str(path.absolute())

    return name


# The name this had before discovery and reading were separable. Kept because
# it says something `discover` does not - that a directory is *expanded* into
# the files it holds - and because it is what the tests ask for.
collect_paths = discover


@dataclass(slots=True)
class Pending:
    """Scan files found but not yet read: what a viewer can be opened on.

    Discovery is cheap and reading is not - walking three thousand directories
    is tens of milliseconds against seconds to parse a hundred and twenty
    scans - so the command does the first and hands the second over. This is
    the hand-over: a list of candidates and nothing else, which is enough to
    answer "is there anything here worth opening" without parsing a byte.
    """

    paths: list[Path] = field(default_factory=list)
    # How to name what is read - decided by the command, which has the roots.
    name: Naming = bare

    def __len__(self) -> int:
        return len(self.paths)


# Fields describing *what the service is*, as opposed to how the port responded.
_IDENTIFICATION = ("name", "product", "version", "extrainfo", "ostype", "tunnel")


def _merge_service(into: Service, other: Service) -> None:
    """Fold ``other`` into ``into``: first non-empty value wins, lists union.

    Except for identification: a scan run with `-sV` actually probes the port,
    while one without it guesses the service from nmap's port table. A probe
    therefore overrides a guess rather than losing to whichever file came first
    - otherwise consolidating a port scan with a service scan reports port 3128
    as `squid-http` (the table's guess for that number) instead of the `http`
    that was really found there.
    """
    probed = other.method == "probed" and into.method != "probed"
    # `method`/`conf` travel with the identification, so the record says how the
    # values it actually carries were arrived at.
    overridable = (*_IDENTIFICATION, "method", "conf")
    for attr in ("state", "reason", *overridable):
        value = getattr(other, attr)
        if value in (None, ""):
            continue
        if (probed and attr in overridable) or getattr(into, attr) in (None, ""):
            setattr(into, attr, value)
    seen = {(s.id, s.output) for s in into.scripts}
    into.scripts.extend(s for s in other.scripts if (s.id, s.output) not in seen)
    for src in other.sources:
        if src not in into.sources:
            into.sources.append(src)


def _merge_host(into: Host, other: Host) -> None:
    for attr in ("addrtype", "os", "osclass"):
        if getattr(into, attr) in (None, "") and getattr(other, attr) not in (None, ""):
            setattr(into, attr, getattr(other, attr))
    # A recorded state beats an asserted one: `-Pn` says `up` for everything.
    # Between two recorded ones, `up` wins in either file order - a host that
    # answered discovery once is up, whatever an earlier or later ping missed.
    # An asserted `up` never replaces a recorded `down`: that is the `-Pn` case.
    if into.state_asserted and not other.state_asserted and other.reason:
        into.state, into.reason = other.state, other.reason
    elif into.state == "down" and other.discovered:
        into.state, into.reason = other.state, other.reason
    elif into.state in (None, ""):
        into.state, into.reason = other.state, other.reason
    for name in other.hostnames:
        if name not in into.hostnames:
            into.hostnames.append(name)
    by_key = {s.key: s for s in into.services}
    for svc in other.services:
        existing = by_key.get(svc.key)
        if existing is None:
            # A copy, never the record itself: `into` belongs to the merged
            # model and is written to for the rest of the run, while `other`
            # belongs to the file it was parsed from and must keep saying what
            # that one scan saw.
            taken = svc.copy()
            into.services.append(taken)
            by_key[svc.key] = taken
        else:
            _merge_service(existing, svc)
    seen = {(s.id, s.output) for s in into.scripts}
    into.scripts.extend(s for s in other.scripts if (s.id, s.output) not in seen)
    for src in other.sources:
        if src not in into.sources:
            into.sources.append(src)


class Accumulator:
    """Files folded in one at a time, with a snapshot available between any two.

    The set is built out of copies. Folding scans together means writing into
    the accumulated host, and doing that to the parsed record would rewrite
    history: the first file to mention an address would end up holding
    everything every later scan found there, and nothing could still answer
    "what did *that* scan see". The Scans tab asks exactly that, and gets it
    from `ScanFile.hosts` rather than by parsing the file a second time.

    Incremental because a hundred and twenty files take seconds to read and the
    viewer opens before they are done, so the model has to be showable partway
    through. That makes one more rule necessary than a single-shot merge had:
    **a host that has been handed out is never written to again.** The next
    file to mention it copies it first, and the copy is what gets the new
    services. Otherwise a snapshot already on screen would grow a half-merged
    host under the reader's cursor - the one thing the spec forbids outright.

    The copy is only paid where a file overlaps what a snapshot has already
    seen: `_private` is the set of hosts no snapshot holds yet, and those are
    written to directly however many files touch them.
    """

    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}
        self._private: set[str] = set()
        self._files: list[ScanFile] = []
        self._disabled_ping = False

    def __len__(self) -> int:
        return len(self._hosts)

    @property
    def fresh(self) -> list[Host]:
        """The hosts that have changed since the last snapshot.

        What a caller has to re-derive after folding a file in - attaching
        names and vulnerabilities, say. Doing that to the whole model on every
        publication would cost more than reading the file that prompted it.
        """
        return [self._hosts[address] for address in self._private]

    def add(self, sf: ScanFile) -> None:
        """Fold one parsed file into the set."""
        self._files.append(sf)
        self._disabled_ping = self._disabled_ping or sf.disabled_ping
        for host in sf.hosts:
            if not host.address:
                continue
            into = self._hosts.get(host.address)
            if into is None:
                into = host.copy()
            else:
                if host.address not in self._private:
                    into = into.copy()              # published; leave it alone
                _merge_host(into, host)
            into.services.sort(key=lambda s: (s.protocol, s.port))
            self._hosts[host.address] = into
            self._private.add(host.address)

    def snapshot(self) -> ScanSet:
        """The set as it stands. Everything in it is now read-only to `add`."""
        self._private.clear()
        return ScanSet(
            hosts=sorted(self._hosts.values(), key=lambda h: addr_key(h.address)),
            sources=[sf.name for sf in self._files],
            disabled_ping=self._disabled_ping,
            files=list(self._files),
        )


def merge(files: list[ScanFile]) -> ScanSet:
    """Reconcile parsed files into one set, in the order they were given."""
    acc = Accumulator()
    for sf in files:
        acc.add(sf)
    return acc.snapshot()


def addr_key(addr: str) -> tuple:
    """Sort IPv4 numerically; anything else lexically after it.

    Public because the viewer sorts by address too, and a second copy of this
    would let the two orderings drift apart.
    """
    parts = addr.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts), "")
    return (1, (), addr)


def read(paths: list[Path], report: Report | None = None,
         name: Naming = bare) -> ScanSet:
    """Parse the files named, in the order given, and consolidate them.

    Discovery has already happened: `paths` are files, not directories. Split
    out from :func:`load` because the two halves have very different costs -
    walking three thousand directories is tens of milliseconds, reading a
    hundred and twenty scans is seconds - and a caller that wants to open a
    viewer before it pays the second one needs the first on its own.
    """
    acc = Accumulator()
    failures: list[tuple[str, str]] = []
    total = len(paths)
    for done, path in enumerate(paths, start=1):
        try:
            acc.add(parse_file(path, name(path)))
        except NmapParseError as exc:
            failures.append((name(path), str(exc)))
        if report is not None:
            report(done, total, FILES)
    scans = acc.snapshot()
    scans.failures = failures
    return scans


def load(paths: list[Path], report: Report | None = None,
         name: Naming | None = None) -> ScanSet:
    """Discover and read. Unreadable files are reported, never fatal.

    `report` is called as the search walks (files found, against a total of
    zero, because the walk cannot know it yet) and again as each file is read
    (files read, out of files found). Scans are named from `paths` unless a
    naming is given - a caller re-reading after a scan passes the run's own.
    """
    return read(discover(paths, report), report, name or naming(paths))
