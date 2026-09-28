"""nmap's own text, cut down to one host or one port.

Everything the viewer shows is derived from the XML, and a derived value can
only be trusted as far as the derivation is. This is the way back: given a
record and the scans that recorded it, produce what nmap actually wrote about
that host, or about that port on that host, so the parse can be checked against
the output - and so that the things nmap reports only in its text are readable
where they matter. `Not shown: 984 filtered tcp ports (no-response)` has no
field in the XML at all, and the `REASON` column is the difference between a
port that answered and one that was assumed.

**This module never interprets a value.** It answers "which lines", not "what
do they mean": the XML stays the single source of the model, and text that
disagreed with it would be a bug to look at, not a second opinion to merge. It
is also read-only in the strongest sense - the `.nmap` file is opened, never
written, and nothing here touches a parsed record.

The cutting is a boundary search, not a parse, because nmap's text is blocks:

- `Nmap scan report for …` opens a host, and the next one closes it. So does
  the `# Nmap done` footer, and the `Service detection performed…` note that
  precedes it.
- A port line opens a port, and the next port line closes it. Its `|` and `|_`
  continuation lines belong to it.

Two traps, both of which the fixtures reproduce. A report line carries either
`<address>` or `<name> (<address>)`, so matching has to accept both - and it
has to match the address *as a whole*, or `10.10.10.1` opens the block that
belongs to `10.10.10.10`. And a port number can occur inside another port's
script output (`the daemon also answers on 80/tcp`), so a port line is
recognised by its shape at the start of a line, never by the number alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from seek.nmap.models import Host, ScanFile, Service

# `Nmap scan report for 192.0.2.1` or `Nmap scan report for a.example (192.0.2.1)`.
# The address is taken from the parenthesised form when there is one, and from
# the bare remainder otherwise; `-v` appends `[host down]` and friends, which
# the trailing group absorbs.
_REPORT = re.compile(r"^Nmap scan report for (?P<rest>.+?)\s*$")
_PARENTHESISED = re.compile(r"^(?P<name>\S+) \((?P<addr>[^)]+)\)")
# `443/tcp open  http    Apache httpd 2.4.52`. Anchored, because the same text
# appears inside script output where it is prose, not a port.
_PORT_LINE = re.compile(r"^(?P<port>\d+)/(?P<proto>[a-z]+)\s+\S+")
# The lines a port's own output continues on.
_CONTINUATION = ("|", " ")
# Where a host block ends even without another report line following it.
_FOOTERS = ("# Nmap done", "Service detection performed", "Read data files from",
            "NSE:", "Nmap done:")


@dataclass(slots=True)
class Entry:
    """One scan's account of a subject, and where to read it from.

    Built from the parsed model alone - listing the entries of a record must
    not touch the disk, because the cursor moves between records continuously
    and a `.nmap` file can be tens of megabytes. `path` is opened only when
    the entry is opened.
    """

    scan: ScanFile
    path: Path | None                       # the `.nmap` beside the XML, if any
    hosts: int = 0                          # what this scan saw of the subject
    open_ports: int = 0

    @property
    def label(self) -> str:
        return self.scan.stem

    @property
    def written(self) -> bool:
        """Did this scan leave output of its own, or must it be reconstructed?"""
        return self.path is not None

    def summary(self) -> str:
        """What this scan established about the subject, in a few words."""
        if self.open_ports:
            return f"{self.open_ports} port(s) open"
        return "no open ports" if self.hosts else "not recorded"


def output_beside(scan: ScanFile) -> Path | None:
    """The `.nmap` file `-oA` writes next to the XML, when it is there."""
    sibling = scan.path.with_suffix(".nmap")
    try:
        return sibling if sibling.is_file() else None
    except OSError:
        return None


class Scanned:
    """Which scans recorded which address, indexed once for a model.

    The record pane redraws on every movement of the list cursor, so deriving
    this per draw means walking every host of every file each time - measured
    at 5 ms for 120 files over 24 200 hosts, against 0.1 ms to draw the record
    itself. Built once and kept with the model it describes, as the scan
    history already is.

    The sibling `.nmap` is looked for here too, once per file rather than once
    per record: that is a `stat`, and the cursor moves continuously.
    """

    def __init__(self, files: list[ScanFile]) -> None:
        # Scan order, so the entries read as the history they are - exactly as
        # the Scans tab orders the same files.
        self._ordered = sorted(files,
                               key=lambda f: (f.start is None, f.start or 0, f.name))
        self._output: dict[int, Path | None] = {}
        self._by_address: dict[str, list[tuple[ScanFile, list[Host]]]] = {}
        for sf in self._ordered:
            self._output[id(sf)] = output_beside(sf)
            seen: dict[str, list[Host]] = {}
            for host in sf.hosts:
                if host.address:
                    seen.setdefault(host.address, []).append(host)
            for address, hosts in seen.items():
                self._by_address.setdefault(address, []).append((sf, hosts))

    def entries(self, host: Host, service: Service | None = None) -> list[Entry]:
        """The scans that recorded this host - or this port on it - in scan order."""
        out: list[Entry] = []
        for sf, seen in self._by_address.get(host.address, ()):
            if service is not None and not any(
                    s.key == service.key for h in seen for s in h.services):
                continue
            out.append(Entry(
                scan=sf, path=self._output[id(sf)], hosts=len(seen),
                open_ports=sum(len(h.open_services) for h in seen),
            ))
        return out


def entries_for(host: Host, files: list[ScanFile],
                service: Service | None = None) -> list[Entry]:
    """The scans that recorded this subject, indexing the files as it goes.

    The convenient form, for a caller with a handful of files and no reason to
    keep an index. Anything drawing a record repeatedly should hold a
    :class:`Scanned` instead.
    """
    return Scanned(files).entries(host, service)


def _address_of(rest: str) -> str:
    """The address a report line names, whichever of its two shapes it is."""
    parenthesised = _PARENTHESISED.match(rest)
    if parenthesised is not None:
        return parenthesised.group("addr")
    # `192.0.2.3 [host down]` under `-v`: the address is the first field.
    return rest.split(" ", 1)[0]


def host_block(text: str, address: str) -> list[str]:
    """The lines one scan wrote about `address`, or none if it wrote none."""
    lines = text.splitlines()
    start = -1
    for i, line in enumerate(lines):
        report = _REPORT.match(line)
        if report is None:
            continue
        if start >= 0:                              # the next host closes this one
            return _trimmed(lines[start:i])
        if _address_of(report.group("rest")) == address:
            start = i
    if start < 0:
        return []
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith(_FOOTERS):
            end = i
            break
    return _trimmed(lines[start:end])


def port_block(text: str, address: str, port: int, protocol: str) -> list[str]:
    """The lines about one port, with the host lines that say whose port it is.

    A port line on its own does not name its host, so the block keeps what
    comes before the port table - the report line, the state, the `Not shown:`
    summary - and the column header, then the port's own line and whatever
    continues it.
    """
    block = host_block(text, address)
    if not block:
        return []
    wanted = f"{port}/{protocol}"
    head: list[str] = []
    header = ""
    body: list[str] = []
    taking = False
    for line in block:
        found = _PORT_LINE.match(line)
        if found is not None:
            if taking:                              # the next port closes ours
                break
            taking = f"{found.group('port')}/{found.group('proto')}" == wanted
            if taking:
                body.append(line)
            continue
        if taking:
            # `|`/`|_` output and indented continuations belong to the port.
            if line.startswith(_CONTINUATION):
                body.append(line)
                continue
            break                                   # back out to the host's own text
        if line.startswith("PORT "):
            header = line
        else:
            head.append(line)
    if not body:
        return []
    return _trimmed([*head, header, *body]) if header else _trimmed([*head, *body])


def _trimmed(lines: list[str]) -> list[str]:
    """Drop the blank lines a block collects at its edges."""
    out = list(lines)
    while out and not out[0].strip():
        out.pop(0)
    while out and not out[-1].strip():
        out.pop()
    return out


def reconstruct(host: Host, service: Service | None = None) -> list[str]:
    """A report in nmap's shape, built from what was parsed.

    For a scan that left no `.nmap` file - an engagement handed over as XML
    alone leaves none - so that the feature does not simply disappear. Whatever
    shows this is required to label it as reconstructed: text presented as
    nmap's own when it was rebuilt from the parse would defeat the only reason
    any of this exists.
    """
    name = f" ({host.address})" if host.hostnames else ""
    who = f"{host.hostnames[0]}{name}" if host.hostnames else host.address
    out = [f"Nmap scan report for {who}"]
    state = host.state or "unknown"
    reason = f", received {host.reason}" if host.reason else ""
    out.append(f"Host is {state}{reason}")
    shown = [service] if service is not None else host.services
    if shown:
        out.append("")
        out.append("PORT      STATE  SERVICE       VERSION")
        for svc in shown:
            label = f"{svc.port}/{svc.protocol}"
            version = " ".join(x for x in (svc.product, svc.version) if x)
            out.append(f"{label:<9} {(svc.state or ''):<6} "
                       f"{(svc.name or ''):<13} {version}".rstrip())
            for script in svc.scripts:
                out.extend(_script_lines(script))
    elif service is None:
        out.append("No open ports recorded")
    if service is None and host.scripts:
        out.append("")
        out.append("Host script results:")
        for script in host.scripts:
            out.extend(_script_lines(script))
    return out


def _script_lines(script) -> list[str]:
    """One script, in the `|`/`|_` shape nmap writes it in."""
    body = [line for line in (script.output or "").splitlines() if line.strip()]
    if not body:
        return [f"|_{script.id}:"]
    if len(body) == 1:
        return [f"|_{script.id}: {body[0].strip()}"]
    out = [f"| {script.id}:"]
    out += [f"|   {line.strip()}" for line in body[:-1]]
    out.append(f"|_  {body[-1].strip()}")
    return out


# --- what a caller gets back -------------------------------------------------


@dataclass(slots=True, repr=False)
class Request:
    """What to read and for whom: one line of a record carries one of these.

    The whole of what `o` needs, in one object, so the record can say "this
    line opens that" without the pane having to reassemble the subject from
    what it happens to be showing.
    """

    entry: Entry
    host: Host
    service: Service | None = None

    def __repr__(self) -> str:
        """Summarised: this is what gets handed to a thread worker, and Textual
        describes a worker by `repr`-ing its arguments. A `Host` prints every
        service it has."""
        return f"Request({self.entry.label} · {self.subject})"

    @property
    def subject(self) -> str:
        """What the excerpt is scoped to, for the heading above it."""
        if self.service is None:
            return self.host.address
        return f"{self.service.port}/{self.service.protocol} on {self.host.address}"


@dataclass(slots=True)
class Excerpt:
    """One entry, read: its lines and how they were arrived at."""

    lines: list[str]
    reconstructed: bool = False
    problem: str = ""                       # set when there is nothing to show

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def read(request: Request, source: str | None = None) -> Excerpt:
    """The scoped output for one request, however it has to be arrived at.

    Both failure states are content, not exceptions: a file that cannot be read
    and a file that does not mention the subject are things the reader has to
    be told, and an empty pane tells them nothing. `source` is the file's text
    when a caller has already read it - which is how the viewer keeps a cache
    without this module owning one.
    """
    entry, host, service = request.entry, request.host, request.service
    if service is not None and service.key not in {s.key for s in host.services}:
        return Excerpt([], problem="that service is not on this host")
    if entry.path is None:
        return Excerpt(reconstruct(host, service), reconstructed=True)
    text = source
    if text is None:
        try:
            text = entry.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return Excerpt([], problem=f"{entry.path.name} could not be read: "
                                       f"{exc.strerror or exc}")
    lines = (host_block(text, host.address) if service is None
             else port_block(text, host.address, service.port, service.protocol))
    if not lines:
        what = host.address if service is None else \
            f"{service.port}/{service.protocol} on {host.address}"
        return Excerpt([], problem=f"{entry.path.name} says nothing about {what}")
    return Excerpt(lines)
