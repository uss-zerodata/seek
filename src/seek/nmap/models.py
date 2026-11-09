"""Records parsed out of nmap XML output.

Deliberately plain dataclasses: the viewer computes its overviews as projections
over these (see `views.py`), so nothing here caches or derives anything that
could drift from the files that were read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Where two ports share a number, the protocol decides - tcp, then udp, then
# the rest - so `8080/tcp` always precedes `8080/udp` rather than whichever the
# model happened to hold first. Keys are all integers so the sort compares them
# as numbers, never as the text "8080/tcp" (which puts 1000 before 22).
_PROTO_ORDER = {"tcp": 0, "udp": 1, "sctp": 2}


def port_key(port: int, protocol: str | None = None) -> tuple[int, int]:
    """How a port sorts: by its number, then its protocol."""
    return (port, _PROTO_ORDER.get((protocol or "").lower(), len(_PROTO_ORDER)))


def by_port(svc: Service) -> tuple[int, int]:
    """`port_key` for a service - the one order a host's ports are held in."""
    return port_key(svc.port, svc.protocol)


@dataclass(slots=True)
class Vulnerability:
    """One finding lifted out of a script result.

    ``state`` is what the NSE `vuln` library reports (`VULNERABLE`,
    `LIKELY VULNERABLE`, `NOT VULNERABLE`). ``severity`` is only ever set by a
    script that actually scores the finding, such as `vulners`' CVSS - a state
    is never mapped onto a severity, because that would be inventing an
    assessment the scan did not make.
    """

    id: str
    title: str | None = None
    state: str | None = None
    severity: str | None = None
    ids: list[str] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    disclosed: str | None = None
    source_script: str | None = None

    def identity(self) -> tuple[str, str | None]:
        """Key for de-duplicating one finding reported against several ports."""
        return (self.id, self.source_script)


@dataclass(slots=True)
class ScriptResult:
    """An NSE script's output: free text plus, when it emits them, its
    ``<table>`` / ``<elem>`` entries as a keyed tree."""

    id: str
    output: str | None = None
    data: dict | list | None = None


@dataclass(slots=True)
class OsMatch:
    """One `<osmatch>`: nmap's name for a guess, how sure it is, and the CPEs
    of its `<osclass>` entries - often several kernel lines for one match."""

    name: str
    accuracy: int | None = None
    cpes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Service:
    protocol: str
    port: int
    state: str | None = None
    reason: str | None = None
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    ostype: str | None = None
    tunnel: str | None = None
    method: str | None = None
    conf: str | None = None
    # The `<cpe>` identifiers nmap gave with the identification, as written
    # (CPE 2.2 URIs). They travel with it when scans merge, like `conf`.
    cpes: list[str] = field(default_factory=list)
    scripts: list[ScriptResult] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    # (name, where it came from) for every DNS name this service revealed -
    # its certificate, a redirect, a Windows identity script. Filled by
    # `names.attach` during `views.prepare`, like `vulnerabilities` is: the
    # views must not re-parse script text on every keystroke.
    names: list[tuple[str, str]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, int]:
        return (self.protocol, self.port)

    def copy(self) -> Service:
        """A private copy: every list is new, the records inside are shared.

        The lists are what get written to - `merge` extends them, and
        `views.prepare` attaches names and vulnerabilities to them - so each
        copy needs its own. A `ScriptResult` or `Vulnerability` is written once
        where it is parsed and only read after that, so copying those too would
        buy nothing and cost the deep copy this replaces.
        """
        return Service(
            protocol=self.protocol, port=self.port, state=self.state,
            reason=self.reason, name=self.name, product=self.product,
            version=self.version, extrainfo=self.extrainfo, ostype=self.ostype,
            tunnel=self.tunnel, method=self.method, conf=self.conf,
            cpes=list(self.cpes), scripts=list(self.scripts),
            vulnerabilities=list(self.vulnerabilities),
            names=list(self.names), sources=list(self.sources),
        )

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    def label(self) -> str:
        bits = [f"{self.port}/{self.protocol}"]
        if self.name:
            bits.append(self.name)
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(bits)


@dataclass(slots=True)
class Host:
    address: str
    addrtype: str | None = None
    hostnames: list[str] = field(default_factory=list)
    state: str | None = None
    reason: str | None = None
    os: str | None = None
    osclass: str | None = None
    services: list[Service] = field(default_factory=list)
    scripts: list[ScriptResult] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    # Every OS match, best first as nmap orders them. `os`/`osclass` stay the
    # best one's name and family for the views that already read them.
    os_matches: list[OsMatch] = field(default_factory=list)
    times: Times | None = None

    @property
    def hostname(self) -> str | None:
        return self.hostnames[0] if self.hostnames else None

    @property
    def open_services(self) -> list[Service]:
        return [s for s in self.services if s.is_open]

    @property
    def state_asserted(self) -> bool:
        """`-Pn` makes nmap record `up` for every target it was given, with the
        reason `user-set`. Such a state is an assumption, not an observation."""
        return self.reason == "user-set"

    @property
    def discovered(self) -> bool:
        """Host discovery really reached it: `up` for a reason other than `-Pn`."""
        return self.state == "up" and not self.state_asserted

    @property
    def up(self) -> bool:
        """The one rule every view and export uses.

        An open port makes a host up however it was scanned; otherwise only a
        real discovery result does. A `-Pn` host with closed or filtered ports,
        an OS guess or script output is *not* up - a filtered port is the
        absence of a reply, and the rule has to agree with the host export.
        """
        return self.discovered or any(s.is_open for s in self.services)

    def copy(self) -> Host:
        """A private copy, on the same terms as `Service.copy`."""
        return Host(
            address=self.address, addrtype=self.addrtype,
            hostnames=list(self.hostnames), state=self.state, reason=self.reason,
            os=self.os, osclass=self.osclass,
            services=[s.copy() for s in self.services],
            scripts=list(self.scripts), sources=list(self.sources),
            os_matches=list(self.os_matches), times=self.times,
        )


@dataclass(frozen=True, slots=True)
class Times:
    """What nmap measured to a host - `<times srtt rttvar to>`, in microseconds:
    the smoothed round-trip time, its variation, and the probe timeout nmap
    settled on. The command builder derives RTT timeouts from them."""

    srtt: int
    rttvar: int
    to: int


@dataclass(slots=True, repr=False)
class ScanFile:
    """One parsed file, before merging."""

    path: Path
    args: str = ""
    hosts: list[Host] = field(default_factory=list)
    start: int | None = None        # <nmaprun start="..."> as a unix epoch
    # What the scan is called everywhere it is named - provenance, the Scans
    # tab, failures, exports. The file name unless several directories were
    # read, where two `scan.xml` would otherwise be one source (`merge.naming`).
    label: str = ""
    # False when the XML stops part-way - a cancelled or crashed scan. The
    # hosts it finished are kept; the viewer says the file is incomplete.
    complete: bool = True

    def __repr__(self) -> str:
        """A summary, for the same reason `ScanSet` has one.

        The generated repr walks every host of the file. Anything holding a
        `ScanFile` - a raw-log entry on a line of a record, and so anything
        that entry is handed to - would pay for that the moment something
        printed it, and Textual prints a worker's arguments.
        """
        return f"ScanFile({self.name}, {len(self.hosts)} host(s))"

    @property
    def name(self) -> str:
        return self.label or self.path.name

    @property
    def stem(self) -> str:
        """The name without its extension, for lists that show many scans."""
        return self.name.removesuffix(self.path.suffix)

    @property
    def disabled_ping(self) -> bool:
        """Was this scan run with host discovery disabled?"""
        return " -Pn" in f" {self.args}" or " -P0" in f" {self.args}"


@dataclass(slots=True, repr=False)
class ScanSet:
    """The consolidated model for one run. Nothing here is persisted."""

    hosts: list[Host] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    disabled_ping: bool = False
    # The individual parsed files behind this set, kept so the Scans tab can
    # present each scan on its own and diff them as a history over time.
    files: list[ScanFile] = field(default_factory=list)

    def __repr__(self) -> str:
        """A summary, never the contents.

        The generated repr walks every host, every service and every script
        result. That is not a debugging aid at this size, it is a hazard:
        Textual builds a description for a worker by `repr`-ing its arguments,
        so handing a model to a thread worker cost seconds on the event loop -
        measured at 2.8 s for 24 200 hosts, which is the whole responsiveness
        budget spent on a string nobody reads. Anything that wants the
        contents has the fields.
        """
        return (f"ScanSet({len(self.hosts)} host(s), {len(self.sources)} source(s), "
                f"{len(self.failures)} failure(s))")

    @property
    def asserted_up(self) -> list[Host]:
        return [h for h in self.hosts if h.state == "up"]

    @property
    def up(self) -> list[Host]:
        return [h for h in self.hosts if h.up]

    @property
    def with_open_ports(self) -> list[Host]:
        return [h for h in self.hosts if h.open_services]

    @property
    def overstated(self) -> bool:
        """True when the scan claims more hosts up than the rule accepts."""
        return len(self.asserted_up) > len(self.up)
