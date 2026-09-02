"""Records parsed out of nmap XML output.

Deliberately plain dataclasses: the viewer computes its overviews as projections
over these (see `views.py`), so nothing here caches or derives anything that
could drift from the files that were read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


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
    scripts: list[ScriptResult] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    # (name, where it came from) for every DNS name this service revealed -
    # its certificate, a redirect, a Windows identity script. Filled by
    # `names.attach` during `views.prepare`, like `vulnerabilities` is: the
    # views must not re-parse script text on every keystroke.
    names: list[tuple[str, str]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    @property
    def cert_names(self) -> list[str]:
        """Just the names this service's own certificate claims."""
        return [n for n, source in self.names if source == "certificate"]

    @property
    def key(self) -> tuple[str, int]:
        return (self.protocol, self.port)

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
    def has_evidence(self) -> bool:
        """Did the scan actually find anything on this host?

        Any port response, service, OS match or script result counts - as does a
        status reason other than `user-set`, which means host discovery really
        did reach it (even if it exposed no port).
        """
        if self.services or self.os or self.scripts:
            return True
        return bool(self.reason) and not self.state_asserted

    @property
    def reachable(self) -> bool:
        """Evidence-based, never the asserted state."""
        return self.state != "down" and self.has_evidence


@dataclass(slots=True)
class ScanFile:
    """One parsed file, before merging."""

    path: Path
    args: str = ""
    hosts: list[Host] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def disabled_ping(self) -> bool:
        """Was this scan run with host discovery disabled?"""
        return " -Pn" in f" {self.args}" or " -P0" in f" {self.args}"


@dataclass(slots=True)
class ScanSet:
    """The consolidated model for one run. Nothing here is persisted."""

    hosts: list[Host] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    failures: list[tuple[str, str]] = field(default_factory=list)
    disabled_ping: bool = False

    @property
    def asserted_up(self) -> list[Host]:
        return [h for h in self.hosts if h.state == "up"]

    @property
    def reachable(self) -> list[Host]:
        return [h for h in self.hosts if h.reachable]

    @property
    def with_open_ports(self) -> list[Host]:
        return [h for h in self.hosts if h.open_services]

    @property
    def overstated(self) -> bool:
        """True when the scan claims more hosts up than show any evidence."""
        return len(self.asserted_up) > len(self.reachable)
