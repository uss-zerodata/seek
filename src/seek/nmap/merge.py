"""Consolidate several scans into one model.

Consolidation is the normal path, not a special case: a single engagement
produces separate discovery, port and service scans that are only useful read
together, so every run goes through here even when one file was given.

Stateless throughout - the files named on the command line are the whole truth
for a run. Nothing is cached, indexed or written.
"""

from __future__ import annotations

from pathlib import Path

from seek.nmap.models import Host, ScanFile, ScanSet, Service
from seek.nmap.parse import NmapParseError, parse_file


def collect_paths(paths: list[Path]) -> list[Path]:
    """Expand directories to the nmap XML files directly inside them.

    Naming five or more scans by hand every run is exactly the friction that
    pushes people towards an import step, so a directory is accepted in place of
    a list. Order is deterministic: given order, directories sorted by name.
    """
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(c for c in p.iterdir() if c.is_file() and c.suffix.lower() == ".xml"))
        else:
            out.append(p)
    return out


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
    if into.state_asserted and not other.state_asserted and other.reason:
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
            into.services.append(svc)
            by_key[svc.key] = svc
        else:
            _merge_service(existing, svc)
    seen = {(s.id, s.output) for s in into.scripts}
    into.scripts.extend(s for s in other.scripts if (s.id, s.output) not in seen)
    for src in other.sources:
        if src not in into.sources:
            into.sources.append(src)


def merge(files: list[ScanFile]) -> ScanSet:
    """Reconcile parsed files into one set, in the order they were given."""
    hosts: dict[str, Host] = {}
    for sf in files:
        for host in sf.hosts:
            if not host.address:
                continue
            existing = hosts.get(host.address)
            if existing is None:
                hosts[host.address] = host
            else:
                _merge_host(existing, host)
    for host in hosts.values():
        host.services.sort(key=lambda s: (s.protocol, s.port))
    return ScanSet(
        hosts=sorted(hosts.values(), key=lambda h: addr_key(h.address)),
        sources=[sf.name for sf in files],
        disabled_ping=any(sf.disabled_ping for sf in files),
        files=list(files),
    )


def addr_key(addr: str) -> tuple:
    """Sort IPv4 numerically; anything else lexically after it.

    Public because the viewer sorts by address too, and a second copy of this
    would let the two orderings drift apart.
    """
    parts = addr.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts), "")
    return (1, (), addr)


def load(paths: list[Path]) -> ScanSet:
    """Parse and consolidate. Unreadable files are reported, never fatal."""
    files: list[ScanFile] = []
    failures: list[tuple[str, str]] = []
    for path in collect_paths(paths):
        try:
            files.append(parse_file(path))
        except NmapParseError as exc:
            failures.append((path.name, str(exc)))
    scans = merge(files)
    scans.failures = failures
    return scans
