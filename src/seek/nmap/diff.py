"""What one scan added to what was already known.

Computed between two *models*, not two files, so the same comparison answers
"what did that scan find" whether the data arrived from a scan started here or a
file that appeared on disk.

The question a diff answers is narrow on purpose: after a scan, the useful thing
is what is new, not a full inventory - that is what the overviews are for.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from seek.nmap.models import Host, Service


@dataclass(slots=True)
class PortChange:
    address: str
    port: int
    protocol: str
    detail: str = ""

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass(slots=True)
class ServiceChange:
    address: str
    port: int
    protocol: str
    before: str
    after: str

    @property
    def label(self) -> str:
        return f"{self.port}/{self.protocol}"


@dataclass(slots=True)
class ScanDiff:
    """The three things worth knowing after a scan, and nothing else."""

    new_hosts: list[Host] = field(default_factory=list)
    new_ports: list[PortChange] = field(default_factory=list)
    changed: list[ServiceChange] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.new_hosts or self.new_ports or self.changed)

    def summary(self) -> str:
        """One line for the run list - said plainly when nothing is new."""
        if self.empty:
            return "nothing new"
        bits = []
        if self.new_hosts:
            bits.append(f"{len(self.new_hosts)} new host(s)")
        if self.new_ports:
            bits.append(f"{len(self.new_ports)} new port(s)")
        if self.changed:
            bits.append(f"{len(self.changed)} changed")
        return " · ".join(bits)


def _identify(svc: Service) -> str:
    """How a service is identified, as one comparable string."""
    return " ".join(p for p in (svc.name, svc.product, svc.version) if p)


def diff(before: list[Host], after: list[Host]) -> ScanDiff:
    """What `after` has that `before` did not.

    Only additions and changes: a port that stopped answering is a real fact but
    not one a scan *found*, and mixing the two into one list makes neither
    readable. The overviews still show the current state either way.
    """
    known = {h.address: h for h in before}
    result = ScanDiff()
    for host in after:
        previous = known.get(host.address)
        if previous is None:
            result.new_hosts.append(host)
            continue
        seen = {(s.protocol, s.port): s for s in previous.open_services}
        for svc in host.open_services:
            key = (svc.protocol, svc.port)
            was = seen.get(key)
            if was is None:
                result.new_ports.append(PortChange(
                    address=host.address, port=svc.port, protocol=svc.protocol,
                    detail=_identify(svc)))
            elif _identify(was) != _identify(svc) and _identify(svc):
                result.changed.append(ServiceChange(
                    address=host.address, port=svc.port, protocol=svc.protocol,
                    before=_identify(was) or "unidentified", after=_identify(svc)))
    return result
