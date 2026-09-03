"""What one scan added to what was already known.

Computed between two *models*, not two files, so the same comparison answers
"what did that scan find" whether the data arrived from a scan started here or a
file that appeared on disk.

The question a diff answers is narrow on purpose: after a scan, the useful thing
is what is new, not a full inventory - that is what the overviews are for.
"""

from __future__ import annotations

from collections.abc import Iterable
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


# All a diff ever asks of the earlier state: which addresses were known, and
# how each open port was identified. Address -> {(protocol, port): identity}.
Snapshot = dict[str, dict[tuple[str, int], str]]


def snapshot(hosts: Iterable[Host]) -> Snapshot:
    """The comparable part of a model, as plain strings.

    A caller that has to hold the earlier state while the model moves on under
    it - the scan history does, once per scan - keeps this instead of a copy of
    the hosts. It is what `diff` reads anyway, and it cannot be invalidated by
    a later merge writing into the records it was taken from.
    """
    return {h.address: {(s.protocol, s.port): _identify(s) for s in h.open_services}
            for h in hosts}


def diff_from(before: Snapshot, after: Iterable[Host]) -> ScanDiff:
    """`diff`, against a snapshot that was taken earlier."""
    result = ScanDiff()
    for host in after:
        seen = before.get(host.address)
        if seen is None:
            result.new_hosts.append(host)
            continue
        for svc in host.open_services:
            was = seen.get((svc.protocol, svc.port))
            identity = _identify(svc)
            if was is None:
                result.new_ports.append(PortChange(
                    address=host.address, port=svc.port, protocol=svc.protocol,
                    detail=identity))
            elif was != identity and identity:
                result.changed.append(ServiceChange(
                    address=host.address, port=svc.port, protocol=svc.protocol,
                    before=was or "unidentified", after=identity))
    return result


def diff(before: list[Host], after: list[Host]) -> ScanDiff:
    """What `after` has that `before` did not.

    Only additions and changes: a port that stopped answering is a real fact but
    not one a scan *found*, and mixing the two into one list makes neither
    readable. The overviews still show the current state either way.
    """
    return diff_from(snapshot(before), after)
