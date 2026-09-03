"""Projections over a consolidated scan set.

Everything here is computed on demand from the hosts handed in - the service
overview, the statistics, the groupings and the export lists are all views, not
stored state, so they cannot drift from the files that were read and they follow
whatever filter the caller has already applied.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from seek.nmap import names, vulns
from seek.nmap.models import Host, ScanSet, Service
from seek.nmap.progress import HOSTS, Report, counted


@dataclass(slots=True)
class ServiceGroup:
    """One row of the service overview: the same service across every host."""

    protocol: str
    port: int
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    members: list[tuple[Host, Service]] = field(default_factory=list)

    @property
    def host_count(self) -> int:
        return len(self.members)

    @property
    def vulnerability_count(self) -> int:
        return sum(len(s.vulnerabilities) for _, s in self.members)

    @property
    def label(self) -> str:
        bits = [f"{self.port}/{self.protocol}"]
        if self.name:
            bits.append(self.name)
        if self.product:
            bits.append(self.product)
        return " ".join(bits)

    def search_text(self) -> str:
        parts = [str(self.port), self.protocol, self.name, self.product,
                 self.version, self.extrainfo]
        return " ".join(p for p in parts if p)


def host_search_text(host: Host) -> str:
    # Names a certificate claims are searchable too: a host whose only name is
    # in its certificate must still be findable by that name.
    parts = [host.address, *names.names_of(host), host.os, host.osclass, host.state]
    parts += [s.name for s in host.open_services if s.name]
    parts += [s.product for s in host.open_services if s.product]
    return " ".join(p for p in parts if p)


def service_groups(hosts: list[Host], report: Report | None = None) -> list[ServiceGroup]:
    """Group open services across hosts.

    Keyed including the version, so two hosts running different releases of the
    same product are separate rows - the version spread is usually the point.
    """
    groups: dict[tuple, ServiceGroup] = {}
    for host in counted(hosts, report, HOSTS):
        for svc in host.open_services:
            key = (svc.protocol, svc.port, svc.name, svc.product, svc.version)
            group = groups.get(key)
            if group is None:
                group = ServiceGroup(
                    protocol=svc.protocol, port=svc.port, name=svc.name,
                    product=svc.product, version=svc.version, extrainfo=svc.extrainfo,
                )
                groups[key] = group
            group.members.append((host, svc))
    return sorted(groups.values(), key=lambda g: (g.protocol, g.port, g.name or ""))


def group_for(hosts: list[Host], svc: Service) -> ServiceGroup | None:
    """The service-overview row ``svc`` belongs to, if it has one.

    Lets a service picked out of one host's record be opened as "the same
    service everywhere", which is the whole point of the overview - keyed
    exactly as :func:`service_groups` keys it, version included. A service that
    is not open anywhere is in no group and the caller has to say what to do.
    """
    key = (svc.protocol, svc.port, svc.name, svc.product, svc.version)
    for group in service_groups(hosts):
        if (group.protocol, group.port, group.name,
                group.product, group.version) == key:
            return group
    return None


@dataclass(slots=True)
class Statistics:
    targets: int = 0
    asserted_up: int = 0
    reachable: int = 0
    with_open_ports: int = 0
    # (service name, how many times it occurs, the ports it was seen on)
    services: list[tuple[str, int, list[str]]] = field(default_factory=list)
    # (port label, how many *hosts* expose it, the services seen on it) - a host
    # cannot expose one port twice, so this counts hosts and occurrences alike.
    ports: list[tuple[str, int, list[str]]] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)

    @property
    def distinct_services(self) -> int:
        return len(self.services)

    @property
    def overstated(self) -> bool:
        """The scan claims more hosts up than show any evidence."""
        return self.asserted_up > self.reachable


def statistics(hosts: list[Host], report: Report | None = None) -> Statistics:
    """Counts over the hosts given, so an active filter is respected."""
    counts: Counter[str] = Counter()
    ports_for: dict[str, set[str]] = defaultdict(set)
    all_ports: set[tuple[int, str]] = set()
    hosts_on: dict[tuple[int, str], set[str]] = defaultdict(set)
    services_on: dict[tuple[int, str], set[str]] = defaultdict(set)
    for host in counted(hosts, report, HOSTS):
        for svc in host.open_services:
            label = svc.name or "unknown"
            counts[label] += 1
            ports_for[label].add(f"{svc.port}/{svc.protocol}")
            key = (svc.port, svc.protocol)
            all_ports.add(key)
            hosts_on[key].add(host.address)
            services_on[key].add(label)
    services = [
        (name, count, sorted(ports_for[name], key=lambda p: int(p.split("/")[0])))
        for name, count in counts.most_common()
    ]
    # Busiest port first, then by number - the same question the service
    # breakdown answers, asked of ports.
    ports = [
        (f"{port}/{proto}", len(hosts_on[(port, proto)]),
         sorted(services_on[(port, proto)]))
        for port, proto in sorted(all_ports,
                                  key=lambda k: (-len(hosts_on[k]), k[0], k[1]))
    ]
    return Statistics(
        targets=len(hosts),
        asserted_up=sum(1 for h in hosts if h.state == "up"),
        reachable=sum(1 for h in hosts if h.reachable),
        with_open_ports=sum(1 for h in hosts if h.open_services),
        services=services,
        ports=ports,
        open_ports=[f"{p}/{proto}" for p, proto in sorted(all_ports)],
    )


def group_by(hosts: list[Host], key: str,
             report: Report | None = None) -> list[tuple[str, list[tuple[Host, Service]]]]:
    """Group open services by ``service``, ``product`` or ``port``.

    Services with no detected product are omitted from the product grouping
    rather than collected under an empty name.
    """
    buckets: dict[str, list[tuple[Host, Service]]] = defaultdict(list)
    for host in counted(hosts, report, HOSTS):
        for svc in host.open_services:
            if key == "product":
                label = svc.product
                if not label:
                    continue
            elif key == "port":
                label = f"{svc.port}/{svc.protocol}"
            else:
                label = svc.name or "unknown"
            buckets[label].append((host, svc))
    return sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0]))


def prepare(scans: ScanSet, hosts: list[Host] | None = None) -> ScanSet:
    """Attach vulnerabilities and certificate names. Called once after loading.

    `hosts` narrows the work to the hosts a read has just added or changed:
    attaching is idempotent, but doing it to twenty-four thousand hosts on
    every publication would cost more than reading the file that prompted it.
    """
    for host in scans.hosts if hosts is None else hosts:
        vulns.attach(host)
        names.attach(host)
    return scans
