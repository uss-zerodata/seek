"""View definitions for the scan viewer.

A view is a column spec plus a way to produce rows from the model. Keeping them
as data means the screen itself stays one table, one filter and one breadcrumb,
whatever is being looked at.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from seek.nmap import views as proj
from seek.nmap.export import Record
from seek.nmap.merge import addr_key as _addr
from seek.nmap.models import Host, ScanSet, Service

ABSENT = "—"


@dataclass(slots=True)
class Row:
    """One table row: its cells, the text a filter matches, and its target."""

    cells: tuple[str, ...]
    text: str
    target: object = None
    sort_key: tuple = ()
    host: Host | None = None   # owner, when the target is one of its services
    addresses: tuple[str, ...] = ()   # what a CIDR filter term tests against
    drill: object = None       # what `Enter` opens, when that is not `target`
    # A view can divide its rows into labelled sections. `section_rank` fixes
    # the order between them and leads the sort key, so no ordering the user
    # picks can interleave two sections or float a heading into the middle of
    # its own lines. Every other view leaves these at their defaults, which
    # makes the whole mechanism a no-op there.
    section: str = ""
    section_rank: int = 0
    heading: bool = False
    style: str = ""            # applied to the whole row, for heading rows
    # What this row stands for, for marking and export: one host, one service on
    # a host, or every pair in a bucket. Filled here because the builders have
    # both halves in hand; the alternative is unwrapping `target` by type at
    # every use site.
    records: tuple[Record, ...] = ()


@dataclass(slots=True)
class Grouping:
    """One bucket of the `by service` / `by product` / `by port` overviews.

    A grouping row used to carry ``target=None``, which cost it two things: it
    could not be opened with `Enter` like every other row, and an export from a
    filtered grouping view fell back to every host in the scan set instead of
    the ones still on screen.
    """

    key: str                                   # "service" | "product" | "port"
    label: str
    members: list[tuple[Host, Service]] = field(default_factory=list)

    @property
    def hosts(self) -> list[Host]:
        """The distinct hosts in this bucket, in address order."""
        seen: dict[str, Host] = {}
        for host, _svc in self.members:
            seen.setdefault(host.address, host)
        return sorted(seen.values(), key=lambda h: _addr(h.address))

    @property
    def ports(self) -> list[str]:
        return sorted({f"{s.port}/{s.protocol}" for _, s in self.members},
                      key=lambda p: int(p.split("/")[0]))


@dataclass(slots=True)
class View:
    title: str
    columns: tuple[str, ...]
    build: Callable[[ScanSet], list[Row]]
    kind: str = "generic"
    subtitle: str = ""
    hosts: list[Host] = field(default_factory=list)
    # The order the view opens in: (column index, descending). A list should
    # arrive in the order that answers what it is for - "how often" for a
    # breakdown - rather than always ascending by its first column.
    default_sort: tuple[int, bool] = (0, False)
    # The tab whose subject this view shows, when it has one. A drill-down that
    # lands on another overview's subject - a service across every host, the
    # hosts in a bucket - marks that tab, so the tab row keeps saying where the
    # user is. A record of one host belongs to whatever it was opened from and
    # leaves this empty.
    tab: str = ""

    def rows(self, scans: ScanSet) -> list[Row]:
        return self.build(scans)


def _fmt(value: object) -> str:
    return ABSENT if value in (None, "") else str(value)


def _reach(host: Host) -> str:
    if host.state == "down":
        return "down"
    if host.reachable:
        return "up" if not host.state_asserted else "up*"
    return "no evidence"


HOST_COLUMNS = ("Address", "Hostname", "OS", "State", "Svcs", "Scans")


def _host_row(h: Host) -> Row:
    return Row(
        cells=(h.address, _fmt(h.hostname), _fmt(h.os), _reach(h),
               str(len(h.open_services)), str(len(h.sources))),
        text=proj.host_search_text(h) + " " + _reach(h),
        target=h,
        records=(Record(h),),
        addresses=(h.address,),
        sort_key=(_addr(h.address), h.hostname or "", h.os or "",
                  _reach(h), len(h.open_services), len(h.sources)),
    )


def hosts_view(only_reachable: bool = False) -> View:
    def build(scans: ScanSet) -> list[Row]:
        return [_host_row(h)
                for h in (scans.reachable if only_reachable else scans.hosts)]

    return View(
        title="Hosts" + (" (reachable)" if only_reachable else ""),
        columns=HOST_COLUMNS, build=build, kind="hosts", tab="hosts",
    )


def host_list(title: str, hosts: list[Host], subtitle: str = "") -> View:
    """The host columns over a subset someone else picked.

    A statistics figure counts hosts; opening it has to show *those* hosts, not
    the ones the host tab happens to be listing.
    """
    def build(_: ScanSet) -> list[Row]:
        return [_host_row(h) for h in hosts]

    return View(title=title, columns=HOST_COLUMNS, build=build, kind="hosts",
                subtitle=subtitle or f"{len(hosts)} host(s)", tab="hosts")


def services_view() -> View:
    def build(scans: ScanSet) -> list[Row]:
        out = []
        for g in proj.service_groups(scans.hosts):
            out.append(Row(
                cells=(str(g.port), g.protocol, _fmt(g.name), _fmt(g.product),
                       _fmt(g.version), _fmt(g.extrainfo),
                       str(g.host_count), str(g.vulnerability_count)),
                text=g.search_text(),
                target=g,
                records=tuple(Record(h, s) for h, s in g.members),
                addresses=tuple(h.address for h, _ in g.members),
                sort_key=(g.port, g.protocol, g.name or "", g.product or "",
                          g.version or "", g.extrainfo or "",
                          g.host_count, g.vulnerability_count),
            ))
        return out

    return View(
        title="Services",
        columns=("Port", "Proto", "Service", "Product", "Version", "Info",
                 "Hosts", "Vulns"),
        build=build, kind="services", tab="services",
    )


def host_detail(host: Host) -> View:
    def build(_: ScanSet) -> list[Row]:
        out = []
        for s in host.services:
            out.append(Row(
                cells=(f"{s.port}/{s.protocol}", _fmt(s.state), _fmt(s.name),
                       _fmt(s.product), _fmt(s.version), _fmt(s.extrainfo),
                       str(len(s.vulnerabilities)), ",".join(s.sources)),
                text=" ".join(filter(None, [str(s.port), s.protocol, s.name,
                                            s.product, s.version, s.extrainfo])),
                target=s,
                host=host,
                records=(Record(host, s),),
                addresses=(host.address,),
                sort_key=(s.port, s.state or "", s.name or "", s.product or "",
                          s.version or "", s.extrainfo or "",
                          len(s.vulnerabilities), ""),
            ))
        return out

    names = ", ".join(host.hostnames) or ABSENT
    return View(
        title=f"Host {host.address}",
        subtitle=(f"{names} · {_fmt(host.os)} · state {_fmt(host.state)} "
                  f"(reason {_fmt(host.reason)}) · seen in {', '.join(host.sources)}"),
        columns=("Port", "State", "Service", "Product", "Version", "Info",
                 "Vulns", "Scans"),
        build=build, kind="host-detail",
    )


def service_detail(group: proj.ServiceGroup) -> View:
    def build(_: ScanSet) -> list[Row]:
        out = []
        for host, svc in group.members:
            out.append(Row(
                cells=(host.address, _fmt(host.hostname), _fmt(svc.version),
                       _fmt(svc.extrainfo), str(len(svc.vulnerabilities)),
                       ",".join(svc.sources)),
                text=f"{host.address} {host.hostname or ''} {svc.version or ''}",
                target=host,
                records=(Record(host, svc),),
                addresses=(host.address,),
                sort_key=(_addr(host.address), host.hostname or "",
                          svc.version or "", svc.extrainfo or "",
                          len(svc.vulnerabilities), ""),
            ))
        return out

    return View(
        title=f"Service {group.label}",
        subtitle=(f"{group.host_count} host(s) · "
                  f"{group.vulnerability_count} vulnerability record(s)"),
        columns=("Address", "Hostname", "Version", "Info", "Vulns", "Scans"),
        build=build, kind="service-detail", tab="services",
    )


def grouping_view(key: str) -> View:
    def build(scans: ScanSet) -> list[Row]:
        out = []
        for label, members in proj.group_by(scans.hosts, key):
            group = Grouping(key=key, label=label, members=list(members))
            addresses = tuple(h.address for h in group.hosts)
            ports = group.ports
            # A `by port` label reads "443/tcp"; compared as text, 1000 sorts
            # before 22. The column sorts on the number the label starts with.
            first: object = int(label.split("/")[0]) if key == "port" else label
            out.append(Row(
                cells=(label, str(len(members)), str(len(addresses)),
                       ", ".join(ports[:6]) + (" …" if len(ports) > 6 else "")),
                text=f"{label} {' '.join(addresses)} {' '.join(ports)}",
                target=group,
                records=tuple(Record(h, s) for h, s in group.members),
                addresses=addresses,
                sort_key=(first, len(members), len(addresses), ""),
            ))
        return out

    return View(
        title=f"Grouped by {key}",
        columns=(key.capitalize(), "Occurrences", "Hosts", "Ports"),
        build=build, kind="grouping", tab=f"group-{key}",
    )


def grouping_detail(group: Grouping) -> View:
    """The hosts behind one grouping row, reached with `Enter`.

    A row describes one service - which is what the detail pane below should
    report - but `Enter` opens the *host* behind it, so an overview drills all
    the way down to a single host's full record without leaving the tab.
    """

    def build(_: ScanSet) -> list[Row]:
        out = []
        for host, svc in sorted(group.members,
                                key=lambda m: (_addr(m[0].address), m[1].port)):
            out.append(Row(
                cells=(host.address, _fmt(host.hostname), f"{svc.port}/{svc.protocol}",
                       _fmt(svc.name), _fmt(svc.version),
                       str(len(svc.vulnerabilities)), ",".join(svc.sources)),
                text=" ".join(filter(None, [host.address, host.hostname, str(svc.port),
                                            svc.name, svc.product, svc.version])),
                target=svc,
                host=host,
                drill=host,
                records=(Record(host, svc),),
                addresses=(host.address,),
                sort_key=(_addr(host.address), host.hostname or "", svc.port,
                          svc.name or "", svc.version or "",
                          len(svc.vulnerabilities), ""),
            ))
        return out

    hosts = group.hosts
    return View(
        title=f"{group.key.capitalize()} {group.label}",
        subtitle=(f"{len(hosts)} host(s) · {len(group.members)} occurrence(s) · "
                  f"ports {', '.join(group.ports)}"),
        columns=("Address", "Hostname", "Port", "Service", "Version", "Vulns", "Scans"),
        build=build, kind="group-hosts", tab=f"group-{group.key}",
    )


SECTIONS = ("Coverage", "Services", "Ports")
HEADING_STYLE = "bold ansi_cyan"


def _heading(name: str, rank: int) -> Row:
    """A section heading is a row - there is only ever one table.

    It carries no filter text and no target: it is not a statistic, so nothing
    can match it and nothing opens from it.
    """
    return Row(cells=(name, "", ""), text="", section=name, section_rank=rank,
               heading=True, style=HEADING_STYLE)


def statistics_view() -> View:
    """The counts, in sections, each line a way into what it counts.

    Everything here used to be one flat list sorted by its first column, so the
    totals and the per-service lines interleaved alphabetically and the open
    ports were a comma list truncated to ten inside one detail cell.
    """

    def build(scans: ScanSet) -> list[Row]:
        st = proj.statistics(scans.hosts)
        out: list[Row] = [_heading("Coverage", 0)]

        def coverage(label: str, count: int, note: str, opens: View,
                     covers: list[Host]) -> Row:
            return Row(cells=(label, str(count), note), text=f"{label} {count} {note}",
                       section="Coverage", section_rank=0,
                       sort_key=(label, count, note),
                       drill=opens,
                       records=tuple(Record(h) for h in covers))

        pn = " (-Pn: assumed)" if scans.disabled_ping else ""
        with_ports = [h for h in scans.hosts if h.open_services]
        out += [
            coverage("Targets", st.targets, "",
                     host_list("Targets", scans.hosts), scans.hosts),
            coverage("Asserted up", st.asserted_up, "reported by the scan" + pn,
                     host_list("Asserted up", scans.asserted_up), scans.asserted_up),
            coverage("Reachable (evidence)", st.reachable,
                     "responded, or was identified" if not st.overstated
                     else "FAR FEWER than asserted",
                     host_list("Reachable (evidence)", scans.reachable),
                     scans.reachable),
            coverage("With open ports", st.with_open_ports, "",
                     host_list("With open ports", with_ports), with_ports),
            coverage("Distinct services", st.distinct_services, "",
                     grouping_view("service"), scans.hosts),
            coverage("Distinct open ports", len(st.open_ports), "",
                     grouping_view("port"), scans.hosts),
        ]

        # A line's bucket is its `target`, so the pane below reports the hosts
        # behind the figure and `Enter` opens them - the same object doing both
        # jobs, as a grouping row does in the `by service` tab.
        out.append(_heading("Services", 1))
        for name, count, ports in st.services:
            members = [(h, s) for h in scans.hosts for s in h.open_services
                       if (s.name or "unknown") == name]
            out.append(Row(
                cells=(name, str(count), ", ".join(ports)),
                text=f"{name} {' '.join(ports)}",
                section="Services", section_rank=1,
                sort_key=(name, count, ", ".join(ports)),
                target=Grouping(key="service", label=name, members=members),
                records=tuple(Record(h, s) for h, s in members),
                addresses=tuple(h.address for h, _ in members),
            ))

        out.append(_heading("Ports", 2))
        for label, count, names in st.ports:
            members = [(h, s) for h in scans.hosts for s in h.open_services
                       if f"{s.port}/{s.protocol}" == label]
            out.append(Row(
                cells=(label, str(count), ", ".join(names)),
                text=f"{label} {' '.join(names)}",
                section="Ports", section_rank=2,
                # The number, not the label: "1000/tcp" sorts before "22/tcp".
                sort_key=(int(label.split("/")[0]), count, ", ".join(names)),
                target=Grouping(key="port", label=label, members=members),
                records=tuple(Record(h, s) for h, s in members),
                addresses=tuple(h.address for h, _ in members),
            ))
        return out

    return View(title="Statistics", columns=("Statistic", "Count", "Detail"),
                build=build, kind="stats", tab="stats",
                # The question a breakdown answers is "how often", so the tab
                # opens on the count, biggest first.
                default_sort=(1, True))
