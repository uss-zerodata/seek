"""View definitions for the scan viewer.

A view is a column spec plus a way to produce rows from the model. Keeping them
as data means the screen itself stays one table, one filter and one breadcrumb,
whatever is being looked at.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from seek.nmap import names as name_mod
from seek.nmap import views as proj
from seek.nmap.export import Record
from seek.nmap.merge import addr_key as _addr
from seek.nmap.models import Host, ScanSet, Service
from seek.nmap.progress import HOSTS, Report, counted
from seek.tui.cells import width_of

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
    # Both derived lists are a full pass over the members, and the record pane
    # asks for them again on every movement of the cursor. A bucket can hold
    # three hundred thousand services, so "recompute on each access" is a
    # second of the event loop per keypress. The bucket is built from a model
    # that cannot change under it - a new model builds new buckets - so the
    # answer is kept.
    _hosts: list[Host] | None = field(default=None, repr=False, compare=False)
    _ports: list[str] | None = field(default=None, repr=False, compare=False)

    @property
    def hosts(self) -> list[Host]:
        """The distinct hosts in this bucket, in address order."""
        if self._hosts is None:
            seen: dict[str, Host] = {}
            for host, _svc in self.members:
                seen.setdefault(host.address, host)
            self._hosts = sorted(seen.values(), key=lambda h: _addr(h.address))
        return self._hosts

    @property
    def ports(self) -> list[str]:
        if self._ports is None:
            self._ports = sorted(
                {f"{s.port}/{s.protocol}" for _, s in self.members},
                key=lambda p: int(p.split("/")[0]))
        return self._ports


@dataclass(slots=True)
class View:
    title: str
    columns: tuple[str, ...]
    build: Callable[..., list[Row]]
    kind: str = "generic"
    subtitle: str = ""
    # `repr=False` for the same reason `ScanSet.__repr__` is hand-written: a
    # view is passed to a thread worker, and Textual reprs what it is passed.
    hosts: list[Host] = field(default_factory=list, repr=False)
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
    # Rows are a pure projection of the model, and the model only changes when
    # a scan finishes - but a sort, a resize, a tab switch and every keystroke
    # in the filter box all ask for them again. Projecting six thousand hosts
    # takes a second or more, so the answer is kept until the model it was
    # built from is replaced.
    #
    # A view whose rows depend on something else - the Scans tab reads the
    # runners' live state - sets `cacheable=False` and is recomputed each time.
    cacheable: bool = True
    # Whether `build` takes the progress report as its second argument. A flag
    # rather than introspection, and false by default, so a view built for one
    # purpose - a test's fixed list, a drill-down over a handful of rows -
    # keeps the one-argument builder it has always had. Only the overviews,
    # which walk the whole model, are worth counting.
    reports: bool = False
    _rows_of: ScanSet | None = field(default=None, repr=False, compare=False)
    _rows: list[Row] = field(default_factory=list, repr=False, compare=False)
    _natural: list[int] | None = field(default=None, repr=False, compare=False)

    def cached_for(self, scans: ScanSet) -> bool:
        """Are this view's rows already built for exactly this model?"""
        return self.cacheable and self._rows_of is scans

    def rows(self, scans: ScanSet, report: Report | None = None) -> list[Row]:
        """This view's rows, built if they are not already there for `scans`.

        `report` is only ever passed by the worker that owns a background
        build; every other caller asks for rows that are either cached or
        cheap, and a report from those would be a bar that flickered on and
        off between keystrokes.
        """
        if not self.cacheable:
            return self._built(scans, report)
        if self._rows_of is not scans:
            self._rows = self._built(scans, report)
            self._rows_of = scans
            self._natural = None
        return self._rows

    def _built(self, scans: ScanSet, report: Report | None) -> list[Row]:
        return self.build(scans, report) if self.reports else self.build(scans)

    def measure(self) -> list[int]:
        """The widest cell in each column, over the rows this view built.

        Budgeting the columns means measuring every cell of every row - a sixth
        of a second for a projection that yields fifty thousand of them, and it
        is a pure function of the rows, so it belongs beside the projection in
        the worker rather than on the event loop with the reader waiting. Kept
        with the rows and thrown away with them.
        """
        if self._natural is None:
            widths = [0] * len(self.columns)
            for row in self._rows:
                for i, cell in enumerate(row.cells[:len(widths)]):
                    width = width_of(cell)
                    if width > widths[i]:
                        widths[i] = width
            self._natural = widths
        return self._natural

    def measured(self, rows: list[Row]) -> list[int] | None:
        """`measure()`, but only if `rows` really are the ones this view built."""
        if not self.cacheable or rows is not self._rows or not rows:
            return None
        return self.measure()


def _fmt(value: object) -> str:
    return ABSENT if value in (None, "") else str(value)


def _reach(host: Host) -> str:
    """Which part of the up rule applies: discovery, only an open port
    (`up*`), a `-Pn` assertion nothing confirmed, or a recorded `down`."""
    if host.discovered:
        return "up"
    if host.up:
        return "up*"
    if host.state_asserted:
        return "unconfirmed"
    return _fmt(host.state)


HOST_COLUMNS = ("Address", "Hostname", "OS", "State", "Svcs", "Scans")


def name_cell(host: Host) -> str:
    """The name a host is best known by, and how many more it has.

    The hostname column used to read `—` for a host whose only name came from a
    certificate, which is the app knowing something and not saying it.
    """
    known = name_mod.names_of(host)
    if not known:
        return ABSENT
    return known[0] if len(known) == 1 else f"{known[0]} +{len(known) - 1}"


def _host_row(h: Host) -> Row:
    return Row(
        cells=(h.address, name_cell(h), _fmt(h.os), _reach(h),
               str(len(h.open_services)), str(len(h.sources))),
        text=proj.host_search_text(h) + " " + _reach(h),
        target=h,
        records=(Record(h),),
        addresses=(h.address,),
        sort_key=(_addr(h.address), h.hostname or "", h.os or "",
                  _reach(h), len(h.open_services), len(h.sources)),
    )


def hosts_view(only_up: bool = False) -> View:
    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        hosts = scans.up if only_up else scans.hosts
        return [_host_row(h) for h in counted(hosts, report, HOSTS)]

    return View(
        title="Hosts" + (" (up)" if only_up else ""),
        columns=HOST_COLUMNS, build=build, kind="hosts", tab="hosts",
        reports=True,
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
    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        out = []
        for g in proj.service_groups(scans.hosts, report):
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
        build=build, kind="services", tab="services", reports=True,
    )


def host_detail(host: Host, only_open: bool = False) -> View:
    """One host's ports. `only_open` is `u` here, as up-only is on the
    host list: the overviews count open ports only, this is the one list that
    shows closed and filtered ones too."""
    def build(_: ScanSet) -> list[Row]:
        out = []
        for s in host.open_services if only_open else host.services:
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
        title=f"Host {host.address}" + (" (open ports)" if only_open else ""),
        subtitle=(f"{names} · {_fmt(host.os)} · state {_fmt(host.state)} "
                  f"(reason {_fmt(host.reason)}) · seen in {', '.join(host.sources)}"),
        columns=("Port", "State", "Service", "Product", "Version", "Info",
                 "Vulns", "Scans"),
        build=build, kind="host-detail", hosts=[host],
    )


def service_detail(group: proj.ServiceGroup) -> View:
    def build(_: ScanSet) -> list[Row]:
        out = []
        for host, svc in group.members:
            out.append(Row(
                cells=(host.address, name_cell(host), _fmt(svc.version),
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
    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        out = []
        for label, members in proj.group_by(scans.hosts, key, report):
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
        build=build, kind="grouping", tab=f"group-{key}", reports=True,
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
                cells=(host.address, name_cell(host), f"{svc.port}/{svc.protocol}",
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


def names_view() -> View:
    """Every DNS name the scans revealed, and what it belongs to.

    Names are the half of an engagement that does not fit in an address column:
    a certificate on one host can name three others, and that is worth seeing as
    a list rather than only inside one host's record.
    """

    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        # `Host` and `Service` are unhashable (slots dataclasses with `eq`), so
        # everything here is keyed by address and port rather than by object.
        hosts_for: dict[str, dict[str, Host]] = {}
        sources_for: dict[str, set[str]] = {}
        members_for: dict[str, dict[tuple, tuple[Host, Service]]] = {}
        for host in counted(scans.hosts, report, HOSTS):
            for name, kinds in name_mod.kinds_of(host).items():
                hosts_for.setdefault(name, {})[host.address] = host
                sources_for.setdefault(name, set()).update(kinds)
                bucket = members_for.setdefault(name, {})
                for svc in host.open_services:
                    bucket[(host.address, svc.protocol, svc.port)] = (host, svc)
        out = []
        for name in sorted(hosts_for):
            hosts = list(hosts_for[name].values())
            members = list(members_for.get(name, {}).values())
            ports = sorted({f"{s.port}/{s.protocol}" for _, s in members},
                           key=lambda p: int(p.split("/")[0]))
            source = ", ".join(sorted(sources_for[name]))
            out.append(Row(
                cells=(name, source, str(len(hosts)),
                       ", ".join(ports[:6]) + (" …" if len(ports) > 6 else "")),
                text=f"{name} {source} " + " ".join(h.address for h in hosts),
                # The pane reports the bucket; `Enter` opens the hosts, which is
                # right even for a name whose host has no open service.
                target=(Grouping(key="name", label=name, members=members)
                        if members else None),
                drill=host_list(name, hosts, f"{source} · {len(hosts)} host(s)"),
                addresses=tuple(h.address for h in hosts),
                records=tuple(Record(h) for h in hosts),
                sort_key=(name, source, len(hosts), ""),
            ))
        return out

    return View(title="Names", columns=("Name", "Source", "Hosts", "Ports"),
                build=build, kind="names", tab="names", reports=True)


def statistics_view() -> View:
    """The counts, in sections, each line a way into what it counts.

    Everything here used to be one flat list sorted by its first column, so the
    totals and the per-service lines interleaved alphabetically and the open
    ports were a comma list truncated to ten inside one detail cell.
    """

    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        # The report follows the dominant pass and stops there. The indexing
        # pass below walks the hosts again, but reporting over it would either
        # restart the count - which is not monotonic - or need a total that
        # counts each host twice, which is not hosts. A bar that reaches its
        # end just before the rows appear is the honest version of that.
        st = proj.statistics(scans.hosts, report)
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
            coverage("Up", st.up,
                     "open port, or answered host discovery" if not st.overstated
                     else "FAR FEWER than asserted",
                     host_list("Up", scans.up), scans.up),
            coverage("With open ports", st.with_open_ports, "",
                     host_list("With open ports", with_ports), with_ports),
            coverage("Distinct services", st.distinct_services, "",
                     grouping_view("service"), scans.hosts),
            coverage("Distinct open ports", len(st.open_ports), "",
                     grouping_view("port"), scans.hosts),
        ]

        # Both breakdowns below need the hosts behind every line, and looking
        # those up per line meant walking the whole model once per line - a
        # hundred services over six thousand hosts is fifteen million service
        # reads, and about seven seconds. One pass, indexed both ways, is the
        # same answer for the cost of the model itself.
        by_service: dict[str, list[tuple[Host, Service]]] = {}
        by_port: dict[str, list[tuple[Host, Service]]] = {}
        for host in scans.hosts:
            for svc in host.open_services:
                by_service.setdefault(svc.name or "unknown", []).append((host, svc))
                by_port.setdefault(f"{svc.port}/{svc.protocol}", []).append((host, svc))

        # A line's bucket is its `target`, so the pane below reports the hosts
        # behind the figure and `Enter` opens them - the same object doing both
        # jobs, as a grouping row does in the `by service` tab.
        out.append(_heading("Services", 1))
        for name, count, ports in st.services:
            members = by_service.get(name, [])
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
            members = by_port.get(label, [])
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
                build=build, kind="stats", tab="stats", reports=True,
                # The question a breakdown answers is "how often", so the tab
                # opens on the count, biggest first.
                default_sort=(1, True))
