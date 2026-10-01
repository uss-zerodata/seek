"""View definitions for the scan viewer.

A view is a column spec plus a way to produce rows from the model. Keeping them
as data means the screen itself stays one table, one filter and one breadcrumb,
whatever is being looked at.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from seek.nmap import inventory as inv_mod
from seek.nmap import names as name_mod
from seek.nmap import views as proj
from seek.nmap.export import Record
from seek.nmap.merge import addr_key as _addr
from seek.nmap.models import Host, ScanSet, Service
from seek.nmap.progress import HOSTS, Report, counted
from seek.tui.cells import width_of
from seek.vulndb import match as vmatch

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
    # Per cell, aligned with `cells`: how a value reads at a glance - "ok",
    # "warn", "bad", "dim" or "". The support column's colour is the answer.
    tones: tuple[str, ...] = ()
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
                key=proj.label_key)
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
    # What else the rows depend on, for a view that reads more than the model:
    # the Inventory tab reads captures, which arrive without the model being
    # replaced. The rows are kept while both the model and the stamp are unchanged.
    stamp: Callable[[], object] | None = field(default=None, repr=False, compare=False)
    _rows_of: ScanSet | None = field(default=None, repr=False, compare=False)
    _stamp_of: object = field(default=None, repr=False, compare=False)
    _rows: list[Row] = field(default_factory=list, repr=False, compare=False)
    _natural: list[int] | None = field(default=None, repr=False, compare=False)

    def cached_for(self, scans: ScanSet) -> bool:
        """Are this view's rows already built for exactly this model?"""
        return (self.cacheable and self._rows_of is scans
                and (self.stamp is None or self._stamp_of == self.stamp()))

    def rows(self, scans: ScanSet, report: Report | None = None) -> list[Row]:
        """This view's rows, built if they are not already there for `scans`.

        `report` is only ever passed by the worker that owns a background
        build; every other caller asks for rows that are either cached or
        cheap, and a report from those would be a bar that flickered on and
        off between keystrokes.
        """
        if not self.cacheable:
            return self._built(scans, report)
        if not self.cached_for(scans):
            stamp = self.stamp() if self.stamp is not None else None
            self._rows = self._built(scans, report)
            self._rows_of, self._stamp_of = scans, stamp
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


def key_at(row: Row, col: int) -> tuple:
    """Sort on the column's own key.

    Keys are pre-normalised by the view (an address becomes its octets, a count
    stays an int), so they must be compared *as they are* - stringifying them is
    what made `10.10.10.11` sort before `10.10.10.2`. Numbers, tuples and strings
    are kept in separate buckets so a mixed column still has a total order.
    """
    if col < len(row.sort_key):
        value = row.sort_key[col]
    else:
        value = row.cells[col] if col < len(row.cells) else ""
    if isinstance(value, bool):
        return (0, (int(value),), "")
    if isinstance(value, int | float):
        return (0, (value,), "")
    if isinstance(value, tuple):
        # an address key: (0, (10, 10, 10, 2), "") - compare the octets
        flat = value[1] if len(value) > 1 and isinstance(value[1], tuple) else value
        if flat and all(isinstance(x, int | float) for x in flat):
            return (0, tuple(flat), "")
        return (1, (), " ".join(str(x) for x in value))
    return (1, (), str(value).lower())


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


def hosts_view(only_up: bool = False, only_ports: bool = False) -> View:
    """The host list, narrowed by `u` (up), `r` (an open port), or both.

    Every host with an open port is up, so both together are `r` alone; they
    stay two flags so that turning one off leaves the other where it was.
    """
    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        hosts = scans.up if only_up else scans.hosts
        if only_ports:
            hosts = [h for h in hosts if h.open_services]
        return [_host_row(h) for h in counted(hosts, report, HOSTS)]

    narrowed = [label for on, label in ((only_up, "up"), (only_ports, "open ports")) if on]
    return View(
        title="Hosts" + (f" ({', '.join(narrowed)})" if narrowed else ""),
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
                sort_key=(proj.port_key(g.port, g.protocol), g.protocol, g.name or "",
                          g.product or "",
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
                sort_key=(proj.port_key(s.port, s.protocol), s.state or "", s.name or "",
                          s.product or "",
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
            first: object = proj.label_key(label) if key == "port" else label
            out.append(Row(
                cells=(label, str(len(members)), str(len(addresses)),
                       ", ".join(ports[:6]) + (" …" if len(ports) > 6 else "")),
                text=f"{label} {' '.join(addresses)} {' '.join(ports)}",
                target=group,
                records=tuple(Record(h, s) for h, s in group.members),
                addresses=addresses,
                sort_key=(first, len(members), len(addresses), proj.ports_key(ports)),
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
                sort_key=(_addr(host.address), host.hostname or "",
                          proj.port_key(svc.port, svc.protocol),
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
                           key=proj.label_key)
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
                sort_key=(name, source, len(hosts), proj.ports_key(ports)),
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
                sort_key=(name, count, proj.ports_key(ports)),
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
                sort_key=(proj.label_key(label), count, ", ".join(names)),
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


def service_everywhere(svc: Service, hosts: list[Host]) -> View:
    """One host's service, opened as that service across the whole set."""
    group = proj.group_for(hosts, svc)
    if group is not None:
        return service_detail(group)
    # Only a closed or filtered port gets here - it is in no overview row, so
    # fall back to every host that reports the same port at all.
    members = [(h, s) for h in hosts for s in h.services
               if s.port == svc.port and s.protocol == svc.protocol]
    return grouping_detail(Grouping(key="port", label=f"{svc.port}/{svc.protocol}",
                                    members=members))


# --- the software inventory ----------------------------------------------------

INVENTORY_COLUMNS = ("Product", "Version", "Support", "Vulns", "Max", "Hosts", "Svcs",
                     "Conflict", "CPE", "Kind", "Confidence")
NO_DB = "no vulndb"
SUPPORT_RANK = {"eol": 4, "behind": 3, "mixed": 2, "current": 1, "unknown": 0}


def _severity_tone(a, missing: bool) -> str:
    if missing or a is None or not a.findings:
        return ""
    sev = a.max_severity.upper()
    return "bad" if sev in ("CRITICAL", "HIGH") else "warn" if sev in ("MEDIUM",
                                                                       "MODERATE") else ""
NO_CPE = "no CPE"
KIND_SHORT = {"a": "app", "o": "os", "h": "hw"}


def version_key(version: str | None) -> tuple:
    """Versions in numeric order - `1.10` after `1.9` - with none first."""
    if not version:
        return ()
    return tuple((0, int(p), "") if p.isdigit() else (1, 0, p.casefold())
                 for p in re.split(r"(\d+)", version) if p)


def cpe_cell(uris: list[str]) -> str:
    if not uris:
        return NO_CPE
    return uris[0] + (f" +{len(uris) - 1}" if len(uris) > 1 else "")


def support_cell(a: vmatch.Assessment | None, missing: bool) -> str:
    if missing:
        return NO_DB
    if a is None or a.support.status == "unknown":
        return ABSENT
    return a.support.label() + (" · ends soon" if a.support.ending_soon else "")


def support_tone(a: vmatch.Assessment | None, missing: bool) -> str:
    if missing or a is None:
        return "dim"
    return "warn" if a.support.ending_soon and a.support.status == "current" \
        else a.support.tone


def vulns_cell(a: vmatch.Assessment | None, versioned: bool, missing: bool) -> str:
    """How many findings - `? · 12` when the version is unknown and the product
    has twelve CVEs in some version, `+2?` for ranges that could not be decided."""
    if missing or a is None or not a.looked_up:
        return ABSENT
    if not versioned:
        return f"? · {a.product_cves}" if a.product_cves else "?"
    text = str(len(a.findings))
    likely = sum(1 for f in a.undecided if f.known)
    return text + (f" +{likely} likely" if likely else "")


def max_cell(a: vmatch.Assessment | None) -> str:
    if a is None or not a.findings:
        return ""
    score = a.max_score
    sev = a.max_severity.lower()
    return f"{score:.1f} {sev}" if score is not None else sev


def lookup_words(a: vmatch.Assessment | None) -> list[str]:
    """What the filter finds a looked-up row by: its support state, the
    severities it has, and every finding's id."""
    if a is None:
        return []
    words = [a.support.status if a.support.status != "unknown" else ""]
    if a.support.status in ("current", "mixed"):
        words.append("supported")
    if a.support.status in ("eol", "behind"):
        words.append("unsupported")
    if a.support.ending_soon:
        words.append("ending-soon")
    words += sorted({f.severity.lower() for f in a.findings if f.severity})
    words += [f.id for f in a.findings]
    if a.undecided:
        words.append("undecided")
    return words


def _entry_row(e: inv_mod.Entry, a: vmatch.Assessment | None = None,
               missing: bool = True) -> Row:
    hosts = e.hosts
    records = tuple(Record(h, s) for h, s, _c in e.places)
    words = [e.product, e.version or "unversioned", inv_mod.KIND_NAMES.get(e.kind, ""),
             *e.cpe22, *e.sources, e.confidence,
             "conflict" if e.conflicting else "", "" if e.cpe22 else "no-cpe",
             *lookup_words(None if missing else a)]
    count = len(a.findings) if a is not None and not missing else -1
    score = (a.max_score or 0.0) if a is not None and not missing else -1.0
    return Row(
        cells=(e.product, e.version or ABSENT, support_cell(a, missing),
               vulns_cell(a, bool(e.version), missing), "" if missing else max_cell(a),
               str(len(hosts)), str(e.service_count), "conflict" if e.conflicting else "",
               cpe_cell(e.cpe22), KIND_SHORT.get(e.kind, e.kind), e.confidence),
        tones=("", "", support_tone(a, missing), "", _severity_tone(a, missing)),
        text=" ".join(w for w in words if w),
        target=e,
        records=records,
        addresses=tuple(h.address for h in hosts),
        sort_key=(e.product.casefold(), version_key(e.version),
                  SUPPORT_RANK.get(a.support.status, -1) if a is not None and not missing
                  else -1, count, score, len(hosts), e.service_count, e.conflicting,
                  e.cpe22[:1], e.kind, -e.rank),
    )


def inventory_view(session) -> View:
    """Every product and version, from every source the session has read."""
    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        inv = session.inventory(report)
        lookup = session.lookup()
        view.subtitle = unplaced_note(session)
        return [_entry_row(e, lookup.of_entry(e), lookup.db_missing)
                for e in inv_mod.entries(inv, scans.hosts)]

    view = View(
        title="Inventory", columns=INVENTORY_COLUMNS, build=build, kind="inventory",
        tab="inventory", reports=True, default_sort=(4, True),
        stamp=lambda: (session.shots.generation, session.vulndb().generation),
    )
    return view


def unplaced_note(session) -> str:
    """Captures that belong to no scanned service, named: their technologies
    are not in the inventory, and saying so is what makes that visible."""
    urls = session.unplaced_captures
    if not urls:
        return ""
    shown = ", ".join(urls[:3]) + (f" and {len(urls) - 3} more" if len(urls) > 3 else "")
    return (f"{len(urls)} capture(s) match no open port in the scans, so their "
            f"technologies are not listed: {shown}")


FINDINGS_COLUMNS = ("Finding", "Basis", "Severity", "Score", "Product", "Version", "Hosts",
                    "Svcs", "Sources", "Support")


def basis(f: vmatch.Finding) -> tuple[str, float]:
    """How a finding was arrived at, in words and as a sort weight: nmap ran
    a test (3), the version is in the range (2), or the version names a family
    and this share of its known releases is affected (1 + share)."""
    if f.tested:
        return f"nmap: {f.state.lower() or 'reported'}", 3.0
    if f.undecided and f.known:
        return f"likely {f.covered}/{f.known}", 1.0 + (f.likelihood or 0.0)
    return "version", 2.0


def _affected_row(a: vmatch.Affected, assessment: vmatch.Assessment | None) -> Row:
    f = a.finding
    hosts = a.hosts
    support = support_cell(assessment, False) if a.entry is not None else ABSENT
    said, weight = basis(f)
    words = [f.id, f.severity.lower(), a.product, a.version or "", *f.sources,
             "likely" if f.undecided else "", "tested confirmed" if f.tested else "",
             f.summary, *lookup_words(assessment)[:3]]
    return Row(
        tones=("", "bad" if f.tested else "", "", "", "", "", "", "", "",
               support_tone(assessment, False) if a.entry is not None else ""),
        cells=(f.id, said, f.severity.lower() or ABSENT,
               f"{f.score:.1f}" if f.score is not None else ABSENT,
               a.product or ABSENT, (a.version or ABSENT) if a.entry is not None else ABSENT,
               str(len(hosts)), str(a.service_count), ", ".join(f.sources), support),
        text=" ".join(w for w in words if w),
        target=a,
        records=tuple(Record(h, s) for h, s, _c in a.places),
        addresses=tuple(h.address for h in hosts),
        sort_key=(f.id, (weight, f.rank[0], f.score or 0.0), f.rank[0], f.score or 0.0,
                  a.product.casefold(),
                  version_key(a.version), len(hosts), a.service_count, f.sources,
                  support),
    )


def findings_view(session) -> View:
    """Every known vulnerability that affects something in the inventory."""
    def build(scans: ScanSet, report: Report | None = None) -> list[Row]:
        inv = session.inventory(report)
        lookup = session.lookup()
        entries = inv_mod.entries(inv, scans.hosts)
        by_entry = {id(e): lookup.of_entry(e) for e in entries}
        return [_affected_row(a, by_entry.get(id(a.entry)) if a.entry is not None else None)
                for a in vmatch.affected(lookup, entries, scans.hosts)]

    return View(
        title="Findings", columns=FINDINGS_COLUMNS, build=build, kind="findings",
        tab="findings", reports=True, default_sort=(1, True),
        stamp=lambda: (session.shots.generation, session.vulndb().generation),
    )


def findings_detail(a: vmatch.Affected) -> View:
    """The services one finding affects, reached with `Enter`."""
    def build(_: ScanSet) -> list[Row]:
        out = []
        for host, svc, _c in a.places:
            port = f"{svc.port}/{svc.protocol}" if svc is not None else "host"
            out.append(Row(
                cells=(host.address, name_cell(host), port,
                       _fmt(svc.name) if svc is not None else ABSENT),
                text=" ".join(filter(None, [host.address, host.hostname, port,
                                            svc.name if svc else ""])),
                target=svc if svc is not None else host,
                host=host if svc is not None else None,
                drill=host,
                records=(Record(host, svc),),
                addresses=(host.address,),
                sort_key=(_addr(host.address), host.hostname or "",
                          proj.port_key(svc.port, svc.protocol) if svc else (-1, 0),
                          svc.name or "" if svc else ""),
            ))
        return out

    label = f"{a.finding.id} · {a.product} {a.version or ''}".strip(" ·")
    return View(
        title=f"Finding {label}",
        subtitle=(f"{a.finding.severity.lower() or 'no severity'} · "
                  f"{len(a.hosts)} host(s) · {a.service_count} service(s)"),
        columns=("Address", "Hostname", "Port", "Service"),
        build=build, kind="findings-detail", tab="findings",
    )


def inventory_detail(entry: inv_mod.Entry) -> View:
    """Where one product and version runs, reached with `Enter`."""
    def build(_: ScanSet) -> list[Row]:
        out = []
        for host, svc, c in entry.places:
            port = f"{svc.port}/{svc.protocol}" if svc is not None else "host"
            out.append(Row(
                cells=(host.address, name_cell(host), port,
                       _fmt(svc.name) if svc is not None else ABSENT,
                       ", ".join(c.sources), "conflict" if c.conflicting else ""),
                text=" ".join(filter(None, [host.address, host.hostname, port,
                                            svc.name if svc else "", *c.sources,
                                            "conflict" if c.conflicting else ""])),
                target=svc if svc is not None else host,
                host=host if svc is not None else None,
                drill=host,
                records=(Record(host, svc),),
                addresses=(host.address,),
                sort_key=(_addr(host.address), host.hostname or "",
                          proj.port_key(svc.port, svc.protocol) if svc else (-1, 0),
                          svc.name or "" if svc else "", c.sources, c.conflicting),
            ))
        return out

    return View(
        title=f"Software {entry.label()}",
        subtitle=(f"{len(entry.hosts)} host(s) · {entry.service_count} service(s) · "
                  f"{cpe_cell(entry.cpe22)}"),
        columns=("Address", "Hostname", "Port", "Service", "Sources", "Conflict"),
        build=build, kind="inventory-detail", tab="inventory",
    )


def open_row(row: Row, hosts: list[Host], only_open: bool = False) -> View | None:
    """Where opening a row goes - the one answer both front ends use.

    `drill` is what a row opens when that is not the record its detail
    reports on; an aggregate line names its own destination as a `View`.
    """
    target = row.drill if row.drill is not None else row.target
    if isinstance(target, View):
        return target
    if isinstance(target, proj.ServiceGroup):
        return service_detail(target)
    if isinstance(target, Grouping):
        return grouping_detail(target)
    if isinstance(target, inv_mod.Entry):
        return inventory_detail(target)
    if isinstance(target, vmatch.Affected):
        return findings_detail(target)
    if isinstance(target, Host):
        return host_detail(target, only_open)
    if isinstance(target, Service):
        return service_everywhere(target, hosts)
    return None
