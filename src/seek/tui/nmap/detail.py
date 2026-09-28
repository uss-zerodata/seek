"""The full record for the selected row, as a readable report.

The table only has room for a few columns. Everything else a scan carried -
script output, vulnerability titles and references, the reason a host was called
up, which scans saw it - is laid out here: a heading, aligned label/value pairs,
and bulleted lists for anything there can be several of.

Nothing a record *says* is elided. The pane is a scrolling region (`←`/`→` and
`J`/`K` move it), so length is not a reason to cut a record short - and a
truncated report is worse than a long one when what was cut is the sentence
describing a finding.

The one exception is a bucket's membership list, which is not a finding but a
list, and which at engagement scale is twenty-four thousand lines long. Those
stop at `_MEMBER_LIMIT` and say how many more there are: building the rest
costs a second of the event loop for one movement of the cursor, and `Enter`
already opens the whole bucket as a table, which is chunked into the terminal
rather than built in one pass.
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.console import Group, RenderableType
from rich.text import Text

from seek.gowitness.results import Capture, Captures
from seek.nmap import names as name_mod
from seek.nmap import rawlog, vulns
from seek.nmap.export import service_url, url_for
from seek.nmap.models import Host, Service, Vulnerability
from seek.nmap.views import ServiceGroup
from seek.tui.nmap.views import Grouping

ABSENT = "—"
_LABEL_W = 11


@dataclass(slots=True)
class Line:
    """One line of a record, and what opening it does - if anything.

    A record is a sequence of these rather than a single renderable because the
    pane is navigated by a cursor: "which line am I on" has to have an answer
    before a line can be chosen. A *line* here is one thing a renderer emitted,
    not one row of the terminal - a long script line that wraps to three rows is
    one stop, which is what it is to someone reading the record and which keeps
    the cursor from moving when the window is resized.
    """

    text: RenderableType
    opens: rawlog.Request | None = None


def lines_of(parts: list[RenderableType | Line]) -> list[Line]:
    """Wrap a renderer's parts, leaving any `Line` it built itself alone."""
    return [p if isinstance(p, Line) else Line(p) for p in parts]


def as_group(lines: list[Line]) -> RenderableType:
    """The whole record as one renderable, for anything that does not navigate it.

    The reader takes this. It is the *same* lines the pane shows, joined - which
    is what keeps the two from becoming two descriptions of a record.
    """
    return Group(*(line.text for line in lines))


def scan_entries(host: Host, scanned: rawlog.Scanned,
                 service: Service | None = None) -> list[Line]:
    """The scans that recorded this subject, one openable line each.

    Provenance used to be a comma-separated run of file names on the end of
    another line, which said which scans saw the subject and nothing else. As
    entries they can say what each scan established, and each is a way into
    what that scan actually wrote.
    """
    found = scanned.entries(host, service)
    if not found:
        return []
    out: list[Line] = [Line(Text("")), Line(_section("Scans", len(found)))]
    width = max(len(e.label) for e in found)
    for entry in found:
        line = Text(" " * 4)
        line.append("• ", style=_KEY)
        line.append(f"{entry.label:<{width}}")
        line.append(f"   {entry.summary()}", style=_KEY)
        if not entry.written:
            line.append("   (no output file)", style="dim italic")
        out.append(Line(line, opens=rawlog.Request(entry, host, service)))
    return out
_KEY = "dim"
_HEAD = "bold cyan"
_SECTION = "bold"


def _heading(title: str, subtitle: str = "") -> Text:
    text = Text()
    text.append(title, style=_HEAD)
    if subtitle:
        text.append(f"   {subtitle}", style="bold")
    return text


def _pair(label: str, value: object, style: str = "") -> Text:
    text = Text()
    text.append(f"  {label:<{_LABEL_W}}", style=_KEY)
    shown = value if value not in (None, "", []) else ABSENT
    text.append(str(shown), style=style)
    return text


def _section(title: str, count: int | None = None, style: str = _SECTION) -> Text:
    text = Text()
    text.append(f"  {title}", style=style)
    if count is not None:
        text.append(f" ({count})", style=_KEY)
    return text


def _bullet(body: str, style: str = "", indent: int = 4) -> Text:
    text = Text(" " * indent, style="")
    text.append("• ", style=_KEY)
    text.append(body, style=style)
    return text


def _status_style(capture: Capture) -> str:
    """Colour reinforces the status code; it never replaces it.

    The number is the information - it is printed either way, and a reader who
    cannot tell the colours apart loses nothing but speed.
    """
    if capture.failed or capture.status is None:
        return "red"
    if capture.status >= 500:
        return "red"
    if capture.status >= 400:
        return "yellow"
    if capture.status >= 300:
        return "cyan"
    return "green"


def _capture_under(capture: Capture, indent: int = 8) -> Text:
    """What a captured URL answered, as a continuation line under it.

    A dim line under the URL rather than a wide column beside it: the pane is
    narrow on a split terminal, and a status code that needs horizontal
    scrolling to reach is a status code nobody reads.
    """
    line = Text(" " * indent)
    if capture.failed:
        line.append("✗ ", style="red")
        line.append(capture.failure, style="red")
        return line
    head = f"{capture.status} {capture.reason}".strip() if capture.status else "no status"
    line.append(head, style=_status_style(capture))
    # An error page's title is usually just its status again ("403 Forbidden"),
    # and saying it twice on one line reads as a rendering bug.
    title = "" if capture.title.strip().lower() == head.lower() else capture.title
    rest = [bit for bit in (title, capture.server, capture.powered_by,
                            ", ".join(capture.technologies)) if bit]
    name, source = capture.derived_system()
    # Labelled with where it came from: a guess shown as a detection is worse
    # than no guess. Suppressed when the header it was derived from is already
    # on the line - saying "authentik · authentik (from x-powered-by)" reads as
    # a rendering fault, not as extra information.
    if name and not any(name in bit for bit in rest):
        rest.append(f"{name} (from {source})")
    if rest:
        line.append("  ·  " + "  ·  ".join(dict.fromkeys(rest)), style=_KEY)
    if capture.redirected:
        line.append(f"  →  {capture.final_url}", style=_KEY)
    return line


def _capture_extra(capture: Capture, full: bool) -> list[Text]:
    """The rest of a capture: a curated line shallow, everything when full."""
    out: list[Text] = []
    if capture.failed:
        return out
    if capture.tls:
        out.append(_sub("tls", capture.tls))
    if not full:
        # Which security headers were looked for, and which were absent. The
        # absence is the point: it cannot be noticed by reading a list of the
        # headers that are present, so it is the half that gets said inline.
        missing = capture.missing_security_headers()
        if capture.headers:
            line = Text(" " * 8)
            line.append(f"{'headers':<10}", style=_KEY)
            line.append(f"{len(capture.headers)} collected")
            if missing:
                line.append("   ·   missing: ", style=_KEY)
                line.append(", ".join(missing), style="yellow")
            out.append(line)
        return out

    if capture.sans:
        out.append(_sub("cert", "   ".join(capture.sans)))
    for label, value in (("content", capture.content_type),
                         ("length", str(capture.content_length or "")),
                         ("probed", capture.probed_at[:19]),
                         ("group", str(capture.perception_group or ""))):
        if value:
            out.append(_sub(label, value))
    missing = capture.missing_security_headers()
    if missing:
        line = Text(" " * 8)
        line.append(f"{'missing':<10}", style=_KEY)
        line.append(", ".join(missing), style="yellow")
        out.append(line)
    for title, items in (("headers", capture.headers),
                         ("cookies", capture.cookies),
                         ("console", capture.console),
                         ("requests", capture.network)):
        if not items:
            continue
        heading = Text(" " * 8)
        heading.append(f"{title} ({len(items)})", style=_SECTION)
        out.append(heading)
        for key, value in items:
            row = Text(" " * 10)
            row.append(f"{key:<28}", style=_KEY)
            # A folded header (`vary` sends two lines) would otherwise break the
            # column and read as two entries.
            row.append(" ".join(str(value).split()))
            out.append(row)
    return out


def _capture_rows(urls: list[str], shots: Captures | None) -> list[Text]:
    """The `Captures` block of a host: one aligned line per captured URL.

    Status first and padded, because the question this block answers is "which
    of these is worth looking at" - and that is read down a column, not along
    a sentence.
    """
    if shots is None:
        return []
    found = shots.for_urls(urls)
    if not found:
        return []
    rows = [_section("Captures", len(found))]
    width = max(len(u.url) for u in found)
    for capture in found:
        line = Text(" " * 4)
        line.append("• ", style=_KEY)
        code = "✗" if capture.failed else str(capture.status or "—")
        line.append(f"{code:<4}", style=_status_style(capture))
        line.append(f"{capture.url:<{width}}")
        tail = capture.failure if capture.failed else capture.title
        if tail:
            line.append(f"   {tail}", style=_KEY)
        rows.append(line)
    return rows


# How many members a bucket's record lists before it stops and says how many
# more there are. The pane is a dozen rows tall and the reader is a pager, so
# beyond this the lines are not read - but they are built, and at engagement
# scale that is tens of thousands of `Text` objects on the event loop for one
# cursor movement. `Enter` opens the bucket as a table, which is the interface's
# own answer to "show me all of them" and is chunked into the terminal.
_MEMBER_LIMIT = 100
# And how many of a bucket's *scripts* it shows in full. Lower, because a
# script is several lines rather than one: the services overview's `https` row
# over four thousand hosts carried four thousand `ssl-cert` results, fifteen
# thousand lines that Textual has to render in full merely to measure the
# pane's height - three hundred milliseconds, three times, for one movement of
# the cursor. One host's own record still shows every script it has.
_SCRIPT_LIMIT = 20


def _more(shown: int, total: int) -> list[Text]:
    """The line that says a listing stopped, and how to see the rest."""
    if total <= shown:
        return []
    return [Text(f"    … and {total - shown} more · Enter opens all of them",
                 style="dim")]


def _member_captures(members: list, shots: Captures | None) -> list[Text]:
    """The capture block for a bucket of (host, service) pairs.

    The grouping views - by service, by product, by port, and the names list -
    are where an operator decides what to look at next, so a bucket that says
    nothing about what its members actually served is the one place the capture
    is least use. Same URL join as a host or a service record; only the set of
    URLs is wider.
    """
    if shots is None or not shots or not members:
        # `not shots` matters at scale: with nothing captured the block is
        # empty either way, but building a URL for every one of three hundred
        # thousand services to find that out is a second of the event loop.
        return []
    urls: list[str] = []
    for host, svc in members:
        urls += _service_urls(svc, host)
    return _capture_rows(list(dict.fromkeys(urls)), shots)


def _sub(label: str, value: str, indent: int = 8) -> Text:
    text = Text(" " * indent)
    text.append(f"{label:<10}", style=_KEY)
    text.append(value)
    return text


def _vuln_block(items: list[Vulnerability]) -> list[Text]:
    out: list[Text] = []
    for v in items:
        head = Text("    ")
        head.append("• ", style="bold red")
        head.append(v.id, style="bold")
        if v.state:
            unaffected = "NOT" in v.state.upper()
            head.append(f" — {v.state}", style=_KEY if unaffected else "bold red")
        if v.severity:
            head.append(f"  CVSS {v.severity}", style="bold yellow")
        out.append(head)
        if v.title:
            out.append(Text(" " * 8 + v.title))
        if v.ids:
            out.append(_sub("ids", ", ".join(v.ids)))
        if v.disclosed:
            out.append(_sub("disclosed", v.disclosed))
        if v.source_script:
            out.append(_sub("via", v.source_script))
        for i, ref in enumerate(v.refs):
            out.append(_sub("refs" if i == 0 else "", ref))
    return out


def _flatten(data, prefix: str = "") -> list[str]:
    out: list[str] = []
    if data is None:
        # A script with no <table>/<elem> children carries `data=None`, which
        # `str()` rendered as a literal "None" line in the report.
        return out
    if isinstance(data, dict):
        for key, value in data.items():
            out.extend(_flatten(value, f"{prefix}{key}." if (prefix or key) else ""))
    elif isinstance(data, list):
        for item in data:
            out.extend(_flatten(item, prefix))
    else:
        text = str(data).strip()
        if text:
            out.append(f"{prefix.rstrip('.')}: {text}" if prefix else text)
    return out


def _script_block(scripts) -> list[Text]:
    """Every script, in full.

    This used to show the first non-blank line of the first five scripts, five
    flattened data lines each, cut at 104 characters - while the README offered
    "the full text of script results". The pane scrolls (`←`/`→`, `J`/`K`), so
    there is somewhere for the rest to go, and script output is often the only
    place a finding is actually described.
    """
    out: list[Text] = []
    for s in scripts:
        out.append(_bullet(s.id, style="bold"))
        for line in (s.output or "").splitlines():
            if line.strip():
                out.append(Text(" " * 8 + line.rstrip(), style=_KEY))
        for line in _flatten(s.data):
            out.append(Text(" " * 8 + line, style=_KEY))
    return out


def _state_text(host: Host) -> tuple[str, str]:
    """The up rule's verdict, with what nmap recorded kept beside it."""
    if host.discovered:
        return str(host.state), "bold green"
    if host.up:
        recorded = "asserted by -Pn" if host.state_asserted else f"recorded {host.state}"
        return f"up — an open port ({recorded})", "bold"
    if host.state_asserted:
        return "unconfirmed — asserted up by -Pn, no open port", "bold yellow"
    if host.state == "down":
        return "down", "bold red"
    return str(host.state or ABSENT), _KEY


def host_detail(host: Host, shots: Captures | None = None, full: bool = False,
                scanned: rawlog.Scanned | None = None) -> list[Line]:
    state, style = _state_text(host)
    os_text = host.os or ABSENT
    if host.os and host.osclass:
        os_text = f"{host.os} ({host.osclass})"
    # Scalars are paired onto shared lines so the lists below them have room -
    # the pane follows the cursor and cannot be scrolled past its height.
    state_line = Text()
    state_line.append(f"  {'state':<{_LABEL_W}}", style=_KEY)
    state_line.append(state, style=style)
    if host.reason:
        state_line.append(f"  ({host.reason})", style=_KEY)
    parts: list[RenderableType] = [
        _heading(host.address, ", ".join(host.hostnames)),
        _pair("os", os_text),
        state_line,
        _pair("ports", f"{len(host.open_services)} open, "
                       f"{len(host.services) - len(host.open_services)} other"),
    ]
    if scanned is not None:
        parts.extend(scan_entries(host, scanned))
    else:
        parts.append(_pair("scans", ", ".join(host.sources) or ABSENT))
    known = name_mod.host_names(host)
    if known:
        parts.append(Text(""))
        parts.append(_section("Names", len(known)))
        for name, source in known:
            line = Text(" " * 4)
            line.append("• ", style=_KEY)
            line.append(f"{name:<32}")
            line.append(source, style=_KEY)
            parts.append(line)
    if host.open_services:
        parts.append(Text(""))
        parts.append(_section("Services", len(host.open_services)))
        for svc in host.open_services:
            parts.append(_bullet(svc.label()))
    every_url = [url for svc in host.open_services
                 for url in _service_urls(svc, host)]
    captures = _capture_rows(list(dict.fromkeys(every_url)), shots)
    if captures:
        parts.append(Text(""))
        parts.extend(captures)
    found = vulns.host_vulnerabilities(host)
    if found:
        parts.append(Text(""))
        parts.append(_section("Vulnerabilities", len(found), "bold red"))
        parts.extend(_vuln_block(found))
    if host.scripts:
        parts.append(Text(""))
        parts.append(_section("Host scripts", len(host.scripts)))
        parts.extend(_script_block(host.scripts))
    return lines_of(parts)


def service_detail(svc: Service, host: Host | None = None,
                   shots: Captures | None = None, full: bool = False,
                   scanned: rawlog.Scanned | None = None) -> list[Line]:
    state_line = Text()
    state_line.append(f"  {'state':<{_LABEL_W}}", style=_KEY)
    state_line.append(str(svc.state or ABSENT), style="bold green" if svc.is_open else _KEY)
    if svc.reason:
        state_line.append(f"  ({svc.reason})", style=_KEY)
    product = " ".join(x for x in (svc.product, svc.version) if x) or ABSENT
    parts: list[RenderableType] = [
        _heading(f"{svc.port}/{svc.protocol}",
                 f"{svc.name or ABSENT}" + (f" on {host.address}" if host else "")),
        state_line,
        _pair("product", product),
        _pair("detected", f"{svc.method or ABSENT}"
                          + (f" (confidence {svc.conf})" if svc.conf else "")),
    ]
    if scanned is not None and host is not None:
        parts.extend(scan_entries(host, scanned, svc))
    else:
        parts.append(_pair("scans", ", ".join(svc.sources) or ABSENT))
    extras = [f"{k} {v}" for k, v in
              (("info", svc.extrainfo), ("tunnel", svc.tunnel), ("ostype", svc.ostype)) if v]
    if extras:
        parts.append(_pair("also", "   ·   ".join(extras)))
    if svc.names:
        parts.append(Text(""))
        parts.append(_section("Names", len(svc.names)))
        for name, source in svc.names:
            line = Text(" " * 4)
            line.append("• ", style=_KEY)
            line.append(f"{name:<32}")
            line.append(source, style=_KEY)
            parts.append(line)
    urls = _service_urls(svc, host)
    if urls:
        parts.append(Text(""))
        parts.append(_section("URLs", len(urls)))
        for url in urls:
            parts.append(_bullet(url))
            # Silence, not "not captured": before any capture has been run
            # every URL in the project would carry the same empty note.
            capture = shots.get(url) if shots is not None else None
            if capture is not None:
                parts.append(_capture_under(capture))
                parts.extend(_capture_extra(capture, full))
    if svc.vulnerabilities:
        parts.append(Text(""))
        parts.append(_section("Vulnerabilities", len(svc.vulnerabilities), "bold red"))
        parts.extend(_vuln_block(svc.vulnerabilities))
    if svc.scripts:
        parts.append(Text(""))
        parts.append(_section("Scripts", len(svc.scripts)))
        parts.extend(_script_block(svc.scripts))
    return lines_of(parts)


def _service_urls(svc: Service, host: Host | None) -> list[str]:
    """Every address the service answers on - the one scanned and every name.

    Virtual hosting means these can serve different things, so a list that shows
    only the address hides half of what was found.
    """
    if host is None:
        return [u for u in [url_for(n, svc) for n, _ in svc.names] if u]
    base = service_url(host, svc)
    if not base:
        return []
    known = [n for n, _ in name_mod.host_names(host)]
    return list(dict.fromkeys([base, *(url_for(n, svc) for n in known)]))


def group_detail(group: ServiceGroup,
                 shots: Captures | None = None) -> list[Line]:
    parts: list[RenderableType] = [
        _heading(group.label),
        _pair("version", group.version),
        _pair("info", group.extrainfo),
        _pair("hosts", group.host_count, "bold"),
    ]
    parts.append(Text(""))
    parts.append(_section("Running on", group.host_count))
    for host, svc in group.members[:_MEMBER_LIMIT]:
        extra = f"  {svc.version}" if svc.version else ""
        parts.append(_bullet(f"{host.address}{extra}"))
    parts.extend(_more(_MEMBER_LIMIT, len(group.members)))

    captures = _member_captures(group.members, shots)
    if captures:
        parts.append(Text(""))
        parts.extend(captures)

    found: list[Vulnerability] = []
    seen: set = set()
    for _, svc in group.members:
        for v in svc.vulnerabilities:
            if v.identity() not in seen:
                seen.add(v.identity())
                found.append(v)
    if found:
        parts.append(Text(""))
        parts.append(_section("Vulnerabilities", len(found), "bold red"))
        parts.extend(_vuln_block(found))
    scripts = [s for _, svc in group.members for s in svc.scripts]
    if scripts:
        parts.append(Text(""))
        parts.append(_section("Scripts", len(scripts)))
        parts.extend(_script_block(scripts[:_SCRIPT_LIMIT]))
        parts.extend(_more(_SCRIPT_LIMIT, len(scripts)))
    return lines_of(parts)


def grouping_detail(group: Grouping,
                    shots: Captures | None = None) -> list[Line]:
    """The report for one `by service` / `by product` / `by port` bucket."""
    hosts = group.hosts
    parts: list[RenderableType] = [
        _heading(group.label, f"grouped by {group.key}"),
        _pair("hosts", len(hosts), "bold"),
        _pair("services", len(group.members)),
        _pair("ports", ", ".join(group.ports)),
        Text(""),
        _section("Hosts", len(hosts)),
    ]
    # Indexed in one pass rather than rescanning every member per host: a
    # bucket can hold twenty-four thousand hosts and three hundred thousand
    # services, and "for each host, scan every member" is their product -
    # seconds of the event loop for one movement of the cursor.
    ports_of: dict[int, list[str]] = {}
    for host, svc in group.members:
        ports_of.setdefault(id(host), []).append(f"{svc.port}/{svc.protocol}")
    for host in hosts[:_MEMBER_LIMIT]:
        ports = ", ".join(ports_of.get(id(host), ()))
        name = f" ({host.hostname})" if host.hostname else ""
        parts.append(_bullet(f"{host.address}{name}   {ports}"))
    parts.extend(_more(_MEMBER_LIMIT, len(hosts)))
    captures = _member_captures(group.members, shots)
    if captures:
        parts.append(Text(""))
        parts.extend(captures)
    return lines_of(parts)


def raw_record(request: rawlog.Request, excerpt: rawlog.Excerpt,
               at: tuple[int, int] | None = None) -> list[Line]:
    """One scan's own text about a subject, headed by what it is.

    The heading is not decoration. nmap's text does not say which scan it came
    from, and a reconstruction does not say that it is one - and text presented
    as nmap's own when it was rebuilt from the parse would defeat the only
    reason any of this exists.
    """
    head = Text()
    head.append(request.entry.label, style=_HEAD)
    head.append(f"   {request.subject}", style=_SECTION)
    if excerpt.reconstructed:
        head.append("   reconstructed from the XML", style="bold yellow")
    elif request.entry.path is not None:
        head.append(f"   {request.entry.path.name}", style=_KEY)
    parts: list[RenderableType] = [head]
    # Which of the subject's scans this is. Without it there is nothing to say
    # that the other four exist, and the arrows that reach them are a key
    # nobody would think to press.
    if at is not None and at[1] > 1:
        where = Text("  ")
        where.append(f"scan {at[0]} of {at[1]}", style=_SECTION)
        where.append("   ← → for the others", style=_KEY)
        parts.append(where)
    parts.append(Text(""))
    if excerpt.problem:
        parts.append(Text(f"  {excerpt.problem}", style="bold yellow"))
    # `no_wrap=False`: nmap pads its columns, and a narrow pane should fold a
    # long line rather than hide the end of it.
    parts += [Text(line) for line in excerpt.lines]
    parts += [Text(""), Text("  Esc goes back to the record", style=_KEY)]
    return lines_of(parts)


def raw_pending(request: rawlog.Request) -> list[Line]:
    """The same heading, while a large output file is still being read."""
    head = Text()
    head.append(request.entry.label, style=_HEAD)
    head.append(f"   {request.subject}", style=_SECTION)
    return lines_of([
        head,
        Text(""),
        Text(f"  reading {request.entry.path.name if request.entry.path else ''}…",
             style=_KEY),
        Text(""),
        Text("  Esc goes back to the record", style=_KEY),
    ])


def render(target: object, host: Host | None = None,
           shots: Captures | None = None, full: bool = False,
           scanned: rawlog.Scanned | None = None) -> list[Line]:
    """The record for one row, as the lines it is made of.

    `full` is the reader's depth: the same record, with everything a capture
    collected laid out rather than summarised. One function, two depths - the
    reader shows everything the pane shows and may show more, and neither
    composes its own version of a record.

    `scanned` indexes the scans behind the model. Given it, a host's and a
    service's record can list the scans that recorded it and offer each one's
    own text; without it - a caller that has a record but not the set it came
    from - the record names its scans as it always did. The bucket records take
    none: they describe a service across many hosts, which has no single block
    of output to show.
    """
    if isinstance(target, ServiceGroup):
        return group_detail(target, shots)
    if isinstance(target, Grouping):
        return grouping_detail(target, shots)
    if isinstance(target, Service):
        return service_detail(target, host, shots, full, scanned)
    if isinstance(target, Host):
        return host_detail(target, shots, full, scanned)
    return [Line(Text(""))]
