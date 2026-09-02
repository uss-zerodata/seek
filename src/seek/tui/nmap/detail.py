"""The full record for the selected row, as a readable report.

The table only has room for a few columns. Everything else a scan carried -
script output, vulnerability titles and references, the reason a host was called
up, which scans saw it - is laid out here: a heading, aligned label/value pairs,
and bulleted lists for anything there can be several of.

Nothing is elided. The pane is a scrolling region (`←`/`→` and `J`/`K` move it),
so length is not a reason to cut a record short - and a truncated report is worse
than a long one when what was cut is the sentence describing a finding.
"""

from __future__ import annotations

from rich.console import Group, RenderableType
from rich.text import Text

from seek.gowitness.results import Capture, Captures
from seek.nmap import names as name_mod
from seek.nmap import vulns
from seek.nmap.export import service_url, url_for
from seek.nmap.models import Host, Service, Vulnerability
from seek.nmap.views import ServiceGroup
from seek.tui.nmap.views import Grouping

ABSENT = "—"
_LABEL_W = 11
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


def _member_captures(members: list, shots: Captures | None) -> list[Text]:
    """The capture block for a bucket of (host, service) pairs.

    The grouping views - by service, by product, by port, and the names list -
    are where an operator decides what to look at next, so a bucket that says
    nothing about what its members actually served is the one place the capture
    is least use. Same URL join as a host or a service record; only the set of
    URLs is wider.
    """
    if shots is None or not members:
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
    if host.state == "down":
        return "down", "bold red"
    if host.state_asserted and not host.has_evidence:
        return "up — asserted by -Pn, no evidence", "bold yellow"
    if host.state_asserted:
        return "up — asserted by -Pn, but responded", "bold"
    return str(host.state or ABSENT), "bold green"


def host_detail(host: Host, shots: Captures | None = None,
                full: bool = False) -> RenderableType:
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
                       f"{len(host.services) - len(host.open_services)} other"
                       f"   ·   scans: {', '.join(host.sources) or ABSENT}"),
    ]
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
    return Group(*parts)


def service_detail(svc: Service, host: Host | None = None,
                   shots: Captures | None = None, full: bool = False) -> RenderableType:
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
                          + (f" (confidence {svc.conf})" if svc.conf else "")
                          + f"   ·   scans: {', '.join(svc.sources) or ABSENT}"),
    ]
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
    return Group(*parts)


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
                 shots: Captures | None = None) -> RenderableType:
    parts: list[RenderableType] = [
        _heading(group.label),
        _pair("version", group.version),
        _pair("info", group.extrainfo),
        _pair("hosts", group.host_count, "bold"),
    ]
    parts.append(Text(""))
    parts.append(_section("Running on", group.host_count))
    for host, svc in group.members:
        extra = f"  {svc.version}" if svc.version else ""
        parts.append(_bullet(f"{host.address}{extra}"))

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
        parts.extend(_script_block(scripts))
    return Group(*parts)


def grouping_detail(group: Grouping,
                    shots: Captures | None = None) -> RenderableType:
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
    for host in hosts:
        ports = ", ".join(
            f"{s.port}/{s.protocol}" for h, s in group.members if h is host
        )
        name = f" ({host.hostname})" if host.hostname else ""
        parts.append(_bullet(f"{host.address}{name}   {ports}"))
    captures = _member_captures(group.members, shots)
    if captures:
        parts.append(Text(""))
        parts.extend(captures)
    return Group(*parts)


def render(target: object, host: Host | None = None,
           shots: Captures | None = None, full: bool = False) -> RenderableType:
    """The record for one row.

    `full` is the reader's depth: the same record, with everything a capture
    collected laid out rather than summarised. One function, two depths - the
    reader shows everything the pane shows and may show more, and neither
    composes its own version of a record.
    """
    if isinstance(target, ServiceGroup):
        return group_detail(target, shots)
    if isinstance(target, Grouping):
        return grouping_detail(target, shots)
    if isinstance(target, Service):
        return service_detail(target, host, shots, full)
    if isinstance(target, Host):
        return host_detail(target, shots, full)
    return Text("")
