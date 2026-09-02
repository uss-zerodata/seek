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

from seek.nmap import vulns
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


def host_detail(host: Host) -> RenderableType:
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
    if host.open_services:
        parts.append(Text(""))
        parts.append(_section("Services", len(host.open_services)))
        for svc in host.open_services:
            parts.append(_bullet(svc.label()))
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


def service_detail(svc: Service, host: Host | None = None) -> RenderableType:
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
    if svc.vulnerabilities:
        parts.append(Text(""))
        parts.append(_section("Vulnerabilities", len(svc.vulnerabilities), "bold red"))
        parts.extend(_vuln_block(svc.vulnerabilities))
    if svc.scripts:
        parts.append(Text(""))
        parts.append(_section("Scripts", len(svc.scripts)))
        parts.extend(_script_block(svc.scripts))
    return Group(*parts)


def group_detail(group: ServiceGroup) -> RenderableType:
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


def grouping_detail(group: Grouping) -> RenderableType:
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
    return Group(*parts)


def render(target: object, host: Host | None = None) -> RenderableType:
    if isinstance(target, ServiceGroup):
        return group_detail(target)
    if isinstance(target, Grouping):
        return grouping_detail(target)
    if isinstance(target, Service):
        return service_detail(target, host)
    if isinstance(target, Host):
        return host_detail(target)
    return Text("")
