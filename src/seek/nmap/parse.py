"""Read nmap XML output into the models.

Uses `iterparse`, clearing each finished `<host>`: at the sizes involved a full
`ET.parse` is no faster (both ~11 ms for 1.4 MB), but streaming keeps peak
memory proportional to one host rather than to the whole consolidation, which
matters when a dozen scans are opened at once.

Strict about shape, lax about content: a missing attribute yields ``None``,
never an exception. Validity is decided by one check - the root element is
``<nmaprun>`` - so a well-formed XML file that is not a scan is rejected
cleanly rather than parsed into an empty model.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from seek.nmap.models import Host, ScanFile, ScriptResult, Service, by_port


class NmapParseError(Exception):
    """A file could not be read as nmap XML output."""


def _tree(el: ET.Element) -> dict | list:
    """Convert an nmap `<table>`/`<elem>` subtree into dicts and lists.

    Keyed children become a mapping, unkeyed children a list; a node with both
    keeps the unkeyed ones under ``_items``.
    """
    keyed: dict[str, object] = {}
    unkeyed: list[object] = []
    for child in el:
        value = _tree(child) if len(child) else (child.text or "").strip()
        key = child.get("key")
        if key is not None:
            keyed[key] = value
        else:
            unkeyed.append(value)
    if keyed and unkeyed:
        return {"_items": unkeyed, **keyed}
    return keyed if keyed else unkeyed


def _script(el: ET.Element) -> ScriptResult:
    data = _tree(el) if len(el) else None
    return ScriptResult(id=el.get("id") or "", output=el.get("output"), data=data or None)


def _service(port_el: ET.Element, source: str) -> Service:
    state_el = port_el.find("state")
    svc = port_el.find("service")
    get = (lambda k: svc.get(k)) if svc is not None else (lambda k: None)
    try:
        port = int(port_el.get("portid") or 0)
    except ValueError:
        port = 0
    return Service(
        protocol=port_el.get("protocol") or "tcp",
        port=port,
        state=state_el.get("state") if state_el is not None else None,
        reason=state_el.get("reason") if state_el is not None else None,
        name=get("name"),
        product=get("product"),
        version=get("version"),
        extrainfo=get("extrainfo"),
        ostype=get("ostype"),
        tunnel=get("tunnel"),
        method=get("method"),
        conf=get("conf"),
        scripts=[_script(s) for s in port_el.findall("script")],
        sources=[source],
    )


def _host(el: ET.Element, source: str) -> Host:
    status = el.find("status")
    addr_el = el.find("address")
    osmatch = el.find("os/osmatch")
    osclass = el.find("os/osmatch/osclass")
    return Host(
        address=(addr_el.get("addr") if addr_el is not None else None) or "",
        addrtype=addr_el.get("addrtype") if addr_el is not None else None,
        hostnames=[h.get("name") or "" for h in el.findall("hostnames/hostname") if h.get("name")],
        state=status.get("state") if status is not None else None,
        reason=status.get("reason") if status is not None else None,
        os=osmatch.get("name") if osmatch is not None else None,
        osclass=osclass.get("osfamily") if osclass is not None else None,
        services=sorted((_service(p, source) for p in el.findall("ports/port")),
                        key=by_port),
        scripts=[_script(s) for s in el.findall("hostscript/script")],
        sources=[source],
    )


def parse_file(path: Path, label: str | None = None) -> ScanFile:
    """Parse one nmap XML file. Raises :class:`NmapParseError` on anything else.

    `label` is what the scan is called - stamped on every host and service as
    their source. The file name when not given; `merge.naming` qualifies it by
    directory when several directories are read.
    """
    hosts: list[Host] = []
    source = label or path.name
    try:
        stream = ET.iterparse(path, events=("start", "end"))
        _, root = next(stream)
        if root.tag != "nmaprun":
            raise NmapParseError(f"{path}: not an nmap scan (root element <{root.tag}>)")
        args = root.get("args") or ""
        start = root.get("start")
        for event, el in stream:
            if event == "end" and el.tag == "host":
                hosts.append(_host(el, source))
                el.clear()  # free the subtree; keeps memory flat over big files
    except ET.ParseError as exc:
        raise NmapParseError(f"{path}: malformed XML ({exc})") from exc
    except OSError as exc:
        raise NmapParseError(f"{path}: {exc}") from exc
    except StopIteration:
        raise NmapParseError(f"{path}: empty file") from None
    return ScanFile(path=path, args=args, hosts=hosts,
                    start=int(start) if start and start.isdigit() else None,
                    label=source)
