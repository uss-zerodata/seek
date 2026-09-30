"""Where everything the model knows about lives in the browser - one mapping.

A host is its port list on the Hosts tab; a port is that list with the port
selected, so its full record is beside it; a service across hosts is its row on
the Services tab; a capture is its own page. Every page that mentions one of
them links it through here, so a thing is always reached the same way.
"""

from __future__ import annotations

from urllib.parse import urlencode

from seek.gowitness.results import Capture
from seek.nmap.models import Host, Service
from seek.nmap.views import ServiceGroup
from seek.web.source import capture_id


def host(address: str) -> str:
    return "/v/hosts?" + urlencode({"path": f"h:{address}"})


def port(address: str, protocol: str, number: int) -> str:
    return "/v/hosts?" + urlencode({"path": f"h:{address}",
                                    "sel": f"p:{address}/{protocol}/{number}"})


def service(group: ServiceGroup) -> str:
    step = (f"s:{group.protocol}/{group.port}/{group.name or ''}/"
            f"{group.product or ''}/{group.version or ''}")
    return "/v/services?" + urlencode({"path": step})


def capture(item: Capture | str) -> str:
    return f"/captures/{item if isinstance(item, str) else capture_id(item)}"


def image(item: Capture | str) -> str:
    return f"/media/shot/{item if isinstance(item, str) else capture_id(item)}"


def href(to: object) -> str | None:
    """The page for whatever a record line is about; `None` when it has none."""
    if isinstance(to, Capture):
        return capture(to)
    if isinstance(to, Host):
        return host(to.address)
    if isinstance(to, tuple) and len(to) == 2 and isinstance(to[1], Service):
        h, svc = to
        return port(h.address, svc.protocol, svc.port)
    if isinstance(to, ServiceGroup):
        return service(to)
    if isinstance(to, str) and to.startswith(("https://", "http://")):
        # An advisory: followed by the reader, never loaded by the page, so the
        # interface still renders completely offline.
        return to
    return None
