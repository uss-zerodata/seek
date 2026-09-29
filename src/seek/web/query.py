"""Listing, filtering, sorting and paging - once, for the API and the pages.

Lists are the TUI's own projections (`seek.tui.nmap.views`) filtered with the
TUI's own grammar (`seek.nmap.filtering`), which is the path `NmapApp._narrow`
takes: a list in the browser and the same tab in the terminal cannot disagree
about which rows a filter keeps, or in what order they come.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TypeVar
from urllib.parse import urlsplit

from seek.nmap import filtering
from seek.nmap.export import Record
from seek.nmap.merge import addr_key
from seek.nmap.models import port_key
from seek.nmap.views import ServiceGroup, service_groups
from seek.tui.nmap import views as vdefs
from seek.web import schemas as s
from seek.web.source import Placed, WebModel

T = TypeVar("T")
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000


class NotFound(LookupError):
    """Something a request named that the model does not contain."""


def _key_at(row: vdefs.Row) -> tuple:
    # The TUI's comparison, so port and address columns sort as numbers.
    return vdefs.key_at(row, 0)


def _narrow(rows: Iterable[vdefs.Row], q: str) -> list[vdefs.Row]:
    spec = filtering.parse_filter(q.strip()) if q.strip() else filtering.FilterSpec()
    kept = [r for r in rows if not r.heading
            and filtering.matches(spec, r.text, r.addresses, r.records)]
    return sorted(kept, key=_key_at)


def _page(items: list, convert: Callable, offset: int, limit: int) -> s.Page:
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    return s.Page(items=[convert(x) for x in items[offset:offset + limit]],
                  total=len(items), offset=offset, limit=limit)


# --- hosts ------------------------------------------------------------------------


def hosts(model: WebModel, q: str = "", offset: int = 0,
          limit: int = DEFAULT_LIMIT) -> s.Page[s.HostSummary]:
    rows = _narrow(model.rows("hosts"), q)
    return _page([r.target for r in rows], lambda h: s.out_host_summary(model, h),
                 offset, limit)


def host(model: WebModel, address: str) -> s.HostOut:
    found = model.hosts.get(address)
    if found is None:
        raise NotFound(f"no host {address}")
    return s.out_host(model, found)


# --- services -----------------------------------------------------------------------


def services(model: WebModel, q: str = "", offset: int = 0,
             limit: int = DEFAULT_LIMIT) -> s.Page[s.ServiceSummary]:
    rows = _narrow(model.rows("services"), q)
    return _page([r.target for r in rows], s.out_service_summary, offset, limit)


def service_group(model: WebModel, protocol: str, port: int, name: str | None = None,
                  product: str | None = None, version: str | None = None) -> ServiceGroup:
    """The service-overview row for these, or every host on the port when the
    identifying fields are left out - one port can carry several products."""
    groups = [g for g in service_groups(model.scans.hosts)
              if g.protocol == protocol and g.port == port]
    exact = [g for g in groups if (name is None or (g.name or "") == name)
             and (product is None or (g.product or "") == product)
             and (version is None or (g.version or "") == version)]
    if not exact:
        raise NotFound(f"no open service {port}/{protocol}"
                       + (f" {name or ''} {product or ''} {version or ''}".rstrip()
                          if name or product or version else ""))
    if len(exact) == 1:
        return exact[0]
    merged = ServiceGroup(protocol=protocol, port=port,
                          name=exact[0].name if len({g.name for g in exact}) == 1 else None)
    for g in exact:
        merged.members.extend(g.members)
    return merged


def service(model: WebModel, protocol: str, port: int, name: str | None = None,
            product: str | None = None, version: str | None = None) -> s.ServiceOut:
    return s.out_service(model, service_group(model, protocol, port, name, product, version))


# --- captures -----------------------------------------------------------------------


def _capture_text(p: Placed) -> str:
    c = p.capture
    port = f"{p.service.port} {p.service.port}/{p.service.protocol}" if p.service else ""
    return " ".join(filter(None, [c.url, c.final_url, c.title, str(c.status or ""),
                                  p.host.address if p.host else "",
                                  " ".join(p.host.hostnames) if p.host else "",
                                  port, str(c.database or ""), c.failure,
                                  *c.technologies]))


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "") if url else ""


def _port_of(p: Placed) -> tuple | None:
    if p.service is not None:
        return port_key(p.service.port, p.service.protocol)
    port = urlsplit(p.capture.url).port if p.capture.url else None
    return (port, 0) if port else None


def _by(value: Callable[[Placed], object]) -> Callable[[Placed], tuple]:
    """`(known, value)`: a capture with nothing to sort on says so, and goes last."""
    def key(p: Placed) -> tuple:
        v = value(p)
        return (False, ()) if v in (None, "", ()) else (True, v)
    return key


# name -> (label, key). Unknowns - a failure with no status, a page with no
# title - go after every known value in either direction, so a list sorted by
# status does not open on a page of failures.
SORTS: dict[str, tuple[str, Callable[[Placed], tuple]]] = {
    "address": ("address", _by(lambda p: (addr_key(p.host.address), _port_of(p) or ())
                               if p.host else None)),
    "host": ("host name", _by(lambda p: (_host_of(p.capture.url), _port_of(p) or ())
                              if _host_of(p.capture.url) else None)),
    "port": ("port", _by(lambda p: (_port_of(p), addr_key(p.host.address) if p.host else ())
                         if _port_of(p) else None)),
    "status": ("HTTP status", _by(lambda p: (p.capture.status, _host_of(p.capture.url))
                                  if p.capture.status else None)),
    "url": ("URL", _by(lambda p: p.capture.url.lower())),
    "title": ("page title", _by(lambda p: p.capture.title.lower())),
    "taken": ("time taken", _by(lambda p: p.capture.probed_at)),
    "database": ("database", _by(lambda p: str(p.capture.database or ""))),
}
DEFAULT_SORT = "address"


def _in_scope(p: Placed, address: str | None, protocol: str | None,
              port: int | None) -> bool:
    """The structured narrowing `w` and a card's "all for this service" use."""
    if address is not None and (p.host is None or p.host.address != address):
        return False
    if port is not None and (p.service is None or p.service.port != port):
        return False
    if protocol is not None and (p.service is None or p.service.protocol != protocol):
        return False
    return True


def captures(model: WebModel, q: str = "", offset: int = 0,
             limit: int = DEFAULT_LIMIT, sort: str = DEFAULT_SORT, desc: bool = False,
             address: str | None = None, protocol: str | None = None,
             port: int | None = None) -> s.Page[s.CaptureSummary]:
    spec = filtering.parse_filter(q.strip()) if q.strip() else filtering.FilterSpec()
    kept = [p for p in model.captures
            if _in_scope(p, address, protocol, port)
            and filtering.matches(spec, _capture_text(p),
                                  (p.host.address,) if p.host else (),
                                  (Record(p.host, p.service),) if p.host and p.service else ())]
    kept, loose = filtering.prefer_firm(spec, kept, _capture_text)
    _label, key = SORTS.get(sort, SORTS[DEFAULT_SORT])
    keyed = [(key(p), p) for p in kept]
    # Reversing must not bring the unknowns to the front: the known ones are
    # sorted in the asked direction and the rest stay behind them.
    known = [(k[1], p) for k, p in keyed if k[0]]
    known.sort(key=lambda kp: kp[0], reverse=desc)
    rest = sorted((p for k, p in keyed if not k[0]), key=lambda p: p.capture.url)
    ordered = [p for _k, p in known] + rest

    def convert(p: Placed) -> s.CaptureSummary:
        siblings = len(model.captures_of(p.host, p.service)) if p.host and p.service else 0
        return s.out_capture(p, siblings=siblings)

    page = _page(ordered, convert, offset, limit)
    page.loose = loose
    return page


def capture(model: WebModel, capture_id: str) -> s.CaptureOut:
    found = model.by_id.get(capture_id)
    if found is None:
        raise NotFound(f"no capture {capture_id}")
    return s.out_capture(found, full=True)
