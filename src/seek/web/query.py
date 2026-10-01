"""Listing, filtering, sorting and paging - once, for the API and the pages.

Lists are the TUI's own projections (`seek.tui.nmap.views`) filtered with the
TUI's own grammar (`seek.nmap.filtering`), which is the path `NmapApp._narrow`
takes: a list in the browser and the same tab in the terminal cannot disagree
about which rows a filter keeps, or in what order they come.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TypeVar
from urllib.parse import urlencode, urlsplit

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


@dataclass(frozen=True, slots=True)
class Scope:
    """What the gallery is narrowed to - one host, one port, one page title,
    one look-alike group - on top of the filter text."""

    address: str | None = None
    protocol: str | None = None
    port: int | None = None
    title: str | None = None
    similar: str | None = None
    # A capture of something not in the scans: the host and port of its URL.
    url_host: str | None = None
    url_port: int | None = None

    def admits(self, p: Placed) -> bool:
        if self.address is not None and (p.host is None or p.host.address != self.address):
            return False
        if self.port is not None and (p.service is None or p.service.port != self.port):
            return False
        if self.protocol is not None and (p.service is None
                                          or p.service.protocol != self.protocol):
            return False
        if self.title is not None and _title_key(p) != _norm(self.title):
            return False
        if self.similar is not None and _similar_key(p) != self.similar:
            return False
        if self.url_host is not None:
            host, port = _url_host(p)
            if p.host is not None or host != self.url_host:
                return False
            if self.url_port is not None and port != self.url_port:
                return False
        return True


def _filtered(model: WebModel, q: str, sort: str, desc: bool,
              scope: Scope) -> tuple[list[Placed], int]:
    """The gallery's captures for a filter and a scope, in order; and how many
    looser matches were left out."""
    spec = filtering.parse_filter(q.strip()) if q.strip() else filtering.FilterSpec()
    kept = [p for p in model.captures
            if scope.admits(p)
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
    return [p for _k, p in known] + rest, loose


def _summary(model: WebModel, p: Placed) -> s.CaptureSummary:
    siblings = len(model.captures_of(p.host, p.service)) if p.host and p.service else 0
    return s.out_capture(p, siblings=siblings)


def captures(model: WebModel, q: str = "", offset: int = 0,
             limit: int = DEFAULT_LIMIT, sort: str = DEFAULT_SORT, desc: bool = False,
             address: str | None = None, protocol: str | None = None,
             port: int | None = None, title: str | None = None,
             similar: str | None = None, url_host: str | None = None,
             url_port: int | None = None) -> s.Page[s.CaptureSummary]:
    ordered, loose = _filtered(model, q, sort, desc,
                               Scope(address, protocol, port, title, similar,
                                     url_host, url_port))
    page = _page(ordered, lambda p: _summary(model, p), offset, limit)
    page.loose = loose
    return page


# --- grouping the gallery ------------------------------------------------------------
#
# The same captures, gathered by what they have in common: one host, one
# service, one page title, or one look-alike group - gowitness's perceptual-hash
# group, which puts screenshots that *look* the same together (every default
# nginx page, every FRITZ!Box login) whatever their title says. Its ids are
# numbered per database, so a group is named by database and id together.

GROUPINGS: dict[str, str] = {
    "host": "Host", "service": "Service", "title": "Page title", "similar": "Look-alike",
}
# The gallery's default: one card per host:port, its other screenshots stacked
# behind it. `group=every` shows each screenshot on its own.
EVERY = "every"
PER_STACK = 24
PER_GROUP = 12


def _norm(title: str) -> str:
    return " ".join(title.split()).casefold()


def _title_key(p: Placed) -> str:
    return _norm(p.capture.title)


def _similar_key(p: Placed) -> str:
    c = p.capture
    if c.failed or c.perception_group is None:
        return ""
    digest = hashlib.sha1(str(c.database or "").encode()).hexdigest()[:6]
    return f"{digest}-{c.perception_group}"


def _url_host(p: Placed) -> tuple[str, int | None]:
    split = urlsplit(p.capture.url)
    return split.hostname or p.capture.url, split.port


def _group_of(p: Placed, by: str) -> tuple[str, str, dict, tuple]:
    """(key, label, the scope that is this group, the group's sort key)."""
    c = p.capture
    if by == "host":
        if p.host is not None:
            names = ", ".join(p.host.hostnames[:2])
            return (f"h:{p.host.address}", " · ".join(filter(None, [p.host.address, names])),
                    {"address": p.host.address}, (0, addr_key(p.host.address)))
        host, _port = _url_host(p)
        return (f"u:{host}", f"{host} (not in the scans)", {"url_host": host},
                (1, host))
    if by == "service":
        if p.host is not None and p.service is not None:
            svc = p.service
            what = " ".join(filter(None, [svc.name, svc.product]))
            return (f"s:{p.host.address}/{svc.protocol}/{svc.port}",
                    f"{p.host.address}  {svc.port}/{svc.protocol}  {what}".strip(),
                    {"address": p.host.address, "protocol": svc.protocol, "port": svc.port},
                    (0, addr_key(p.host.address), port_key(svc.port, svc.protocol)))
        host, port = _url_host(p)
        scope = {"url_host": host, **({"url_port": port} if port else {})}
        return (f"u:{host}:{port}", f"{host}:{port or '-'} (not in the scans)",
                scope, (1, host, port or 0))
    if by == "title":
        key = _title_key(p)
        if c.failed:
            return "failed", "(capture failed)", {"q": "failed"}, (2, "")
        if not key:
            return "untitled", "(no title)", {"title": ""}, (1, "")
        return f"t:{key}", " ".join(c.title.split()), {"title": c.title}, (0, key)
    key = _similar_key(p)
    if not key:
        return "none", "(no screenshot to compare)", {"q": "failed"}, (1, "")
    return f"p:{key}", "", {"similar": key}, (0, key)


def capture_stacks(model: WebModel, q: str = "", sort: str = DEFAULT_SORT,
                   desc: bool = False, offset: int = 0, limit: int = DEFAULT_LIMIT,
                   per_stack: int = PER_STACK) -> s.StackPage:
    """The filtered captures, one stack per host:port - so ten screenshots of
    one web server (by address, by each name, run after run) read as one
    service, not ten. A stack sits where its first capture sorts; its front card
    is that capture."""
    ordered, loose = _filtered(model, q, sort, desc, Scope())
    stacks: dict[str, list] = {}
    for p in ordered:
        key, label, scope, _order = _group_of(p, "service")
        stacks.setdefault(key, [label, scope, []])[2].append(p)
    entries = list(stacks.items())
    limit = max(1, min(limit, MAX_LIMIT))
    offset = max(0, offset)
    out = []
    for key, (label, scope, members) in entries[offset:offset + limit]:
        out.append(s.Stack(
            key=key, label=label, count=len(members),
            first=_summary(model, members[0]),
            rest=[_summary(model, p) for p in members[1:per_stack]],
            more=urlencode({k: v for k, v in scope.items() if k != "q"})))
    return s.StackPage(stacks=out, total=len(entries), captures=len(ordered),
                       offset=offset, limit=limit, loose=loose)


def capture_groups(model: WebModel, by: str, q: str = "", sort: str = DEFAULT_SORT,
                   desc: bool = False, offset: int = 0, limit: int = 100,
                   per_group: int = PER_GROUP) -> s.GroupPage:
    """The filtered captures gathered by `by` - largest groups first for title
    and look-alike, address and port order for host and service."""
    ordered, loose = _filtered(model, q, sort, desc, Scope())
    groups: dict[str, list] = {}
    for p in ordered:
        key, label, scope, order = _group_of(p, by)
        entry = groups.setdefault(key, [label, scope, order, []])
        entry[3].append(p)
    if by == "similar":
        for entry in groups.values():
            if not entry[0]:
                # Named by what its members most often say they are.
                titles = [" ".join(p.capture.title.split()) for p in entry[3]
                          if p.capture.title.strip()]
                if titles:
                    entry[0] = f"looks like: {max(set(titles), key=titles.count)}"
                else:
                    codes = [str(p.capture.status) for p in entry[3] if p.capture.status]
                    code = max(set(codes), key=codes.count) if codes else ""
                    entry[0] = "untitled pages" + (f" · {code}" if code else "")
    if by in ("title", "similar"):
        ranked = sorted(groups.items(), key=lambda kv: (kv[1][2][0], -len(kv[1][3]),
                                                        kv[1][0].casefold()))
    else:
        ranked = sorted(groups.items(), key=lambda kv: kv[1][2])
    out = []
    for key, (label, scope, _order, members) in ranked[max(0, offset):offset + limit]:
        more = {k: v for k, v in scope.items() if k != "q"}
        text = " ".join(filter(None, [q.strip(), scope.get("q", "")]))
        query_ = urlencode({**({"q": text} if text else {}), "sort": sort,
                            **({"desc": "1"} if desc else {}), **more})
        out.append(s.CaptureGroup(key=key, label=label, count=len(members), more=query_,
                                  items=[_summary(model, p) for p in members[:per_group]]))
    return s.GroupPage(by=by, groups=out, total=len(groups), captures=len(ordered),
                       offset=offset, limit=limit, loose=loose)


def capture(model: WebModel, capture_id: str) -> s.CaptureOut:
    found = model.by_id.get(capture_id)
    if found is None:
        raise NotFound(f"no capture {capture_id}")
    return s.out_capture(found, full=True)
