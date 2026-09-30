"""One search across everything the session knows, grouped by what was found.

The per-tab filters narrow one list; this answers "where is X" - an address, a
name, a product, a page title - from anywhere. It is the same grammar and the
same lists: each group is the tab's own rows for the query (`views.listing`),
so a group's "all N" link opens that tab filtered by the very same text and
shows the very same rows.
"""

from __future__ import annotations

from urllib.parse import urlencode

from seek.nmap import filtering
from seek.nmap.session import Session
from seek.tui.nmap import views as vdefs
from seek.web import links, query
from seek.web import schemas as s
from seek.web.views import ViewCache, listing, row_shots, step_of


def _more(tab: str, q: str) -> str:
    return f"/v/{tab}?" + urlencode({"q": q})


def _host_hit(model, row: vdefs.Row) -> s.Hit:
    host = row.target
    names = ", ".join(host.hostnames[:3])
    ports = ", ".join(f"{p.port}/{p.protocol}" for p in host.open_services[:8])
    shots, _total = row_shots(model, row)
    return s.Hit(title=host.address, subtitle=" · ".join(filter(None, [names, ports])),
                 href=links.host(host.address),
                 image=next((x.image for x in shots if x.image), None))


def _service_hit(model, row: vdefs.Row) -> s.Hit:
    g = row.target
    what = " ".join(filter(None, [g.name, g.product, g.version]))
    shots, _total = row_shots(model, row)
    return s.Hit(title=f"{g.port}/{g.protocol} {what}".strip(),
                 subtitle=f"{g.host_count} host(s)", href=links.service(g),
                 image=next((x.image for x in shots if x.image), None))


def _name_hit(row: vdefs.Row) -> s.Hit:
    name, source, hosts = row.cells[0], row.cells[1], row.cells[2]
    return s.Hit(title=name, subtitle=f"{source} · {hosts} host(s)",
                 href="/v/names?" + urlencode({"path": step_of(row)}))


def search(session: Session, model, cache: ViewCache, q: str, per_group: int = 8
           ) -> s.SearchOut:
    q = q.strip()
    out = s.SearchOut(q=q)
    if not q:
        return out
    out.understood = filtering.explain(filtering.parse_filter(q))

    loose: dict[str, int] = {}

    def rows_of(tab: str) -> list[vdefs.Row]:
        place = cache.resolve(session, tab, [])
        shown = listing(session, place.view, q)
        if shown.loose:
            loose[tab] = shown.loose
        return [r for r in shown.rows if not r.heading]

    hosts = rows_of("hosts")
    services = rows_of("services")
    names = rows_of("names")
    shots = query.captures(model, q, 0, per_group) if model is not None else None
    if shots is not None and shots.loose:
        loose["screenshots"] = shots.loose
    out.groups = [g for g in (
        s.HitGroup(kind="hosts", label="Hosts", total=len(hosts), more=_more("hosts", q),
                   hits=[_host_hit(model, r) for r in hosts[:per_group]]),
        s.HitGroup(kind="services", label="Services", total=len(services),
                   more=_more("services", q),
                   hits=[_service_hit(model, r) for r in services[:per_group]]),
        s.HitGroup(kind="names", label="Names", total=len(names), more=_more("names", q),
                   hits=[_name_hit(r) for r in names[:per_group]]),
        s.HitGroup(kind="screenshots", label="Screenshots",
                   total=shots.total if shots else 0,
                   more="/?" + urlencode({"q": q}),
                   hits=[s.Hit(title=c.title or c.url,
                               subtitle=" · ".join(filter(None, [
                                   str(c.status or ("failed" if c.failed else "")),
                                   c.url if c.title else "",
                                   f"{c.address}:{c.port}" if c.address else ""])),
                               href=links.capture(c.id), image=c.image)
                         for c in (shots.items if shots else [])]),
    ) if g.total]
    for group in out.groups:
        group.loose = loose.get(group.kind, 0)
    return out
