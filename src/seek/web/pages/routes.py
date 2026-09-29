"""The HTML pages: templates over the same objects the API returns.

Every list page takes `q`, `offset` and `limit` like its API twin, and
`fragment=1` for the list alone - which is what the filter box fetches as the
user types, so filtering happens on the server with the TUI's grammar and scales
to lists the browser could not hold.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from seek.nmap import filtering
from seek.tui.nmap.tabs import TABS
from seek.web import links, pages_data, query, views
from seek.web import search as search_mod
from seek.web.api.v1.views import split_path
from seek.web.deps import model, places, session
from seek.web.source import WebModel

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")
TEMPLATES.env.globals["TABS"] = TABS


def _static_version() -> str:
    """A tag for the static files as they are now, so an upgrade is not served
    from a browser's cache of the old ones."""
    import hashlib

    digest = hashlib.sha1()
    static = Path(__file__).parent.parent / "static"
    for path in sorted(static.rglob("*")):
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()[:10]


TEMPLATES.env.globals["V"] = _static_version()


def gallery_scope(step: str) -> str:
    """The gallery narrowed to what a list row stands for, as a query string."""
    kind, _, rest = step.partition(":")
    if kind == "h":
        return urlencode({"address": rest})
    if kind == "p":
        address, protocol, port = rest.split("/", 2)
        return urlencode({"address": address, "protocol": protocol, "port": port})
    if kind == "s":
        protocol, port = rest.split("/")[:2]
        return urlencode({"protocol": protocol, "port": port})
    if kind == "b" and rest.startswith("port/"):
        port, protocol = rest.removeprefix("port/").split("/")[:2]
        return urlencode({"protocol": protocol, "port": port})
    return ""


TEMPLATES.env.globals["gallery_scope"] = gallery_scope
TEMPLATES.env.globals["links"] = links

router = APIRouter(include_in_schema=False)


def _render(request: Request, name: str, status: int = 200, **context) -> HTMLResponse:
    return TEMPLATES.TemplateResponse(request, name, context, status_code=status)


def _list(request: Request, template: str, part: str, only_part: bool, **context):
    return _render(request, part if only_part else template, **context)


def _missing(request: Request, what: str) -> HTMLResponse:
    return _render(request, "missing.html", status=404, what=what)


@router.get("/", response_class=HTMLResponse)
def gallery(request: Request, q: str = "", offset: int = 0,
            limit: int = query.DEFAULT_LIMIT, fragment: bool = False,
            sort: str = query.DEFAULT_SORT, desc: bool = False,
            address: str | None = None, protocol: str | None = None,
            port: int | None = None, title: str | None = None,
            similar: str | None = None, url_host: str | None = None,
            url_port: int | None = None, group: str = "",
            m: WebModel = Depends(model)):
    sort = sort if sort in query.SORTS else query.DEFAULT_SORT
    group = group if group in query.GROUPINGS else ""
    # What the list is narrowed to, and the parameters that keep it narrowed
    # when paging - the "next" link must not drop the sort, the scope or the
    # grouping.
    scope = {k: v for k, v in (("address", address), ("protocol", protocol),
                               ("port", port), ("title", title), ("similar", similar),
                               ("url_host", url_host), ("url_port", url_port))
             if v is not None}
    keep = {"q": q, "sort": sort, **({"desc": "1"} if desc else {}), **scope}
    if group and not scope:
        page = query.capture_groups(m, group, q, sort, desc, offset, min(limit, 100))
        template, part = "gallery.html", "_groups.html"
    else:
        page = query.captures(m, q, offset, limit, sort, desc, address, protocol, port,
                              title, similar, url_host, url_port)
        template, part = "gallery.html", "_captures.html"
    return _list(request, template, part, fragment,
                 page=page, q=q, nav="gallery", sort=sort, desc=desc, group=group,
                 groupings=query.GROUPINGS, sorts=query.SORTS, scope=scope, keep=keep,
                 understood=filtering.explain(filtering.parse_filter(q)) if q.strip() else [])


# The first version's own host and service pages are the tabs now: one page per
# thing, so an old link or bookmark lands where that thing lives.


@router.get("/hosts")
def hosts(q: str = ""):
    return RedirectResponse("/v/hosts" + (f"?{urlencode({'q': q})}" if q else ""), 302)


@router.get("/hosts/{address}")
def host(address: str):
    return RedirectResponse(links.host(address), 302)


@router.get("/services")
def services(q: str = ""):
    return RedirectResponse("/v/services" + (f"?{urlencode({'q': q})}" if q else ""), 302)


@router.get("/services/{protocol}/{port}")
def service(request: Request, protocol: str, port: int, name: str | None = None,
            product: str | None = None, version: str | None = None,
            m: WebModel = Depends(model)):
    try:
        group = query.service_group(m, protocol, port, name, product, version)
    except query.NotFound as exc:
        return _missing(request, str(exc))
    if name is None and product is None and version is None and len(
            {(g.name, g.product, g.version) for g in _groups_on(m, protocol, port)}) > 1:
        # Several products on the port: the list of them, filtered to it.
        return RedirectResponse("/v/services?" + urlencode({"q": f"^{port}$"}), 302)
    return RedirectResponse(links.service(group), 302)


def _groups_on(m: WebModel, protocol: str, port: int):
    from seek.nmap.views import service_groups

    return [g for g in service_groups(m.scans.hosts)
            if g.protocol == protocol and g.port == port]


@router.get("/captures/{capture_id}", response_class=HTMLResponse)
def capture(request: Request, capture_id: str, m: WebModel = Depends(model)):
    try:
        found = query.capture(m, capture_id)
    except query.NotFound as exc:
        return _missing(request, str(exc))
    return _render(request, "capture.html", capture=found, nav="gallery")


# --- every overview, as the terminal has them --------------------------------------


@router.get("/v/{tab}", response_class=HTMLResponse)
def overview(request: Request, tab: str, path: str = "", q: str = "",
             sort: int | None = None, desc: bool = False, up: bool = False,
             ports: bool = False, open: bool = False, sel: str = "", offset: int = 0,
             limit: int = 500, fragment: bool = False,
             sess=Depends(session), cache=Depends(places), m=Depends(model)):
    """One level of one tab. Its URL is its state: the browser's back button
    returns to the level before with its own filter, sort and selected row."""
    try:
        found = views.overview(sess, cache, tab, split_path(path), q, sort, desc, up,
                               ports, open, offset, limit, m)
    except views.Unresolved as exc:
        return _missing(request, str(exc))
    # The selected row's record is in the page itself: it shows at once, and
    # without script. The script takes over from there.
    step = sel or next((r.step for r in found.rows if not r.heading), "")
    record = None
    if step and not fragment:
        try:
            record = pages_data.record(sess, cache, tab, split_path(path), step)
        except views.Unresolved:
            record = None
    here = {k: v for k, v in (("path", path), ("q", q), ("up", "1" if up else ""),
                              ("ports", "1" if ports else ""),
                              ("open", "1" if open else "")) if v}
    return _render(request, "_overview.html" if fragment else "overview.html",
                   view=found, tabs=TABS, here=here, sel=step, nav=found.marked_tab,
                   record=record,
                   sort_arg=sort, desc=desc)


@router.get("/search", response_class=HTMLResponse)
def search_page(request: Request, q: str = "", fragment: bool = False,
                sess=Depends(session), cache=Depends(places), m=Depends(model)):
    """Everything matching `q`, grouped - the header box's results, in full."""
    found = search_mod.search(sess, m, cache, q, per_group=8 if fragment else 50)
    return _render(request, "_search.html" if fragment else "search.html",
                   found=found, q=q, nav="")
