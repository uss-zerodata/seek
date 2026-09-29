"""The HTML pages: templates over the same objects the API returns.

Every list page takes `q`, `offset` and `limit` like its API twin, and
`fragment=1` for the list alone - which is what the filter box fetches as the
user types, so filtering happens on the server with the TUI's grammar and scales
to lists the browser could not hold.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from seek.tui.nmap.tabs import TABS
from seek.web import pages_data, query, views
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
            port: int | None = None, m: WebModel = Depends(model)):
    sort = sort if sort in query.SORTS else query.DEFAULT_SORT
    page = query.captures(m, q, offset, limit, sort, desc, address, protocol, port)
    # What the list is narrowed to, and the parameters that keep it narrowed
    # when paging - the "next" link must not drop the sort or the scope.
    scope = {k: v for k, v in (("address", address), ("protocol", protocol),
                               ("port", port)) if v is not None}
    keep = {"q": q, "sort": sort, **({"desc": "1"} if desc else {}), **scope}
    return _list(request, "gallery.html", "_captures.html", fragment,
                 page=page, q=q, nav="gallery", sort=sort, desc=desc,
                 sorts=query.SORTS, scope=scope, keep=keep)


@router.get("/hosts", response_class=HTMLResponse)
def hosts(request: Request, q: str = "", offset: int = 0,
          limit: int = query.DEFAULT_LIMIT, fragment: bool = False,
          m: WebModel = Depends(model)):
    page = query.hosts(m, q, offset, limit)
    return _list(request, "hosts.html", "_hosts.html", fragment,
                 page=page, q=q, nav="hosts")


@router.get("/hosts/{address}", response_class=HTMLResponse)
def host(request: Request, address: str, m: WebModel = Depends(model)):
    try:
        found = query.host(m, address)
    except query.NotFound as exc:
        return _missing(request, str(exc))
    return _render(request, "host.html", host=found, nav="hosts")


@router.get("/services", response_class=HTMLResponse)
def services(request: Request, q: str = "", offset: int = 0,
             limit: int = query.DEFAULT_LIMIT, fragment: bool = False,
             m: WebModel = Depends(model)):
    page = query.services(m, q, offset, limit)
    return _list(request, "services.html", "_services.html", fragment,
                 page=page, q=q, nav="services")


@router.get("/services/{protocol}/{port}", response_class=HTMLResponse)
def service(request: Request, protocol: str, port: int, name: str | None = None,
            product: str | None = None, version: str | None = None,
            m: WebModel = Depends(model)):
    try:
        found = query.service(m, protocol, port, name, product, version)
    except query.NotFound as exc:
        return _missing(request, str(exc))
    return _render(request, "service.html", service=found, nav="services")


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
             sess=Depends(session), cache=Depends(places)):
    """One level of one tab. Its URL is its state: the browser's back button
    returns to the level before with its own filter, sort and selected row."""
    try:
        found = views.overview(sess, cache, tab, split_path(path), q, sort, desc, up,
                               ports, open, offset, limit)
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
