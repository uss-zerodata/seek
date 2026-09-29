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

from seek.web import query
from seek.web.deps import model
from seek.web.source import WebModel

TEMPLATES = Jinja2Templates(directory=Path(__file__).parent.parent / "templates")

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
            m: WebModel = Depends(model)):
    page = query.captures(m, q, offset, limit)
    return _list(request, "gallery.html", "_captures.html", fragment,
                 page=page, q=q, nav="gallery")


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
