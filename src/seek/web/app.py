"""The application: every router, registered in one list.

Adding a resource is a schema, a query function and a router appended to
`ROUTERS` - nothing else in the stack changes. FastAPI's own interactive docs
are off: they load their scripts from a CDN, and the interface has to work on
a network with no route out. The OpenAPI description is still served.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from seek.web import media
from seek.web.api.v1 import builder as builder_api
from seek.web.api.v1 import captures, hosts, inventory, services, vulndb
from seek.web.api.v1 import marks as marks_api
from seek.web.api.v1 import records as records_api
from seek.web.api.v1 import runs as runs_api
from seek.web.api.v1 import search as search_api
from seek.web.api.v1 import views as views_api
from seek.web.pages import routes as pages
from seek.web.source import ModelSource
from seek.web.views import ViewCache

STATIC = Path(__file__).parent / "static"

ROUTERS = [
    builder_api.router,
    hosts.router,
    services.router,
    captures.router,
    inventory.router,
    vulndb.router,
    views_api.router,
    records_api.router,
    marks_api.router,
    runs_api.router,
    search_api.router,
    media.router,
    pages.router,
]


_SAFE = {"GET", "HEAD", "OPTIONS"}


class _Static(StaticFiles):
    """Static files the browser asks about every time.

    The page's own files carry a version in their URL, but the modules they
    import (`keys.js`, `actions.js`, `events.js`) do not, and a browser that
    kept an old one beside a new `viewer.js` fails the import and runs none of
    it. `no-cache` is a revalidation, not a download: on loopback it is free.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


def create_app(source: ModelSource, session=None,
               origin: Callable[[], str] | None = None) -> FastAPI:
    """The application over `source`; `session` is what the actions change.

    `origin` gives the interface's own `http://host:port` - a callable, since
    the port is only known once the server is listening.
    """
    app = FastAPI(title="seek", docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.source = source
    app.state.session = session
    app.state.places = ViewCache()
    for router in ROUTERS:
        app.include_router(router)
    app.mount("/static", _Static(directory=STATIC), name="static")

    @app.middleware("http")
    async def same_origin(request: Request, call_next):
        """A change is accepted only from the interface's own pages.

        The whole of the protection, by agreement: it stops a page on another
        site, open in the same browser, from driving the API. A request with
        neither `Origin` nor `Referer` - a script, curl - is a local program
        run by the user, and is let through like the user themselves.
        """
        if request.method not in _SAFE:
            claimed = request.headers.get("origin") or _origin_of(
                request.headers.get("referer", ""))
            own = origin() if origin is not None else f"{request.url.scheme}://{request.url.netloc}"
            if claimed and claimed.rstrip("/") != own.rstrip("/"):
                return JSONResponse({"detail": "refused: request from another origin"},
                                    status_code=403)
        return await call_next(request)

    return app


def _origin_of(url: str) -> str:
    split = urlsplit(url)
    return f"{split.scheme}://{split.netloc}" if split.scheme and split.netloc else ""
