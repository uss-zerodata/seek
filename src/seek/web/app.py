"""The application: every router, registered in one list.

Adding a resource is a schema, a query function and a router appended to
`ROUTERS` - nothing else in the stack changes. FastAPI's own interactive docs
are off: they load their scripts from a CDN, and the interface has to work on
a network with no route out. The OpenAPI description is still served.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from seek.web import media
from seek.web.api.v1 import captures, hosts, services
from seek.web.pages import routes as pages
from seek.web.source import ModelSource

STATIC = Path(__file__).parent / "static"

ROUTERS = [
    hosts.router,
    services.router,
    captures.router,
    media.router,
    pages.router,
]


def create_app(source: ModelSource) -> FastAPI:
    app = FastAPI(title="seek", docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.state.source = source
    for router in ROUTERS:
        app.include_router(router)
    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
