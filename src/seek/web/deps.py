"""What a route needs from the request: the model as it stands right now."""

from __future__ import annotations

from fastapi import Request

from seek.nmap.session import Session
from seek.web.source import WebModel
from seek.web.views import ViewCache


def model(request: Request) -> WebModel:
    return request.app.state.source.snapshot()


def session(request: Request) -> Session:
    """The session the actions change; 503 when the app was built without one."""
    from fastapi import HTTPException

    found = request.app.state.session
    if found is None:
        raise HTTPException(503, "this interface is read-only: no session attached")
    return found


def places(request: Request) -> ViewCache:
    return request.app.state.places
