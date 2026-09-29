"""What a route needs from the request: the model as it stands right now."""

from __future__ import annotations

from fastapi import Request

from seek.web.source import WebModel


def model(request: Request) -> WebModel:
    return request.app.state.source.snapshot()
