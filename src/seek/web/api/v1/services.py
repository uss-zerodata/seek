"""`/api/v1/services` - services across hosts, and one service everywhere."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from seek.web import query
from seek.web import schemas as s
from seek.web.deps import model
from seek.web.source import WebModel

router = APIRouter(prefix="/api/v1/services", tags=["services"])


@router.get("", response_model=s.Page[s.ServiceSummary])
def list_services(q: str = "", offset: int = 0, limit: int = query.DEFAULT_LIMIT,
                  m: WebModel = Depends(model)):
    return query.services(m, q, offset, limit)


@router.get("/{protocol}/{port}", response_model=s.ServiceOut,
            responses={404: {"model": s.ErrorOut}})
def get_service(protocol: str, port: int, name: str | None = None,
                product: str | None = None, version: str | None = None,
                m: WebModel = Depends(model)):
    try:
        return query.service(m, protocol, port, name, product, version)
    except query.NotFound as exc:
        raise HTTPException(404, str(exc)) from None
