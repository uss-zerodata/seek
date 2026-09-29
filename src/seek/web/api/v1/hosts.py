"""`/api/v1/hosts` - the host list and one host's record."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from seek.web import query
from seek.web import schemas as s
from seek.web.deps import model
from seek.web.source import WebModel

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.get("", response_model=s.Page[s.HostSummary])
def list_hosts(q: str = "", offset: int = 0, limit: int = query.DEFAULT_LIMIT,
               m: WebModel = Depends(model)):
    return query.hosts(m, q, offset, limit)


@router.get("/{address}", response_model=s.HostOut,
            responses={404: {"model": s.ErrorOut}})
def get_host(address: str, m: WebModel = Depends(model)):
    try:
        return query.host(m, address)
    except query.NotFound as exc:
        raise HTTPException(404, str(exc)) from None
