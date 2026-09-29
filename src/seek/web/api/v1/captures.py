"""`/api/v1/captures` - every capture from every database, and one in full."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from seek.web import query
from seek.web import schemas as s
from seek.web.deps import model
from seek.web.source import WebModel

router = APIRouter(prefix="/api/v1/captures", tags=["captures"])


@router.get("", response_model=s.Page[s.CaptureSummary])
def list_captures(q: str = "", offset: int = 0, limit: int = query.DEFAULT_LIMIT,
                  m: WebModel = Depends(model)):
    return query.captures(m, q, offset, limit)


@router.get("/{capture_id}", response_model=s.CaptureOut,
            responses={404: {"model": s.ErrorOut}})
def get_capture(capture_id: str, m: WebModel = Depends(model)):
    try:
        return query.capture(m, capture_id)
    except query.NotFound as exc:
        raise HTTPException(404, str(exc)) from None
