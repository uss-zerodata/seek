"""`/api/v1/records` and `/api/v1/raw` - a row's record, and nmap's own text."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from seek.web import pages_data
from seek.web import schemas as s
from seek.web.api.v1.views import split_path
from seek.web.deps import places, session
from seek.web.views import Unresolved

router = APIRouter(prefix="/api/v1", tags=["records"])


@router.get("/records/{tab}", response_model=s.RecordOut,
            responses={404: {"model": s.ErrorOut}})
def get_record(tab: str, step: str, path: str = "", mode: str = "condensed",
               sess=Depends(session), cache=Depends(places)) -> s.RecordOut:
    """The record of the row named `step` in the view at `tab` + `path`."""
    try:
        return pages_data.record(sess, cache, tab, split_path(path), step, mode)
    except Unresolved as exc:
        raise HTTPException(404, str(exc)) from None


@router.get("/raw", response_model=s.RawOut, responses={404: {"model": s.ErrorOut}})
def get_raw(scan: str, address: str, protocol: str | None = None, port: int | None = None,
            sess=Depends(session)) -> s.RawOut:
    """What one scan wrote about a host, or one of its ports."""
    try:
        return pages_data.raw(sess, scan, address, protocol, port)
    except Unresolved as exc:
        raise HTTPException(404, str(exc)) from None
