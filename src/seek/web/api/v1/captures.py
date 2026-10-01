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
                  sort: str = query.DEFAULT_SORT, desc: bool = False,
                  address: str | None = None, protocol: str | None = None,
                  port: int | None = None, title: str | None = None,
                  similar: str | None = None, url_host: str | None = None,
                  url_port: int | None = None, m: WebModel = Depends(model)):
    """Every capture; `sort` is one of the keys of `query.SORTS`. `title` and
    `similar` narrow to one page title or one look-alike group."""
    if sort not in query.SORTS:
        raise HTTPException(422, f"sort must be one of {', '.join(query.SORTS)}")
    return query.captures(m, q, offset, limit, sort, desc, address, protocol, port,
                          title, similar, url_host, url_port)


@router.get("/groups", response_model=s.GroupPage)
def capture_groups(by: str, q: str = "", sort: str = query.DEFAULT_SORT, desc: bool = False,
                   offset: int = 0, limit: int = 100, per_group: int = query.PER_GROUP,
                   m: WebModel = Depends(model)):
    """The captures gathered by `by`: host, service, title or similar (look-alike)."""
    if by not in query.GROUPINGS:
        raise HTTPException(422, f"by must be one of {', '.join(query.GROUPINGS)}")
    if sort not in query.SORTS:
        raise HTTPException(422, f"sort must be one of {', '.join(query.SORTS)}")
    return query.capture_groups(m, by, q, sort, desc, offset, max(1, min(limit, 500)),
                                max(1, min(per_group, 100)))


@router.get("/stacks", response_model=s.StackPage)
def capture_stacks(q: str = "", sort: str = query.DEFAULT_SORT, desc: bool = False,
                   offset: int = 0, limit: int = query.DEFAULT_LIMIT,
                   per_stack: int = query.PER_STACK, m: WebModel = Depends(model)):
    """The gallery's default: one stack per host:port, its first capture in front."""
    if sort not in query.SORTS:
        raise HTTPException(422, f"sort must be one of {', '.join(query.SORTS)}")
    return query.capture_stacks(m, q, sort, desc, offset, limit, max(1, min(per_stack, 100)))


@router.get("/{capture_id}", response_model=s.CaptureOut,
            responses={404: {"model": s.ErrorOut}})
def get_capture(capture_id: str, m: WebModel = Depends(model)):
    try:
        return query.capture(m, capture_id)
    except query.NotFound as exc:
        raise HTTPException(404, str(exc)) from None
