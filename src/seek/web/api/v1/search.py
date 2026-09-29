"""`/api/v1/search` - everything the session knows, found by one query."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from seek.web import schemas as s
from seek.web import search as search_mod
from seek.web.deps import model, places, session

router = APIRouter(prefix="/api/v1", tags=["search"])


@router.get("/search", response_model=s.SearchOut)
def search(q: str = "", limit: int = 8, sess=Depends(session), cache=Depends(places),
           m=Depends(model)):
    """Hosts, services, names and screenshots matching `q`, a few of each."""
    return search_mod.search(sess, m, cache, q, max(1, min(limit, 100)))
