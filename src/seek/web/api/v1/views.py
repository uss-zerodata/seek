"""`/api/v1/views/{tab}` - every overview and drill-down, as the terminal shows it.

`path` is the drill-down, steps joined by `|`; the other parameters are the
current level's filter (`q`, the viewer's grammar), sort (`sort` column index,
`desc`), and the list toggles (`up`, `ports` on the host list, `open` on a
host's own port list).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from seek.web import schemas as s
from seek.web import views
from seek.web.deps import places, session

router = APIRouter(prefix="/api/v1/views", tags=["views"])


def split_path(path: str) -> list[str]:
    return [p for p in path.split(views.SEP) if p] if path else []


@router.get("/{tab}", response_model=s.ViewOut, responses={404: {"model": s.ErrorOut}})
def get_view(tab: str, path: str = "", q: str = "", sort: int | None = None,
             desc: bool = False, up: bool = False, ports: bool = False,
             open: bool = False, offset: int = 0, limit: int = 500,
             sess=Depends(session), cache=Depends(places)):
    try:
        return views.overview(sess, cache, tab, split_path(path), q, sort, desc, up,
                              ports, open, offset, limit)
    except views.Unresolved as exc:
        raise HTTPException(404, str(exc)) from None
