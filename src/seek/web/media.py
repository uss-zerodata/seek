"""Screenshots, addressed by capture - never by path.

There is no route here that takes a path, so a traversal has nothing to act
on: an id either names a capture in the model or it does not, and the file sent
is the one that capture refers to.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from seek.web.deps import model
from seek.web.source import WebModel

router = APIRouter(prefix="/media", tags=["media"])

_TYPES = {".jpeg": "image/jpeg", ".jpg": "image/jpeg", ".png": "image/png",
          ".webp": "image/webp"}


@router.get("/shot/{capture_id}")
def shot(capture_id: str, m: WebModel = Depends(model)):
    placed = m.by_id.get(capture_id)
    path = placed.capture.shot if placed is not None else None
    if path is None or not path.is_file():
        raise HTTPException(404, f"no screenshot for {capture_id}")
    return FileResponse(path, media_type=_TYPES.get(path.suffix.lower(), "image/jpeg"))
