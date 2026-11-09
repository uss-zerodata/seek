"""Stopping the web interface from the browser.

What Stop means is the server's to say (`WebServer.on_stop`): in the viewer it
stops this interface and the terminal carries on; for `seek nmap serve` it ends
the process as Ctrl+C does. A change, so the same-origin rule applies.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/api/v1", tags=["web"])


@router.get("/web")
def web_state(request: Request) -> dict:
    """Which kind of server this is, so the confirmation can say what Stop ends."""
    return {"mode": request.app.state.mode,
            "stoppable": request.app.state.on_stop is not None}


@router.post("/web/stop")
async def stop_web(request: Request) -> dict:
    on_stop = request.app.state.on_stop
    if on_stop is None:
        raise HTTPException(409, "this interface cannot be stopped from here")
    # Answered first, stopped a moment later: the reply has to be written
    # before the server begins to close.
    asyncio.get_running_loop().call_later(0.1, on_stop)
    return {"stopping": True,
            "ends": "process" if request.app.state.mode == "serve" else "web"}
