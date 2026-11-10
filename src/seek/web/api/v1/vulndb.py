"""`/api/v1/vulndb` and `/api/v1/findings` - the database's state, the update
the browser can ask for, and every finding in the model.

Reading is a plain `def` (the threadpool): a lookup may be built on the first
request. Starting and cancelling an update are `async` - they act on the session
on its own loop - and the update itself runs in a thread, as the terminal's
does, so the viewer keeps answering while it downloads. It is only ever started
by an explicit request; nothing here fetches on its own.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request

from seek.nmap import inventory as inv_mod
from seek.nmap.session import Event
from seek.vulndb import match as vmatch
from seek.web import schemas as s
from seek.web.deps import session

router = APIRouter(prefix="/api/v1", tags=["vulndb"])


def _state(sess) -> s.VulndbOut:
    store = sess.vulndb()
    return s.VulndbOut(label=sess.vulndb_label(), missing=store.missing,
                       age_days=store.age_days(), stale=sess.vulndb_stale(),
                       updating=sess.vulndb_updating, progress=sess.vulndb_progress,
                       path=str(store.path))


@router.get("/vulndb", response_model=s.VulndbOut)
def vulndb_state(sess=Depends(session)) -> s.VulndbOut:
    return _state(sess)


@router.post("/vulndb/update", response_model=s.VulndbOut, status_code=202)
async def vulndb_update(request: Request) -> s.VulndbOut:
    """Start the update the user confirmed in the browser. Returns at once;
    `GET /vulndb` follows it, and the session's `vulndb` event ends it."""
    sess = session(request)
    if sess.vulndb_updating:
        raise HTTPException(409, "the vulnerability database is already being updated")

    async def run() -> None:
        try:
            results = await asyncio.to_thread(sess.update_vulndb)
        except Exception as exc:                  # noqa: BLE001 - reported, never raised
            sess.emit(Event("vulndb", "web", text=f"failed: {exc}"))
            return
        text = ", ".join(f"{r.source} {'failed' if r.error else r.records}" for r in results)
        sess.emit(Event("vulndb", "web", text=text))

    task = asyncio.get_running_loop().create_task(run())
    sess._tasks.add(task)
    task.add_done_callback(sess._tasks.discard)
    await asyncio.sleep(0)
    out = _state(sess)
    out.updating = True
    return out


@router.post("/vulndb/cancel", response_model=s.VulndbOut)
async def vulndb_cancel(request: Request) -> s.VulndbOut:
    sess = session(request)
    if not sess.cancel_vulndb():
        raise HTTPException(409, "no update is running")
    return _state(sess)


@router.get("/findings", response_model=list[s.FindingOut])
def findings(sess=Depends(session)) -> list[s.FindingOut]:
    """Every finding on every product version, as the Findings tab lists them."""
    lookup = sess.lookup()
    entries = inv_mod.entries(sess.inventory(), sess.scans.hosts)
    out = []
    for a in vmatch.affected(lookup, entries, sess.scans.hosts):
        f = a.finding
        support = lookup.of_entry(a.entry).support.status if a.entry is not None else None
        out.append(s.FindingOut(
            id=f.id, severity=f.severity or None, score=f.score, summary=f.summary or None,
            url=f.url or None, sources=list(f.sources), tested=f.tested,
            state=f.state or None, likely=f.undecided,
            releases_known=f.known or None, releases_affected=f.covered or None,
            product=a.product or None,
            version=a.version, support=support,
            places=[s.FindingPlace(address=h.address,
                                   protocol=svc.protocol if svc is not None else None,
                                   port=svc.port if svc is not None else None)
                    for h, svc, _c in a.places]))
    return out
