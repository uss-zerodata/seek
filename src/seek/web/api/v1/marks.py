"""`/api/v1/marks` and `/api/v1/export` - the session's marks, and exporting.

Marks are the session's: a mark made here is a mark in the terminal and the
other way round. An export takes the marks when there are any, else the rows
the view's filter leaves - the terminal's rule - and produces exactly the text
the terminal would, through the same `export.produce`.

Changing endpoints are `async` so they change the session on its own loop;
finding the row is a model walk, so it happens in the threadpool first.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from starlette.concurrency import run_in_threadpool

from seek.nmap import export as exporter
from seek.web import schemas as s
from seek.web import views
from seek.web.api.v1.views import split_path
from seek.web.deps import places, session

router = APIRouter(prefix="/api/v1", tags=["marks"])


def _marks(sess, marked: bool | None = None) -> s.MarksOut:
    out = []
    for record in sess.marks.values():
        svc = record.service
        out.append(s.MarkOut(
            address=record.host.address,
            protocol=svc.protocol if svc else None, port=svc.port if svc else None,
            label=f"{record.host.address} {svc.port}/{svc.protocol}" if svc
            else record.host.address))
    return s.MarksOut(count=len(out), marked=marked, marks=out)


def _row_records(sess, cache, ref: s.RowRef):
    place = cache.resolve(sess, ref.tab, split_path(ref.path))
    row = next((r for r in place.view.rows(sess.scans)
                if not r.heading and views.step_of(r) == ref.step), None)
    if row is None:
        raise views.Unresolved(f"nothing called {ref.step} in {place.view.title}")
    return row.records


@router.get("/marks", response_model=s.MarksOut)
def list_marks(sess=Depends(session)):
    return _marks(sess)


@router.post("/marks", response_model=s.MarksOut, responses={404: {"model": s.ErrorOut}})
async def toggle_mark(ref: s.RowRef, request: Request):
    """Mark the row's records - or unmark them when every one is marked."""
    sess, cache = session(request), places(request)
    try:
        records = await run_in_threadpool(_row_records, sess, cache, ref)
    except views.Unresolved as exc:
        raise HTTPException(404, str(exc)) from None
    if not records:
        raise HTTPException(422, f"{ref.step} stands for nothing that can be marked")
    return _marks(sess, sess.toggle(records, origin="web"))


@router.delete("/marks", response_model=s.MarksOut)
async def clear_marks(request: Request):
    sess = session(request)
    sess.clear_marks(origin="web")
    return _marks(sess)


def _source(sess, cache, tab: str, path: str, q: str):
    """Marks when there are any, else what the view's filter leaves."""
    if sess.marks:
        records = list(sess.marks.values())
        return records, f"{len(records)} marked record(s)"
    if not tab:
        return [], "nothing"
    place = cache.resolve(sess, tab, split_path(path))
    shown = views.listing(sess, place.view, q)
    out: dict[tuple, exporter.Record] = {}
    for row in shown.rows:
        for record in row.records:
            out.setdefault(record.identity, record)
    return list(out.values()), f"the {len(out)} record(s) listed"


@router.get("/export/options", response_model=s.ExportOptions)
def export_options(tab: str = "", path: str = "", q: str = "",
                   sess=Depends(session), cache=Depends(places)):
    records, source = _source(sess, cache, tab, path, q)
    return s.ExportOptions(
        source=source, count=len(records),
        recipes=[s.Choice(key=k, label=label) for k, (label, _, _) in exporter.EXPORTS.items()]
        + [s.Choice(key="custom", label="custom… (pick the fields)")],
        fields=list(exporter.FIELD_NAMES),
        formats=[s.Choice(key=k, label=label) for k, (label, _) in exporter.FORMATS.items()],
        fixed_format=[k for k, (_, _, column) in exporter.EXPORTS.items() if column is None],
        # Shown disabled with the reason rather than hidden: a feature that
        # vanishes when its tool is missing teaches nothing about why.
        capture="" if sess.gowitness.available else sess.gowitness.reason,
        scan="" if sess.nmap.available else sess.nmap.reason)


@router.get("/export", response_class=PlainTextResponse)
def export(which: str, fmt: str = "text", fields: list[str] = Query(default=[]),
           tab: str = "", path: str = "", q: str = "", download: bool = False,
           sess=Depends(session), cache=Depends(places)):
    if which != "custom" and which not in exporter.EXPORTS:
        raise HTTPException(422, f"no export {which}")
    if fmt not in exporter.FORMATS:
        raise HTTPException(422, f"no format {fmt}")
    records, _source_label = _source(sess, cache, tab, path, q)
    if not records:
        raise HTTPException(422, "nothing to export")
    text, used = exporter.produce(records, which, fmt, fields)
    headers = {}
    if download:
        headers["Content-Disposition"] = (
            f'attachment; filename="export-{which}{exporter.FORMATS[used][1]}"')
    return PlainTextResponse(text + "\n", headers=headers)
