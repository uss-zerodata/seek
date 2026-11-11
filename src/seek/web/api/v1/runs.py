"""Runs: listing, logs, cancelling, starting scans and captures, and events.

Starting and cancelling are `async` - they act on the session on its loop, the
same calls the terminal's own dialogs end in (`Session.draft_command`,
`plan_scan`, `start_scan`, `plan_capture`, `start_capture`, `cancel`). What
reaches a browser is exactly what the terminal would run.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from seek import notify
from seek.gowitness.capture import CaptureRun
from seek.nmap import presets as presets_mod
from seek.nmap.runner import elevation_help, sudo_ready
from seek.nmap.session import Busy, Event, ScanError
from seek.runner import Run
from seek.web import schemas as s
from seek.web.api.v1.marks import _source
from seek.web.deps import places, session

router = APIRouter(prefix="/api/v1", tags=["runs"])

_PING_SECONDS = 15.0


def run_id(run: Run) -> str:
    return f"{id(run):x}"


def run_out(run: Run) -> s.RunOut:
    return s.RunOut(id=run_id(run),
                    tool="gowitness" if isinstance(run, CaptureRun) else "nmap",
                    label=run.label, scope=getattr(run, "scope", ""),
                    state=run.state.value if hasattr(run.state, "value") else str(run.state),
                    running=run.running, elapsed=run.elapsed, result=run.result,
                    lines=len(run.log) + run.dropped)


def _runs(sess) -> list[Run]:
    return [*sess.runner.runs, *sess.captures.runs]


def _find(sess, rid: str) -> Run:
    run = next((r for r in _runs(sess) if run_id(r) == rid), None)
    if run is None:
        raise HTTPException(404, f"no run {rid}")
    return run


@router.get("/runs", response_model=list[s.RunOut])
def list_runs(sess=Depends(session)) -> list[s.RunOut]:
    return [run_out(r) for r in _runs(sess)]


@router.get("/runs/{rid}/log", response_model=s.LogOut)
def run_log(rid: str, since: int = 0, sess=Depends(session)) -> s.LogOut:
    """The log from line `since` on - counted over the whole run, so a client
    that fell behind the bounded log is told where it resumes."""
    run = _find(sess, rid)
    first = run.dropped
    lines = list(run.log)
    start = max(since, first)
    return s.LogOut(run=run_out(run), since=start, lines=lines[start - first:])


@router.post("/runs/{which}/cancel", response_model=s.RunOut | None)
async def cancel(which: str, request: Request) -> s.RunOut | None:
    """`which` is a tool - its one running run - or a run's id."""
    sess = session(request)
    if which in ("nmap", "gowitness"):
        tool, run = which, None
        if len((sess.runner if tool == "nmap" else sess.captures).active()) > 1:
            raise HTTPException(409, f"several {tool} runs are running - name one by its id")
    else:
        run = _find(sess, which)
        tool = "nmap" if any(r is run for r in sess.runner.runs) else "gowitness"
    cancelled = sess.cancel(tool, run)
    if cancelled is None:
        raise HTTPException(409, f"no {tool} run to cancel" if run is None
                            else f"{run.label} is not running")
    return run_out(cancelled)


# --- scans ---------------------------------------------------------------------------


@router.get("/scans/presets", response_model=list[s.PresetOut])
def scan_presets(sess=Depends(session)) -> list[s.PresetOut]:
    # Listed without nmap too: a plan can be copied to a machine that has it.
    return [s.PresetOut(name=name, args=args,
                        needs_root=presets_mod.needs_root(args.split()))
            for name, args in sess.config.nmap_presets.items()]


def _plan(sess, body: s.ScanPlanIn):
    """The review, and the plan behind it - `None` when the command is refused."""
    if body.preset == presets_mod.VERSION_GAPS_PRESET:
        # Drafted from a view by `/scans/gaps`, not from a preset and a scope:
        # what comes back is the command that draft produced, maybe edited.
        if not body.command:
            raise ScanError("the unversioned-ports scan is drafted by /scans/gaps")
        command, note = body.command, ""
        out_base = presets_mod.output_base(sess.scan_dir, body.preset)
    elif body.args is not None:
        command, note, out_base = sess.draft_args(body.preset, body.args, body.targets)
    else:
        command, note, out_base = sess.draft_command(body.preset, body.targets)
    out = s.ScanPlanOut(preset=body.preset, command=body.command or command, note=note)
    try:
        plan = sess.plan_scan(body.preset, out.command, out_base)
    except presets_mod.CommandError as exc:
        out.error = str(exc)
        return out, None
    out.argv, out.targets = plan.argv, plan.targets
    out.out_base, out.elevated, out.privilege = str(plan.out_base), plan.elevated, plan.privilege
    out.via = plan.via
    out.notify_url, out.notify_progress = plan.notify_url, plan.notify_progress
    out.blocked = plan.blocked or ""
    out.warning = plan.warning or ""
    out.copy_local, out.copy_remote = plan.copy_local, plan.copy_remote
    return out, plan


@router.post("/scans/review", response_model=s.ScanPlanOut)
async def review(body: s.ScanPlanIn, request: Request) -> s.ScanPlanOut:
    """What this preset and command would run, exactly, or why it would not."""
    try:
        out, _plan_ = await run_in_threadpool(_plan, session(request), body)
    except ScanError as exc:
        raise HTTPException(409, str(exc)) from None
    return out


@router.post("/scans/gaps", response_model=s.ScanPlanOut)
async def gaps(body: s.CaptureIn, request: Request) -> s.ScanPlanOut:
    """The terminal's `U`: version the open ports the inventory has no version
    for, among the marks or the listed rows. A draft to review, never a run."""
    sess, cache = session(request), places(request)

    def draft() -> s.ScanPlanOut:
        records, _label = _source(sess, cache, body.tab, body.path, body.q)
        command, note, _out, targets = sess.draft_version_gaps(records)
        out, _ = _plan(sess, s.ScanPlanIn(preset=presets_mod.VERSION_GAPS_PRESET,
                                          targets=targets, command=command))
        out.note = note
        return out

    try:
        return await run_in_threadpool(draft)
    except ScanError as exc:
        raise HTTPException(409, str(exc)) from None


@router.post("/scans", response_model=s.RunOut)
async def start_scan(body: s.ScanPlanIn, request: Request) -> s.RunOut:
    """Run what the review showed: the same checks, the same argv."""
    sess = session(request)
    try:
        out, plan = await run_in_threadpool(_plan, sess, body)
    except ScanError as exc:
        raise HTTPException(409, str(exc)) from None
    if plan is None:
        raise HTTPException(422, out.error)
    if plan.blocked:
        raise HTTPException(409, plan.blocked)
    run = plan.run()
    _notify_choice(run, body)
    if run.elevated:
        # Nothing here can let sudo ask, so a scan it would not run is refused
        # before it starts rather than failing once it has.
        problem = await sudo_ready(run.argv)
        if problem is not None:
            raise HTTPException(409, f"{problem}. {elevation_help(sess.config.nmap_path)}")
    try:
        sess.start_scan(run, origin="web")
    except (ScanError, Busy) as exc:
        raise HTTPException(409, str(exc)) from None
    return run_out(run)


# --- captures ------------------------------------------------------------------------


def _capture_out(run) -> s.CapturePlanOut:
    return s.CapturePlanOut(argv=run.argv, urls=run.urls, where=str(run.paths.root),
                            backend=run.backend, blocked=run.blocked or "",
                            copy_local=run.copy_local, copy_remote=run.copy_remote,
                            notify_url=run.notify_url, notify_progress=run.notify_progress)


def _notify_choice(run, body) -> None:
    """Apply the review's notification choice to a run; 422 for a bad URL."""
    try:
        if body.notify_url is not None:
            run.notify_url = notify.normalise(body.notify_url)
    except notify.NotifyError as exc:
        raise HTTPException(422, f"notification URL: {exc}") from None
    if body.notify_progress is not None:
        run.notify_progress = body.notify_progress


@router.post("/captures/review", response_model=s.CapturePlanOut)
async def capture_review(body: s.CaptureIn, request: Request) -> s.CapturePlanOut:
    """What a capture of the marks - or the listed rows - would run. Nothing
    is written; the review may only be copied."""
    sess, cache = session(request), places(request)
    records, _label = await run_in_threadpool(_source, sess, cache, body.tab, body.path, body.q)
    try:
        run = await run_in_threadpool(sess.plan_capture, records)
    except ScanError as exc:
        raise HTTPException(409, str(exc)) from None
    return _capture_out(run)


@router.post("/captures/runs", response_model=s.RunOut)
async def start_capture(body: s.CaptureIn, request: Request) -> s.RunOut:
    """Capture the marks' URLs - or the listed rows' when nothing is marked."""
    sess, cache = session(request), places(request)
    records, _label = await run_in_threadpool(_source, sess, cache, body.tab, body.path, body.q)
    try:
        run = await run_in_threadpool(sess.plan_capture, records)
        if run.blocked:
            raise ScanError(run.blocked)
        _notify_choice(run, body)
        sess.start_capture(run, origin="web")
    except (ScanError, Busy) as exc:
        raise HTTPException(409, str(exc)) from None
    return run_out(run)


# --- events ----------------------------------------------------------------------------


def _event_json(event: Event) -> str:
    body: dict = {"type": event.type, "origin": event.origin}
    if event.run is not None:
        body["run"] = run_out(event.run).model_dump()
    if event.type in ("line", "tags"):
        body["text"] = event.text
    return json.dumps(body)


@router.get("/events")
async def events(request: Request) -> StreamingResponse:
    """Server-Sent Events: runs, their lines, a new model, changed marks."""
    sess = session(request)
    sub, stop = sess.subscribe()

    closing: asyncio.Event = request.app.state.closing

    async def stream() -> AsyncIterator[str]:
        try:
            yield "retry: 2000\n\n"
            while True:
                if closing.is_set():
                    # The interface is stopping: say so, and end - the server
                    # does not wait for a stream that would never end itself.
                    yield "event: closing\ndata: {}\n\n"
                    return
                if await request.is_disconnected():
                    return
                get = asyncio.ensure_future(sub.queue.get())
                wake = asyncio.ensure_future(closing.wait())
                done, pending = await asyncio.wait({get, wake}, timeout=_PING_SECONDS,
                                                   return_when=asyncio.FIRST_COMPLETED)
                for waiting in pending:
                    waiting.cancel()
                if get in done:
                    event = get.result()
                    yield f"event: {event.type}\ndata: {_event_json(event)}\n\n"
                elif not closing.is_set():
                    yield ": ping\n\n"
        finally:
            stop()

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store"})
