"""`/api/v1/tags` - tags, manual tagging, definitions, and the rule builder.

The session's tags, exactly as the terminal shows them. Reading routes, and the
builder's proposals (a model walk, no change), are plain functions in the
threadpool; routes that write a tag file are `async`, find their rows in the
threadpool and change the session on its own loop, as the marks do. Every
changing request passes the interface's origin check (`web/app.py`).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from seek.nmap import tagbuild as tb
from seek.nmap import tagrules as tr
from seek.web import schemas as s
from seek.web import views
from seek.web.api.v1.marks import _row_records
from seek.web.deps import places, session

router = APIRouter(prefix="/api/v1/tags", tags=["tags"])


def _records(sess, cache, rows: list[s.RowRef]) -> list:
    """The rows' records, or the marks when no row is named - the terminal's rule."""
    if not rows:
        return list(sess.marks.values())
    out: dict[tuple, object] = {}
    for ref in rows:
        for record in _row_records(sess, cache, ref):
            out.setdefault(record.identity, record)
    return list(out.values())


def _change_out(result, summary: str) -> s.TagChangeOut:
    return s.TagChangeOut(saved=[str(p) for p in result.saved], errors=list(result.errors),
                          summary=summary if result.ok else "")


@router.get("", response_model=s.TagsOut)
def list_tags(sess=Depends(session)) -> s.TagsOut:
    tags = sess.tags()
    loaded = sess.tag_files
    out = []
    for name in tags.tag_names:
        d = tags.defs.get(name)
        count = tags.counts.get(name)
        out.append(s.TagOut(
            name=name, description=d.description if d else "",
            issues=[s.IssueIn(title=i.title, severity=i.severity.value,
                              description=i.description, references=list(i.references))
                    for i in (d.issues if d else ())],
            sources=[str(src) for src in (d.sources if d else ())],
            hosts=count.hosts if count else 0, services=count.services if count else 0,
            uncertain=count.uncertain if count else 0, notes=list(tags.notes.get(name, ()))))
    return s.TagsOut(
        ready=True, tags=out,
        problems=[s.ProblemOut(level=p.level.value, message=p.message,
                               where=str(p.source) if p.source else "", tag=p.tag)
                  for p in tags.problems],
        unmatched_entries=tags.unmatched_entries,
        files=[str(f.path) for f in loaded.files] if loaded else [],
        home=str(sess.tag_home) if sess.tag_home else None)


@router.post("/entries", response_model=s.TagChangeOut,
             responses={404: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}})
async def tag_rows(body: s.TagEntriesIn, request: Request) -> s.TagChangeOut:
    sess, cache = session(request), places(request)
    try:
        records = await run_in_threadpool(_records, sess, cache, body.rows)
        change = sess.plan_tag(records, body.tag, body.add)
    except views.Unresolved as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _change_out(await sess.apply_tag_change(change, origin="web"), change.summary)


def _issues(items: list[s.IssueIn]) -> list[tr.Issue]:
    out = []
    for i in items:
        if i.severity.lower() not in {v.value for v in tr.Severity}:
            raise ValueError(f"severity {i.severity!r} is not one of "
                             f"{', '.join(v.value for v in tr.Severity)}")
        if not i.title.strip():
            raise ValueError("an issue needs a title")
        out.append(tr.Issue(i.title.strip(), tr.Severity(i.severity.lower()),
                            i.description.strip(), tuple(i.references)))
    return out


@router.put("/{name}", response_model=s.TagChangeOut, responses={422: {"model": s.ErrorOut}})
async def set_definition(name: str, body: s.DefinitionIn, request: Request) -> s.TagChangeOut:
    sess = session(request)
    try:
        change = sess.plan_definition(name, body.description.strip(), _issues(body.issues))
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _change_out(await sess.apply_tag_change(change, origin="web"), change.summary)


@router.post("/{name}/global", response_model=s.TagChangeOut,
             responses={422: {"model": s.ErrorOut}})
async def copy_global(name: str, request: Request) -> s.TagChangeOut:
    sess = session(request)
    try:
        change = await run_in_threadpool(sess.plan_copy_global, name)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _change_out(await sess.apply_tag_change(change, origin="web"), change.summary)


@router.post("/reload", response_model=s.TagsOut)
async def reload_tags(request: Request) -> s.TagsOut:
    sess = session(request)
    await sess.reload_tags(origin="web")
    return await run_in_threadpool(list_tags, sess)


# --- the rule builder ----------------------------------------------------------


def _fact_out(f: tb.Fact) -> s.FactIO:
    return s.FactIO(kind=f.kind.value, protocol=f.protocol, port=f.port, value=f.value,
                    partial=f.partial, label=f.label)


def _fact_in(f: s.FactIO) -> tb.Fact:
    try:
        return tb.Fact(tb.Kind(f.kind), f.protocol, f.port, f.value, f.partial)
    except ValueError:
        raise HTTPException(422, f"no fact kind {f.kind!r}") from None


def _proposal(p: tb.Proposal) -> s.ProposalOut:
    return s.ProposalOut(fact=_fact_out(p.fact), selected=p.selected, others=p.others,
                         excludes=p.excludes, assumed_on=list(p.assumed_on))


def _builder(sess, cache, rows):
    try:
        records = _records(sess, cache, rows)
    except views.Unresolved as exc:
        raise HTTPException(404, str(exc)) from None
    if not records:
        raise HTTPException(422, "nothing selected - mark the hosts a rule should find")
    return sess.rule_builder(records)


@router.post("/builder", response_model=s.SharedOut,
             responses={404: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}})
def propose(body: s.BuilderIn, sess=Depends(session), cache=Depends(places)) -> s.SharedOut:
    shared = tb.shared(_builder(sess, cache, body.rows))
    return s.SharedOut(selected=list(shared.selected),
                       facts=[_proposal(p) for p in shared.facts],
                       partial=[_proposal(p) for p in shared.partial], notes=list(shared.notes))


@router.post("/builder/exclusions", response_model=s.ExclusionsOut,
             responses={404: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}})
def exclusions(body: s.BuilderIn, sess=Depends(session),
               cache=Depends(places)) -> s.ExclusionsOut:
    ex = tb.exclusions(_builder(sess, cache, body.rows), [_fact_in(f) for f in body.positive])
    combo = (s.CombinationOut(facts=[_fact_out(f) for f in ex.combination.facts],
                              excludes=ex.combination.excludes,
                              remaining=ex.combination.remaining)
             if ex.combination else None)
    return s.ExclusionsOut(matched=ex.matched, unwanted=ex.unwanted,
                           single=[_proposal(p) for p in ex.single], combination=combo,
                           notes=list(ex.notes))


@router.post("/builder/preview", response_model=s.PreviewOut,
             responses={404: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}})
def preview(body: s.BuilderIn, sess=Depends(session), cache=Depends(places)) -> s.PreviewOut:
    shown = tb.preview(_builder(sess, cache, body.rows), [_fact_in(f) for f in body.positive],
                       [_fact_in(f) for f in body.negative])
    return s.PreviewOut(matched=list(shown.matched), selected=shown.selected,
                        assumed=list(shown.assumed), of_selection=shown.of_selection,
                        confirm=shown.confirm)


@router.post("/{name}/rules", response_model=s.TagChangeOut,
             responses={422: {"model": s.ErrorOut}})
async def save_rule(name: str, body: s.RuleIn, request: Request) -> s.TagChangeOut:
    sess = session(request)
    if not body.positive:
        raise HTTPException(422, "a rule needs at least one fact")
    try:
        grant = tr.Grant(body.grant)
    except ValueError:
        raise HTTPException(422, f"grant {body.grant!r} is not host, service or both") from None
    count = len(body.rows) or len(sess.marks)
    raw = tb.draft(f"built from {count} row(s)", [_fact_in(f) for f in body.positive],
                   [_fact_in(f) for f in body.negative], grant)
    try:
        change = sess.plan_rule(name, raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _change_out(await sess.apply_tag_change(change, origin="web"), change.summary)
