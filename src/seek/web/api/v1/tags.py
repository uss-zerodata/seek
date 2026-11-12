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
from seek.web.api.v1.marks import _row_records, _source
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
#
# Stateless: every request carries its draft. The counting is the session's kept
# builder (`Session.bench_builder`), so a draft costs here what it costs in the
# terminal.

# The rows in view a rule is built from, at most - as in the terminal.
VIEW_LIMIT = 2000


def _fact_out(f: tb.Fact) -> s.FactIO:
    return s.FactIO(kind=f.kind.value, protocol=f.protocol,
                    ports=tr.format_ports(f.ports) if f.ports else "", value=f.value,
                    mode=f.mode.value, case=f.case, label=f.label, group=f.group)


def _fact_in(f: s.FactIO) -> tb.Fact:
    try:
        return tb.fact_from(f.kind, protocol=f.protocol, ports=f.ports, value=f.value,
                            mode=f.mode, case=f.case)
    except tr.RuleError as exc:
        raise HTTPException(422, str(exc)) from None
    except ValueError:
        raise HTTPException(422, f"no fact kind {f.kind!r} or mode {f.mode!r}") from None


def _limit_in(limit: list[str] | None) -> frozenset[tuple[str, int]] | None:
    if limit is None:
        return None
    out = set()
    for item in limit:
        proto, _, port = item.partition("/")
        if not port.isdigit() or proto not in tr.PROTOCOLS:
            raise HTTPException(422, f"{item!r} is not a limit such as tcp/80")
        out.add((proto, int(port)))
    return frozenset(out)


def _draft_in(d: s.DraftIO) -> tb.Draft:
    facts = []
    for item in d.facts:
        try:
            state = tb.State(item.state)
        except ValueError:
            raise HTTPException(422, f"no fact state {item.state!r}") from None
        facts.append((_fact_in(item.fact), state))
    return tb.Draft(tuple(d.selection), tuple(facts), d.same_port)


def _draft_out(d: tb.Draft, limit) -> s.DraftIO:
    return s.DraftIO(selection=list(d.selection),
                     facts=[s.DraftFactIO(fact=_fact_out(f), state=st.value)
                            for f, st in d.facts],
                     same_port=d.same_port,
                     limit=sorted(f"{p}/{n}" for p, n in limit) if limit is not None else None)


def _proposal(p: tb.Proposal) -> s.ProposalOut:
    return s.ProposalOut(fact=_fact_out(p.fact), selected=p.selected, others=p.others,
                         excludes=p.excludes, assumed_on=list(p.assumed_on))


def _match_out(m: tb.Match) -> s.MatchOut:
    return s.MatchOut(address=m.address, ports=m.ports, title=m.title, matched=m.matched,
                      assumed=m.assumed)


def _assess_out(a: tb.Assessment) -> s.AssessOut:
    combo = (s.CombinationOut(facts=[_fact_out(f) for f in a.combination.facts],
                              excludes=a.combination.excludes,
                              remaining=a.combination.remaining)
             if a.combination else None)
    return s.AssessOut(
        of_selection=a.of_selection,
        rows=[s.FactRowOut(fact=_fact_out(r.fact), state=r.state.value, selected=r.selected,
                           others=r.others) for r in a.rows],
        selection=[_match_out(m) for m in a.selection],
        others=[_match_out(m) for m in a.others], matched=a.matched,
        selected_matched=a.selected_matched, other_count=a.other_count,
        assumed=list(a.assumed), exclusions=[_proposal(p) for p in a.exclusions],
        combination=combo, rule=list(a.rule), notes=list(a.notes), confirm=a.confirm)


def _bench(sess, d: s.DraftIO) -> tuple[tb.Builder, tb.Draft]:
    return sess.bench_builder(_limit_in(d.limit)), _draft_in(d)


@router.post("/builder", response_model=s.BenchOut,
             responses={404: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}})
def start_builder(body: s.BenchIn, sess=Depends(session),
                  cache=Depends(places)) -> s.BenchOut:
    """The builder's first draft: the marks, the named rows, or the rows in view."""
    try:
        if not body.rows and not sess.marks and body.view is not None:
            records, _label = _source(sess, cache, body.view.tab, body.view.path,
                                      body.view.q)
            records = records[:VIEW_LIMIT]
        else:
            records = _records(sess, cache, body.rows)
    except views.Unresolved as exc:
        raise HTTPException(404, str(exc)) from None
    if not records:
        raise HTTPException(422, "nothing selected - mark the hosts a rule should find")
    started = sess.rule_builder(records)
    b = sess.bench_builder(started.limit)
    draft = tb.Draft(started.initial)
    a = tb.assess(b, draft)
    out = _assess_out(a)
    out.notes = [*started.notes, *out.notes]
    return s.BenchOut(draft=_draft_out(draft, started.limit), assessment=out)


@router.post("/builder/assess", response_model=s.AssessOut,
             responses={422: {"model": s.ErrorOut}})
def assess(body: s.AssessIn, sess=Depends(session)) -> s.AssessOut:
    b, draft = _bench(sess, body.draft)
    return _assess_out(tb.assess(b, draft))


@router.post("/builder/refine", response_model=s.RefineOut,
             responses={422: {"model": s.ErrorOut}})
def refine(body: s.RefineIn, sess=Depends(session)) -> s.RefineOut:
    b, draft = _bench(sess, body.draft)
    fact = _fact_in(body.fact)
    got = tb.refine(b, draft, fact)
    return s.RefineOut(fact=_fact_out(fact), selected=got.selected,
                       of_selection=got.of_selection, others=got.others,
                       dropped=list(got.dropped))


@router.get("/{name}/rules", response_model=s.RulesOut)
def list_rules(name: str, sess=Depends(session)) -> s.RulesOut:
    out = []
    for k, rule in enumerate(sess.rules_of(name)):
        opened = tb.from_rule(rule)
        out.append(s.RuleRefOut(index=k, name=rule.name, source=str(rule.source),
                                editable=not isinstance(opened, str),
                                reason=opened if isinstance(opened, str) else ""))
    return s.RulesOut(rules=out)


def _rule_at(sess, name: str, index: int):
    rules = sess.rules_of(name)
    if not 0 <= index < len(rules):
        raise HTTPException(404, f"{name} has no rule {index}")
    return rules[index]


@router.post("/{name}/rules/{index}/open", response_model=s.BenchOut,
             responses={404: {"model": s.ErrorOut}, 422: {"model": s.ErrorOut}})
def open_rule(name: str, index: int, sess=Depends(session)) -> s.BenchOut:
    rule = _rule_at(sess, name, index)
    opened = sess.open_rule(rule)
    if isinstance(opened, str):
        raise HTTPException(422, opened)
    started, draft = opened
    b = sess.bench_builder(None)
    out = _assess_out(tb.assess(b, draft))
    out.notes = [*started.notes, *out.notes]
    return s.BenchOut(draft=_draft_out(draft, None), assessment=out, rule_name=rule.name,
                      grant=rule.grant.value, replaces=dict(rule.raw))


def _grant(text: str) -> tr.Grant:
    try:
        return tr.Grant(text)
    except ValueError:
        raise HTTPException(422, f"grant {text!r} is not host, service or both") from None


def _rule_raw(body: s.RuleIn) -> dict:
    draft = _draft_in(body.draft)
    if not tb.draft_when(draft):
        raise HTTPException(422, "a rule needs at least one required or excluded fact")
    if not body.rule_name.strip():
        raise HTTPException(422, "give the rule a name")
    return tb.draft_rule(draft, body.rule_name.strip(), _grant(body.grant))


@router.post("/{name}/rules", response_model=s.TagChangeOut,
             responses={422: {"model": s.ErrorOut}})
async def save_rule(name: str, body: s.RuleIn, request: Request) -> s.TagChangeOut:
    sess = session(request)
    raw = _rule_raw(body)
    try:
        change = sess.plan_rule(name, raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _change_out(await sess.apply_tag_change(change, origin="web"), change.summary)


@router.put("/{name}/rules/{index}", response_model=s.TagChangeOut,
            responses={404: {"model": s.ErrorOut}, 409: {"model": s.ErrorOut},
                       422: {"model": s.ErrorOut}})
async def replace_rule(name: str, index: int, body: s.RuleReplaceIn,
                       request: Request) -> s.TagChangeOut:
    """Replace the rule the builder opened - refused when it is no longer the rule
    that was opened."""
    sess = session(request)
    raw = _rule_raw(body)
    rule = _rule_at(sess, name, index)
    if dict(rule.raw) != body.replaces:
        raise HTTPException(409, "the rule changed - reload and open it again")
    try:
        change = sess.plan_rule_replace(rule, raw)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    return _change_out(await sess.apply_tag_change(change, origin="web"), change.summary)
