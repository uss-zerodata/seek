"""The command builder and the earlier commands, for the browser.

The same model as the terminal's (`seek.nmap.builder`): the browser sends the
builder's state back on every request as JSON, so the server keeps none, and
the same answers give the same two commands in both front ends. Reading the
model is plain `def` (the threadpool), as every model-reading route is; the
measurement is too, because it blocks for a few seconds.
"""

from __future__ import annotations

import json
from dataclasses import replace

from fastapi import APIRouter, Depends, HTTPException

from seek.nmap import builder as model
from seek.nmap import options, timing
from seek.nmap.options import BY_NAME
from seek.nmap.recent import text
from seek.web import schemas as s
from seek.web.deps import session

router = APIRouter(prefix="/api/v1", tags=["builder"])


def _targets(raw: str) -> list[str]:
    return [t for t in raw.replace(",", " ").split() if t]


def _measured(raw: str) -> tuple[timing.Rtt, ...]:
    try:
        pairs = json.loads(raw or "[]")
        return tuple(timing.Rtt(str(h), float(ms), "measured now") for h, ms in pairs)
    except (ValueError, TypeError):
        return ()


def _move(state: model.State, facts: model.Facts, action: str, value: str) -> model.State:
    if action == "choose":
        return model.advance(state, state.step, value)
    if action == "back":
        return model.back(state)
    if action == "jump":
        return model.jump(state, value)
    if action == "finish" and state.answer("goal"):
        return replace(state, step="choose")
    if action in ("set", "toggle", "reset"):
        name, _, given = value.partition("=")
        if name not in BY_NAME or BY_NAME[name].owner:
            raise HTTPException(422, f"{name or 'an option'} cannot be set here")
        if action == "reset":
            return state.reset(name)
        option = BY_NAME[name]
        if action == "toggle":
            on = name in model.resolve(state, facts, model.RELIABLE).settings
            return state.set(name, None if on else "")
        problem = options.check(option, given)
        if given and problem:
            raise HTTPException(422, f"{name}: {problem}")
        return state.set(name, given or None)
    return state


@router.get("/builder", response_model=s.BuilderOut)
def builder_view(targets: str, state: str = "", measured: str = "", action: str = "",
                 value: str = "", query: str = "", sess=Depends(session)):
    """Where the builder is, what to show, and both commands - after `action`
    (choose, back, jump, finish, set, toggle, reset) when one is given."""
    facts = replace(sess.builder_facts(_targets(targets)), measured=_measured(measured))
    try:
        current = model.State.from_json(state)
    except ValueError:
        raise HTTPException(422, "the builder state is not valid JSON") from None
    if action:
        current = _move(current, facts, action, value)
    step = next(st for st in model.STEPS if st.key == current.step)
    out = s.BuilderOut(
        state=current.to_json(), step=current.step, question=step.question,
        steps=[s.BuilderStepOut(key=st.key, title=st.title, number=i,
                                status=model.status(st.key, current))
               for i, st in enumerate(model.STEPS, 1)],
        commands=[], measured=[[r.host, r.ms] for r in facts.measured])
    if current.step == "tune":
        view = model.tune_view(current, facts, query=query)
        out.groups = [s.BuilderGroupOut(group=group, rows=[
            s.BuilderRowOut(name=r.option.name, about=r.option.about, flag=r.option.flag,
                            hint=r.option.value.hint if r.option.value else "",
                            value=r.setting.value if r.setting else None,
                            on=r.setting is not None,
                            source=r.setting.source if r.setting else "",
                            owner=r.option.owner) for r in rows])
            for group, rows in view.groups]
    elif current.step != "choose":
        chosen = current.answer(current.step)
        out.choices = [s.BuilderChoiceOut(key=c.key, label=c.label, adds=c.adds, gain=c.gain,
                                          cost=c.cost, recommended=c.recommended,
                                          selected=c.key == chosen)
                       for c in model.choices(current.step, current, facts)]
    for built, profile in zip(model.both(current, facts), (model.FAST, model.RELIABLE),
                              strict=True):
        out.commands.append(s.BuilderCommandOut(profile=profile, args=built.args,
                                                text=text(built.args), misses=built.misses,
                                                notes=built.notes))
    return out


@router.get("/builder/help")
def builder_help(name: str):
    if name not in BY_NAME:
        raise HTTPException(404, f"no option {name}")
    return {"name": name, "lines": model.help_text(name)}


@router.post("/builder/measure", response_model=s.BuilderMeasureOut)
def builder_measure(body: s.BuilderMeasureIn, sess=Depends(session)):
    """Sends packets - so only with `confirmed: true`, which the dialog sets
    after saying what will be sent."""
    if not body.confirmed:
        raise HTTPException(422, "a measurement sends packets: confirm it first")
    facts = sess.builder_facts(body.targets)
    ports = [int(p) for p in facts.tcp_ports.split(",") if p.isdigit()]
    up = [t for t in facts.targets if t in facts.up] or list(facts.targets)
    if ports:
        pairs = [(host, ports[0]) for host in up[:timing.HOSTS]]
        rtts = timing.measure_connect(pairs)
        what = f"{timing.TRIES} TCP connections each to {len(pairs)} host(s), port {ports[0]}"
    elif sess.nmap.available:
        rtts = timing.measure_ping(sess.config.nmap_path, up[:timing.HOSTS])
        what = f"one nmap ping scan of {min(len(up), timing.HOSTS)} host(s)"
    else:
        raise HTTPException(409, "nothing to measure with: no known open port and no nmap")
    note = (timing.derive(rtts, model.RELIABLE, len(facts.targets)).note if rtts
            else "no host answered - defaults apply")
    return s.BuilderMeasureOut(what=what, measured=[[r.host, r.ms] for r in rtts], note=note)


@router.get("/scans/recent", response_model=s.EarlierListsOut)
def earlier_commands(sess=Depends(session)):
    recent, frequent = sess.earlier_commands()
    convert = lambda items: [s.EarlierOut(args=e.args, where=e.where, last=e.last,  # noqa: E731
                                          count=e.count) for e in items]
    return s.EarlierListsOut(recent=convert(recent), frequent=convert(frequent))
