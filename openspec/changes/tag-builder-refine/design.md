# Design

## Context

The rule builder lives in `nmap/tagbuild.py`, and its terminal flow in
`tui/nmap/tagflows.py`. The flow is three modal screens in a row, with no state
shared between them.

The parts this design builds on:
- **Facts.** `tagbuild.Fact(kind, protocol, port, value, partial)` turns into
  seek's rule form through `Fact.condition()`.
- **Counting.** Every count goes through `tagging.evaluate` over a prepared
  index, so the counts and the saved rule cannot differ.
- **Ports in rules.** `PortClause.port` is an `int` or `None`.
- **Text tests.** `TextMatch` supports `regex` and `literal`. A literal searches
  anywhere in the value.
- **Saving.** Rules are written by `tagfiles` operations. Each operation is
  applied to the file as it is on disk, under a lock, and is planned by
  `Session.plan_*`.
- **The browser.** It posts facts as `FactIO` to `/api/v1/tags/builder*`.

The motivation is in proposal.md, and the behaviour is in the specs.

## Goals / Non-Goals

**Goals:**
- One draft model in the core, `Draft`, assessed by one pure function. Both
  front ends only render and change it, as ARC-4 requires.
- Every change shows its effect in under 0.3 s at 24 200 hosts, without
  blocking the viewer.
- Rule files stay readable, with `equals:` rather than escaped anchored
  expressions.

**Non-Goals:**
- Changing the field of a fact, for example product to title, or entering a
  condition the builder did not propose. Those are written in the file, and `R`
  reloads it.
- Script, host-script, hostname and network facts in proposals. When an edited
  rule holds them, they are kept read-only (D8).
- Undo after a save. The saved rule can be opened again and changed, or
  removed in the file.
- Opening the builder from the Tags block of a record. The tag menu is the one
  way in for now.

## Decisions

**D1. `equals` is a third kind of text test.**
`text_match` accepts `{equals: v}`, which compiles to `\A(?:re.escape(v))\Z`
with `IGNORECASE` unless `case: true`. `TextMatch` gets `kind: regex|literal|equals`,
replacing the `literal: bool`, with a property kept for readers. Exactly one of
`regex`, `literal` and `equals` is allowed. The canonical and written form is
`{equals: v}`, or `{equals: v, case: true}`.
*Alternative:* an escaped anchored regex. Rejected because it is unreadable in
a rule file.

**D2. A port list is a normalised tuple of ranges on `PortClause`.**
`port: int | None` becomes `ports: tuple[tuple[int, int], ...] | None`: sorted,
merged, with `None` for any port. The parser accepts the following forms:
- an int;
- a YAML list of ints or strings;
- text such as `"80,443,8000-8999/tcp"`. A protocol after the list applies to
  the whole list, and `protocol:` still works.

The written form is an int for one port, so existing files round-trip
unchanged, and text otherwise.
*Alternative:* `any:` over one clause per port. Rejected: the fields must hold
on one port of the list, and a range would expand to a thousand clauses.

**D3. The index works over ranges.**
- `candidates` and `_port_hosts` take the union over the ranges.
- When a range covers more ports than the index has distinct ports, it is
  resolved by walking the keys of `by_port` instead. So `1-65535` costs no more
  than any port.
- `probed` for a list is the intersection over its ports.
- An assumption names the unprobed ports: up to five, then "and N more".

**D4. The `Fact` model.**

```
Fact(kind, protocol, ports: tuple[(lo,hi)] | None, value,
     mode: equals|contains|start|end|regex = equals, case = False)
```

`condition()` gives `{equals}`, `{literal}`, `{regex: ^esc}` and `{regex: esc$}`,
and `{regex}` as typed, each with `case` when it is set. A service is proposed
as `equals` (it was an anchored regex before). An open-port fact has no value.
The OS and tag facts have no ports. `FactIO` gets optional `ports`, `mode` and
`case`; `partial` is still read, as an alias for start and end.

**D5. The `Draft` and one `assess`.**

```
Draft(selection: tuple[address], facts: tuple[(Fact, State)],
      excluded: tuple[address], same_port: bool = True)
State = ignore | require | exclude
assess(index, files, tags, draft) -> Assessment(
      facts: per fact k/N selected, others          # the proposals, incl. near-shared
      total, selected_matched, unmatched_selected, others (first 200, with ports+title),
      assumed, exclusions (singles + combination, while others exist),
      problems)
```

- **The proposals are cached per selection.** They are recomputed only when
  the selection changes, by add, drop or a new start. Counts per fact are
  cached by fact as well.
- **What a state change recomputes.** It reruns only the evaluation of the
  draft and the exclusions. Today these are 0.05 to 0.15 s at 24 000 hosts,
  measured by the existing slow test.
- **Near-shared facts** are those held by at least ⌈N/2⌉ selected hosts, with
  at least two when N is two or more. Facts every selected host has are listed
  first.
- **Broader proposals:**
  - *Same value on different ports:* text facts are keyed by `(kind, protocol,
    value)` without the port. A value that every host has, on ports that
    differ, is proposed with the union of those ports.
  - *Shared words:* the values of one slot are split on `\W+` and their words
    intersected, case ignored. Up to three words of four or more characters
    are kept, longest first, skipping the common start and end, and proposed as
    `contains`.
- **Excluding an address** becomes `not: {address: a}`.
- **The draft becomes a rule through `draft_rule(draft) -> dict`.**
  - Required facts with equal `(protocol, ports)` are merged into one port
    condition when `same_port` is on. Two values of the same field become two
    clauses under `all`.
  - Excluded facts are never merged: `not {A and B}` is not "not A and not B",
    and negated groups are not allowed (host-tagging D1).
  - The assessment evaluates exactly this dict. That is the invariant the
    tests check.

**D6. The terminal workbench is a `Screen`, not a modal: `tui/nmap/rulebench.py`.**
A modal at 56 columns is the root of the cut-off labels.

```
┌ Rule builder · 5 selected ───────────────────────── same port: on (p) ┐
│ FACTS                      sel    others │ SELECTION (5)               │
│  80/tcp                                  │ ✓ 192.0.2.1                 │
│ + open                     5/5     500   │ ✓ 192.0.2.2  …              │
│ · product = 'Zebra httpd'  5/5     500   │ MATCHES ALSO (500)          │
│ · title ends '- READY'     5/5       0   │   198.51.0.1  22,80,515 …   │
│  any port                                │   …                         │
│ · product ~ 'Zebra'        5/5     500   │                             │
│ EXCLUDE TO DROP 500                      │                             │
│ − 22/tcp open              −500          │                             │
├──────────────────────────────────────────┴─────────────────────────────┤
│ matches 505 · 5/5 selected · 500 others · 0 assumed                    │
│ space cycle · + require · - exclude · e edit · p same port · tab pane… │
└────────────────────────────────────────────────────────────────────────┘
```

**Facts pane keys:**
- `space` cycles ignore, require, exclude.
- `+` and `-` set the state directly.
- `e` edits the fact.

**Selection and matches pane keys:**
- `a` adds a match to the selection.
- `d` drops a selected host.
- `x` excludes a match by its address.

The list shows each host's open ports and title. Opening the full record from
the builder is left out: the viewer's reader belongs to the main screen.

**Screen-wide keys:**
- `p` toggles same port.
- `s` saves.
- `Esc` leaves, and asks first when the draft changed.

**How it updates:** every change starts `@work(exclusive=True, group="bench")`
with a 120 ms debounce, running `assess` in `asyncio.to_thread`. A sequence
number is kept, and a stale result is dropped.

**D7. The fact editor and the save dialog are modals,
`FactEditScreen` and `RuleSaveScreen`, in the same module as the workbench.**
- **The editor** has value, mode (`Select`), case (`Checkbox`) and ports
  (`Input`: empty means any port). Ports are disabled for OS and tag facts. It
  shows live counts from `tb.refine(draft, fact)`, run the same way as D6. An
  error from `tr.RuleError` is shown inline, and Save stays disabled while
  there is one.
- **The save dialog** offers:
  - a tag: an `Input` with the existing tags as suggestions (Textual
    `SuggestFromList`), validated by `tr.tag_name`;
  - a rule name, prefilled with "built from N host(s)", or the name of the rule
    being edited;
  - the grant: host, service or both;
  - a confirmation line when nothing selected matches.

**D8. Editing a saved rule: `tb.from_rule(rule) -> Draft | str`.**
A rule can be opened when it meets all of these:
- it is in seek's own form;
- its `when` is a flat `all` of port, host and tag clauses and single
  negations;
- each port clause has text fields, ports and a state of open.

Other clauses (scripts, a hostname, a network, a state other than open) are
kept as *fixed* facts. They are shown, cannot be edited, and are written back
unchanged.

A rule with `any:` or nested groups, or in the colleague's format, returns the
reason with its `Source`. The selection is the hosts the rule matches today,
capped at 200 with a note.

Saving uses the new `tagfiles.replace_rule(path, tag, old_raw, new_raw)`. The
operation finds `old_raw` in that file's tag by its canonical form and replaces
it. If it is not there, it raises `Conflict("the rule changed on disk - press R
and open it again")` and writes nothing. `Session.plan_rule_replace` plans it.

**D9. Ways to open the builder.**
- `T` starts from the marks.
- With no marks and an active filter, it offers "this row" or "the N rows in
  view". The rows in view are the default, capped at 2000 hosts with a note.
- With no marks and no filter, it starts from this row.
- The `t` menu gets "edit a tag's rules in the builder…", which asks for a tag,
  then a rule.

**D10. The browser.**
- `POST /api/v1/tags/builder/assess` takes `{draft}` and returns the
  assessment.
- `POST /api/v1/tags/builder/refine` takes `{draft, fact}`.
- `POST /api/v1/tags/{name}/rules` takes `{draft, rule_name, grant}`.
- `PUT /api/v1/tags/{name}/rules` takes `{draft, rule_name, grant, replaces:
  raw}`.
- `GET /api/v1/tags/{name}/rules` lists the rules with `editable` and a
  `reason`.

Requests are validated through `tb.fact_from` and `tr.condition`, and a
`RuleError` is a 422. The rule endpoints that change files keep the origin
check. The workbench is one large `<dialog>` with the same panes and keys
(`keys.js`). Requests use an `AbortController`, so only the last answer is
shown. The old `/builder`, `/builder/exclusions` and `/builder/preview` are
removed together with the old flow; the browser is the only caller.

## Risks / Trade-offs

- **[Removing the old endpoints breaks a script that used them]** → They were
  never documented as an interface, and the changelog names them.
- **[A regex on any port scans every service on each change]** → It runs off
  the loop and is debounced, and the existing "nothing narrows it" note is
  shown. The benchmark gains an assess step with a 0.3 s target.
- **[Catastrophic backtracking in a typed regex]** → The 1000-character cap
  stays, and a worker that is superseded is abandoned. `re` cannot be
  interrupted. The viewer stays responsive, but that thread spins until it
  finishes.
- **[Near-shared facts lengthen the list]** → Facts every selected host has
  come first, and the list is capped at `MAX_SHOWN` per group.
- **[An older seek reads a rule with `equals:` or a port list]** → It disables
  that rule with a problem and loads the others, so it fails safe.

## Migration Plan

No data migration. `host-tagging` must be archived first, so that this change's
MODIFIED requirements have their main spec.

## Open Questions

None.
