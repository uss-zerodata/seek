## Context

Two rules answer "is this host up" today:

- `Host.reachable` (`nmap/models.py`): `state != "down" and has_evidence`, where
  `has_evidence` is true for *any* service (open, closed or filtered), an OS
  match, a script result, or a status reason other than `user-set`. It drives
  `u`, the "Reachable (evidence)" statistic, the `-Pn` warning banner and the
  State column (`up`, `up*`, `no evidence`, `down`).
- `export.export_hosts`: a host with at least one open port. It drives the
  "Hosts with open ports" recipe.

`-Pn` is detected per host, not per file: nmap writes reason `user-set` on
every host of such a scan (`Host.state_asserted`). `ScanFile.disabled_ping`
reads the command line, but a merged host can come from several files with
different flags, so the per-host reason is the only signal that survives
merging. `_merge_host` already lets an observed state replace an asserted one;
otherwise the first recorded state wins.

## Goals / Non-Goals

**Goals:**

- One predicate, used by every place that says whether a host is up.
- An open port always makes a host up. An asserted `up` never does on its own.
- A real discovery result (`-Pn` not used) counts as up even with no open port.
- Observed `up` wins over observed `down` when scans disagree.

**Non-Goals:**

- Changing the host port list's `u` (open ports only), which is already done.
- A setting to choose between rules.
- Reading scan flags to classify hosts. The `user-set` reason already does it.

## Decisions

### D1. The predicate

```
Host.up = bool(open_services) or (state == "up" and not state_asserted)
```

`Host.reachable` is renamed `Host.up` rather than kept as an alias, so no
caller keeps the old meaning by accident. `ScanSet.reachable` becomes
`ScanSet.up`. `has_evidence` has no remaining caller and is removed.

Why not keep closed ports as evidence: a RST does prove a host is alive, but
the user's rule for `-Pn` is explicit (open port or nothing). It also makes the
viewer and the "Up hosts" export give the same answer for one question.

`state == "up"` rather than `state != "down"`: nmap writes `up` or `down`; an
absent state (a hand-built host, a truncated file) is not evidence of anything.

### D2. Merging: observed `up` beats observed `down`

In `_merge_host`, after the existing asserted-vs-observed rule, an observed
`up` in `other` replaces an observed `down` in `into`. The order of the files
then does not matter. An asserted `up` still never replaces an observed
`down`: that is exactly the `-Pn` case. An open port found later makes the
host up through D1 anyway, whatever its merged state says.

The merged `state`/`reason` stay what nmap recorded (one of them), so the host
record keeps showing a real reason, never a synthesised one.

### D3. State column labels

| Condition | Label |
|---|---|
| `up` by discovery (state `up`, not asserted) | `up` |
| up only through an open port (asserted, or recorded `down`) | `up*` |
| asserted `up`, no open port | `unconfirmed` |
| recorded `down`, no open port | `down` |
| no state recorded, no open port | `—` (absent) |

`up*` keeps its current meaning ("up, but not because nmap said so").
`no evidence` becomes `unconfirmed`, because such a host may well have closed
or filtered ports now, and "no evidence" would be wrong.

### D4. Wording: "reachable" becomes "up"

The words users see change; the `u` key and the action name `reachable` in
the command palette are renamed to match (`action_up`, "Up hosts / open ports
only"). Changes:

- host-list title `Hosts (reachable)` → `Hosts (up)`; hint `u reachable` → `u up`
- statistics line `Reachable (evidence)` → `Up`, note "open port, or answered
  host discovery" (or "FAR FEWER than asserted" when overstated, as now)
- banner: "scan asserted N hosts up (-Pn) but only M are up — an open port or
  host discovery"
- empty list: "No host is up" / "u lists every host the scan named"
- help overlay line for `u`

`_only_reachable` becomes `_only_up`. Spec scenarios move to the same words.

### D5. Export recipe

`EXPORTS["up-hosts"] = ("Up hosts", export_up_hosts, "address")`, placed
between "Hosts with open ports" and "All hosts". `export_up_hosts` filters
records by `r.host.up`. It reads only the model, so `export.py` stays pure.
Like every recipe it applies to the marked records or the current view, so
`u` then "All hosts" and "Up hosts" on the unfiltered list give the same list.

## Risks / Trade-offs

- **A `-Pn` host that only answered with a RST is no longer up.** → That is
  the rule the user asked for. The host record still shows its closed ports,
  and "All hosts" still exports it.
- **Merge order change can move a host from `down` to `up`.** → Only when a
  scan really recorded it `up`. Covered by a both-orders test, like the
  existing probed-over-guessed test.
- **Renaming `reachable` touches tests and AGENTS.md.** → Mechanical, done in
  one task, and a leftover name fails at import rather than silently.
- **Large engagements**: the predicate reads `open_services`, which builds a
  list per call. `ScanSet.up` walks every host, the same cost as
  `ScanSet.reachable` now (which also touched `services`). No new pass.

## Migration Plan

None. Nothing is persisted; the next run uses the new rule.
