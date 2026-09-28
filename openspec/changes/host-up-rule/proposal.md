## Why

The viewer and the export disagree about which hosts are up. `u` keeps hosts
that show *any* evidence: a filtered port (which is the absence of a reply), a
closed port, an OS guess or a script result. The export's "Hosts with open
ports" recipe keeps only hosts with an open port. So `u` followed by an export
gives two different host lists for one question.

The evidence rule is also wrong in both directions for how scans are run in
practice:

- Under `-Pn`, nmap records every target `up` with the reason `user-set`. A
  target that answered nothing still gets a port table of `filtered` entries
  when few ports were scanned, and today that counts as evidence. Such a host
  is listed as reachable although nothing ever answered.
- Without `-Pn`, nmap's host discovery *is* the evidence. A host that answered
  a ping but exposes no scanned port is up, and the viewer must say so.
- A host that one discovery scan recorded `down` and a later scan found open
  ports on is listed as `down` today, because `reachable` requires a state
  other than `down` and the first recorded state wins the merge.

## What Changes

- **One rule decides whether a host is up**, and the viewer, the statistics,
  the warning banner and the export all use it. A host is up when:
  - it has at least one open port, whatever way it was scanned; or
  - a scan that did host discovery (run without `-Pn`) recorded it `up`.

  A state asserted by `-Pn` counts for nothing on its own. Closed ports,
  filtered ports, OS guesses and script results no longer decide it.
- **Merging prefers `up` from any real discovery.** When one scan without `-Pn`
  records a host `down` and another records it `up`, the merged host is `up`.
  An asserted `up` still never replaces a recorded state.
- **"Reachable" is renamed "up" in the interface**: the `u` key label, the
  host list's State column, the statistics figure, the `-Pn` warning banner,
  the help overlay and the empty-list message. nmap's own recorded state and
  reason stay visible in the host record, unchanged.
- **The export gains an "Up hosts" recipe** that uses the rule above. The
  "Hosts with open ports" and "All hosts" recipes stay as they are.

Non-goals: no change to what `u` does on a host's own port list (open ports
only). No new setting to choose between rules. No change to how a scan's
`-Pn` is detected: the per-host `user-set` reason stays the signal, because a
merged model has no single "how was this run".

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `nmap-scan-viewer`: the rule that decides whether a host is up (replacing
  evidence-based reachability), how host state merges across scans, the
  wording of the statistics and the empty list, and a new host export recipe.

## Impact

- `src/seek/nmap/models.py`: `Host.reachable` becomes `Host.up` with the new
  rule; `ScanSet.reachable` and `overstated` follow. `has_evidence` loses its
  last user.
- `src/seek/nmap/merge.py`: `_merge_host` lets an observed `up` replace an
  observed `down`.
- `src/seek/nmap/views.py`: the statistics field that counts reachable hosts.
- `src/seek/nmap/export.py`: the new "Up hosts" recipe in `EXPORTS`.
- `src/seek/tui/nmap/views.py`, `app.py`, `help.py`: the State column labels,
  the host-list title, the statistics line, the banner, the key hints, the
  binding description and the empty-list message.
- Tests: `pn-asserted.xml` keeps its counts (its two hosts with evidence both
  have open ports). A new synthetic fixture is needed for the cases that
  change: `-Pn` hosts with only closed or filtered ports, OS or script data,
  and a discovery scan that pings a host with no open port.
- AGENTS.md names `Host.reachable` in the nmap invariants; that entry changes.
- No new dependencies. No configuration change.
