## 1. Fixture

- [x] 1.1 Add a synthetic fixture pair (no real addresses) covering every case of the rule: a `-Pn` scan with a host that has an open port, a host with only closed and filtered ports plus an OS guess and a script result, and a host with nothing; and a discovery scan (no `-Pn`) with a host recorded `up` (`echo-reply`) with no open port, a host recorded `down`, and a host that the `-Pn` scan saw with an open port but this scan recorded `down`
- [x] 1.2 Add a second discovery-scan file recording one host `down` that the first records `up`, for the merge-order test

## 2. The rule (model, no terminal)

- [x] 2.1 Replace `Host.reachable` with `Host.up` (`open_services` or an observed `up`), rename `ScanSet.reachable` to `ScanSet.up`, update `overstated`, and remove `has_evidence` once nothing uses it
- [x] 2.2 Rename the statistics field in `nmap/views.py` that counts reachable hosts, and update every other caller of the old names
- [x] 2.3 Test the rule against every host in the fixture from 1.1, one assertion per case, including the `-Pn` host with closed/filtered ports, OS and scripts being not up
- [x] 2.4 Test that `pn-asserted.xml` still reports 2 of 10 hosts up

## 3. Merging

- [x] 3.1 In `_merge_host`, let an observed `up` replace an observed `down`; keep an asserted `up` from replacing an observed `down`
- [x] 3.2 Test both file orders for observed `up` against observed `down` (fixture 1.2), and that an asserted `up` with no open port leaves an observed `down` in place
- [x] 3.3 Test that a host recorded `down` by discovery but with an open port from a `-Pn` scan is up after merging, in both orders

## 4. Export

- [x] 4.1 Add `export_up_hosts` and the `up-hosts` entry ("Up hosts") to `EXPORTS`, between "Hosts with open ports" and "All hosts"
- [x] 4.2 Test the recipe against the fixture: the `-Pn` host with no open port is left out, the open-port host and the discovery-only host are in
- [x] 4.3 Test that "All hosts" exported from the up-filtered host list equals "Up hosts" exported from the unfiltered list

## 5. Interface wording

- [x] 5.1 Change the State column labels to `up`, `up*`, `unconfirmed`, `down` as laid out in design.md D3
- [x] 5.2 Rename `_only_reachable` / `action_reachable` to `_only_up` / `action_up`; update the binding description, the `u` key hint, the host-list title, the help overlay line and the empty-list message
- [x] 5.3 Change the statistics coverage line to "Up" with its new note, and the `-Pn` warning banner text
- [x] 5.4 Update the TUI tests that assert the old words (`reachable`, `no evidence`, "u lists every host") and add one that `u` on the fixture from 1.1 lists exactly the up hosts
- [x] 5.5 Test the State column labels for each case in the fixture

## 6. Finish

- [x] 6.1 Update the nmap invariants in AGENTS.md that name `Host.reachable` and describe evidence-based reachability
- [x] 6.2 Run `benchmarks/check_nmap_real.py` against the local scans and compare the up counts with what nmap itself reports for the discovery scans
- [x] 6.3 `uv run ruff check`, `uv run pytest -q`, and `openspec validate host-up-rule --strict`
- [x] 6.4 Remove the item from `todo.md` (the user ticked it instead; left as they have it)

## 7. Sorting toggle and the `r` filter (added on request)

- [x] 7.1 `action_sort`: the already-sorted column reverses, another column starts ascending; heading clicks go the same way
- [x] 7.2 Drop the `r` → reverse binding and every `r reverse` hint; keep "Reverse sort" in the palette with its new key description
- [x] 7.3 `r` toggles hosts-with-open-ports on the host list (`hosts_view(only_up, only_ports)`, title names both), goes to the host list from other tabs, and means open ports only on a host's port list
- [x] 7.4 Empty-list message for `r`, naming every key that is on
- [x] 7.5 Help overlay, palette entry, README; spec delta for Sorting and the `r` filter
- [x] 7.6 Tests: toggle and flip-back, opening order counts as chosen, heading click reverses, `r` alone / with `u` / from another tab / on a port list / empty
- [x] 7.7 `uv run ruff check`, full `uv run pytest -q`, `openspec validate host-up-rule --strict`
