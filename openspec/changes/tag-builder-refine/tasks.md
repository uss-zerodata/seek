# Tasks

## 1. Rule format: equals and port lists

- [x] 1.1 `tagrules`: add `equals` to `text_match` as a match kind (D1), allowing exactly one of regex, literal and equals. Verify with new `test_nmap_tagrules` cases for "an equal value", "case-sensitive" and "more than one kind".
- [x] 1.2 `tagrules`: replace `PortClause.port` with normalised `ports` ranges (D2), parse the three forms, reject reversed and out-of-range values naming the value, and write one port as an int. Verify with parser tests and a round-trip test showing existing rule files are byte-identical.
- [x] 1.3 `tagging`: candidates, `_port_hosts`, `probed` and the negation over ranges, with the assumption naming the unprobed ports (D3). Update every reader of `PortClause.port`. Verify with the scenarios for "one port of a list", "fields on one port of a list" and "one port not scanned", `grep -n "\.port\b"` over the three modules, and the full tagging suite.
- [x] 1.4 Document `equals:` and port lists in `examples/seek-rules.yaml` and `README.md`. Verify with a test that the example loads without problems.

## 2. Builder core

- [x] 2.1 `Fact` with `ports`, `mode` and `case` (D4), and `fact_from` validation. Verify with a test per mode, and "values are equal matches".
- [x] 2.2 `Draft`, `assess` and `draft_rule` (D5): fact states, same port, excluded addresses, others with ports and title, assumptions, inline exclusions, proposals cached per selection. Verify with tests for "same port", "independent", "excluding one host" and "nothing to exclude", plus the invariant that `assess` counts what `draft_rule` saves.
- [x] 2.3 Near-shared facts, the same value on different ports, and shared words (D5). Verify with tests for "a host marked by mistake", "printers on two ports" and "two models".
- [x] 2.4 `refine(draft, fact)` with the dropped count and errors. Verify with tests for "an edit that drops a host" and "an invalid expression".
- [x] 2.5 `from_rule` with fixed facts and refusals, `tagfiles.replace_rule` with `Conflict`, and `Session.plan_rule_replace` (D8). Verify with tests for "editing a saved rule", "the rule changed on disk" and "a rule beyond the builder".
- [x] 2.6 Replace the builder steps of the benchmark with `assess` and `refine` at 24 200 hosts, both under 0.3 s. Verify with `benchmarks/bench_nmap.py` and the slow test in `test_nmap_tagbuild`.

## 3. Terminal

- [x] 3.1 `tui/nmap/rulebench.py`: the workbench screen with its panes, keys, debounced exclusive assess and dropping of stale results, and the confirmation on Esc (D6). Verify with pilot tests for "changing one's mind", "leaving with changes" and "a forgotten printer".
- [x] 3.2 `FactEditScreen` and `RuleSaveScreen` (D7). Verify with pilot tests for "toggling equals", "widening a product", "an invalid expression", "an existing tag" and "a service rule".
- [x] 3.3 Ways to open the builder (D9): marks, row, rows in view, and "edit a tag's rules" in the `t` menu. Replace the old `T` flow in `tagflows.py`. Verify with pilot tests for "from the filtered view" and "editing a saved rule". Rework the five-printer end-to-end test for the workbench.
- [x] 3.4 Help text, hint bar and commands for the workbench keys. Verify with the help test and the hint-overflow test at 80 columns.

## 4. Browser

- [x] 4.1 Schemas and endpoints for assess, refine, save, replace and the rule list (D10); remove the old builder endpoints. Verify with `test_web_tags` cases, including the 422 for an invalid draft and the refusal of another origin.
- [ ] 4.2 The workbench dialog in `actions.js`, with its keys in `keys.js`, aborting stale requests. Verify with "the same rule from both" (the terminal and the browser save equal raw rules), the parity test, and a manual run of `seek nmap serve`.

## 5. Integration

- [ ] 5.1 Run ruff, the full suite and the checker. Raise the minor version and note the removed endpoints in the changelog. Run `seek nmap` by hand: build, edit, save and reopen a rule on a fixture. Verify that everything is green and that the run matches the specs.

## Workflow follow-up

- Archive `host-tagging` before archiving this change.
