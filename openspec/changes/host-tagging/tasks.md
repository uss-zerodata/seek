## 0. Prerequisites

- [x] 0.1 Archive `nmap-web-parity`, so `openspec/specs/nmap-session` and `openspec/specs/nmap-web-frontend` exist; verify with `openspec list --specs`
- [ ] 0.2 Add `pyyaml` to the runtime dependencies with `uv add pyyaml`; verify `uv lock --check` and `tests/test_lock.py` pass, and that `import yaml; yaml.CSafeLoader` works or the fallback to `SafeLoader` is taken

## 1. Scan coverage

- [ ] 1.1 `nmap/models.py`: add `ScanFile.coverage` (protocol to sorted, merged port ranges), `ScanFile.timed_out` and `ScanFile.not_scanned` (address sets); keep `ScanFile.__repr__` a summary; verify the repr test still passes
- [ ] 1.2 `nmap/parse.py`: read `<scaninfo protocol services>` (skip protocol `ip`, record a malformed `services` as a failure for that protocol only), `<host timedout="true">` and down hosts; verify with new synthetic fixtures `tests/fixtures/nmap/coverage-*.xml` (TCP and UDP lists, a timed-out host, a down host, a ping sweep, a truncated file after `<scaninfo>`)
- [ ] 1.3 `nmap/coverage.py`: `Coverage.of(host)` from `host.sources` and the files with those labels, excluding files where the host timed out or was down, cached per tuple of sources, searched with `bisect`; verify every scenario of "Each scan's port coverage is recorded" in a unit test
- [ ] 1.4 Run `benchmarks/check_nmap_real.py` and `benchmarks/bench_nmap.py` on the generated corpus; verify the parse time stays within 5 % of the recorded baseline

## 2. Rule language

- [ ] 2.1 `nmap/tagrules.py`: `TextMatch` (expression by default, ignoring case; `literal`; `case: true`; 1 000-character limit; compiled once); verify unit tests for search, case, literal special characters and a broken pattern
- [ ] 2.2 The loaded types from design D1 (`TagDef`, `Issue`, `Rule`, `All`, `Any`, `PortClause`, `HostClause`, `TagClause`, `Not` over one clause), immutable; tag name validation and lowercasing; severity validation; verify unit tests for each invalid name and severity scenario
- [ ] 2.3 YAML loader: `SafeLoader` or `CSafeLoader` subclass that records mapping lines; 2 MiB file and 100 000 node limits; the `seek:` version check; strict types with "quote it" problems for YAML 1.1 coercions (`no`, `1.10`, `22:30`); unknown keys disable their rule; verify with fixtures for each case, each problem naming file and line
- [ ] 2.4 The colleague's dialect: map `nmap_port` (open by default, `service` full match, `product` expression), `html_title`, `html_body`, `html_redirect`, `service_match` (including `cert:issuer`, `cert:subject`, `hostname` as a host clause, `network_log`), `has_tag`, `all`, `any`, `host_tags`, `service_tags`; verify by loading a synthetic copy of his example rules and every pattern type without problems
- [ ] 2.5 Seek's native `tags:` section with descriptions, issues, rules, `grant`, `when` and `not`; both sections in one file; verify the "Both formats in one file" and "A misspelt key" scenarios
- [ ] 2.6 Dependency order with Kahn's algorithm and cycle detection over tag clauses; verify a cycle disables exactly its tags with one problem naming them, and that order in the file does not change results
- [ ] 2.7 README: a tagging section with the rule format in both dialects, `not`, literals and case; ship `examples/seek-rules.yaml` with synthetic rules (printers, a switch, a camera, the Zebra PIN issue); verify a test loads the example file and every YAML block in the README without problems

## 3. Tag files

- [ ] 3.1 `nmap/merge.py`: collect `seek-rules.yaml`, `seek-rules.yml` and `seek-tags.yaml` in `_scans_below`, look in a named file's own folder only, add the global `rules.yaml` and `tags.yaml` from `paths.config_dir()`; verify discovery tests for nested folders, a named file, dot folders and no files at all, and that `test_nmap_*` discovery tests are unchanged
- [ ] 3.2 `nmap/tagfiles.py`: precedence by folder (descendant replaces ancestor, project replaces global, unrelated and same folder merge), canonical comparison so identical definitions do not warn, issue merge by title with the higher severity, description from the first file; verify every scenario of "A more specific definition wins, with a warning"
- [ ] 3.3 Broken files: unreadable, invalid YAML, a list instead of a mapping, a newer `seek:` version; verify each is skipped with a problem and every other file still applies
- [ ] 3.4 `TagFiles` stat tracking (`mtime_ns`, `size`) and reload of all files on change; verify a test edits a file and sees the new definitions after a reload
- [ ] 3.5 The writer: `.lock` with `O_CREAT | O_EXCL`, 2 s retry and 30 s stale break; read and parse the current file; refuse to write a file that does not parse; apply an idempotent operation; serialise in a fixed order with the header comment; temporary file, `fsync`, `os.replace`, keep the file mode; verify unit tests for each step
- [ ] 3.6 Writer robustness tests: two processes adding different entries at once keep both (`multiprocessing`); a kill between write and replace leaves the old file whole; a read-only folder gives a clear error and no change; removal across several files reports a partial failure by file
- [ ] 3.7 Manual entries: canonical addresses with `ipaddress`, service keys `address, protocol, port`, `added` timestamps in UTC, entries for hosts not loaded kept and counted; copy to global writes definitions only; verify a test that scans `tags.yaml` for any address after every operation
- [ ] 3.8 README: file names, where seek writes, the precedence table and the dot-folder rule; verify the README test from 2.7 still passes

## 4. Evaluation

- [ ] 4.1 `gowitness/results.py`: add `Capture.tls_subject` and `Capture.tls_issuer`, selected only when the columns exist; verify with the existing fixture database and one without a `tls` table
- [ ] 4.2 Field values: certificate subject and issuer from the `ssl-cert` script data and from captures, script id and output, host script output, hostnames including `Service.names`, OS best match; verify a unit test per field against `tests/fixtures/nmap/scripts.xml` and the capture fixture
- [ ] 4.3 `nmap/tagging.py`: `build(...) -> TagSet` with the port index, required-port subset test, cheap-first clause order, topological tag order, the "slow: no port" note, and the service grant rule (ports of positive clauses only); verify every scenario of the rule, port-condition, host-condition, negation and service-tag requirements
- [ ] 4.4 Three-valued results per design D5, with evidence text; verify every scenario of "A negation without evidence is an assumption", including the preference for a certain match and propagation through tag clauses, and that a host is never granted a tag and its negation
- [ ] 4.5 Body reads: batched `substr(html, 1, BODY_CAP)` per database in chunks of 500, read-only with a 2 s busy timeout, "not evaluated" counts for missing or empty bodies and locked databases, LRU cache on `(path, mtime_ns, size, row_id, pattern)`; verify tests with a database that has bodies, one without the `html` column and one held locked by another connection
- [ ] 4.6 Compatibility test: run a synthetic copy of the colleague's example rules over synthetic scans of a Ricoh printer, a Catalyst switch and an AXIS camera; verify the host tags equal those `categorize_systems` gives, and that the documented service-tag difference holds
- [ ] 4.7 Add a tagging phase to `benchmarks/bench_nmap.py` with 200 generated rules over the 24 200-host corpus; verify it finishes in at most 1 s, and record the baseline in the script's docstring
- [ ] 4.8 README and help text: the uncertainty marker and its evidence, the body cap, port-less negations, and the warning about nested quantifiers; verify the help text test lists them

## 5. Session

- [ ] 5.1 `nmap/session.py`: `tag_files`, `tag_defs`, `manual_tags`, `tags()` cached on `(scans, shots.generation, defs.generation, manual.generation)`, `tags_ready()` with `INLINE_TAG_HOSTS`, and building in the rows worker after the inventory; verify `tags_ready()` returns `None` above the limit until the worker has run
- [ ] 5.2 Change methods: `reload_tags`, `tag_records`, `save_definition`, `copy_to_global`, with file work off the loop and `adopt_manual` on the loop emitting `Event("tags", origin)`; verify the event reaches a subscriber and memory changes only after a successful write
- [ ] 5.3 Tests for "Tags follow the model": a live scan adds a matching host, a finished capture adds a title without re-reading scans, marks survive a recomputation, and no reader sees a mixed `TagSet`
- [ ] 5.4 Re-stat tag files on every model publication; verify an edited rule file is picked up on the next re-read

## 6. Filter, rows, grouping, export and record

- [ ] 6.1 `nmap/filtering.py`: the `tag:` field in `FIELDS`, `Field.test` and the sample key; `matches(..., tags_of=None)`; "tags not ready" in `FilterSpec.ignored`; verify the new filter scenarios and add `tag:` queries to the `test_nmap_query` corpus while the plain-path comparison stays green
- [ ] 6.2 `Session.row_text` appends tag names, with the tags generation in its cache key; verify fuzzy `zebra` finds a tagged host and stops finding it after the tag is removed
- [ ] 6.3 `nmap/views.py`: `group_by(..., key="tag", tags=...)`; host tags bucket all open services or the host record; verify the grouping scenarios, including a host under several tags and untagged services left out
- [ ] 6.4 `nmap/export.py`: `Record.tags` and `Record.issues`, `records_for(hosts, tagset=None)`, fields `tags` and `issues` with uncertain tags marked; verify every export format test and that `test_version_1_fields_are_pinned` still passes
- [ ] 6.5 `tui/nmap/record.py`: the Tags block after the names block, with source, issues, severity styles and evidence; verify record tests in the terminal and in `web/record.py` output
- [ ] 6.6 Update AGENTS.md: the changed stateless rule, the tag file names and precedence, the `tag:` field and sample key, and the "never rewrite a human file" rule; verify `uv run ruff check` and the docs links

## 7. Rule builder

- [ ] 7.1 `nmap/tagbuild.py`: facts per host, shared facts ranked by rarity, service-anchored facts, common prefix or suffix proposals of at least 4 characters as anchored literals; verify the "Five printers", rarity and literal scenarios
- [ ] 7.2 Exclusions through the tagging evaluator: contrast set, ranking, greedy cover up to 3, uncovered selected hosts listed as assumptions; verify the 5-of-505 scenario, the no-single-fact scenario and the assumption scenario
- [ ] 7.3 Preview counts and the confirmation for a draft that excludes the whole selection; edge cases for one host, nothing shared and vanished hosts; verify each in unit tests
- [ ] 7.4 Measure the builder on the 24 200-host corpus; verify each step takes at most 300 ms
- [ ] 7.5 README: the builder workflow, from marks to a saved rule, and how to scan the ports an uncertain tag names; verify the README test from 2.7 still passes

## 8. Terminal viewer

- [ ] 8.1 Tags column in the host view: ASCII names, `?` for uncertain, `+N` overflow, highest-severity colour, tags generation in `View.stamp`; verify view tests and `test_web_layout` colour tokens are unaffected
- [ ] 8.2 `t` tag dialog (`OptionList` of tags with counts, new name input, add or remove, "Edit definition…", "Copy to global"), with file work in a thread worker and errors on the status line; verify with `Pilot` tests marked `slow`
- [ ] 8.3 Definition editor for description and issues, severity from a list; verify a `Pilot` test that adds an issue and sees it in the record
- [ ] 8.4 `T` builder screen with fact and exclusion lists, preview line and save; verify a `Pilot` test that builds the five-printer rule end to end
- [ ] 8.5 `R` reload, rule problems on the status line, help overlay entries for `t`, `T`, `R` and the `tag:` field; verify help and key hint tests

## 9. Web interface

- [ ] 9.1 `web/schemas.py` and `web/api/v1/tags.py` with the routes from design D12, registered in `ROUTERS`; reading routes plain `def`, changing routes `async def` with the origin check and `asyncio.to_thread` for file work; verify `test_no_route_on_the_loop_reads_the_model` and an origin refusal test
- [ ] 9.2 `keys.js` gains `t`, `T` and `R` with hints, and `actions.js` handlers using `dialog(...)`; verify `test_every_terminal_key_has_a_browser_key` and `test_web_layout.py`
- [ ] 9.3 Pages: Tags column, record block, `tag:` filter and tag grouping through the shared projections; verify `test_every_overview_lists_what_the_terminal_lists` with tags present
- [ ] 9.4 A tag added in the browser appears in the terminal viewer and the reverse, via `Event("tags")`; verify with the session event tests and an SSE test

## 10. Integration checks

- [ ] 10.1 Run `uv run ruff check`, `uv run pytest -q`, and `openspec validate host-tagging --strict`; verify all are clean
- [ ] 10.2 Open the gitignored real scans with a copy of the colleague's rules and a nested folder layout; verify by hand that tags, uncertainty and collisions match expectations, and that no file is written until a tag is changed

## Workflow follow-up

- Agree the native format extensions with the colleague, so his tool can read seek's `tags:` section later.
- Archive this change after review.
