## 1. Reading the database

- [x] 1.1 Build the fixture first, from the real capture databases in the scratchpad: one with a TLS SAN list and console logs carrying a version string, one with a failed/empty case. A generated `.sqlite3` committed under `tests/fixtures/gowitness/`, plus the script that regenerates it.
- [x] 1.2 `results.py`: open the database read-only (`file:…?mode=ro`), introspect `sqlite_master` and `PRAGMA table_info`, and select only columns that exist - never a fixed column list.
- [x] 1.3 Read `results` into `Capture`, adding `id`, `probed_at`, `content_length`, `perception_hash_group_id`. **The column is `filename`, not the JSONL's `file_name`** - a field-for-field port silently loses every screenshot path.
- [x] 1.4 Read the child tables into the capture: all `headers` (keys are lowercased), `technologies`, `console_logs`, `cookies`, and `tls` with its `tls_san_lists`. A missing optional table is empty data, not an error.
- [x] 1.5 Defensive failure: a missing `results` table is reportable ("not a gowitness database"); any `sqlite3.DatabaseError` becomes an entry in `Captures.problems` and leaves the viewer usable.
- [x] 1.6 Delete the JSONL reader and its tests; `Captures.load` takes the database. Keep `add_failures`, which is still the only source for a target that never answered.
- [x] 1.7 Tests: a real database is read; a database-only directory (no jsonl) yields results - the defect that motivated this change; a missing database is no captures and no error; a corrupt file is reported not raised; a database missing an optional table still reads; `filename` maps to the screenshot path.

## 2. Capturing

- [x] 2.1 `capture.py`: drop `--write-jsonl` and `--write-jsonl-file`. Keep `--write-db`, `--log-scan-errors` and the db-uri path translation exactly as they are.
- [x] 2.2 `gowitness_collect_all` config key (default `false`) with its range/type registration and a line in `config.example.toml`. True drops `--skip-network-logs` and `--skip-html`.
- [x] 2.3 Tests: the flags follow the setting for both backends; the setting changes collection only - a database recorded with it on reads identically with it off.

## 3. Two depths

- [x] 3.1 `_detail_content(row, full=False)` in `app.py`; the reader is passed `full=True`, the pane `False`. One function still decides what a row's detail is - this is a superset relation, not a second description. `_refresh_detail` passes the flag through so a streaming capture keeps working at both depths.
- [x] 3.2 `detail.py` inline: the curated set - `server`, `x-powered-by`, `content-type` - plus the security headers looked for by name, showing **which were absent**, since an absence cannot be seen in a list of what is present.
- [x] 3.3 `detail.py` full: every header as a key/value block, cookies, console messages, the complete TLS record with its SAN list, `probed_at`, content length, and the perception-hash group where other captures share it - laid out the way script output already is.
- [x] 3.4 Derive a system name from the page title and `server` / `x-powered-by` / `x-*-id` headers when no technology was detected, labelled with the source it came from. A guess presented as a detection is worse than no guess.
- [x] 3.5 Tests: the curated facts are inline; a missing security header is visible; every header reaches the reader and none reaches the pane; the derived name says where it came from; a record with no captures still gains nothing.

## 4. The deep link

- [x] 4.1 `W` opens `/results/detail/<id>` when the selected record identifies exactly one capture, and the gallery otherwise. `:id` is the database row id.
- [x] 4.2 A capture with no id - a failure recovered from a run's log - falls back to the gallery rather than building a link that will not resolve.
- [x] 4.3 Tests: one selected result deep-links; several or none opens the gallery; an id-less failure opens the gallery.

## 5. Say so

- [x] 5.1 AGENTS.md: amend the reader invariant to the superset relation - the reader shows everything the pane shows and may show more, both from one `_detail_content` - and record the `filename` / `file_name` trap and the read-only introspecting reader.
- [x] 5.2 README: results come from the capture database, so a capture run by hand with `--write-db` is picked up; the two depths; `W` opening the selected result; `gowitness_collect_all`.
- [x] 5.3 Help and palette: the two depths and what `W` now does.

## 6. Finalisation

- [x] 6.1 `uv run ruff check` clean.
- [x] 6.2 `uv run pytest -q` green.
- [x] 6.3 `openspec validate gowitness-output-parsing --strict` passes.
- [x] 6.4 Check by hand: point the viewer at a capture directory holding only `gowitness.sqlite3` and `screenshots/` and confirm the results appear; open a record's full headers in the reader; press `W` on a captured row and land on that result in the browser.
