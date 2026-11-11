# AGENTS.md

Guidance for coding agents working in this repository.

## Standard

Follows the tool standard 1.2: the agent skill `python-standard` (the folder
`../standards/`). Load the skill before you work here. Do not copy a listed
deviation into new code; migrate one only when you change that code anyway.

| Rule | State | Reason |
| --- | --- | --- |
| ARC-2 | not met | `config.py` imports `textual.keys` to validate `[keys]`; `__main__.py` imports `cli` because that is its job. |
| CAP-20 | not met | Predates `stdkit`: no capability entry point. |
| CLI-31 | not met | No shared console: `print` only after Textual returns the terminal and in `seek nmap serve`; `Console` renders records to text/HTML. |
| CLI-40 | decided otherwise | `actions.perform_exec` replaces the process: that is the exec hand-off. |
| CLI-12 | not met | `seek init` with no shell shows Typer's missing-argument error, not the help. |
| CLI-44 | checker false positive | The `except Exception` handlers it finds are in TUI workers and web routes, not at a command boundary. |
| CLI-45 | decided otherwise | The two `assert`s narrow a type (`process.stdout`, `_outbox`); they never validate input. |
| DOC-2 | not met | The headings below are the project's own; the Standard section carries the version and this table. |
| REL-20 | not met | No `release.yml` yet; `ci.yml` is ready to be called. |
| TC-3 | decided otherwise | `hatchling`; switching the backend buys nothing for an installed tool. |
| TC-4 | decided otherwise | `>=3.11`: the features used (`tomllib`, `StrEnum`) are there, and users run 3.11. |
| TC-30 | decided otherwise | `SIM` is not selected. |
| UI-30 | checker false positive | The `!` it finds is fzf's negation syntax inside the query parsers, not text for the user. |

## Commands

`seek [search] [patterns…]` (the default command), `seek init <bash|zsh>`,
`seek nmap [paths…] [--serve] [--open]` (`seek nmap serve …` is the headless
form), `seek vulndb update|status`. A change to this tree is a decision, not a
side effect.

## What this is

`seek` — an interactive terminal search application. One persistent TUI that
fuzzy-matches **filenames, directory names, and file contents at the same
time**, ranks them into a single list, and lets you preview and act on results
(open in an editor / the OS default app, copy paths, `cd`, export). It replaces
a set of one-shot `fzf` + `fd` + `rg` shell functions.

The user-facing docs are in [README.md](README.md). The full behavioural
specification lives in `openspec/` (see [OpenSpec](#openspec) below) — treat the
specs as the source of truth for *what* the app must do.

## Toolchain — use `uv` for everything

This project uses [uv](https://docs.astral.sh/uv/) exclusively. **Never invoke
bare `python`, `python3`, or `pip`.**

```bash
uv sync                     # install deps (first time / after pyproject change)
uv add <pkg>                # add a runtime dependency
uv add --dev <pkg>          # add a dev dependency
uv run seek                 # run the app
uv run pytest               # run the tests
uv run pytest tests/test_engine.py -q       # one file
uv run pytest -q -k "cursor or preview"     # by keyword
uv run ruff check           # lint
uv run ruff check --fix     # lint + autofix
uv lock --check             # verify the lockfile is current

uv run python benchmarks/bench_search.py [PATH]   # search throughput benchmark

uv run python benchmarks/gen_nmap_corpus.py /tmp/engagement   # 120 files, 24 200 hosts
uv run python benchmarks/bench_nmap.py /tmp/engagement        # pipeline split
uv run python benchmarks/bench_nmap.py /tmp/engagement --latency   # event-loop pauses
uv run python benchmarks/drive_nmap.py /tmp/engagement        # walk the viewer at scale
```

`benchmarks/` is **not** collected by `pytest` (`testpaths = ["tests"]`) — it is
slow and needs a corpus. Run it before and after any change to `engine/` and
compare against the baseline recorded in the script's docstring.

If a stale-virtualenv warning is noisy, prefix commands with `env -u VIRTUAL_ENV`.

Python **3.11+** (uses `tomllib`, `enum.StrEnum`). Runtime deps are kept minimal:
`typer`, `textual`, `rich` (via textual), and `fastapi`, `uvicorn`,
`jinja2` for the nmap viewer's web interface (shipped in the package on purpose -
one application, no extra install); `pathspec` is an optional extra used only
for `.gitignore` support. Tests use `httpx2` for FastAPI's `TestClient`.

## Before you finish a change

1. `uv run ruff check` — must be clean.
2. `uv run pytest -q -m "not slow"` — must be green (~1600 tests, ~1 min). The
   full suite (`uv run pytest -q`, ~2100 tests, ~13 min) adds the twenty files
   marked `slow`, which drive the TUI through Textual's `Pilot` and need real
   time to settle; run it before a version bump, and whenever you touched
   `tui/` or `web/`.
3. If you changed `Config` fields: regenerate the example file —
   `uv run python -c "from seek.config import example_toml; open('config.example.toml','w').write(example_toml())"`.
4. If you changed observable behaviour: update the matching spec - in
   `openspec/specs/<capability>/spec.md`, or in the open change that owns it
   under `openspec/changes/<change>/specs/` - and run
   `openspec validate <change> --strict`.

## Layout

```
src/seek/
  __main__.py       `python -m seek` -> `cli.main`
  cli.py            Typer entry point: flags, mode/scope resolution, `seek init`
  config.py         Config dataclass, TOML load + strict validation, DEFAULT_THEME
  paths.py          per-platform config/state dir resolution (hand-rolled, no platformdirs)
  scope.py          positional glob / -r regex path patterns (fd-style, smart-case)
  walk.py           streaming os.scandir walk: symlink-loop guard, prune, .gitignore opt-in
  models.py         Candidate, Result, MatchKind, ResultSet
  session.py        SessionConfig handed from CLI to the TUI
  history.py        persisted query history (Alt+Up/Down)
  shell.py          `seek init bash|zsh` code + the SEEK_CD_FILE hand-off channel
  actions.py        pure action logic: argv construction, clipboard fallback chain
  engine/
    query.py        fzf extended-syntax parser (^ $ ! ' and AND terms)
    score.py        pure-Python fzf-style scorer -> (score, matched positions)
    content.py      ContentCache (byte-budgeted, LRU, thread-locked) + binary sniff
    format.py       parser-free re-indenters for minified JSON/XML/HTML
    engine.py       SearchEngine: name index + content search, modes, cap, publish
  tui/
    app.py          SeekApp: layout, key bindings, search/preview workers, actions
    results.py      RowList (cursor + marks) and ResultsList: row rendering, clipping
    preview.py      build_preview(): windowed syntax + query highlight; header
    detail.py       DetailScreen: full-file pager (j/k/g/G/Ctrl+D…)
    tree.py         tree_rows() / render_tree(); TreeList: the empty-query tree as a list
    menu.py         action menu / confirm / prompt / choice modal screens
    help.py         help overlay
    query_input.py  QueryInput(Input): `?`-on-empty opens help
    actions_mixin.py  ActionsMixin: result actions + perform_exit_request()
    keyhints.py     the hint bar: which key hints fit the width, and in what order
    cells.py        width_of(): the ASCII shortcut for cell width (rich.cells.cell_len walks the string)
  nmap/
    models.py       Host / Service / ScriptResult / Vulnerability / ScanSet
    parse.py        iterparse reader (`<nmaprun>` root check, else NmapParseError)
    merge.py        consolidate several scans; directory expansion; provenance
    vulns.py        lift findings out of script results (NSE `vuln`, vulners)
    views.py        projections: service groups, statistics, grouping
    export.py       Record (host + optional service), field catalogue, writers
    presets.py      is nmap here, preset -> argv, privilege from flags, targets
    runner.py       one scan: launch, stream, cancel, classify. No Textual.
    remote.py       a plan as text to copy: as run here, or a snippet for another machine
    options.py      every documented nmap option: form, attach, default, root, page, rules
    builder.py      the guided builder's model: steps, choices, precedence, two profiles
    timing.py       RTT timeouts from round trips (nmap's 2x/3x/4x rule), bounded measuring
    recent.py       earlier commands without targets; the arguments-only history file
    diff.py         what a scan added to what was already known
    cpe.py          CPE 2.2/2.3 bindings + the alias table (one product, every spelling, its CPE)
    inventory.py    software inventory: recognisers -> observations -> reconciled components
    filtering.py    the filter grammar: FilterSpec (fuzzy / ranges / field terms), prefer_firm, explain
    names.py        the names a host is known by, read from what the server gives away
    rawlog.py       which lines of a `.nmap` text are one host or one port - boundary search, no meaning
    timeline.py     the Scans tab history: every file by `<nmaprun start>`, diffed against what came before
    progress.py     the one report shape (done, total, unit) and counted() for every long step
    bulk.py         the collector policy: bulk() suspends gc for a phase and freezes, responsive() yields
  tui/nmap/
    views.py        column specs + row builders per view
    detail.py       full record for the selected row (scripts, vulnerabilities)
    reader.py       `d`: that record full-screen - scroll, search, step entries
    app.py          NmapApp: table + detail pane, one filter, one breadcrumb
    flows.py        ScanFlows mixin: the scan, capture and vulnerability-database flows
    scans.py        the Scans tab: run list + the three report modes
    scope.py        scope editor, editable command, the review before it runs
    builder.py      the chooser (build / recent / frequent / presets) and the builder screen
  gowitness/
    detect.py       docker or native, or neither - never raises
    capture.py      one argv for both backends, output layout, the CaptureRun
    results.py      the capture database -> Capture records, indexed by URL
    locate.py       find results databases below the sources; ShotFinder / ShotIndex for their images
  runner.py         supervision shared by every tool: stream, cancel, settle
  notify.py         ntfy-format notifications: URL check, minimal messages, send
  vulndb/           the local vulnerability database - public data only, no Textual
    versions.py     release-order comparison; `None` = undecidable, never "safe"
    store.py        SQLite schema, read-only `Store` for sessions, `open_write` for updates
    sources.py      the fixed URL set; NVD 2.0 / OSV / endoflife.date parsers (streamed)
    update.py       download + ingest, one transaction per source, incremental
    progress.py     Tracker: one bar over a source's download and indexing together
    eol.py          product key -> endoflife.date slug / npm package; support status
    match.py        inventory + store -> findings and support per component
    commands.py     `seek vulndb update` / `status`
  nmap/session.py   the shared session: model, runners, marks, events, scan planning
  tui/nmap/tabs.py  the tab list and tab_view() - both front ends build tabs here
  tui/nmap/record.py  record_lines(): what a row's record is, for pane, reader and web
  web/
    source.py       ModelSource protocol; WebModel (indexes, capture ids); CachedSource
    views.py        every overview and drill-down by URL; step names; ViewCache
    record.py       Rich record -> HTML by style attribute; raw-text links
    serve.py        `seek nmap serve`: headless build, owner and signal handling
    api/v1/         JSON routers: hosts, services, captures, views, records (+ raw), marks (+ export),
                    runs (scans, captures, events as SSE), builder, search, vulndb, inventory (the
                    versioned JSON document the export writes), control (`/web`, `/web/stop`)
    deps.py         what a route takes from the request: model(), session() (503 without one), places()
    pages_data.py   record() and raw(): one builder for the JSON record and the page fragment
    static/js/      viewer.js (list/record, key bar), keys.js (the key table + hints), actions.js, events.js
    schemas.py      pydantic shapes - the API returns them, the templates render them
    query.py        list/filter/sort/page over the TUI's own view projections
    pages/routes.py HTML routers (same query functions), `fragment=1` for filtering
    media.py        screenshots by capture id - no route takes a path
    app.py          create_app(source); ROUTERS is the one registration list
    server.py       WebServer: loopback check, port probe, uvicorn on a thread; path_for(row)
    templates/ static/   Jinja2 + one stylesheet (tokens first) + app.js; nothing from a CDN
tests/              pytest; conftest.py has the `tree` / `symlink_loop` fixtures
tests/fixtures/nmap/  synthetic scan XML (no real addresses)
```

## Architecture notes

**Threading / responsiveness.** The Textual event loop must never block.

- The **walk** runs in `@work(thread=True, group="walk", exclusive=True)`,
  pushing `Candidate`s onto a thread-safe `CandidateStore`.
- **Search** runs in `@work(thread=True, exclusive=True, group="search")`. A
  monotonically increasing `_generation` counter + an `is_stale` callback let a
  superseded search bail; `exclusive=True` marks the old worker cancelled but it
  keeps running until it cooperatively checks `is_stale`, so overlapping threads
  are possible — that's why `ContentCache` holds a lock.
- **Preview building** (disk read + Pygments) runs in
  `@work(thread=True, exclusive=True, group="preview")`, ~50 ms-debounced. The
  pane height is measured on the main thread first, then passed in.
- Anything a worker's `call_from_thread` callback touches must guard against
  teardown — `try: query_one(...) except NoMatches: return`.

**Result flow.** `on_input_changed` → debounce (`config.debounce_ms`) →
`_trigger_search` → worker → `engine.search()` returns a `ResultSet` (and calls
`publish` with ranked partial snapshots during the content pass) →
`_apply_results` on the main thread → `ResultsList.set_results`.
`_apply_results` **preserves the cursor by identity** when the query text is
unchanged (streaming / mid-scan updates), and only snaps to the best match when
the query actually changed.

**Result cap.** `engine.search` returns at most `config.max_results` (default
500) and reports the pre-cap `total`. Results are collected into a **heap
bounded by the cap** (`(score, -seq, result)` entries — the negated sequence
number makes the latest insertion the eviction victim among equal scores, which
is what `heapq.nlargest` used to do). A candidate that cannot beat `heap[0]` is
never turned into a `Result` at all, and **spans are computed only for the
survivors** (`_ranked`), so peak memory is set by the cap rather than by how
many lines matched.

**Search performance.** Four invariants worth not regressing — run
`benchmarks/bench_search.py` before and after any change to `engine/`:

- The reject path must stay in C. `score._score` tries `hay.find(needle)`, then
  `query.fuzzy_ok` (first-char gate + shared-iterator subsequence test), and only
  then the per-character Python `_greedy`. **Do not replace `fuzzy_ok` with a
  regex** — `m.*?a.*?i.*?n` backtracks catastrophically on common-letter needles.
- Each line is folded once (`match_spans` passes `lowered` down; `Term.needle`
  and `ParsedQuery.needs_fold` are precomputed at parse time).
- `match_score` is the scanning hot path; `match_spans` is only for survivors.
- **Narrowing:** when `query.can_narrow(old, new)` holds, the search runs over
  the previous query's matches (`SearchEngine._pool`) instead of every
  candidate. The predicate compares *parsed terms*, not raw text — appending
  after `$` re-types a term and can widen it. The pool is invalidated by a mode
  toggle, a `store.clear()` (epoch bump), new candidates, a cancelled scan, and
  is disabled entirely while the walk is running.

**Two line numbers.** Minified files are re-indented before indexing
(`engine/format.py`), so "position in the text we searched" and "line in the file
on disk" diverge. `Result.line_no` is **always the line in the file as stored** —
row label, detail title, export `path:line`, `editor +{line}`. `Result.view_line`
is the position in the indexed text and drives preview/detail positioning *and*
`identity()` / `ResultsList._oid`, because a reformatted minified file maps every
match to line 1 and keying identity on `line_no` would make marking one match
mark its neighbours. `view_line` falls back to `line_no` when nothing was
reformatted. `ContentCache.content()` returns `(lines, origin)` where `origin[i]`
is the stored-file line for indexed line `i`, or `None` when untouched.

The re-indenters **must not** be replaced with `json`/`minidom` parsing: they are
not faster (minidom is 2.3x slower) and they raise on truncated JSON, JSONL,
JSON-with-comments and unclosed HTML, all of which are ordinary tree contents.
`preview.py` applies the *same* `format_lines` so the preview cannot disagree
with the index. Flipping the toggle clears the whole content cache and the
narrowing pool — formatted and raw content cannot share an entry.

**Changing root does not re-walk.** The filesystem is treated as stable for the
session: `_on_walk_finished` keeps the completed launch-root scan in
`SeekApp._base_candidates`, and `_reset_for_new_root` derives the new root's
candidates from it via `walk.rebase()` (`_reuse_walk`). Popping a breadcrumb used
to re-walk the whole tree. It falls back to a real walk when the launch scan
never finished, the new root is outside it, or a positional scope is active
(`scope.accepts` was resolved against the launch root). **`refresh` clears
`_base_candidates` first** - it is the explicit escape hatch, so never serve it
from the cache.

**Progress snapshots are time-throttled**, not hit-count-throttled
(`config.publish_interval_ms`, default 500 ms). Each snapshot costs a ranked
`_ranked()` pass *and* a full `ResultsList` rebuild on the UI thread, so tying
them to match rate made the broadest queries pay the most. `0` disables the
throttle (tests only).

**Content reads are capped.** `ContentCache` reads the sniff header first and
rejects binaries before reading the body, then reads at most
`config.content_size_cap` (5 MB) of any one file, dropping a trailing partial
line. Its budget is accounted in real bytes (characters *plus* `str` object
overhead) and its LRU is an `OrderedDict`, so bookkeeping is O(1) per access.
`_read` runs outside the lock — two threads may read the same file, which is
cheaper than serialising every reader behind one slow read.

**Display ordering.** The engine returns best-first; `ResultsList` displays
**bottom-up** (best match on the bottom row, next to the query — fzf's default
layout). `↑`/`↓` follow visual direction. `ResultsList.ranked()` gives back
best-first order for exports.

**Rows never wrap by default.** Textual's `OptionList` wraps and ignores Rich
`no_wrap`, so `results.py` pre-clips each row to the list width, windowing a
long content line around its match (`_clip`). `config.wrap_results` disables it.

**Colour under ANSI themes.** The app uses the `ansi-dark` Textual theme, in
which `$panel` / `$surface` / `$boost` all collapse to the terminal background.
**Widget defaults will fight you on this.** Textual styles several components
with a filled `$primary`, which under an ANSI theme is raw bright blue behind
default-coloured text - unreadable. This has had to be undone twice already: the
search session's status bar, and `DataTable`'s `datatable--header`. When adding a
widget, check its component classes and set `background: transparent` with an
explicit `color:` rather than accepting the default fill.

So **do not rely on background shades for separation.** Region dividers are thin
blue `border-bottom` rules (`$primary`): one under the preview and one under the
result area, fencing off the status / hint / prompt cluster at the bottom. No
filled bands — a saturated ANSI-blue fill reads as harsh and its `dim` text is
unreadable. Rendered *text* (rows, tree, preview, status, hints) is styled with explicit Rich
colours pulled from `config.theme` (`DEFAULT_THEME` in `config.py`) so users can
override them; the highlighted row uses `text-style: reverse` (theme-independent).

**Opening keeps the session.** An editor is run inside `App.suspend()`
(`ActionsMixin._run_in_terminal`): Textual gives the terminal back, the editor
runs to completion on the event loop's thread, and the app resumes exactly as
it was. Afterwards `after_external_edit` drops the content cache and re-runs the
query - the cursor survives because the query text is unchanged. The default
application and `code` are windows of their own, so they are `spawn_detached`
and nothing is suspended. Where the driver cannot suspend (the headless driver
tests run under, among others) the editor falls back to the old exec-and-exit;
a test that wants the real path replaces `app.suspend` with a null context.

**Actions that end the session** (print to stdout, `cd`) cannot run while
Textual owns the screen. They set `app.exit_request` and call `self.exit(0)`;
`run_session` then calls `perform_exit_request` *after* `app.run()` returns and
the terminal is restored.

**The tree is a list, and a tree entry is a `Result`.** `TreeList` and
`ResultsList` share `RowList` (cursor, marks, `current()` /
`selected_results()`), and `SeekApp._active_list()` returns whichever one the
query state puts on screen. Navigation, marking and every action go through it,
so nothing downstream knows which list a target came from. Two things differ on
purpose: the tree reads top-down, and `Enter` on a directory re-roots instead of
opening a detail view. Marks belong to their list - the two are never on screen
together. Do not `query_one(RowList)`: it matches both.

## Conventions

- `ruff` config is in `pyproject.toml` (line length 100, rules `E F I UP B W`).
- Keep new runtime dependencies to a minimum and justify them.
- Prefer `from __future__ import annotations` + lowercase builtin generics.
- Tests: put pure-logic tests in the matching `test_<module>.py`; TUI behaviour
  goes in `test_tui.py` using `async with app.run_test() as pilot` and the
  `_settle(pilot)` helper (waits for the walk to finish). Snapshot-style checks
  use `widget.render_lines(Region(...))`.
- Don't commit or push unless the user asks.

**nmap viewer invariants.**

- **Stateless.** The files named on the command line are the whole truth for a
  run: no import, no database, nothing written but an explicit export. Parsing
  1.4 MB takes ~11 ms, so there is no performance argument for caching.
- **A scan's label is unique within a run; provenance is per file, never per
  file name.** `merge.naming(roots)` decides it once, from the command line:
  the bare file name for one directory or for files, the path below the
  directories' common parent for two or more. Merging unions `sources` *as
  strings*, so two `scan.xml` labelled alike were one source and a host seen in
  both read as seen once. The naming rides on `Pending` and the viewer keeps it
  (`Session.name`, `NmapApp._naming`) so a re-read after a finished scan names every file exactly
  as the first read did. Anything that shows a scan uses `ScanFile.name` /
  `.stem`, never `path.name`. Output goes to the first directory, and the
  status line says so when there are several.
- **A capture is found, not assumed.** `gowitness/locate.py` walks the sources
  for results databases by the scan search's rules, at any depth and under any
  name, and accepts a file only if it is SQLite *with gowitness's `results`
  table* - other databases are passed over silently. The stored screenshot is a
  bare file name, so `ShotFinder` resolves it nearest-first (the database's
  `screenshots/`, its directory, below it, then a `ShotIndex` over the sources,
  walked once and shared); never rebuild `db.parent / "screenshots" / name` by
  hand, which is the assumption this replaced. `Paths.db_name` exists because a
  found database keeps its own name. The capture *this* app writes still goes
  to `<scan_dir>/gowitness/gowitness.sqlite3`, and the report server serves
  only that one.
- **The filter has two paths, chosen by the text.** `filtering.parse_filter`
  builds today's `FilterSpec` - fuzzy query, range union, negated ranges -
  whenever the text has no field term (`open:`/`closed:`/`service:`/
  `product:`), no uppercase `AND`/`OR`/`NOT`, no `|` and no parenthesis. Only
  then does it build an expression tree (`FilterSpec.expr`). Keep it that way:
  the plain path is the tuned one, and `test_nmap_query` runs a corpus of plain
  queries through both and requires the same rows. Two semantic rules live in
  `_Row.eval`: field terms directly under one AND are **one clause satisfied by
  a single port**, and `NOT` negates the child evaluated on the whole row, so
  it reads as "none of the ports". A multi-record row (a service group, a
  bucket) is reduced to one sample port per distinct
  `(port, protocol, state, name, product)`, cached by the records tuple's
  identity - a field term reads nothing else, and walking 20 000 pairs a
  keystroke was 200 ms. Add a field by teaching `Field.test` *and* that sample
  key, or the samples will answer it wrongly. Port-state keys are
  `open:`/`closed:`, never `up:`/`down:` - "up" is the host rule.
- **`line_no`-style split, again:** a host's *recorded* state (`state`/`reason`)
  and whether it is `up` are different things. `-Pn` makes nmap report `up`
  with reason `user-set` for every target — 255 of 256 in the real sample, 9 of
  which had any evidence. Never present the asserted count as observed;
  `Host.up` is the one to list, filter and export by, and it is **one rule for
  every consumer**: an open port, or a real discovery answer (`Host.discovered`
  - `up` for a reason other than `user-set`). Closed and filtered ports, OS
  guesses and script output do not count: a filtered port is the absence of a
  reply, and the rule has to agree with the "Up hosts" export. Merging lets an
  observed `up` beat an observed `down` in either order; an asserted `up` never
  replaces a recorded `down`.
- **Merging prefers a probe over a guess.** A scan run without `-sV` names
  services from nmap's port table (port 3128 → `squid-http`). A `method="probed"`
  record overrides a table guess in either file order; `method`/`conf` travel
  with the identification.
- **Scripts are generic, vulnerabilities are a recogniser on top.** The NSE
  `vuln` library keys its table by the identifier and reports a **state**
  (`VULNERABLE`), not a severity — `severity` is only ever set by a script that
  actually scores, such as `vulners`. Do not map one onto the other.
- Actions are on modifiers because the filter box keeps focus, exactly as the
  query box does in a search session — a bare digit has to reach the filter.
- **The detail pane is where most parsed data actually surfaces.** Script output
  and vulnerability records (title, ids, refs, disclosure) have no column; if you
  add a field to the models, render it in `tui/nmap/detail.py` or it is invisible.
- **Reference text is a grid, not space-padded strings.** The help overlay
  builds a `rich.table.Table.grid` per section: a long description wraps *inside
  its own column* instead of falling back to the left margin, which is what made
  the old `{key:<20} {desc}` version unreadable. Titles carry weight, keys the
  cyan accent, secondary lines are dim - ANSI names, not hex, so it adapts to
  the terminal palette like the rest of the viewer.
- **The preset chooser is two lines per option** (`PresetScreen`): a bold name
  with the privilege badge right-aligned, and a dim, clipped preview of the
  flags. Both lines are `no_wrap` + ellipsis so neither the name nor the badge
  can spill onto a line of its own - the bug that made the old single-line
  chooser tear names apart. Scan-flow modals share an 84-wide frame.
- **Textual auto-focuses the first focusable widget on mount, `display: none`
  included.** `DetailReader`'s search `Input` was the only focusable widget in
  its `compose()`, so it silently held focus from the moment the screen
  mounted - the very `/` that was meant to *open* search instead got typed
  straight into the (still-hidden) box, and no amount of deferring `.focus()`
  in the handler fixed it, because the Input already owned focus before the
  handler ever ran. The fix is a focusable `_Body` (`can_focus = True` on a
  `Static` subclass) placed before the Input in `compose()`, so auto-focus
  lands there instead; `action_search()` can then focus the Input directly and
  synchronously, no workaround needed. Check what a screen's *default* focus
  lands on before chasing a stray-keystroke bug as a key-event race.
- **A `ModalScreen` captures unhandled input - but an App binding with
  `priority=True` pierces it.** Two halves of the same lesson, learned in
  opposite directions. Going *out*: `DetailReader` assumed `p` (freeze) would
  reach `NmapApp.action_freeze_log` while it was open, since neither the
  reader nor its focused child bind `p` - it does not. Unhandled keys stop at
  the modal, so the fix is an explicit callback
  (`DetailReader(..., on_freeze=self.action_freeze_log)`) rather than reliance
  on bubbling. Going *in*: `home,g` / `end,G` are `priority=True` so they beat
  DataTable's own home/end, and priority is checked *before* the screen - so
  they fired straight past every modal, and `G` in the reader, the help or the
  scan dialog silently jumped the list underneath to its last row while the
  reader's own `G` never ran. `App.check_action` is the fix, returning `None`
  for `jump` whenever `len(self.screen_stack) > 1`: that *declines* the
  binding instead of swallowing the key, so it carries on to the modal that
  should have had it. Returning early from the action itself would have been
  the wrong fix - the key would have been consumed and the modal would still
  never see it. Any `priority=True` binding is a modal leak until it is
  scoped.
- **The reader shows everything the pane shows, and may show more.** This is
  the amended form of what used to read "exactly what the pane shows". A
  capture collects fourteen headers, its cookies and its console log per URL;
  putting all of that in a pane that is often twelve rows tall would push a
  host's services and vulnerabilities off the screen, which is the failure the
  pane's own docstring was written against. So `_detail_content` takes
  `full: bool` and the reader passes `True`. The guarantee that matters is
  unchanged and is why the flag lives *there*: one function still decides what
  a row's detail is, so the two depths cannot drift into being two
  descriptions. A second renderer for "the detailed version" would have been
  the wrong shape.
- **A tool's own database is read defensively, or not at all.** gowitness's
  schema is generated by its ORM and is not a published interface, so
  `results.py` names no fixed column list: it reads `sqlite_master` and
  `PRAGMA table_info` first and selects only what exists, treats a missing
  optional table as empty data, and turns any `DatabaseError` into an entry on
  `Captures.problems` rather than an exception. It opens the file read-only
  (`file:…?mode=ro`) because a capture may still be writing to it. Two traps
  found the hard way, both silent: the screenshot column is **`filename`**
  while the JSON field was `file_name`, and header key casing depends on the
  protocol - HTTP/1.1 keeps what the server sent, HTTP/2 lowercases it - so
  every header lookup is case-insensitive.
- **A tool's results annotate the list that already shows its subject; they do
  not get a parallel section.** A service's record already listed every URL it
  answers on (`_service_urls` - the address plus every name, because virtual
  hosting means they serve different things). gowitness captures exactly those
  URLs, so a capture is a dim continuation line *under its own URL*, not a
  second "Captures" block listing the same URLs again with statuses. The host
  record does get a block, because there the question is "which of these forty
  is worth looking at" and that is read down a status column. Before reaching
  for a new section - or a new tab - check whether the thing the new data
  describes is already on screen.
- **A screenshot waits for the page, not for a clock.** gowitness has no
  wait-for-load flag; `capture.settle_script` is a function passed inline with
  `--javascript` that resolves when the document is complete, every image is
  in, and nothing has changed or finished downloading for
  `gowitness_settle_ms` - or at `gowitness_settle_cap_ms`. Three traps, all
  measured against 3.2.2 and all silent: the default `chromedp` driver does
  **not** await the promise (0.7 s for a promise of 8 s), so the capture runs
  `--driver gorod`; `--javascript-file` is not awaited under either driver, so
  the script travels in the argv on one line; and `gorod` *without* a script
  does not wait for navigation at all (title `about:blank`), so the driver and
  the script go together - `settle_ms=0` puts back `chromedp` and `--delay 3`.
  A page cannot see a request still in flight: one that is silent for longer
  than the quiet window before a single late response is captured early. That
  is the platform's limit; the quiet window is the knob. `--timeout` is raised
  to cover the delay and the cap, never lowered. A fourth trap, found on a real
  network's dashboards: a page that redirects itself as it loads
  (`location.replace`) destroys the page the script runs in, gowitness logs
  "Inspected target navigated or closed" and photographs at once - blank. It
  sleeps `--delay` *before* the script, so `gowitness_settle_delay_s` (1 s)
  lets the redirect finish first; 0 s gave a blank page, 1 s the login.
  Also observed and not explained: through an added 1.5 s per response,
  dashboards came out blank more often with six captures in parallel than one
  at a time (background-tab throttling is the suspect), while the old fixed
  delay was unaffected.
- **One `Runner` per tool; whether a second run may start is the caller's call.**
  A `Runner` supervises any number of runs (`active()`, a process per run,
  `cancel(run)`), so `self.runner` (nmap) and `self.captures` (gowitness) need
  no scheduler and no locks. Scans may run together: they share the network
  path and skew each other's timing, which the review says (`ScanPlan.warning`,
  `Session.scan_warning`) and the user may accept - a two-day scan must not
  block the quick version scan of what it already found. Two scans writing one
  `-oA` base are refused, and `output_base` adds `-2` when the XML exists.
  Captures stay one at a time (`capture_blocked`). Anything that asks "is
  something running" must ask both tools and every run - the quit guard,
  `on_unmount` (`Session.cancel_all`) and the run count; `cancel()` with no run
  named does nothing while several run.
- **A tool's absence is a state to render, not an entry to hide.** The capture
  entry stays in the export dialog when gowitness is missing, disabled, with
  the reason as its label; the status bar carries `◉ gowitness not found`. A
  feature that vanishes teaches nothing about why. `ChoiceScreen` takes a
  `disabled` set for exactly this.
- **A scan dialog gives way; its choices do not.** The four scan-flow modals
  (`scope.py`) share `_FRAME` (84 wide but `max-width: 100%`, `max-height:
  100%`) and `_Fits`: the one `.flex` part - the scope, the preset list, the
  command, the reviewed arguments - gets its `max-height` from the room the
  rest of the frame leaves, recomputed on mount, on resize and when a
  neighbour changes height. CSS alone cannot do it: an `fr` part makes an
  auto-height frame fill the whole screen. With 300 addresses the old fixed
  frames pushed start and the key line off an 80x24 terminal.
  `test_every_scan_dialog_fits_with_hundreds_of_targets` holds it at three
  sizes. Textual's `Checkbox` draws `X` on and off alike - `_Tick` draws
  `[x]` / `[ ]`.
- **A modal offers choices as an `OptionList`, never a stack of `Button`s.**
  Textual buttons are three rows tall: six export recipes needed more than
  twenty, ran off a 24-row terminal, and put the last choice out of reach with
  nothing to scroll. `ChoiceScreen` is one line per choice, moves with the same
  keys as every list in the app, and every modal states how to leave it.
- **An empty list is a state, not an absence.** `_refresh_empty` keeps the
  column headers (they say what would be here), shrinks the table to them, and
  puts a headline and a way out underneath - a filter that matched nothing has
  to read differently from a scan that found nothing. The region rule lives on
  `#list-area`, not on the table, so the message stays inside the fenced region
  when the table shrinks.
- **The hint bar chooses what to drop.** Clipping took whatever came last,
  which was `m`, `x` and `?` - the least guessable keys. `_fit_hints` keeps the
  two navigation hints, `?` and `Esc`, fills the rest in order, and appends `…`
  when something did not fit.
- **The command box is not a shell.** `presets.parse_command` splits with
  `shlex`, refuses shell metacharacters *by name*, pins the program to nmap and
  refuses user-supplied output flags; `runner` executes the argv with
  `create_subprocess_exec`. Nothing anywhere re-joins it into a string. Whether
  a command needs root is **derived from its flags** (`needs_root`), never
  declared per preset, so a pasted command is classified like a shipped one.
- **A tool runs in the viewer's session, never a new one.** `seek.runner`
  starts it with `process_group=0` (its own group, so cancelling reaches its
  children) and `stdin=DEVNULL`. It used `start_new_session=True`, and that
  is why no password-sudo scan could ever start: a new session has no
  controlling terminal, and sudo keeps its authorisation *per terminal*, so a
  `sudo -v` - here or "in another terminal", as the old error told the user -
  never counted (reproduced in a container). stdin is closed because a
  background group that reads the terminal is stopped, and nmap reads keys.
  Elevation takes the first route that works (`ScanPlan.via`): root, nmap's
  file capabilities (`presets.raw_capable`, which also checks the bounding
  set - a capability outside it makes the exec fail), then sudo.
  `nmap.runner.sudo_ready` asks by running `sudo -n <nmap> --version`, not
  `sudo -n -l`: with a password rule beside any unrelated NOPASSWD rule, `-l`
  says yes and the scan is refused. If sudo would ask, the TUI suspends and
  runs `sudo -v` (`_sudo_validate`); the browser refuses up front. seek never
  reads a password.
- **One catalogue of nmap options; the builder only reads it.**
  `nmap/options.py` holds every option nmap documents (7.99, the summary and the
  man-page sections). Each entry records its value form, how the value attaches
  (`-T4`, `-PS22,80`, `--opt v`), its default, root, its page, and an `owner`
  reason for the options seek sets itself. `RULES` say how options combine:
  exclusive, ignored or advice, each with a source. Four things read the
  catalogue: the builder, `recent.strip` (option arity tells a value from a
  target), the fine-tune list, and `test_nmap_options`, which pins the catalogue
  to nmap's summary and to `presets.needs_root`. `needs_root` gained the
  raw-packet evasion options for that reason. When nmap adds an option, add it
  here with its page.
  `nmap/builder.py` is pure: `State` (answers, user overrides in order, step) is
  immutable and JSON-serialisable. The web sends it back each time, so the
  server keeps none. Precedence is **user > answers > profile > measured >
  earlier scans > default**; every `Setting` keeps its source and what it
  overrode. A profile never touches a value the user set. Explanations quote
  nmap's guide, and the figures are pinned by a test.
  The history of commands (`recent.CommandHistory`,
  `nmap-commands.json` in the state dir) is the viewer's one exception to "writes
  nothing": arguments only, stripped of targets, paths and owned options, so it
  records habits, never an engagement. `Host.times` is what nmap measured; a
  merge keeps the slower one, because file order is not time order.
- **A notification says nothing about the engagement.** `seek/notify.py`
  builds a message from the preset or tool name, the outcome and the elapsed
  time, and is never handed anything else. That is why `CaptureRun.notify_name`
  exists: its `label` carries a directory name. The session sends: milestones
  from `on_line` (when `Run.fraction()` crosses 25/50/75), the end from
  `on_done`. One daemon thread (`_send_notices`) sends everything from a
  queue: in order, because concurrent threads delivered "finished" before
  "75 %", and a daemon rather than `asyncio.to_thread`, because `asyncio.run`
  waits for the loop's pool at exit and an unreachable webhook held the
  terminal for the whole timeout after quitting. A failure is posted back to
  the loop and `Run.append`ed to the log, never a state change. A URL
  with credentials is refused: no authentication is supported, and the URL is
  shown in every review. The config holds the default, and the plan carries
  it. The review returns the run's own choice on `ReviewScreen.notify_url` /
  `notify_progress`, and the web takes it on `ScanPlanIn` / `CaptureIn`.
- **Copied text is for a person; executed text is never joined.**
  `nmap/remote.py` is the one place an argv becomes a string (`shlex.join`),
  because the result is pasted into a shell by a person. The remote snippet is
  built by the same `build_argv` / `scan_argv` as the local run - bare program,
  relative paths, native backend - so the two forms cannot drift on a flag.
  Planning never depends on the tool being here: `Session.scan_blocked` /
  `capture_blocked` put *why it cannot start* on the plan (`blocked`), the
  review disables start and still copies, and `start_capture` writes
  `urls.txt` - a plan writes nothing, so a cancelled or copied review leaves
  the disk alone and a running capture's list is never replaced.
- **The shipped presets are derived from `nmap.md`**, the project's own nmap
  reference: its phase numbering (01 discovery, 02 services, 03 service
  specific) is the preset order and the output file names. A preset holds
  arguments only - no `sudo`, no `-iL`, no `-oA` - and `{ports}` expands to the
  open ports already in the model, which is the grep step the reference does
  between the top-1000 scan and the version scan.
- **A host is known by more names than its address, and none of them come from
  the address.** DNS has no reverse index for aliases, so `nmap/names.py` reads
  what the *server* gives away: certificate subjects and SANs, HTTP redirect
  targets, the FQDN Windows identity scripts announce, and certificate
  transparency lookups. It is to names what `vulns.py` is to findings - a
  recogniser run once by `views.prepare`, attaching `Service.names` as
  `(name, source)` pairs so no view re-parses script text on a keystroke.
  Two traps: the `ssl-cert` SANs live only in the structured `data`, never in
  `output`; and the redirect pattern is **anchored on "redirect to"/"Location:"**
  because a `http-vuln-*` script's advisory links are URLs too and their hosts
  are not this host. Wildcards and addresses are dropped. A hand-built `Host` in
  a test has no names until `names.attach` is called, exactly as it has no
  vulnerabilities.
  Names surface in the Names tab, the hostname column (`name +N`), both detail
  panes, `host_search_text` (so the filter finds them) and the URL export; the
  `url` *field* stays address-only, so both forms remain reachable.
- **The web interface is a second consumer of the viewer's model, never a
  second loader.** `w` starts `seek.web` in-process as a task on the viewer's
  event loop (see the session rule below); it reads the model through a
  `CachedSource` over the session, and `seek.web` imports neither Textual nor
  the app - `seek nmap serve` runs the same server with no app at all. Lists are the TUI's own projections filtered with
  `filtering.parse_filter`/`matches` and sorted with `vdefs.key_at` - the path
  `_narrow` takes - so the browser and the tab cannot disagree; do not re-derive
  a list in `seek.web`. `WebModel` is rebuilt only when the `ScanSet` identity
  or `Captures.generation` changes (2.9 s at 24 200 hosts / 95 000 captures,
  under `bulk.responsive()`). Three traps: FastAPI's `/docs` loads from a CDN
  and is off; uvicorn logs to stderr, over the viewer's terminal, so its
  loggers are silenced before it starts; and FastAPI is imported on the first
  `w` only - `seek` and `seek nmap` must not pay for it. Screenshots are served
  by capture id (`sha1(database, url, time)`), never by path. `Captures.all()`
  keeps every capture (two databases, one URL, two pictures) while `get()`
  stays newest-wins for the TUI. The browser opener is `app._open_browser`, a
  module function, so tests can replace it without patching `subprocess`.
- **One session, many front ends; one loop owns it.** `nmap/session.py` holds
  the model, both `Runner`s, the marks, capture discovery, the scan history and
  the per-run diffs - no Textual, no FastAPI. `NmapApp` keeps its old attribute
  names as properties onto it (`app.scans`, `app.runner`, `app._marked`, ...), so
  code and tests read as before; `_naming` is not `_name` because Textual's
  `DOMNode` owns that attribute. A finished run is folded back by the session's
  `owner` - the viewer's reading pipeline, or `web.serve.HeadlessOwner` - never
  by the session itself. Every change carries an `origin` so a front end can
  tell its own actions from another's: the viewer switches to the Scans tab for
  a run *it* started, never for a browser's. The web server runs on the same
  loop as the session because the `Runner`s are asyncio: a changing endpoint is
  `async def` and calls the session directly; anything that reads the model is a
  plain `def` (the threadpool) - `test_no_route_on_the_loop_reads_the_model`
  enforces it, and a blocking test must fetch via `asyncio.to_thread`, or it
  deadlocks against a server on its own loop. uvicorn's `capture_signals` is
  switched off; it would take SIGINT from Textual.
- **The browser's position is its URL.** Tab, drill path, filter, sort, toggles
  and selected row are query parameters (`/v/<tab>?path=h:10.0.0.5|p:...`), so
  back is the browser's history and two windows are independent. A drill step is
  named by what its row *is* (`web.views.step_of`), resolved by rebuilding the
  parent view and finding the same name - robust to a grown model. Lists,
  records, exports and scan plans all come from the functions the TUI uses
  (`tabs.tab_view`, `views.open_row`, `record.record_lines`, `export.produce`,
  `Session.draft_command`/`plan_scan`/`plan_capture`), and the record is
  converted to HTML *by style attribute* (`web/record.py`), so it cannot drift
  from the terminal's. **Parity rule: a viewer feature lands with its API
  endpoint**, and `keys.js` carries every viewer binding -
  `test_every_terminal_key_has_a_browser_key` fails otherwise.
  **Links come from the record, not from parsing it.** `detail.Line.to` says
  what a line is about (a `Host`, a `(Host, Service)`, a `Capture`); the web
  turns it into a link through `web/links.py` - the one place that says where a
  thing lives - and puts a capture's thumbnail after the last line about it.
  Never regex addresses or URLs out of rendered text to link them.
- **Search is one grammar and one rule set, everywhere.** `filtering` parses;
  a complete address is a *beginning* (`Range.prefixes`, or `FilterSpec.prefixes`
  on the fast path), `=addr`/`/32` is one host, `:443`/`443/tcp` are `port:`
  fields. After matching, both front ends call `filtering.prefer_firm` so rows
  holding the words beat scattered-letter matches (`~` opts out), and both match
  against `Session.row_text(row)` - the row's text plus its screenshots' titles,
  URLs, technologies and status. `filtering.explain` is the filter in words;
  every web list shows it. A list, the header search group and the TUI must list
  the same rows for the same text - `test_every_overview_lists_what_the_terminal_lists`.
- **The web layout is a shell, and a control is its key.** A viewer page
  (`body.shell`) is a fixed frame: bar, tab strip, two panes that scroll on
  their own, key bar. Do not put `position: sticky` with a pixel offset back -
  that is what broke whenever the header wrapped. The list pane's scroller
  (`.list-scroll`) is *inside* the fragment `fragment=1` replaces, so `app.js`
  restores its `scrollTop` after every swap; the record pane's header is
  outside what `showRecord` replaces. Three rules keep mouse and keyboard one
  interface: a toggle is a checkbox of the list form styled as a chip (it works
  without script and the URL stays the state); an action control is
  `button[data-action]`, dispatched to `HANDLERS` - the table the key handler
  uses - so it cannot do what its key does not; and a control's `<kbd>` is
  filled from `KEYS` (`data-key-of`), as the key bar is (`keys.js` `HINTS`,
  placed *after* the first `export function` because the parity test reads
  every string before it as a key). `test_web_layout.py` holds all three.
- **Colours are tokens, named by meaning, and the tests read them.** `app.css`
  opens with two token blocks (light, dark); every rule below takes its colour
  from them - a literal hex in a rule fails `test_no_colour_outside_the_tokens`.
  `test_web_layout.py` computes contrast for every text token on every surface
  and for the sixteen record colours (`--c-*`) on the pane and on the cursor
  tint, both themes, at 4.5:1; this has caught three near misses already.
  One accent (`--key`): position, focus, the primary action. `--open`,
  `--filtered`, `--closed` state a fact; `--mark` is a mark. A dim record span
  takes `--ink-3`, and a colour beats dim, because a dimmed colour falls under
  the contrast the colour is held to. Every dialog is `dialog(title, body,
  buttons, note)` in `actions.js`: one frame, one primary.
- **The software inventory is a session projection, never a model attachment.**
  `nmap/inventory.py` turns every source into `Observation`s - nmap's probe and
  its `<cpe>`s, OS matches, the scripts that *state* this service's software
  (`http-server-header`, header lines and greetings in `fingerprint-strings` /
  `banner`, `http-generator`, `smb-os-discovery`, `vulners` keys) and gowitness
  captures joined by `captures_by_service` - and reconciles each product in each
  place into one `Component`. Unlike `names`/`vulns` it is not attached in
  `views.prepare`: half the evidence is captures, which change without the model
  changing, so `Session.inventory()` caches it on `(scans identity, shots.generation)`
  and `View.stamp` adds the generation to the Inventory tab's row cache. Three
  rules: **observations are never discarded** - the version shown comes from
  the best rank (probe < banner < header < detection), a more specific version
  refines rather than conflicts, and a real disagreement is flagged with every
  version listed; **a CPE is never guessed** - nmap's are kept as written,
  anything else gets one only from `cpe.ALIASES`, and an unmapped product is
  shown as having none; **a recogniser reads only anchored text** - header
  lines, greetings, generator strings - never a page body or an advisory (the
  `http-vuln-*` fixture names Struts to prove it). A record reads it through
  `Session.inventory_ready()`, which builds inline only below
  `INLINE_INVENTORY_HOSTS`; above that the rows worker builds it. The JSON
  export and `GET /api/v1/inventory` are one document (`export.inventory_document`,
  `schema`/`version`) - the contract the vulnerability lookup reads; adding a
  field keeps the version, renaming or redefining one bumps it, and
  `test_version_1_fields_are_pinned` holds it. `U` drafts `-sV --version-all`
  over the union of the unversioned ports (one command has one port list) and
  states the extra pairs that costs.
- **The vulnerability database is reference data, and only an explicit update
  writes it.** `seek vulndb update`, or `A` confirmed in the viewer or the
  browser - never a session on its own: the viewer *offers* once (a notice
  naming `A`), and `A` states sources, size and age before anything runs. The
  URL set is fixed (`sources.Urls`, every slug in `eol.SLUGS`) so no request
  can carry session data - `test_requests_are_exactly_the_fixed_url_set` holds
  it. Sessions open the file read-only; each source ingests in one transaction,
  so a failed or cancelled update leaves the old data; the WAL is checkpointed
  on close so the file alone can be copied to an offline machine. Matching: a
  product is looked up under **every** CPE name it is known by
  (`cpe.cpe_keys` - NVD renamed nginx's vendor), only `vulnerable: true`
  criteria are stored (that is what drops "running on Linux"), and a version
  that cannot be ordered makes a CVE *undecided* - never affected, never safe;
  so does a version *less precise* than the bound (`versions.less_precise`:
  `4` vs `4.4.1`). OS/device components (kind `o`/`h`) are never CVE-matched -
  on the real sample `linux_kernel:4` from OS detection produced over 4 000
  findings and made the viewer crawl. Sources update smallest first.
  What a vulnerability script *tested* (everything but `vulners`, which is a
  version lookup) is `Finding.tested`, sorts first, survives the OS exclusion,
  and host scripts are filed under `match.host_key`. A version family is
  expanded into NVD's known releases (`rel`, from the CPE dictionary,
  pre-releases excluded): all covered = finding, none = nothing, some =
  candidate with `covered/known`. Tests cannot leave loopback (`_no_internet`
  in conftest) - a source added without a fixture once downloaded the real feed.
  An unversioned component gets no findings, only a count and the `U` hint.
  Database findings are per `Component` (shared across ports), scan-reported
  ones (`vulners`, NSE `vuln`) per service - `Lookup.of(c, where)` merges them.
  `Session.lookup()` is keyed on the inventory *and* `store.generation`, and the
  lookup views put the generation in `View.stamp`. Tests get a private
  `XDG_STATE_HOME` (conftest) so a real database never leaks into them.
- **A scan's progress is of the whole scan, read from -v lines.** nmap's
  `About X% done` is one phase of the current host group. `ScanRun` reads
  `Initiating <phase>`, `Scanning N hosts [`, the timing line and every
  `Nmap scan report for` - down hosts included, which nmap prints only at -v -
  and `fraction()` is (finished + group × phase %) / total: monotonic, below 1
  until the end, `None` without -v or a total. The total is nmap's own
  (`count_argv` → `nmap -sL -n` over the targets, `-iL`, `--exclude`, `-6`;
  none for `-iR`), counted in the background as the scan starts, with the last
  line kept only (a /8 lists 16 M lines). Two facts measured on 7.94 shape it:
  `--stats-every` prints **nothing** with stdin closed (it comes from the
  keypress handler, which wants a terminal nmap owns; a pty on stdin is not
  enough, and a session of its own breaks sudo), and stdout is block-buffered
  into the pipe, flushed at phase starts, timing lines and group ends - so
  counts can lag one flush. Milestones read the same `fraction()`.
- **Freezing the log is not pausing the scan.** nmap's timers run against the
  wall clock, so `SIGSTOP` can time hosts out on resume; `p` is a view state and
  the pane header says the scan is still running. `runner` only runs or cancels.
- **A scan is folded in by re-reading every source**, not by an incremental
  merge - one loading path means a scan started here and one run outside get
  identical treatment. The rebuild invalidates marks, so `_resolve_marks`
  re-finds them by identity afterwards. That happens at the end, whatever the
  outcome (a cancelled scan keeps what it finished), and **while it runs**:
  nmap writes each finished host group to the XML and prints `Nmap scan report
  for` per host, and the first such line starts a per-run timer
  (`Session._scan_line`) that fires after the burst - not on the next line,
  which may be hours away - calls `Owner.scan_grew`, and re-reads only if the
  file grew. The TUI's live read is quiet (`_live_token`, no `_Busy`, the
  "so far" note on the status line) and is declined while any read or
  projection runs; the timer asks again. Pacing is `max(60 s, 4 × a re-read)`.
  A run's diff baseline is taken as it starts, in a thread
  (`Session._take_baseline`), and `run_diff` counts only the hosts in the
  run's own file - every read re-reads every source, so a baseline taken at the
  run's first read already held what another scan's read put in, and two scans
  ending together counted each other's hosts (both found with a real nmap).
  The TUI refreshes with `growing=True` so the cursor follows its row by key:
  new hosts sort in above it on every read. A running run's
  file is not "cut off" and is listed once, as the run (`running_paths`).
- **The Scans tab is a history over `ScanSet.files`, not just this session's
  runs.** `nmap/timeline.py` orders every scan file by its `<nmaprun start>`
  epoch and diffs each against the merged state of all earlier ones.
  Two traps it exists to avoid: (1) `merge` mutates the earliest file's `Host`
  objects, so the retained per-file `hosts` are NOT "what that scan saw" - the
  timeline **re-parses** each file pristinely; (2) `merge` mutates in place, so
  the cumulative `before` snapshot is a `deepcopy` taken ahead of each step, or
  every diff reads back empty. The build re-parses, so the app caches it
  (`_scan_history`, keyed on `self.scans` identity) and rebuilds only when the
  model changes; the Scans `View.build` recomputes only the live-run rows each
  refresh. A finished in-app run is deduped against its own output file so it is
  listed once, as the file.
- **A running scan redraws four times a second, not once a line.** nmap at
  `-v` prints hundreds of lines a second, and each line used to rebuild the run
  list and render the record pane three times, each render rebuilding the whole
  log as one Rich `Text` per line (2.5 million objects for 1200 lines, 1.9 s of
  frozen interface). Now `_on_scan_line` only schedules `_live_refresh`
  (`_LIVE_REFRESH`), the pane's log is one `Text` of the newest `PANE_TAIL` lines,
  cached per run and depth (`scans._log_lines`), and `_refresh_detail` coalesces
  to one `_draw_detail` per refresh. The reader (`full=True`) still has every
  line. The browser gets the tail while a run is running, because it re-fetches
  the record every 400 ms in the same process. So does the reader (`d`) while a run is live
  and not frozen: the whole 20 000 lines took 0.9 s to render, four times a
  second (`record_lines`). A run's row is redrawn once a second by `_on_tick`
  even when the tool is silent, so its elapsed clock never stops. Output is
  read with a 16 MiB line limit (`runner.LINE_LIMIT`), and a longer line is
  cut, not raised: asyncio's 64 KiB default raised out of the read loop, the
  run stayed "running" for ever, and the undrained pipe blocked nmap. Built
  commands carry `-v`, because the progress lines are only printed then.
- **A stale tab report is not a click.** `_activate`/`_sync_tab` set
  `Tabs.active`, and Textual reports that later as `TabActivated`. When a second
  switch comes first (a scan starting while a key was pressed, a lagging loop),
  the first report is stale. Taken as a click, it switched back, its own report
  switched forward, and two tabs alternated for as long as the loop lagged.
  `on_tabs_tab_activated` ignores a report that no longer matches the tab row;
  `test_two_quick_tab_switches_settle_on_the_last` holds it.
- **A view sorts its rows once.** `View.ordered` caches the shown order with the
  rows (24 200 hosts are about 60 ms of `key_at`), and the projection worker
  warms it, so a redraw only copies. `_narrow` uses it when no filter is set.
  `_refresh_warning` counts per model, not per redraw.
- **The collector is the pause, not the work.** At engagement scale the model is
  millions of tracked container objects and every generational collection walks
  all of them - measured at 1.9 s of frozen interface in the middle of a
  projection. `nmap/bulk.py` holds the policy: `bulk()` suspends collection for
  one phase **and freezes what survived on the way out**, because suspending
  alone only moves the pause to the first allocation after the phase (354 ms
  against 4 ms, measured). `responsive()` shortens the thread switch interval so
  the event loop gets its turn between keystrokes. The policy is applied at the
  two phase *owners* - the reading worker and the projection worker - and
  nowhere else: `load`, `merge`, `timeline.build` and the projections are pure,
  are imported directly by tests and by the export path, and a library call that
  turns the host program's collector off is a surprise that outlives it. The
  freeze/unfreeze pair lives in `NmapApp._publish`, the one place `self.scans`
  is ever replaced, because it is a *pair*. On CPython 3.14 `gc.freeze()` costs in
  proportion to what was allocated since the last freeze (144 ms for a whole
  engagement at once), so the two owners also freeze as they go - per file in
  `_read_scans`, per progress report in `_build_rows` - and the freeze in
  `_publish` finds almost nothing left (100 ms → 3 ms).
- **One report shape for every long step.** `nmap/progress.py` defines it: work
  done, work total, and the unit counted. `merge.load` reports files (with a
  total of zero during the walk, which means "cannot count itself yet"),
  `timeline.build` reports scans, every overview reports hosts. One renderer in
  the viewer draws any of them, so a step that learns to count needs no new
  drawing code and no mapping table. `counted()` wraps a loop and guarantees the
  two properties the renderer relies on: monotonic, and a last report at
  `done == total`. A `View` opts in with `reports=True`; the default is the
  one-argument builder every drill-down and every test fixture still uses.
- **The viewer opens on files, not on a model.** `NmapApp` takes a `ScanSet`
  *or* a `merge.Pending`. The finished-model path is untouched - that is what
  every existing test exercises - and the `Pending` path reads in a worker,
  folding file by file into a `merge.Accumulator` and publishing an immutable
  snapshot on a throttled cadence. The accumulator copies a host before a later
  file writes to it again (`_private` is the set nothing has seen yet), which is
  what makes "never half-merged" true rather than hoped for. Publications
  *coalesce*: a snapshot arriving while a projection runs supersedes the one
  waiting instead of queueing. Consequence recorded in the specs: candidates
  that all fail to parse can no longer be found out before the viewer opens, so
  the viewer says so and the process exits non-zero.
- **A batch must never take the list away.** Three rules make that true, and
  dropping any one of them puts a progress bar back over working rows.
  (1) A rebuild for the *same* view over a grown model is `quiet`: the rows
  stay, the report goes to the status line, and `Esc` keeps its ordinary
  meaning because the reader is not waiting for anything. (2) Nothing is ever
  published while a build or a fill is running - not even the last snapshot of
  a read - because a build left projecting a superseded model clears the table
  when it finishes. Everything that ends a build or a fill drains the park
  instead. (3) The next batch is taken no sooner than the last one took to
  absorb (`_ABSORB_HEADROOM`), so the interface spends at most half its time
  replacing the list and the rest answering the reader.
- **The cursor is placed once per fill, not once per chunk.** Resolved against
  the whole list in `_fill` and applied by the first chunk that reaches it. Per
  chunk, a list long enough to arrive in instalments dragged the selection back
  every frame and could not be moved around while it filled. For the same
  reason the mark a growing model restores to is taken when the rows are
  actually replaced, not when the batch was published - the reader may have
  moved in between.
- **A filter belongs to a level, not to the box.** The `#filter` Input is one
  widget shared by every view, so a level's filter survives only by being
  carried in its `_Mark` (`_Mark.filter`): a drill-down saves it and starts
  the new level empty, `Esc` puts it back. Tabs do the same through
  `_tab_marks`, filed under the tab of `stack[0]` - `_sync_tab` may have moved
  the tab row on during a drill-down. Restoring goes through `_set_filter`,
  which suppresses `Input.Changed`: the debounced rebuild it would schedule has
  no mark and would put the cursor back at the top after the restore placed it.
- **A mark finds its row by identity, then by what the row *is*, then by
  position.** The middle one is what a growing model needs: `merge` copies a
  host before a later file writes to it, so after a batch the row the cursor
  was on is a different object describing the same host. Identity alone found
  it only while nothing had touched it, and the fall-through to the row number
  then put the cursor on whatever had since been inserted there. `_Mark.key` is
  the row's section and first cell - an address, a name, a bucket label - the
  one part of a row a later scan cannot change.
- **The fill is budgeted in time, and reaches the cursor before it stops.**
  `_FILL_CHUNK` rows unconditionally (a screenful), then as many more as fit in
  `_FILL_BUDGET`, except that it keeps going up to `_FILL_REACH` while the row
  the reader was on has not been handed over yet. Without that last part the
  table sits at the top of the list until the reader's row arrives with its own
  chunk - a second of it on a large engagement, on every batch, which is what
  "the selection jumps around" looks like from the outside. The record pane is
  refreshed the moment the cursor lands rather than when the last chunk does,
  for the same reason.
- **Measuring the columns is a pass over every cell.** `View.measure()` does it
  in the projection worker and caches it with the rows; `_column_widths` only
  does the trimming. On the event loop it was 165 ms for a fifty-thousand-row
  projection. `seek.tui.cells.width_of` is the ASCII shortcut that makes the
  pass itself cheap - `rich.cells.cell_len` walks the string.
- **Textual `repr`s a worker's arguments.** `_build_rows(view, scans, token)`
  meant a dataclass repr of every host, service and script result on the event
  loop - 2.8 s at 24 200 hosts, for a string nobody reads. `ScanSet.__repr__` is
  hand-written and `View.hosts` is `repr=False`. Anything handed to a thread
  worker has to be cheap to `repr`.
- **A record pane is a dozen rows; a bucket can hold twenty-four thousand.**
  `detail.py` lists a bucket's members up to `_MEMBER_LIMIT` and its aggregated
  scripts up to `_SCRIPT_LIMIT`, then says how many more there are - `Enter`
  already opens the whole bucket as a table, which is chunked into the terminal.
  Before that, `grouping_detail` rescanned every member per host (their product,
  billions of operations) and a service group carried every `ssl-cert` on every
  host: fifteen thousand lines that Textual renders in full merely to *measure*
  the pane. Nothing a record says is elided; a list of members is not a finding.
- **A record is a list of lines, and a line may carry an action.**
  `detail.render()` returns `list[Line]`, not a `Group`; `as_group` joins them
  for the reader. That is what lets the pane have a cursor - "which line am I
  on" has to have an answer before a line can be chosen - while keeping one
  builder for both views, which is the invariant that stops the pane and the
  reader becoming two descriptions of a record. A *line* is one thing a
  renderer emitted, not one row of the terminal: a wrapped line is one cursor
  stop, so the cursor does not move when the window is resized.
- **One key pair per axis, and every arrow has its vim twin.** `↑`/`↓` and
  `j`/`k` move the list; `←`/`→` and `h`/`l` move the record pane's line
  cursor, like a text editor's: every line is a stop, the record scrolls to
  keep the cursor in view, and a line that opens something is *underlined*
  (`detail._LINK`) so it reads as a link before the cursor reaches it - `o`
  opens the line under the cursor. There is no `J`/`K`: a second pair doing
  what an arrow does is the divergence this rule exists to prevent. The arrows
  are bound on `ScanTable`, not the app, so the filter box keeps them for
  editing; `h`/`l` are app bindings because a focused `Input` swallows
  printable keys anyway. The pane does not step between rows or between scans
  - reading one record after another is the full-screen reader's job (`d`:
  `↑`/`↓` scroll, `←`/`→` step rows), or the list's.
  **When the cursor cannot move, the keys scroll a line.** A scan's report
  and a capture's log are one renderable as far as the pane is concerned, so
  the cursor has one stop; without the fall-back those records could not be
  read past the fold at all.
- **The reader has the pane's two levels, and an arrow never leaves one.**
  `DetailReader` is handed a record as `list[Line]` (so it has a cursor and
  links, like the pane) or anything else as one block (plain scroll - a live
  log, and every test that builds one from a `Group`). `o` asks the app
  (`on_open` → `NmapApp._raw_page`) for a scan's text and keeps the record in
  `_record` for `Esc`; in the text `←`/`→` ask `on_sibling` for the other
  scans of the *same subject*, never `on_step` for another row - that was the
  bug: stepping from nmap's text landed on a different row's record. A reader
  opened while the pane shows raw output starts in the text with the row's
  record behind it (`raw=`), and `_opening` finds the link by scan, address
  and port, because the pane's record and the reader's fuller one are built
  separately. `update()` while in the text refreshes the record behind it,
  not the text on screen.
- **`nmap/rawlog.py` answers "which lines", never "what do they mean".** It
  cuts one host or one port out of a scan's `.nmap` text by boundary search -
  a report line opens a host, a port line opens a port, `|`/`|_` continue it.
  The XML stays the single source of the model; text that disagreed with it
  would be a bug to look at, not a second opinion to merge. Three traps it
  exists to survive, all in the fixtures: a report line carries either
  `<addr>` or `<name> (<addr>)`; `10.10.10.1` must not open `10.10.10.10`'s
  block; and a port number occurs inside other ports' script output, so a port
  line is recognised by its shape at the start of a line.
- **Nothing expensive happens while the record pane redraws.** It redraws on
  every movement of the *list* cursor, so the entries come from
  `rawlog.Scanned` - built once per model and kept beside it, like the scan
  history - and the `.nmap` file is opened only when an entry is opened, cached
  by path. Deriving the entries per draw was 5 ms against 0.13 ms to draw the
  record; a `stat` per file per draw was in there too. Above
  `_RAW_INLINE_MAX` the read goes to a worker: measured at ~6 ms per MB, so a
  14 MB engagement is inline and a 70 MB one is not.
- **Real scan output is never committed.** `test_scans/` is gitignored, so the
  `.nmap` fixtures beside `tests/fixtures/nmap/*.xml` are written by hand to
  reproduce the shapes nmap writes, and the real directory is what the cutting
  is checked against by hand. `xml-only.xml` deliberately has no sibling - it
  is what the reconstruction path is tested against, so do not add one.
- **No test ever runs nmap.** `Config.nmap_path` exists so tests can point at a
  stub script; a stub must answer `--version`, because the app probes with it.
- **Marks are keyed by record identity, never by row.** Every view is rebuilt
  from the model on every filter keystroke, sort, resize and tab switch, so a
  mark held as a row index or a row object is stale immediately.
  `NmapApp._marked` is an insertion-ordered `dict[identity, Record]`; the order
  is the export order. Each `Row` carries the `Record`s it stands for
  (`Row.records`), which is also what makes a bucket row mark every pair in it.
- **`nmap/export.py` is pure** - records in, text out, no Textual and no
  `ScanSet`. That is deliberate: the same selection is meant to be handed to a
  tool runner later. Keep the screen out of it, and keep the field catalogue's
  order meaningful (it *is* the column order in every format).
- **The tab row follows the stack, but only a tab click rebuilds it.** A `View`
  names the tab whose subject it shows (`View.tab`); `_sync_tab` marks the
  topmost view in the stack that claims one, after every push and pop. It sets
  `_active_tab` *before* assigning `Tabs.active`, which is what keeps
  `on_tabs_tab_activated` from treating the sync as a user selection and
  replacing the stack. A host's own record claims no tab, so it inherits the
  context it was opened from.
- **A section heading is a row.** The statistics view is divided into sections,
  and `Row.section`/`section_rank`/`heading`/`style` are how: `_narrow` sorts in
  **two stable passes** - by the chosen column with `reverse`, then by
  `(section_rank, heading)` - so the section order leads and `reverse` belongs to
  the column alone. One compound key with `reverse=True` would turn the sections
  upside down and push every heading below its own lines. Headings carry no
  filter text (nothing should match the word "Ports"), so they survive the filter
  and `_drop_empty_sections` removes the ones left with nothing under them.
  Every other view leaves these fields at their defaults, which makes the whole
  mechanism a no-op there - keep it that way.
- **`App.on_resize` is never dispatched** - `Resize` goes to the Screen. The nmap
  viewer polls on an interval instead; `SeekApp.on_resize` is likewise dead code
  and only works because `_on_tick` calls `_apply_responsive_layout` anyway.
- `benchmarks/check_nmap_real.py` parses the gitignored `nmap/` scans; run it
  after touching `seek.nmap.parse`. Real scan data must never be committed.

## OpenSpec

Archived behaviour lives in `openspec/specs/<capability>/spec.md` (**the source
of truth**). Work in progress is a change under `openspec/changes/<change>/`:

- `proposal.md` — why + what + capabilities
- `specs/<capability>/spec.md` — the delta to the behaviour contract
- `design.md` — how, and the rationale behind the technical decisions
- `tasks.md` — the implementation checklist

`openspec list` shows the open changes. When you change behaviour, update the
relevant spec in the same change and keep it valid
(`openspec validate <change> --strict`). `openspec status --change <change>
--json` shows artifact state.
