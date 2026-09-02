# AGENTS.md

Guidance for coding agents working in this repository.

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
```

`benchmarks/` is **not** collected by `pytest` (`testpaths = ["tests"]`) — it is
slow and needs a corpus. Run it before and after any change to `engine/` and
compare against the baseline recorded in the script's docstring.

If a stale-virtualenv warning is noisy, prefix commands with `env -u VIRTUAL_ENV`.

Python **3.11+** (uses `tomllib`, `enum.StrEnum`). Runtime deps are kept minimal:
`typer`, `textual`, `rich` (via textual), `pyperclip`; `pathspec` is an optional
extra used only for `.gitignore` support.

## Before you finish a change

1. `uv run ruff check` — must be clean.
2. `uv run pytest -q` — must be green (~100 tests, ~1 min; many drive the TUI
   via Textual's `Pilot` and need real time to settle).
3. If you changed `Config` fields: regenerate the example file —
   `uv run python -c "from seek.config import example_toml; open('config.example.toml','w').write(example_toml())"`.
4. If you changed observable behaviour: update the matching spec in
   `openspec/changes/terminal-search-app/specs/` and run
   `openspec validate terminal-search-app --strict`.

## Layout

```
src/seek/
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
    results.py      ResultsList (OptionList subclass): row rendering, clipping, marks
    preview.py      build_preview(): windowed syntax + query highlight; header
    detail.py       DetailScreen: full-file pager (j/k/g/G/Ctrl+D…)
    tree.py         render_tree(): coloured directory tree (Rich Text)
    menu.py         action menu / confirm / prompt / choice modal screens
    help.py         help overlay
    query_input.py  QueryInput(Input): `?`-on-empty opens help
    actions_mixin.py  ActionsMixin: result actions + perform_exit_request()
  nmap/
    models.py       Host / Service / ScriptResult / Vulnerability / ScanSet
    parse.py        iterparse reader (`<nmaprun>` root check, else NmapParseError)
    merge.py        consolidate several scans; directory expansion; provenance
    vulns.py        lift findings out of script results (NSE `vuln`, vulners)
    views.py        projections: service groups, statistics, grouping
    export.py       Record (host + optional service), field catalogue, writers
    presets.py      is nmap here, preset -> argv, privilege from flags, targets
    runner.py       one scan: launch, stream, cancel, classify. No Textual.
    diff.py         what a scan added to what was already known
  tui/nmap/
    views.py        column specs + row builders per view
    detail.py       full record for the selected row (scripts, vulnerabilities)
    app.py          NmapApp: table + detail pane, one filter, one breadcrumb
    scans.py        the Scans tab: run list + the three report modes
    scope.py        scope editor, editable command, the review before it runs
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

**Actions that hand off the terminal** (open in editor / default app, print to
stdout, `cd`) cannot run while Textual owns the screen. They set
`app.exit_request` and call `self.exit(0)`; `run_session` then calls
`perform_exit_request` *after* `app.run()` returns and the terminal is restored.

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
- **`line_no`-style split, again:** a host's *recorded* state (`state`/`reason`)
  and its *evidence-based* `reachable` are different things. `-Pn` makes nmap
  report `up` with reason `user-set` for every target — 255 of 256 in the real
  sample, 9 of which had any evidence. Never present the asserted count as
  observed; `Host.reachable` is the one to list and filter by.
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
- **The shipped presets are derived from `nmap.md`**, the project's own nmap
  reference: its phase numbering (01 discovery, 02 services, 03 service
  specific) is the preset order and the output file names. A preset holds
  arguments only - no `sudo`, no `-iL`, no `-oA` - and `{ports}` expands to the
  open ports already in the model, which is the grep step the reference does
  between the top-1000 scan and the version scan.
- **A host is known by more names than its address.** `nmap/names.py` is to
  names what `vulns.py` is to findings: a recogniser run once by
  `views.prepare`, attaching `Service.cert_names` so no view re-parses script
  text on a keystroke. It reads the `ssl-cert` subject *and* its SAN table - the
  SANs are only in the structured `data`, never in `output`, so text-only
  parsing misses half. Wildcards and addresses are dropped: nothing resolves
  `*.example.test`. A hand-built `Host` in a test has no names until
  `names.attach` is called, exactly as it has no vulnerabilities.
  Names surface in the Names tab, the hostname column (`name +N`), both detail
  panes, `host_search_text` (so the filter finds them) and the URL export; the
  `url` *field* stays address-only, so both forms remain reachable.
- **Freezing the log is not pausing the scan.** nmap's timers run against the
  wall clock, so `SIGSTOP` can time hosts out on resume; `p` is a view state and
  the pane header says the scan is still running. `runner` only runs or cancels.
- **A finished scan is folded in by re-reading every source**, not by an
  incremental merge - one loading path means a scan started here and one run
  outside get identical treatment. The rebuild invalidates marks, so
  `_resolve_marks` re-finds them by identity afterwards.
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

Planning artifacts for the current body of work live in
`openspec/changes/terminal-search-app/`:

- `proposal.md` — why + what + capabilities
- `specs/<capability>/spec.md` — the behaviour contract (**source of truth**)
- `design.md` — how, and the rationale behind the technical decisions
- `tasks.md` — the implementation checklist (all currently checked)

When you change behaviour, update the relevant `specs/**/spec.md` in the same
change and keep it valid (`openspec validate terminal-search-app --strict`).
`openspec status --change terminal-search-app --json` shows artifact state.
