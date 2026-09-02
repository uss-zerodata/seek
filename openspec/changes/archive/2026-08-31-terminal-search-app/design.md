## Context

See `proposal.md` — Why for motivation. This is a greenfield Python application in an otherwise empty repo. The workflow being replaced is three one-shot fzf wrappers (`s`/`f`/`d`) that shell out to `fdfind`, `ripgrep`, `batcat`, and `wl-copy` per invocation and reset on every run.

Constraints that shape the approach:

- Target platforms: Linux (primary, Wayland), macOS, and Windows. No compiled extensions should be required.
- Python is slower than `fd`/`rg`, so the walk and content search must be incremental, debounced, and cancellable to stay responsive on large trees.
- The query box owns keyboard text at all times (see `interactive-tui`), so every action must bind to a modifier or non-printable key, or live in a menu.
- Distribution for v1 is `uvx --from git+…` / `uv run` from a clone — no PyPI release — so the entry point and shell integration must work from that form.

## Goals / Non-Goals

**Goals:**

- One persistent process per `seek` invocation; query, streamed candidates, selection, preview, and breadcrumb stack all share state until exit.
- Responsive typing on large trees: name matching from an in-memory index, content matching from a budgeted in-memory cache with a disk-rescan fallback, all behind a 150 ms debounce and a generation counter that discards stale work.
- Robust preview for arbitrarily large files via bounded reads (never "load the whole file and hope").
- Pure-Python runtime dependencies plus optional external CLIs only at action time (opener, editors, clipboard fallback).

**Non-Goals:**

- Any non-interactive / scriptable / `--json` mode (explicitly deferred to a later change).
- A PyPI release, Homebrew formula, or standalone binary in v1.
- fish / PowerShell shell integration in v1 (bash + zsh only).
- Replacing the editors it shells out to; full-file viewing beyond the size cap is delegated to them.
- Project-local config files, per-directory remembered queries, undo/redo. Global query history is in scope; the rest is not.
- Honoring `.gitignore` by default (opt-in only).

## Decisions

### Language and libraries: Python 3.11+, uv, Typer, Textual, Rich

- **Python 3.11+** for standard-library `tomllib` (config parsing with no dependency) and modern typing. Managed with **uv** (`pyproject.toml` + `uv.lock`); run via `uv run seek` / `uvx --from git+…`.
- **Typer** for the CLI: the `-f/-d/-c/-r` flags, positional patterns, and the `init` subcommand. Chosen over argparse for declarative subcommands and generated help; over Click directly because Typer is a thin, typed layer over it.
- **Textual** for the TUI (query input, streamed list, preview, detail view, action menu, help overlay, breadcrumb). It provides an async event loop, a worker API with cancellation, a virtualized list widget, mouse support, and a command-palette widget reusable as the action menu. Rejected: raw `curses` (no async, poor Windows story, no widget layer); `prompt_toolkit` (excellent input handling but a heavier lift for the multi-pane layout and streaming list); wrapping `fzf` as a subprocess (was the whole old UI — precludes first-class multi-type rows, live mode toggles, and bounded previews).

**Layout mirrors fzf's default.** Top to bottom: preview pane, result list (fills), status bar, prompt row (`❯` glyph + query input). The list is rendered bottom-up — best match on the bottom row next to the query box, weaker matches above — and the cursor starts on that best match. `↑`/`↓` follow visual direction. The result list is the priority: `on_resize` (backed by the 0.3 s tick as a safety net) drops the preview pane below a terminal height threshold (~15 rows) or when there is nothing to preview, so the list is always visible and readable. A no-match query swaps the list for a centred hint.

**Colour under ANSI themes.** The `ansi-dark` theme collapses Textual's `$panel` / `$surface` / `$boost` to the terminal background, so region separation cannot rely on subtle background shades. Instead: the preview/list divider and the list/input divider are the blue `border-bottom` on the preview and a solid blue (`$primary`) status band; the status band carries the `[f d c]` mode letters (bold when active, dim when off) and the `shown/total` count (right-aligned via a `Table.grid`), styled to read on blue. The highlighted row is reverse video (theme-independent). Rendered *text* — result rows (path / basename / matched content / match spans in separate colours), the tree view (directories, branch glyphs, and files-by-extension), and the preview — is styled with explicit Rich colours from the `theme` config table, so those stay overridable.

**Result rows are shortened, not wrapped.** Textual's `OptionList` wraps option text and ignores Rich's `no_wrap`, so each row is pre-clipped to the list width before it is handed to the widget: a content line is windowed around its first match (`…` on the elided sides), a path keeps its tail (basename). `wrap_results = true` disables the clipping and lets the widget wrap. Rows re-render on resize when the width changes. The path prefix, the file's basename, and the matched source text are drawn in separate theme colours so a row parses at a glance.

**Preview centres on the match within the real pane height.** The side preview is not scrollable, so it is rendered to exactly the pane's visible line count with the matched line in the middle (measured on the main thread, then built in a worker — see the search-execution notes). The detail view renders the whole file (to the size cap) once with syntax + match highlighting baked in, so a plain `VerticalScroll` keeps matches highlighted while paging; syntax highlighting is skipped past ~5000 visible lines to keep it responsive.
- **Rich** (bundled with Textual) for syntax highlighting in previews via `rich.syntax.Syntax`, rendered against the terminal palette (ANSI theme) so the app stays terminal-native. Falls back to plain text when no lexer matches.
- **Fuzzy matching:** a self-contained pure-Python fzf-style scorer — greedy forward/backward subsequence match with bonuses for word starts, camelCase, and path separators, plus gap penalties — behind a stable `score(term, text) -> (int, list[int]) | None` interface (score + matched positions for highlighting). A thin parser on top handles the extended syntax (`^ $ ! '` and AND terms). `rapidfuzz` was evaluated as the primitive but is edit-distance oriented and exposes no subsequence match positions, so it added a dependency without the fzf-style ranking; the hand-rolled scorer is ~120 lines and the interface lets it be swapped later. Rejected: `thefuzz`/`fuzzywuzzy` (no matched-span output, GPL), shelling to `fzf --filter` (loses per-row type metadata and content line numbers).
- **Clipboard:** `pyperclip` as the primary mechanism, with an explicit fallback chain to `wl-copy` → `xclip`/`xsel` → `pbcopy` → `clip.exe` detected at runtime. Rejected relying only on shelling out: less portable to macOS/Windows; rejected relying only on `pyperclip`: unreliable under headless Wayland.
- **Config:** stdlib `tomllib` (read-only, which is all v1 needs). Path resolution via a tiny XDG helper (`platformdirs` if a dependency is acceptable, else hand-rolled: `$XDG_CONFIG_HOME`/`~/.config` on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows).

### Walk: streaming producer with `os.scandir`, symlink-loop guard, default noise excludes

A background worker walks the scoped root with `os.scandir` (fast, no stat unless needed), pushing `Candidate` records onto a queue the UI drains on a timer. Symlinked directories are followed, but every directory's real path (`os.stat` `st_dev`/`st_ino`, or `realpath` on Windows) is tracked in a visited set to break cycles. `.git` and the built-in noise set (`node_modules`, `.venv`, `__pycache__`, `target`, `dist`) are pruned at the directory level before descending; config can extend the exclude globs or disable the noise set. `.gitignore` is ignored unless the opt-in flag/config is set, in which case a `pathspec`-based matcher (or `gitignore_parser`) is layered on. Positional glob patterns compile to `fnmatch`/`pathspec` matchers (basename vs relative-path by the presence of `/`); `-r` compiles to `re.Pattern`. Smart-case is applied per pattern.

Rejected: eager full walk before showing anything (multi-second freeze on big trees); re-walking per keystroke like the old functions (the dominant cost the proposal calls out).

### Search execution: generation counter + Textual workers, no per-keystroke disk re-walk

Every query change (after the 150 ms debounce) increments a generation counter and starts a Textual worker. The worker:

1. Re-scores the in-memory name/dir index against the parsed query (cheap, all in RAM).
2. If content mode is active and the content portion of the query is ≥ the minimum length, scans file contents: from the in-memory content cache for cached files, by reading from disk for the overflow. Content scanning yields results in chunks so the list fills progressively.
3. Checks the generation counter before every chunk it publishes and stops immediately if it is stale.

The content cache is populated lazily (first time a file is needed) up to a byte budget (default e.g. 512 MB, configurable); a simple size-aware policy keeps the most recently used files and lets the rest fall back to disk reads. Because cooperatively-cancelled search threads can briefly overlap, the cache guards its bookkeeping with a lock. Results from all three types go into one list sorted by score (`interactive-tui` shows the type via a marker only).

**The result set is capped** (`max_results`, default 500) with `heapq.nlargest`, and the engine reports the pre-cap total so the status line can show `shown / total`. This is what keeps a broad query (`e` over a 100k-file tree) from building and rendering a 100k-row list. During the content pass the engine also calls a `publish` callback with ranked, capped snapshots every ~300 new hits, so content matches stream into the list instead of appearing all at once.

**Mid-scan updates keep the cursor put.** During the walk the app re-runs the search only when the candidate count has grown enough to matter (not on every 0.3 s tick), and `_apply_results` preserves the highlighted result by identity whenever the query text is unchanged — it only snaps the cursor to the best match when the query itself changed. Otherwise the streaming updates would yank the selection out from under the user.

**Previews are built off the UI thread.** Selecting a row schedules a ~50 ms-debounced `@work(thread=True, exclusive=True)` that does the disk read and Pygments pass and then pushes the renderable back via `call_from_thread`; the pane height is measured on the main thread before the worker starts. This keeps navigation and typing responsive even over multi-megabyte files or slow storage. A one-line header (path + `:line` + language) is rendered above the window so context survives row shortening.

Rejected: an async runtime like `trio` on top of Textual's own loop (unnecessary — Textual workers + a thread pool for blocking file I/O suffice); caching every file unconditionally (unbounded memory on large trees).

### Preview: bounded reads, windowed on the match

The preview reads at most a bounded window (default ~200 lines) centered on the target line — or from the top for a name match — and never the whole file. The detail view reads the whole file **only up to the size cap** (default 5 MB) and then shows a truncation marker; beyond that the user opens an editor. Both syntax-highlight only the loaded window via `rich.syntax.Syntax(...).highlight()`, then overlay per-character query-match highlights on every visible line (tabs are expanded first so match positions line up). Directory previews are a depth-limited `os.scandir` walk formatted as a tree, reusing the same exclusion logic. Binary files (NUL in the first chunk) render as `<binary file>` rather than garbage.

### Keymap (query box always focused)

Defaults, all overridable via config:

| Key | Action |
| --- | --- |
| printable | edit query |
| `←` / `→` | move query cursor |
| `↑` / `↓` | move highlighted row |
| `PageUp` / `PageDown` | page the list / scroll the detail view |
| `Enter` | open detail view of the highlighted row |
| `Esc` | close overlay/menu → close detail view → pop breadcrumb → quit |
| `Tab` | toggle mark on the highlighted row |
| `Shift+Tab` | clear all marks |
| `Alt+↑` / `Alt+↓` | recall previous / next query from history |
| `Ctrl+F` / `Ctrl+D` / `Ctrl+T` | toggle filename / directory / content mode |
| `Ctrl+R` | re-root at the highlighted/detail directory |
| `Alt+←` | pop one breadcrumb level |
| `Ctrl+G` | manual refresh (re-walk) |
| `Ctrl+K` | open the action menu |
| `Ctrl+O` | open in OS default application |
| `Ctrl+E` | open in the default editor |
| `Ctrl+B` | open in `code` |
| `Ctrl+Y` | copy path(s) |
| `Ctrl+X` | export (choose stdout / clipboard / file) |
| `Ctrl+P` | go to directory (shell `cd`) |
| `?` | help overlay |

`Ctrl+C` maps to quit. If Textual reserves a chosen combo on some terminals, the action menu is always the fallback path; final bindings are tuned during implementation without changing the specs.

### Actions and terminal hand-off

Actions resolve their targets (selection, else highlighted row) and, for >1 target, show a confirm dialog. "Open in default app / editor / code" and "export to stdout" and "go to directory" tear down the Textual app (restoring the terminal) and then either `os.execvp` the external program or `print` the output — mirroring the old `fzf --become` exit behavior. "Copy" and "export to file/clipboard" run in-process and keep the session alive.

### Directory hand-off to the shell wrapper

`seek init <shell>` prints a function that runs the program with an extra file descriptor (or a temp file path passed via an env var) into which the program writes the chosen directory on a "go to directory" action; the function reads it and `cd`s (quoted, so spaces are safe). The full-screen UI uses `/dev/tty` for rendering, keeping fd 3 / the temp file clean. If no wrapper is present, the program falls back to printing the path on stdout at exit.

### Testing

`pytest` for the CLI parser, pattern/smart-case resolution, the walk (fixtures with symlink loops, noise dirs, `.gitignore`), the query-syntax parser, the scorer (contiguous vs scattered, smart-case, ranking), the content cache + overflow, and output formatting. Textual's `Pilot` / `run_test` harness for TUI behaviors: streaming, mode toggles, multi-select persistence across requery, detail-view state round-trip, breadcrumb push/pop. A GitHub Actions workflow runs `uv run pytest` and a linter (`ruff`) on Linux + macOS + Windows.

## Risks / Trade-offs

- [Python content search on very large trees may lag despite caching] → 150 ms debounce, generation-counter cancellation, progressive chunked results, and the in-memory cache; scope with globs / re-root for the pathological cases; expose cache budget and debounce in config.
- [The hand-rolled scorer may not rank exactly like fzf] → keep the `score(term, text) -> (int, list[int]) | None` interface stable so it can be swapped; tune bonuses against a fixture of expected orderings (see `tests/test_query.py`).
- [Clipboard on headless Wayland / SSH is fragile] → runtime-detected fallback chain (`wl-copy`/`xclip`/`xsel`/`pbcopy`/`clip.exe`); surface a clear error and stay in-session rather than crash.
- [Following symlinks can still be slow or hit permission errors mid-walk] → inode/realpath visited-set for cycles; per-entry `try/except` so an unreadable directory is skipped with a note, not fatal; manual refresh to recover from staleness.
- [Terminal hand-off (execvp / stdout) can leave the terminal dirty if teardown is incomplete] → single teardown path asserted before any exec/print; covered by an integration test that checks no escape sequences precede action output.
- [Windows differences: `os.execvp` semantics, `start`, path separators, `clip.exe`, no `/dev/tty`] → platform branch for the opener and the directory hand-off (temp file + env var instead of fd 3 on Windows); CI on Windows exercises the CLI and non-exec actions.
- [Textual reserving keybindings (`Ctrl+P` palette, etc.) on some terminals] → the action menu covers every action; direct keys are conveniences and are config-overridable.

## Migration Plan

1. Ship `seek` runnable via `uvx --from git+<repo-url> seek` and `uv run seek` from a clone; document both.
2. Add `eval "$(seek init zsh)"` to `~/.zshrc` to get the `seek` wrapper (and `cd` behavior).
3. Keep the existing `s` / `f` / `d` bash functions in place during a transition period.
4. Once `seek` covers the daily cases, replace `s` / `f` / `d` with thin aliases (`f() { seek -f "$@" }`, `d() { seek -d "$@" }`, `s() { seek "$@" }`) or remove them.
5. Rollback is simply keeping (or restoring) the old functions; nothing about them is deleted by this change.

## Open Questions

- Exact default keybinding for each mode toggle and the breadcrumb-pop key, subject to which combos Textual can reliably capture across the user's terminals — resolvable during implementation without touching the specs (the action menu is the stable fallback).
- Default numeric values for the content-cache byte budget and the preview line window — start with the values in this document, tune against real trees; all are config-exposed.
- Whether `platformdirs` is worth a dependency versus a ~15-line hand-rolled path resolver — a packaging detail, no behavior impact.
