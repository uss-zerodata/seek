## 1. Project Setup

- [x] 1.1 Initialize the uv project: `pyproject.toml` (Python 3.11+), `uv.lock`, `src/seek/` package layout, `seek` console entry point, `.gitignore`.
- [x] 1.2 Add runtime dependencies: `typer`, `textual`, `rich` (via textual), `pyperclip` (`pathspec` as an optional/dev extra for gitignore support); hand-rolled path helper (no `platformdirs`). Add dev deps: `pytest`, `pytest-asyncio`, `ruff`.
- [x] 1.3 Create the module skeleton: `cli.py`, `config.py`, `walk.py`, `engine/` (`query.py`, `score.py`, `content.py`), `tui/` (`app.py`, `results.py`, `preview.py`, `detail.py`, `menu.py`, `help.py`), `actions.py`, `shell.py`.
- [x] 1.4 Add a GitHub Actions workflow running `uv run pytest` and `uv run ruff check` on Linux, macOS, and Windows; document the local check commands in the README.

## 2. Configuration (`configuration`)

- [x] 2.1 Implement per-platform config path resolution (`XDG_CONFIG_HOME`/`~/.config` on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows) and expose it (e.g. `seek --config-path` or in `--help`).
- [x] 2.2 Define the settings schema with defaults: keybindings map, theme colors, preview size cap, detail size cap, debounce ms, min content-query length, content-cache byte budget, honor-gitignore flag, extra exclude globs, apply-noise-excludes flag, absolute-path output flag, editor table + default editor.
- [x] 2.3 Load and validate `config.toml` with `tomllib`: missing file ⇒ defaults; parse error / unknown key / wrong type ⇒ non-zero exit before the UI with a message naming the file and key.
- [x] 2.4 Implement precedence: CLI flag > config file > built-in default.
- [x] 2.5 Write and ship a commented `config.example.toml` with every key at its default.
- [x] 2.6 Tests: path resolution per platform, missing/invalid/unknown-key handling, precedence.

## 3. Search CLI (`search-cli`)

- [x] 3.1 Define the Typer app: `-f/--file`, `-d/--directory`, `-c/--content`, `-r/--regex`, honor-gitignore flag, positional patterns; plus the `init` subcommand (see section 8).
- [x] 3.2 Resolve initial match modes: no mode flags ⇒ all three active; otherwise exactly the flagged ones.
- [x] 3.3 Resolve path scope: compile positionals as basename-vs-relative glob matchers (by presence of `/`), or as `re.Pattern` under `-r`; apply smart-case per pattern; non-zero exit with a clear message for an invalid regex before the UI opens.
- [x] 3.4 Detect non-interactive stdout and either attach to the controlling terminal or exit with "requires an interactive terminal"; never emit a plain result list as primary behavior.
- [x] 3.5 Assemble the resolved `SessionConfig` (modes, scope, walker settings, merged config) and launch the TUI app with it.
- [x] 3.6 Tests: mode resolution, glob basename vs path, `-r` partial match, smart-case, invalid-regex exit, non-interactive handling.

## 4. Walk (`search-cli`)

- [x] 4.1 Implement the streaming walker with `os.scandir`, pushing `Candidate` records (path, kind, is_symlink) onto a queue; UI drains on a timer.
- [x] 4.2 Implement directory-level pruning: `.git` + built-in noise set (`node_modules`, `.venv`, `__pycache__`, `target`, `dist`), plus config exclude globs; honor the disable-noise-excludes setting.
- [x] 4.3 Follow symlinked directories with a visited real-path/inode set to break cycles; skip unreadable entries with a recorded note instead of failing.
- [x] 4.4 Implement optional `.gitignore`/`.ignore` handling (layered matcher) gated by the flag/config.
- [x] 4.5 Apply the positional glob/regex scope as a filter during the walk.
- [x] 4.6 Expose a re-walk entrypoint (used by manual refresh and re-root) that resets candidates and restarts streaming for a given root.
- [x] 4.7 Tests with fixture trees: hidden files included, gitignored file present by default and absent with the flag, noise dir pruned, symlink loop terminates, scope filter, unreadable dir skipped.

## 5. Fuzzy Search Engine (`fuzzy-search-engine`)

- [x] 5.1 Implement the query parser for fzf extended syntax: split AND terms, recognize `^`, `$`, `!`, `'exact'`; produce a structured query with per-term smart-case.
- [x] 5.2 Implement `score(term, text) -> (int, list[int]) | None` as a pure-Python fzf-style scorer (greedy fwd/bwd subsequence match + word-start/camelCase/separator bonuses + gap penalties) returning score + matched positions, behind a stable interface so it can be swapped later.
- [x] 5.3 Implement candidate evaluation combining all terms (AND, negation, anchors, exact) over a text, yielding a combined score and merged highlight spans.
- [x] 5.4 Implement the in-memory name/dir index and matching against it (filename + dirname results).
- [x] 5.5 Implement content matching: iterate candidate files, produce one `Result` per matching line with 1-based line number and in-line span.
- [x] 5.6 Implement the budgeted content cache (lazy fill, byte budget, size-aware eviction) with a disk-read fallback for overflow files; skip binary files (NUL sniff).
- [x] 5.7 Define the unified `Result` type (kind, path, optional line, score, spans, display label) and the single score-sorted, type-interleaved ordering.
- [x] 5.8 Implement the generation counter + Textual worker: debounce (config ms), bump generation per query change, publish results in chunks, abandon on stale generation.
- [x] 5.9 Implement empty-query behavior (no results, distinct flag), no-match behavior (distinct flag), and the minimum-length gate for content matching.
- [x] 5.10 Honor active modes and scope, including live mode toggles mid-session and candidates still streaming from the walk.
- [x] 5.11 Tests: query parser cases; contiguous vs scattered ranking; smart-case; negation/anchors/exact; type interleaving; one-row-per-line uncapped; cache hit vs overflow correctness; binary skip; stale-generation discard; empty vs no-match states; mode/scope filtering.

## 6. Interactive TUI (`interactive-tui`)

- [x] 6.1 Build the Textual app shell: layout (query box, results area, side preview, status/breadcrumb line), terminal-palette theme with config color overrides, setup/teardown, `/dev/tty` rendering.
- [x] 6.2 Implement the always-focused query input: printable keys edit it, `←`/`→` move its cursor, keystrokes feed the debounced engine.
- [x] 6.3 Implement the streaming results list widget: type marker per row, highlighted match spans, `path:line` + line text for content rows, virtualized for large sets, "scanning… N found" indicator while walking.
- [x] 6.4 Implement the empty-query tree view (display-only) and switching to/from the ranked list as the query becomes non-empty/empty.
- [x] 6.5 Implement keyboard navigation: `↑`/`↓` row move, `PageUp`/`PageDown` paging; update side preview on highlight change.
- [x] 6.6 Implement live mode toggles (`Ctrl+F`/`Ctrl+D`/`Ctrl+T` or config) with a visible active-modes indicator and engine recompute.
- [x] 6.7 Implement query history: persist submitted queries to a state file; `Alt+↑`/`Alt+↓` recall across the current and past sessions.
- [x] 6.8 Implement multi-select: `Tab` toggle keyed by path(+line), `Shift+Tab` clear all, selection persists across requery while the item still matches, visible marks.
- [x] 6.9 Implement the always-on side preview: bounded windowed file read centered on the target line (top for name matches), `rich.syntax.Syntax` highlighting, matched-line marker, truncation indicator past the size cap, depth-limited directory tree, `<binary file>` for binaries; non-scrollable.
- [x] 6.10 Implement the full-screen detail view: whole file to the detail size cap then truncated, scrollable (`↑`/`↓`/`PageUp`/`PageDown`), highlighted, scrolled to the matched line; scrollable directory tree; `Esc` back.
- [x] 6.11 Implement session-state preservation across the detail-view round trip (query, scroll, highlight, selection).
- [x] 6.12 Implement re-root from a directory detail view (`Ctrl+R`): push breadcrumb, keep query, re-walk scoped to the new root; `Alt+←` pops one level; cannot pop past the launch root; breadcrumb shown in the status line.
- [x] 6.13 Implement manual refresh (`Ctrl+G`): re-walk current root from scratch and re-run the current query.
- [x] 6.14 Implement the no-match indication (distinct from the empty-query tree) and an empty side preview in that state.
- [x] 6.15 Implement mouse support: wheel scrolls the results list and detail view, click highlights a row.
- [x] 6.16 Implement the help overlay (`?`) listing all current keybindings; `Esc` closes it.
- [x] 6.17 Implement the `Esc`/`Ctrl+C` quit path (only at top level with nothing open and breadcrumb at launch root) with clean terminal restore and no stray output.
- [x] 6.18 Tests via Textual `Pilot`: streaming fill, tree↔list switch, mode toggle recompute, multi-select persistence across requery, detail-view state round trip, breadcrumb push/pop bounds, refresh picks up a new file, no-match state.

## 7. Result Actions (`result-actions`)

- [x] 7.1 Implement target resolution (selection else highlighted row) and the >1-target confirm dialog (all vs highlighted only); "nothing selected" message when there is no target.
- [x] 7.2 Implement the action menu (`Ctrl+K`) listing every action with its key, plus direct keybindings for the common actions; ensure all bindings are modifier/non-printable.
- [x] 7.3 Implement the single teardown path: restore the terminal before any `execvp` or stdout write.
- [x] 7.4 Implement "open in OS default application" (`xdg-open`/`open`/`start`), then exit.
- [x] 7.5 Implement "open via editor table": resolve editor, substitute `{file}`/`{line}`, jump to line for content matches, pass multiple paths to one invocation, hand over the terminal, exit.
- [x] 7.6 Implement "open in `code`" (`code --goto {file}:{line}` / `code {file}`), then exit.
- [x] 7.7 Implement "copy path(s)" via `pyperclip` with the runtime-detected fallback chain (`wl-copy`/`xclip`/`xsel`/`pbcopy`/`clip.exe`); stay in session; clear error if unavailable.
- [x] 7.8 Implement the "export" action with destination choice: stdout (exit), clipboard (stay), file at a user-supplied path (stay); one-per-line output.
- [x] 7.9 Implement output path formatting: root-relative, `:line` for content matches, absolute when configured.
- [x] 7.10 Implement "go to directory" (`Ctrl+P`): write the chosen path to the shell hand-off channel and exit, or print to stdout when no wrapper is present.
- [x] 7.11 Tests: target resolution + confirm, path formatting (relative/absolute/`:line`), one-per-line serialization, nothing-selected path, opener/editor/code argv construction per platform, clipboard fallback selection, clean-terminal-before-output (no escape codes precede action output).

## 8. Shell Integration (`shell-integration`)

- [x] 8.1 Implement `seek init <bash|zsh>`: print shell code to stdout; unsupported shell ⇒ non-zero exit naming `bash`/`zsh`; never launch the UI.
- [x] 8.2 Design and implement the directory hand-off channel: extra fd (POSIX) or temp file via env var (Windows/portable); program writes the chosen dir there on "go to directory"; UI renders on `/dev/tty` so the channel stays clean.
- [x] 8.3 Emit a `seek` wrapper function that runs the program, `cd`s (quoted, space-safe) when a directory was chosen, preserves exit status otherwise, and is safe to `eval` when the program is absent from `PATH`.
- [x] 8.4 Fallback: print the directory path on stdout at exit when no wrapper channel is present.
- [x] 8.5 Tests: `init` output per shell, unsupported-shell exit, hand-off with spaces in the path, exit-status pass-through, eval-safe when binary missing (shell-level integration test where feasible).

## 9. Integration, Docs & Migration

- [x] 9.1 End-to-end manual pass: bare `seek`, each mode flag and combinations, glob and `-r` scoping, live mode toggles, a >5 MB file preview + detail view, a deep directory tree, re-root + breadcrumb pop, query history across two runs, each action, `seek` wrapper `cd`.
- [x] 9.2 Sanity-check content-search and smart-case results against `rg` on the same queries; document any deliberate differences in `--help`/README.
- [x] 9.3 Write the README: install via `uvx --from git+…` / `uv run`, `eval "$(seek init zsh)"` setup, flag reference, full keybinding table, config file location + `config.example.toml`, examples mirroring the proposal.
- [x] 9.4 Document the transitional `s`/`f`/`d` → `seek` aliases and the rollback path.
