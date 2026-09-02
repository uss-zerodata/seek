## Why

The current workflow — separate `s`, `f`, and `d` bash functions wrapping fzf, fdfind, ripgrep, and batcat — resets on every invocation, cannot scope to a subdirectory or file type, cannot narrow the search type mid-session, and breaks previewing large files. A single persistent interactive application that combines filename, directory, and content search behind one interface, with a consistent set of actions, removes these limits.

## What Changes

- New `seek` command (Python, invoked via `uvx`/`uv run` for v1) that launches an interactive terminal UI. No non-interactive/scriptable mode in v1.
- CLI flags `-f/--file`, `-d/--directory`, `-c/--content` set the initial match modes; with none given, all three are active. Positional patterns scope the walk as fd-style globs (or regexes with `-r/--regex`), with smart-case.
- The walk streams results into the UI as it runs (instant open, "scanning… N found" indicator). Symlinks are followed with loop detection; `.git` plus common noise directories (`node_modules`, `.venv`, `__pycache__`, `target`, `dist`, …) are excluded by default; `.gitignore` is **not** honored by default (a flag/config re-enables it).
- One query box (always focused) drives fuzzy matching with fzf extended syntax (`^`, `$`, `!`, `'exact'`, space = AND) across filenames, directory names, and file contents simultaneously. Results are one flat list ranked by score with all match types interleaved, each row tagged by type and its matched characters highlighted; content matches are one row per matching line (`path:line`), uncapped.
- With an empty query the results area shows a non-interactive tree view of the current root; typing switches to the ranked result list.
- An always-on side preview shows a fixed centered glance of the highlighted result (file window centered on the matched line, or directory tree), truncated past 5 MB. `Enter` opens a full-screen detail view: a scrollable syntax-highlighted file (whole file to 5 MB, then truncated) or a directory tree, from which the search can be re-rooted into that directory (breadcrumb stack, one key pops up a level). `Esc`/back returns with query, scroll, and selection intact.
- Match modes are toggleable live from inside the UI, not just at launch.
- Multi-select with `Tab`; selection survives requery while the item still matches. `Shift+Tab` clears all marks. `Alt+↑`/`Alt+↓` recall query history (persisted globally).
- Result actions, reachable by direct `Ctrl-` keys and from an action menu: open in the OS default application, open in an editor (configurable editor table with `{file}`/`{line}` templates; presets for nvim, vim, code, emacs, hx), open in `code`, copy path(s), and a single **export** action that writes the selection to stdout, the clipboard, or a file. Opening more than one selected result prompts for confirmation. Output is relative paths, with `:line` appended for content matches.
- New `seek init <bash|zsh>` subcommand emits shell code for `eval "$(seek init zsh)"`; it defines a `seek` shell function that wraps the binary and performs `cd` when a directory result is chosen.
- New TOML configuration at `~/.config/seek/config.toml` (with platform equivalents): keybindings, theme colors, size/line thresholds, content-cache budget, editor table, and extra exclude globs, all overridable, shipped with documented defaults.
- Terminal-native look (uses the terminal's own colors), keyboard-first; mouse is supported for scrolling and selecting.

## Capabilities

### New Capabilities
- `search-cli`: The `seek` command-line entry point — Typer argument parsing, mode-flag resolution, fd-style glob/regex path scoping with smart-case, walker configuration (symlink following with loop detection, default exclusions, `.gitignore` opt-in), and launching the interactive session.
- `fuzzy-search-engine`: Real-time matching of the query (fzf extended syntax, smart-case) against filenames, directory names, and file contents at once; produces score-ranked, typed results (filename / dirname / content-with-line); debounced and cancellable re-search; in-memory name index and a budgeted content cache with disk rescan for the overflow; binary-file skipping.
- `interactive-tui`: The persistent Textual interface — always-focused query box, streaming result list with highlighted spans and type markers, empty-query tree view, keyboard navigation, live mode toggles, query-history recall, multi-select, always-on side preview, full-screen detail view with search re-rooting and a breadcrumb stack, and preservation of session state across views.
- `result-actions`: Acting on the highlighted result or the current multi-selection — open in OS default application, open via the configurable editor table, open in `code`, copy path(s), and a unified export action (stdout / clipboard / file); confirmation when acting on more than one; relative-path output with `:line` for content matches.
- `shell-integration`: The `seek init <shell>` subcommand and the shell wrapper it installs — a `seek` function for bash and zsh that runs the binary and `cd`s into a chosen directory result, plus the contract for how a directory selection is communicated back to the shell.
- `configuration`: Loading and applying the TOML config file — its location per platform, the set of overridable settings (keybindings, theme, thresholds, cache budget, editor table, exclude globs), precedence over built-in defaults, and behavior on a missing or malformed file.

### Modified Capabilities
(none — this is a new application; no existing specs are being changed)

## Impact

- New standalone Python application in this repo (`seek`), managed with `uv`; no existing code is modified since none exists here yet.
- Replaces the user's `s` / `f` / `d` shell functions as the daily search workflow; a transition period keeps them in place.
- Runtime: Python 3.11+, Textual + Rich (TUI/preview/highlighting), Typer (CLI), a fuzzy matcher (fzf-style scoring), a clipboard library with a `wl-copy`/`xclip`/`pbcopy`/`clip.exe` fallback path, and standard-library `tomllib` for config. Distribution for v1 is `uvx --from git+…` / cloned-repo `uv run`; no PyPI publish.
- Adds a `seek` shell function to the user's `~/.zshrc` (via `eval "$(seek init zsh)"`) and a config file under `~/.config/seek/`.
- External programs invoked at action time: the OS opener (`xdg-open` / `open` / `start`), the configured editors, and a clipboard utility.
