"""The interactive Textual application."""

from __future__ import annotations

import threading
from pathlib import Path

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.css.query import NoMatches
from textual.timer import Timer
from textual.widgets import Input, Static

from seek.config import DEFAULT_KEYS
from seek.engine.engine import CandidateStore, SearchEngine
from seek.engine.query import ParsedQuery, parse_query
from seek.history import History
from seek.models import MatchKind, ResultSet, ResultSetState
from seek.session import SessionConfig
from seek.tui.actions_mixin import ActionsMixin, perform_exit_request
from seek.tui.commands import SeekCommands
from seek.tui.detail import DetailScreen
from seek.tui.help import HelpScreen
from seek.tui.keyhints import pretty_key
from seek.tui.preview import build_preview
from seek.tui.query_input import QueryInput
from seek.tui.results import ResultsList
from seek.tui.tree import render_tree
from seek.walk import rebase, walk

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# Per-context hint-bar items. Each entry is (key, verb): `key` is an action id
# (resolved through config.keys) when it names one, otherwise a literal glyph.
# The Esc segment is appended separately and always shown last.
_HINT_ITEMS: dict[str, list[tuple[str, str]]] = {
    "tree": [("↑↓", "scroll"), ("help", "help")],
    "results": [
        ("↵", "view"),
        ("open_editor", "edit"),
        ("open_default", "open"),
        ("copy", "copy"),
        ("mark", "mark"),
        ("action_menu", "more"),
    ],
    "no_match_scanning": [("help", "help")],
    "no_match_settled": [
        ("toggle_file", "filenames"),
        ("toggle_content", "contents"),
        ("help", "help"),
    ],
}

_ACTION_KEYS = {
    "open_default": "seek_open_default",
    "open_editor": "seek_open_editor",
    "open_code": "seek_open_code",
    "copy": "seek_copy",
    "export": "seek_export",
    "goto_dir": "seek_goto_dir",
    "action_menu": "seek_action_menu",
    "toggle_file": "seek_toggle_file",
    "toggle_dir": "seek_toggle_dir",
    "toggle_content": "seek_toggle_content",
    "toggle_format": "seek_toggle_format",
    "reroot": "seek_reroot",
    "breadcrumb_pop": "seek_breadcrumb_pop",
    "refresh": "seek_refresh",
    "history_prev": "seek_history_prev",
    "history_next": "seek_history_next",
    "mark": "seek_mark",
    "clear_marks": "seek_clear_marks",
    "help": "seek_help",
}


def _default_bindings() -> list[Binding]:
    b = [
        # Non-priority: a modal screen (detail view, menus) must get these first.
        # The query Input ignores up/down/pageup/pagedown, so they still reach
        # the app on the main screen.
        Binding("up", "seek_nav(-1)", "Up", show=False),
        Binding("down", "seek_nav(1)", "Down", show=False),
        Binding("pageup", "seek_page(-1)", "Page up", show=False),
        Binding("pagedown", "seek_page(1)", "Page down", show=False),
        Binding("escape", "seek_back", "Back / quit", show=False),
        Binding("f1", "seek_help", "Help", priority=True, show=False),
    ]
    for action, key in DEFAULT_KEYS.items():
        b.append(Binding(key, _ACTION_KEYS[action], action, priority=True, show=False))
    return b


class SeekApp(ActionsMixin, App[int]):
    CSS = """
    /* Top-to-bottom: preview, results/tree (fills), status bar, hint bar,
       prompt row. ANSI themes collapse $panel/$surface/$boost to the terminal
       background, so region separation comes from thin blue rules, not fills:
       one under the preview and one under the result area, which fences off the
       status/hint/prompt cluster at the bottom. */
    #preview {
        height: 45%;
        max-height: 24;
        overflow: hidden;
        padding: 0 1;
        border-bottom: solid $primary;
    }
    ResultsList { height: 1fr; min-height: 3; padding: 0 1; border-bottom: solid $primary; }
    ResultsList > .option-list--option-highlighted { text-style: reverse bold; }
    #tree { height: 1fr; padding: 0 1; border-bottom: solid $primary; }
    #nomatch {
        height: 1fr; content-align: center middle; color: $text-muted;
        border-bottom: solid $primary;
    }

    /* Status bar: modes on the left, count on the right. Plain background - the
       blue rule above it is the separator; text carries its own colour. */
    #status { height: 1; padding: 0 1; }

    /* Hint bar: dim, context-relevant keybindings. Always present, never
       dropped for space. */
    #hint-bar { height: 1; color: $text-muted; padding: 0 1; }

    /* Prompt row: the accent glyph + the query input. */
    #prompt-row { height: 1; }
    #prompt { width: 3; color: $accent; text-style: bold; content-align: center middle; }
    #query { width: 1fr; height: 1; border: none; padding: 0; }
    """
    # Below this terminal height the preview is dropped so the list stays usable.
    MIN_HEIGHT_FOR_PREVIEW = 15
    # `Ctrl+P` lists every action by name, as it does in the scan viewer - the
    # same key for the same thing in both halves of the app.
    COMMANDS = App.COMMANDS | {SeekCommands}
    BINDINGS = _default_bindings()

    def __init__(self, session: SessionConfig) -> None:
        super().__init__()
        self.session = session
        self.config = session.config
        self.root = session.root
        self.modes = session.modes
        self.store = CandidateStore()
        self.engine = SearchEngine(self.config, self.store)
        self.history = History.load()
        self._generation = 0
        self._debounce: Timer | None = None
        self._preview_debounce: Timer | None = None
        self._walk_stop = threading.Event()
        self._breadcrumb: list[Path] = [session.root]
        # The completed launch-root walk, reused when changing root.
        self._base_candidates: list | None = None
        self._last_committed_query = ""
        self._parsed_query: ParsedQuery | None = None
        self._applied_query: str | None = None  # query text of the shown results
        self._scan_search_at = 0  # candidate count at the last mid-scan search
        self._tree_mode = True
        self._no_match = False
        self._total = 0
        self._spin = 0
        self._searching = False  # a search worker is running for the live query
        self._prompt_glyph = "❯"
        self._preview_target = None
        self.exit_request = None  # set by ActionsMixin before exit

    # --- layout --------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(id="preview")
        yield ResultsList(self.config)
        with VerticalScroll(id="tree"):
            yield Static(id="tree-body")
        yield Static("", id="nomatch")
        yield Static(id="status")
        yield Static(id="hint-bar")
        with Horizontal(id="prompt-row"):
            yield Static("❯", id="prompt")
            yield QueryInput(
                placeholder="Search files, directories and contents…", id="query"
            )

    def on_mount(self) -> None:
        self.theme = "ansi-dark"
        self._apply_key_overrides(self.config.keys)
        self.query_one("#query", Input).focus()
        self._show_tree_view(True)
        self._render_tree()
        self._start_walk()
        self.set_interval(0.1, self._on_tick)

    def _apply_key_overrides(self, keys: dict[str, str]) -> None:
        """Lay the user's ``[keys]`` table over the built-in bindings.

        Both halves matter: binding the new key *and* withdrawing the default it
        replaces. Adding only the new one left the old key live as well, so a
        key the user had deliberately freed still ran its original action.

        The default is withdrawn by *action*, not by key, so anything else bound
        to that key (Textual's own bindings, or another action the user moved
        onto it) survives - which also makes a straight swap of two keys come
        out right whichever order the table is read in.
        """
        table = self._bindings.key_to_bindings
        for action, key in keys.items():
            default = DEFAULT_KEYS.get(action)
            if not key or key == default:
                continue
            target = _ACTION_KEYS[action]
            if default and default in table:
                kept = [b for b in table[default] if b.action != target]
                if kept:
                    table[default] = kept
                else:
                    del table[default]
            self._bindings.bind(key, target, priority=True)

    # --- walk --------------------------------------------------------------

    def _start_walk(self) -> None:
        self._walk_stop = threading.Event()
        self.store.clear()
        self._run_walk(self.root, self._walk_stop, self.store.epoch)

    @work(thread=True, group="walk", exclusive=True)
    def _run_walk(self, root: Path, stop: threading.Event, epoch: int) -> None:
        # Checked against the store's epoch as well as the stop flag: between
        # this thread's `stop.is_set()` and its `store.add`, the main thread can
        # clear the store and repopulate it for a new root, and the candidate in
        # flight - addressed relative to the *old* root - would land in it.
        try:
            for cand in walk(root, self.config, self.session.scope):
                if stop.is_set() or self.store.epoch != epoch:
                    return
                self.store.add(cand, epoch)
        finally:
            if not stop.is_set() and self.store.epoch == epoch:
                self.store.finish()
                self.call_from_thread(self._on_walk_finished)

    def _on_walk_finished(self) -> None:
        # Keep the completed launch-root scan so re-rooting and popping a
        # breadcrumb can filter it instead of walking the tree again.
        if self._base_candidates is None and self.root == self._breadcrumb[0]:
            self._base_candidates = self.store.snapshot()
        self._refresh_status()
        if self.query_one("#query", Input).value.strip():
            self._trigger_search()

    def _reuse_walk(self) -> bool:
        """Populate the store for the current root from the launch-root scan.

        Files are assumed stable for the session, so changing root is a filter
        rather than a rescan - popping back to the launch root of a large tree
        used to cost a full re-walk. Returns False when the scan cannot be
        reused and a real walk is needed.
        """
        base = self._base_candidates
        if base is None or not self.session.scope.is_unrestricted:
            # A positional scope was resolved against the launch root, so its
            # accept decisions do not carry over to a different root.
            return False
        try:
            rel_root = self.root.relative_to(self._breadcrumb[0]).as_posix()
        except ValueError:
            return False
        self.store.clear()  # bumps the epoch, dropping the engine's narrowing pool
        for cand in rebase(base, "" if rel_root == "." else rel_root):
            self.store.add(cand)
        self.store.finish()
        return True

    def _on_tick(self) -> None:
        self._spin = (self._spin + 1) % len(_SPINNER)
        self._apply_responsive_layout()
        streaming = self.store.scanning or self._searching
        self._update_prompt_glyph(streaming)
        if not streaming:
            return
        self._refresh_status()  # animate the spinner + count
        if not self.store.scanning:
            return
        # Re-run the search during the walk only once enough new candidates have
        # turned up to be worth it - avoids rebuilding the list every tick.
        found = len(self.store)
        grew = found - self._scan_search_at
        if self.query_one("#query", Input).value.strip() and (
            grew >= 400 or grew >= self._scan_search_at // 4
        ):
            self._trigger_search()

    def _update_prompt_glyph(self, streaming: bool) -> None:
        """Swap the `❯` prompt for a spinner while results are still streaming
        in - the most visible place for a "working" cue."""
        glyph = _SPINNER[self._spin] if streaming else "❯"
        if glyph == self._prompt_glyph:
            return
        self._prompt_glyph = glyph
        try:
            self.query_one("#prompt", Static).update(glyph)
        except NoMatches:
            return

    # --- query / search --------------------------------------------------

    def on_query_input_help_requested(self, _: QueryInput.HelpRequested) -> None:
        self.action_seek_help()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "query":
            self.action_seek_detail()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "query":
            return
        if self._debounce is not None:
            self._debounce.stop()
        empty = not event.value.strip()
        if empty:
            self._parsed_query = None
            self._generation += 1
            self._searching = False
            self.query_one(ResultsList).set_results([])
            self._show_tree_view(True)
            self._update_preview(None)
            self._refresh_status()
            return
        # The query changed, so any in-flight search is now stale: invalidate it
        # at once (bumping the generation trips its `is_stale()` and makes
        # `_apply_results` drop whatever it returns) instead of letting it run
        # until the debounced restart would supersede it.
        self._generation += 1
        self._searching = False
        self._debounce = self.set_timer(
            self.config.debounce_ms / 1000, self._trigger_search
        )
        self._refresh_hints()  # flip the Esc hint to "clear query" right away

    def _trigger_search(self) -> None:
        self._generation += 1
        gen = self._generation
        query_text = self.query_one("#query", Input).value
        self._parsed_query = parse_query(query_text)
        self._scan_search_at = len(self.store)
        self._searching = True
        self._search_worker(self._parsed_query, query_text, gen)
        self._refresh_status()  # show the "searching…" cue right away

    @work(thread=True, exclusive=True, group="search")
    def _search_worker(self, parsed: ParsedQuery, query_text: str, gen: int) -> None:
        def publish(snapshot, g: int, total: int) -> None:
            if g == self._generation:
                self.call_from_thread(
                    self._apply_results,
                    ResultSet(ResultSetState.RESULTS, snapshot, g,
                              self.store.scanning, total=total, partial=True),
                    query_text,
                )

        rs = self.engine.search(
            parsed, self.modes, gen,
            is_stale=lambda: gen != self._generation, publish=publish,
        )
        if gen == self._generation:
            self.call_from_thread(self._apply_results, rs, query_text)

    def _apply_results(self, rs: ResultSet, query_text: str = "") -> None:
        if rs.generation != self._generation:
            return
        if not rs.partial:  # the final snapshot for this query - streaming done
            self._searching = False
        results_list = self.query_one(ResultsList)
        if rs.state is ResultSetState.EMPTY_QUERY:
            self._set_middle("tree")
            return
        self._no_match = rs.state is ResultSetState.NO_MATCH
        self._total = rs.total or len(rs.results)
        # Keep the cursor put unless this is the first result set for a new query.
        preserve = query_text == self._applied_query
        self._applied_query = query_text
        results_list.set_results(rs.results, preserve=preserve)
        if self._no_match:
            self.query_one("#nomatch", Static).update(
                self._no_match_message(query_text, scanning=rs.scanning)
            )
            self._set_middle("nomatch")
        else:
            self._set_middle("list")
        self._refresh_status()

    def _no_match_message(self, query_text: str, *, scanning: bool) -> Text:
        """The centred message shown when a non-empty query matches nothing.

        While the walk is still running this is a provisional "still scanning"
        note; once settled it names the query and points the user away from
        regex expectations (and at a disabled content mode, if that is why).
        """
        if scanning:
            return Text(
                f"scanning… no matches yet for {query_text!r}",
                style="bold bright_yellow",
            )
        msg = Text(f"no matches for {query_text!r}\n", style="dim")
        help_key = pretty_key(self.config.keys.get("help", "question_mark"))
        msg.append(
            f"the query box is fuzzy matching, not regex — {help_key} for the syntax",
            style="dim",
        )
        if not self.modes.content:
            tkey = pretty_key(self.config.keys.get("toggle_content", "ctrl+t"))
            msg.append(
                f"\n{tkey} also searches inside file contents", style="dim"
            )
        return msg

    # --- view helpers --------------------------------------------------

    def _set_middle(self, mode: str) -> None:
        """mode: 'tree' (empty query) | 'list' (results) | 'nomatch' (no match)."""
        self._tree_mode = mode == "tree"
        self.query_one("#tree", VerticalScroll).display = mode == "tree"
        self.query_one(ResultsList).display = mode == "list"
        self.query_one("#nomatch", Static).display = mode == "nomatch"
        if mode != "list":
            self._update_preview(None)
        if mode == "tree":
            self._no_match = False
        self._apply_responsive_layout()
        self._refresh_hints()

    def _show_tree_view(self, show_tree: bool) -> None:
        self._set_middle("tree" if show_tree else "list")

    def _apply_responsive_layout(self) -> None:
        """The result list is the priority: drop the preview on short terminals
        or when there is nothing to preview."""
        try:
            rl = self.query_one(ResultsList)
            panel = self.query_one("#preview", Static)
        except NoMatches:  # torn down (a late worker callback)
            return
        tall_enough = self.size.height >= self.MIN_HEIGHT_FOR_PREVIEW
        panel.display = rl.display and tall_enough and bool(rl.results)

    def _tree_heading(self) -> Text:
        """One-line orientation above the empty-query tree: the current root and
        the walk semantics in effect, plus a prompt to start typing."""
        gi = "honoured" if self.config.honor_gitignore else "off"
        noise = "pruned" if self.config.apply_noise_excludes else "kept"
        h = Text()
        h.append(f"root: {self.root.name or self.root}", style="bold")
        h.append(
            f"   hidden files shown · .gitignore {gi} · noise dirs {noise}",
            style="dim",
        )
        h.append("\n\ntype to search files, directories and contents\n", style="dim")
        return h

    def _render_tree(self) -> None:
        body = self.query_one("#tree-body", Static)
        body.update(Group(self._tree_heading(), render_tree(self.root, self.config)))

    def _update_preview(self, result) -> None:
        """Clear or (debounced) refresh the preview for ``result``."""
        self._preview_target = result
        if self._preview_debounce is not None:
            self._preview_debounce.stop()
        if result is None:
            self.query_one("#preview", Static).update(Text(""))
            self._apply_responsive_layout()
            return
        self._preview_debounce = self.set_timer(0.05, self._launch_preview)

    def _launch_preview(self) -> None:
        result = self._preview_target
        if result is None:
            return
        panel = self.query_one("#preview", Static)
        vp = panel.content_size.height or panel.size.height or 18
        self._build_preview_worker(result, vp, self._parsed_query)

    @work(thread=True, exclusive=True, group="preview")
    def _build_preview_worker(self, result, vp: int, query) -> None:
        # Disk read + syntax highlighting happen off the UI thread.
        renderable = build_preview(
            result, self.config, full=False, query=query, viewport_lines=vp,
            cache=self.engine.cache,
        )
        if result is self._preview_target:
            self.call_from_thread(self._show_preview, renderable)

    def _show_preview(self, renderable) -> None:
        try:
            self.query_one("#preview", Static).update(renderable)
        except NoMatches:  # torn down while the preview worker was running
            return
        self._apply_responsive_layout()

    def on_option_list_option_highlighted(self, event) -> None:
        """Keep the preview in sync when the row changes by mouse or key."""
        if isinstance(event.option_list, ResultsList):
            self._update_preview(event.option_list.current())

    def _refresh_status(self) -> None:
        try:
            rl = self.query_one(ResultsList)
        except NoMatches:
            return
        # Rendered on the terminal background (no fill); active = bold, else dim.
        on_st, off_st = "bold", "dim"

        # Mode indicator: each mode spelled out (its first letter is the row
        # marker for that kind), bold when on / dim when off, then the keys
        # that toggle them.
        left = Text()
        modes = (
            ("files", "toggle_file", self.modes.file),
            ("dirs", "toggle_dir", self.modes.dir),
            ("content", "toggle_content", self.modes.content),
        )
        for i, (word, _action, active) in enumerate(modes):
            if i:
                left.append("·", style=off_st)
            left.append(word, style=on_st if active else off_st)
        toggle_keys = " ".join(
            pretty_key(self.config.keys.get(a, "")) for _, a, _ in modes
        )
        left.append(f"  {toggle_keys} toggle", style=off_st)
        fmt_key = pretty_key(self.config.keys.get("toggle_format", ""))
        left.append("   fmt", style=on_st if self.config.format_content else off_st)
        left.append(f" {fmt_key}", style=off_st)
        if len(self._breadcrumb) > 1:
            crumb = "/".join(p.name or str(p) for p in self._breadcrumb)
            left.append(f"   {crumb}", style=on_st)

        right = Text()
        if rl.marked:
            right.append(f"{len(rl.marked)} marked  ", style="bold bright_magenta")
        shown = len(rl.results)
        if self._no_match:
            right.append("0", style=off_st)
        elif shown:
            right.append(str(shown), style="bold")
            if self._total > shown:
                right.append(f"/{self._total}", style=off_st)
        spin = _SPINNER[self._spin]
        if self.store.scanning:
            right.append(
                f"  {spin} scanning {len(self.store):,}", style="bold bright_yellow"
            )
        elif self._searching:
            right.append(f"  {spin} searching…", style="bold bright_yellow")

        bar = Table.grid(expand=True, padding=0)
        bar.add_column(justify="left", ratio=1)
        bar.add_column(justify="right")
        bar.add_row(left, right)
        self.query_one("#status", Static).update(bar)
        self._refresh_hints()
        self._update_prompt_glyph(self.store.scanning or self._searching)

    # --- context hint bar ---------------------------------------------------

    def _hint_context(self) -> str:
        if self._tree_mode:
            return "tree"
        if self._no_match:
            return "no_match_scanning" if self.store.scanning else "no_match_settled"
        return "results"

    def _esc_hint_label(self) -> str:
        """What `Esc` will do next - kept in step with ``action_seek_back``."""
        try:
            has_query = bool(self.query_one("#query", Input).value.strip())
        except NoMatches:
            has_query = False
        if has_query:
            return "clear query"
        if len(self._breadcrumb) > 1:
            return "up a level"
        return "quit"

    def _refresh_hints(self) -> None:
        try:
            bar = self.query_one("#hint-bar", Static)
        except NoMatches:
            return
        ctx = self._hint_context()
        text = Text(no_wrap=True, overflow="ellipsis")
        if ctx == "tree":
            text.append("type to search", style="dim")
            text.append("   ")
        elif ctx == "no_match_scanning":
            text.append("scanning…", style="dim")
            text.append("   ")
        for i, (key, verb) in enumerate(_HINT_ITEMS[ctx]):
            disp = pretty_key(self.config.keys[key]) if key in self.config.keys else key
            if i:
                text.append("   ")
            text.append(disp, style="bold")
            text.append(f" {verb}", style="dim")
        text.append("   ")
        text.append("Esc", style="bold")
        text.append(f" {self._esc_hint_label()}", style="dim")
        bar.update(text)

    def _commit_history(self, query_text: str) -> None:
        q = query_text.strip()
        if q and q != self._last_committed_query:
            self._last_committed_query = q
            self.history.add(q)

    def commit_query_history(self) -> None:
        """Record the current query as one the user actually meant.

        Committing on every debounced search recorded the prefixes typed on the
        way to a query as well as the query - `ma`, `mai`, `main` - so `Alt+↑`
        walked back through fragments of one search. It is committed instead
        when the query is *used*: opening a result, acting on one, or leaving.
        """
        try:
            self._commit_history(self.query_one("#query", Input).value)
        except NoMatches:  # torn down
            return

    def on_unmount(self) -> None:
        # Covers a plain quit and every action that hands the terminal over,
        # since those all exit the app.
        self.commit_query_history()

    # --- navigation actions ------------------------------------------

    def action_seek_nav(self, delta: int) -> None:
        rl = self.query_one(ResultsList)
        if not rl.display:
            self.query_one("#tree", VerticalScroll).scroll_relative(y=delta, animate=False)
            return
        rl.nav(delta)  # preview follows via OptionHighlighted

    def action_seek_page(self, direction: int) -> None:
        rl = self.query_one(ResultsList)
        if not rl.display:
            scroller = self.query_one("#tree", VerticalScroll)
            (scroller.scroll_page_down if direction > 0 else scroller.scroll_page_up)(
                animate=False
            )
            return
        page = max(1, rl.scrollable_content_region.height - 1)
        rl.nav(direction * page)

    def action_seek_mark(self) -> None:
        self.query_one(ResultsList).toggle_mark()
        self._refresh_status()

    def action_seek_clear_marks(self) -> None:
        self.query_one(ResultsList).clear_marks()
        self._refresh_status()

    def action_seek_history_prev(self) -> None:
        self._recall(self.history.prev())

    def action_seek_history_next(self) -> None:
        self._recall(self.history.next())

    def _recall(self, text: str | None) -> None:
        if text is None:
            return
        q = self.query_one("#query", Input)
        q.value = text
        q.cursor_position = len(text)

    @work(exclusive=True, group="modal")
    async def action_seek_detail(self) -> None:
        rl = self.query_one(ResultsList)
        if not rl.display:
            return
        cur = rl.current()
        if cur is None:
            return
        self.commit_query_history()
        choice = await self.push_screen_wait(
            DetailScreen(cur, self.config, self._parsed_query)
        )
        if choice:  # an open action chosen from inside the detail view
            await self._dispatch_menu(choice)

    def action_seek_back(self) -> None:
        # Resolve one level of state per press: clear a non-empty query, then
        # pop a breadcrumb level, then quit. `_esc_hint_label` mirrors this.
        q = self.query_one("#query", Input)
        if q.value.strip():
            q.value = ""
            q.cursor_position = 0
            return
        if len(self._breadcrumb) > 1:
            self.action_seek_breadcrumb_pop()
            return
        self.exit(0)

    # --- mode toggles ----------------------------------------------

    def _toggle(self, which: str) -> None:
        self.modes = self.modes.toggled(which)
        label = {"file": "filename", "dir": "directory", "content": "content"}[which]
        self.notify(f"{label} search {'on' if getattr(self.modes, which) else 'off'}")
        self._refresh_status()
        if self.query_one("#query", Input).value.strip():
            self._trigger_search()

    def action_seek_toggle_file(self) -> None:
        self._toggle("file")

    def action_seek_toggle_dir(self) -> None:
        self._toggle("dir")

    def action_seek_toggle_content(self) -> None:
        self._toggle("content")

    def action_seek_toggle_format(self) -> None:
        """Turn re-indenting of over-long structured files on or off.

        Formatted and raw content cannot share a cache entry, so this drops the
        content cache and the narrowing pool (which holds positions into the old
        text) and recomputes the current query.
        """
        on = not self.config.format_content
        self.config.format_content = on
        self.engine.cache.format_content = on
        self.engine.invalidate_content()
        self.notify(f"content formatting {'on' if on else 'off'}")
        self._refresh_status()
        if self.query_one("#query", Input).value.strip():
            self._trigger_search()

    # --- re-root / refresh --------------------------------------

    def action_seek_reroot(self) -> None:
        rl = self.query_one(ResultsList)
        cur = rl.current()
        if cur is None or cur.kind is not MatchKind.DIRNAME:
            self.notify("Re-root needs a directory result", severity="warning")
            return
        self.root = cur.path
        self._breadcrumb.append(cur.path)
        self._reset_for_new_root()

    def action_seek_breadcrumb_pop(self) -> None:
        if len(self._breadcrumb) <= 1:
            return
        self._breadcrumb.pop()
        self.root = self._breadcrumb[-1]
        self._reset_for_new_root()

    def action_seek_refresh(self) -> None:
        # The explicit escape hatch from "files are stable for this session":
        # throw away the cached scan *and* the cached file contents, then hit
        # the filesystem again. Dropping only the scan re-walked the tree but
        # kept serving content matches from text read before the edit.
        self._base_candidates = None
        self.engine.invalidate_content()
        self._reset_for_new_root()
        self.notify("Re-walking…")

    def _reset_for_new_root(self) -> None:
        self._walk_stop.set()
        self._render_tree()
        if not self._reuse_walk():
            self._start_walk()
        if self.query_one("#query", Input).value.strip():
            self._trigger_search()
        else:
            self._show_tree_view(True)
        self._refresh_status()

    @work(exclusive=True, group="modal")
    async def action_seek_help(self) -> None:
        await self.push_screen_wait(HelpScreen(self.config.keys))


def run_session(session: SessionConfig) -> int:
    app = SeekApp(session)
    result = app.run()
    if app.exit_request is not None:
        return perform_exit_request(app.exit_request)
    return result if isinstance(result, int) else 0
