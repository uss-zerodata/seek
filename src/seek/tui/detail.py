"""Full-screen detail view for the highlighted result.

Scrolls like a pager (arrows, `j`/`k`, `g`/`G`, `Ctrl+D`/`Ctrl+U`, Space,
PageUp/PageDown). Query matches stay highlighted while scrolling.

**It renders only the lines on screen.** The whole file used to be built into one
Rich ``Text`` inside a scrolling ``Static``, which made Textual lay out every
line of it before the screen could appear: 800 ms for 2,000 lines and 29 s for
120,000, during which nothing responded. Keeping the prepared lines in memory and
re-rendering just the visible slice costs the same work per keypress whatever the
file's size. The file is read and prepared off the event loop, as the side
preview already is.

The view can also hand an action back to the app: pressing the open-in-editor /
open-in-default-app / open-in-code key dismisses the screen with that action id,
which the app then runs on the same target.
"""

from __future__ import annotations

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Static

from seek.config import Config
from seek.engine.query import ParsedQuery
from seek.models import MatchKind, Result
from seek.tui.keyhints import pretty_key
from seek.tui.preview import FileView, _render_window, build_preview, load_file

# action id -> short verb shown in the controls line
_OPEN_ACTIONS = [
    ("open_editor", "edit"),
    ("open_default", "open"),
    ("open_code", "code"),
]

_FALLBACK_HEIGHT = 20


class DetailScreen(ModalScreen[str | None]):
    """Returns an action id to run after closing, or None for a plain back."""

    BINDINGS = [
        Binding("escape,q", "back", "Back"),
        Binding("up,k", "scroll(-1)", "Up", show=False),
        Binding("down,j", "scroll(1)", "Down", show=False),
        Binding("ctrl+u", "half(-1)", "½ page up", show=False),
        Binding("ctrl+d", "half(1)", "½ page down", show=False),
        Binding("pageup,b", "page(-1)", "Page up", show=False),
        Binding("pagedown,space", "page(1)", "Page down", show=False),
        Binding("g,home", "to_top", "Top", show=False),
        Binding("G,end", "to_bottom", "Bottom", show=False),
    ]
    DEFAULT_CSS = """
    DetailScreen { background: $surface; }
    DetailScreen .title { background: $panel; padding: 0 1; text-style: bold; }
    DetailScreen #detail-body { height: 1fr; padding: 0 1; overflow: hidden; }
    DetailScreen .controls { color: $text-muted; padding: 0 1; height: 1; }
    """

    def __init__(
        self,
        result: Result,
        config: Config,
        query: ParsedQuery | None = None,
        *,
        top: int | None = None,
    ) -> None:
        super().__init__()
        self._result = result
        self._config = config
        self._query = query
        self._view: FileView | None = None
        self._top = 1  # 1-based first visible line
        # Where to open instead of on the match: the line this view was on
        # before it closed to run an open action.
        self._resume_top = top
        # configured key -> open action id, dismissed back to the app to run
        self._open_keys = {
            config.keys[a]: a for a, _ in _OPEN_ACTIONS if config.keys.get(a)
        }

    async def on_key(self, event) -> None:  # noqa: ANN001 - Textual event
        action = self._open_keys.get(event.key)
        if action is not None:
            event.stop()
            event.prevent_default()
            self.dismiss(action)

    def compose(self) -> ComposeResult:
        r = self._result
        loc = f":{r.line_no}" if r.kind is MatchKind.CONTENT and r.line_no else ""
        yield Static(f" {r.rel}{loc} ", classes="title")
        yield Static("  reading…", id="detail-body")
        yield Static(self._controls_text(), classes="controls")

    def _controls_text(self) -> str:
        opens = "  ".join(
            f"{pretty_key(self._config.keys[a])} {v}"
            for a, v in _OPEN_ACTIONS
            if self._config.keys.get(a)
        )
        return f"j/k ↑↓ scroll   ^U/^D ½page   g/G ends   {opens}   q back"

    # --- loading -----------------------------------------------------------

    def on_mount(self) -> None:
        self._load()

    @work(thread=True, exclusive=True, group="detail")
    def _load(self) -> None:
        """Disk read, re-indenting and lexer lookup, off the event loop."""
        result = self._result
        if result.kind is MatchKind.DIRNAME:
            # A directory renders as a bounded tree; there is nothing to page.
            renderable = build_preview(result, self._config, full=True)
            self.app.call_from_thread(self._show_static, renderable)
            return
        self.app.call_from_thread(
            self._ready, load_file(result, self._config, full=True)
        )

    def _show_static(self, renderable) -> None:
        try:
            self.query_one("#detail-body", Static).update(renderable)
        except NoMatches:  # dismissed while the read was running
            return

    def _ready(self, view: FileView) -> None:
        self._view = view
        if view.error is not None:
            self._show_static(view.error)
            return
        # Open centred on the match, the way the side preview frames it.
        if self._resume_top is not None:
            self._top = self._clamp(self._resume_top)
        else:
            self._top = self._clamp((view.target or 1) - self._height() // 2)
        self._paint()

    # --- paging ------------------------------------------------------------

    def _body(self) -> Static | None:
        try:
            return self.query_one("#detail-body", Static)
        except NoMatches:
            return None

    def _height(self) -> int:
        body = self._body()
        return (body.size.height if body else 0) or _FALLBACK_HEIGHT

    def _clamp(self, top: int) -> int:
        if self._view is None:
            return 1
        return max(1, min(top, max(1, len(self._view.lines) - self._height() + 1)))

    def _paint(self) -> None:
        view, body = self._view, self._body()
        if view is None or body is None or view.error is not None:
            return
        height = self._height()
        start = self._top
        end = min(len(view.lines), start + height - 1)
        at_end = end >= len(view.lines)
        if view.truncated and at_end:
            end = max(start, end - 1)  # leave a line for the note
        window = _render_window(
            view.lines, start, end, view.target, self._query,
            self._config.theme.get("match", "bold yellow"), view.lexer,
        )
        if view.truncated and at_end:
            window.append_text(view.truncation_note)
        body.update(window)

    def _move(self, delta: int) -> None:
        if self._view is None:
            return
        top = self._clamp(self._top + delta)
        if top != self._top:
            self._top = top
            self._paint()

    # --- actions -----------------------------------------------------------

    @property
    def top_line(self) -> int:
        """First visible line, 1-based. Exposed so tests can assert on paging."""
        return self._top

    def action_back(self) -> None:
        self.dismiss(None)

    def action_scroll(self, direction: int) -> None:
        self._move(direction)

    def action_half(self, direction: int) -> None:
        self._move(direction * max(1, self._height() // 2))

    def action_page(self, direction: int) -> None:
        self._move(direction * max(1, self._height() - 1))

    def action_to_top(self) -> None:
        self._move(-len(self._view.lines) if self._view else 0)

    def action_to_bottom(self) -> None:
        self._move(len(self._view.lines) if self._view else 0)
