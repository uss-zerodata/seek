"""Full-screen, searchable reader for the selected row's detail.

The inline pane is right for a glance, but caps out on anything taller than a
few lines — a host with many services, a vulnerability write-up, and above all
a scan's raw nmap output. `d` opens this reader instead: the same content, using
the whole screen, scrollable like a pager and searchable.

**It shows exactly what the inline pane shows.** `render_to_lines` turns
whatever Rich renderable the pane would display into one styled `Text` per
screen line, at the reader's own width - so the reader is never a second
description of a record that can drift from the first, only a bigger one. A
running scan's raw output is pushed into an open reader the same way it is
pushed into the pane (`NmapApp._refresh_detail`), so it keeps streaming; a
search is re-applied to the new lines as they arrive.

**Two levels, like the pane.** Handed a record as `list[Line]`, the reader has
a line cursor: `↑`/`↓` move it a line, lines that open something are links, and
`o` follows one into a scan's own text. That is the second level, where `↑`/`↓`
scroll and `←`/`→` step between the scans that saw the same subject; `Esc`
comes back to the record at the link it left from. `←`/`→` on the record step
between rows. Each level steps only within itself, so a reader in nmap's text
is never handed a record by an arrow key. The app owns the data - the reader
asks it through `on_step`, `on_open` and `on_sibling`.

**Windowed like the search session's own `DetailScreen`.** Only the visible
slice is painted per keystroke - a raw scan log can run to `runner.LOG_LIMIT`
(20 000) lines, and laying all of them into one `Static` at once is the exact
mistake that screen's docstring measured at seconds, not milliseconds.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console, Group, RenderableType
from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from seek.nmap import rawlog
from seek.tui.nmap.detail import Line

_FALLBACK_HEIGHT = 20
_FALLBACK_WIDTH = 80
_MATCH_STYLE = "black on yellow"
_CURRENT_MATCH_STYLE = "bold black on bright_yellow"

# A record handed over as lines, or anything else as one block.
Content = RenderableType | list[Line]
# What `on_open` / `on_sibling` hand back for a scan's text: the request it
# answers, a title, and the text.
RawPage = tuple[rawlog.Request, str, RenderableType]


def render_to_lines(renderable: RenderableType, width: int,
                    console: Console | None = None) -> list[Text]:
    """One styled `Text` per screen line, wrapped at `width`, style kept.

    A throwaway `Console` is used only to get Rich's own wrapping and to read
    each `Segment`'s `Style` object back - the console never actually prints
    anything, so its own colour system has no bearing on how the lines end up
    looking once Textual renders them.
    """
    if console is None:
        console = _console(width)
    lines: list[Text] = []
    for segments in console.render_lines(renderable, pad=False):
        text = Text()
        for segment in segments:
            text.append(segment.text, style=segment.style or "")
        lines.append(text)
    return lines or [Text("")]


def _console(width: int) -> Console:
    return Console(width=max(1, width), height=None, color_system="standard")


class _Body(Static):
    """The reader's content pane, made focusable for one reason only: Textual
    focuses the first focusable widget on mount, and the only OTHER candidate
    here is the search `Input`. Left as the default, every keystroke - the "/"
    that opens search included - would be typed straight into that Input even
    while it is `display: none`, since auto-focus does not check visibility."""

    can_focus = True


class DetailReader(ModalScreen[None]):
    """The selected row's record, full-screen. Returns nothing; it only reads."""

    BINDINGS = [
        Binding("escape,q", "back", "Back", show=False),
        Binding("up,k", "scroll(-1)", "Up", show=False),
        Binding("down,j", "scroll(1)", "Down", show=False),
        Binding("o", "open", "Open the link", show=False),
        Binding("ctrl+u", "half(-1)", "½ page up", show=False),
        Binding("ctrl+d", "half(1)", "½ page down", show=False),
        Binding("pageup,b", "page(-1)", "Page up", show=False),
        Binding("pagedown,space", "page(1)", "Page down", show=False),
        Binding("g,home", "to_top", "Top", show=False),
        Binding("G,end", "to_bottom", "Bottom", show=False),
        Binding("right,l", "step(1)", "Next entry", show=False),
        Binding("left,h", "step(-1)", "Previous entry", show=False),
        Binding("slash", "search", "Search", show=False),
        Binding("n", "next_match", "Next match", show=False),
        Binding("N", "prev_match", "Previous match", show=False),
        Binding("p", "freeze", "Freeze", show=False),
    ]
    DEFAULT_CSS = """
    DetailReader { background: $surface; }
    DetailReader .title { background: $panel; padding: 0 1; text-style: bold; }
    DetailReader #reader-body { height: 1fr; padding: 0 1; overflow: hidden; }
    DetailReader #search-row { height: 1; padding: 0 1; display: none; }
    DetailReader #search-row.-shown { display: block; }
    DetailReader #search-prompt { width: 2; color: $accent; text-style: bold; }
    DetailReader #search-input { width: 1fr; height: 1; border: none; padding: 0; }
    DetailReader .controls { color: $text-muted; padding: 0 1; height: 1; }
    """

    def __init__(self, title: str, renderable: Content,
                 on_freeze: Callable[[], None] | None = None,
                 on_step: Callable[[int], tuple[str, Content, bool] | None]
                 | None = None,
                 follow: bool = False,
                 on_open: Callable[[rawlog.Request], RawPage | None] | None = None,
                 on_sibling: Callable[[rawlog.Request, int], RawPage | None]
                 | None = None,
                 raw: RawPage | None = None) -> None:
        super().__init__()
        self._title = title
        self._source = renderable
        # The record's lines and the cursor over them; a single item, and no
        # cursor to speak of, when the content is one block.
        self._items: list[Line] = []
        self._cursor = 0
        self._starts: list[int] = [0]
        self._on_open = on_open
        self._on_sibling = on_sibling
        # While a scan's text is showing: the request it answers, and the
        # record to go back to - (title, content, cursor, top).
        self._raw: rawlog.Request | None = None
        self._record: tuple[str, Content, int, int] | None = None
        if raw is not None:
            self._enter_raw(raw, cursor=_opening(renderable, raw[0]))
        # `<-`/`->`: hand a direction to the list and get the neighbouring
        # row's record back, so entries are read one after another without
        # going back to the list and reopening. `None` at either end - the
        # list does not wrap on `j`/`k` either.
        self._on_step = on_step
        # A modal captures all input, so `p` never reaches the app's own
        # freeze binding underneath - this is how the reader still freezes in
        # step with the pane rather than the two disagreeing about whether a
        # scan's log is moving. `None` outside the Scans tab, where there is
        # nothing to freeze.
        self._on_freeze = on_freeze
        self._lines: list[Text] = [Text("")]
        self._top = 0
        # Only meaningful while a live scan is streaming: True chases the
        # newest line, exactly like the inline pane; any manual scroll turns it
        # off, and `G`/`end` turns it back on - the same "stick to the bottom
        # unless you scrolled away" rule as everywhere else output streams.
        # Defaults off: a host record or a finished report is read from the
        # top, like any other document - only a running scan's raw log, opened
        # with `follow=True`, starts at the newest line the way the pane does.
        self._follow = follow
        self._term = ""
        self._matches: list[tuple[int, int, int]] = []   # (line, start, end)
        self._match_index = -1

    # --- layout --------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(f" {self._title} ", classes="title")
        yield _Body(id="reader-body")
        with Horizontal(id="search-row"):
            yield Static("/", id="search-prompt")
            yield Input(placeholder="search…", id="search-input")
        yield Static(self._controls_text(), classes="controls")

    def on_mount(self) -> None:
        # The body has no real size until a layout pass has run.
        self.call_after_refresh(lambda: self._set_renderable(self._source))
        if self._raw is not None:
            self._set_title(self._title)

    def on_resize(self, _event: object) -> None:
        # Re-wrapping at the new width is the only correct response to a
        # resize; `Screen.on_resize` fires reliably (unlike `App.on_resize`).
        self._set_renderable(self._source)

    # --- content -------------------------------------------------------

    def update(self, renderable: Content) -> None:
        """Replace the record - the live path, called as a scan streams.

        While a scan's text is showing, the record underneath is what changed,
        so it is the one kept up to date; the text on screen stays.
        """
        if self._record is not None:
            title, _old, cursor, top = self._record
            self._record = (title, renderable, cursor, top)
            return
        self._source = renderable
        self._set_renderable(renderable)

    def _set_renderable(self, renderable: Content) -> None:
        width = self._width()
        if isinstance(renderable, list):
            self._items = renderable or [Line(Text(""))]
            console = _console(width)
            self._lines, self._starts = [], []
            for item in self._items:
                self._starts.append(len(self._lines))
                self._lines += render_to_lines(item.text, width, console)
        else:
            self._items = [Line(renderable)]
            self._starts = [0]
            self._lines = render_to_lines(renderable, width)
        self._cursor = max(0, min(self._cursor, len(self._items) - 1))
        self._reapply_search()
        if self._follow:
            self._top = self._clamp(len(self._lines) - self._height())
        else:
            self._top = self._clamp(self._top)
        self._paint()
        self._update_controls()

    # --- geometry --------------------------------------------------------

    def _body_widget(self) -> _Body:
        return self.query_one("#reader-body", _Body)

    def _body(self) -> _Body | None:
        try:
            return self.query_one("#reader-body", _Body)
        except NoMatches:
            return None

    def _height(self) -> int:
        body = self._body()
        return (body.size.height if body else 0) or _FALLBACK_HEIGHT

    def _width(self) -> int:
        body = self._body()
        return (body.size.width if body else 0) or _FALLBACK_WIDTH

    def _clamp(self, top: int) -> int:
        return max(0, min(top, max(0, len(self._lines) - self._height())))

    # --- painting ------------------------------------------------------

    def _has_cursor(self) -> bool:
        return len(self._items) > 1

    def _span(self, index: int) -> tuple[int, int]:
        """The screen lines one record line occupies."""
        start = self._starts[index]
        end = self._starts[index + 1] if index + 1 < len(self._starts) else len(self._lines)
        return start, end

    def _item_at(self, screen_line: int) -> int:
        """The record line that covers a screen line."""
        found = 0
        for i, start in enumerate(self._starts):
            if start > screen_line:
                break
            found = i
        return found

    def _paint(self) -> None:
        body = self._body()
        if body is None:
            return
        height = self._height()
        start, end = self._top, min(len(self._lines), self._top + height)
        marked = self._span(self._cursor) if self._has_cursor() else (0, 0)
        by_line: dict[int, list[tuple[int, int, bool]]] = {}
        for i, (line, s, e) in enumerate(self._matches):
            by_line.setdefault(line, []).append((s, e, i == self._match_index))
        window: list[Text] = []
        for idx in range(start, end):
            line = self._lines[idx].copy()
            if marked[0] <= idx < marked[1]:
                # As in the pane: reverse video on the line itself, composed
                # with what it already carries.
                line.style = f"{line.style} reverse".strip()
                if not line.plain.strip():
                    line = Text(" " * 3, style="reverse")
            for s, e, current in by_line.get(idx, []):
                line.stylize(_CURRENT_MATCH_STYLE if current else _MATCH_STYLE, s, e)
            window.append(line)
        body.update(Group(*window))

    # --- scrolling -------------------------------------------------------

    @property
    def top_line(self) -> int:
        """First visible line, 0-based. Exposed so tests can assert on paging."""
        return self._top

    def _move(self, delta: int, *, follow: bool) -> None:
        self._top = self._clamp(self._top + delta)
        self._follow = follow
        self._paint()

    def action_scroll(self, direction: int) -> None:
        """A line of the cursor on a record, a line of text otherwise.

        Where the cursor cannot move - the ends, or one block of text - the
        key scrolls instead, as it does in the pane.
        """
        if self._has_cursor():
            at = max(0, min(len(self._items) - 1, self._cursor + direction))
            if at != self._cursor:
                self._cursor = at
                self._follow = False
                self._reveal_cursor()
                self._update_controls()
                return
        self._move(direction, follow=False)

    def _reveal_cursor(self) -> None:
        start, end = self._span(self._cursor)
        height = self._height()
        if start < self._top:
            self._top = start
        elif end > self._top + height:
            self._top = start if end - start > height else end - height
        self._top = self._clamp(self._top)
        self._paint()

    def _cursor_into_view(self) -> None:
        """After a jump by pages, the cursor goes where the reader is looking."""
        if not self._has_cursor():
            return
        start, end = self._span(self._cursor)
        if end <= self._top or start >= self._top + self._height():
            self._cursor = self._item_at(self._top)
        self._update_controls()

    def action_half(self, direction: int) -> None:
        self._move(direction * max(1, self._height() // 2), follow=False)
        self._cursor_into_view()
        self._paint()

    def action_page(self, direction: int) -> None:
        self._move(direction * max(1, self._height() - 1), follow=False)
        self._cursor_into_view()
        self._paint()

    def action_to_top(self) -> None:
        self._top = 0
        self._follow = False
        self._cursor = 0
        self._paint()
        self._update_controls()

    def action_to_bottom(self) -> None:
        self._top = self._clamp(len(self._lines))
        self._follow = True
        self._cursor = max(0, len(self._items) - 1)
        self._paint()
        self._update_controls()

    # --- following a link, and the scan's text it leads to ------------------

    def _opens_here(self) -> rawlog.Request | None:
        if self._raw is not None or not self._has_cursor():
            return None
        return self._items[self._cursor].opens

    def action_open(self) -> None:
        request = self._opens_here()
        if request is None or self._on_open is None:
            return
        page = self._on_open(request)
        if page is None:
            return
        self._record = (self._title, self._source, self._cursor, self._top)
        self._enter_raw(page)
        self._display_raw()

    def _display_raw(self) -> None:
        """Show the scan's text just entered, from its top. A search carries."""
        self._top = 0
        self._follow = False
        self._match_index = -1
        self._set_title(self._title)
        self._set_renderable(self._source)

    def _enter_raw(self, page: RawPage, cursor: int = 0) -> None:
        """Take the scan's text as the content; keep the record to go back to."""
        request, title, text = page
        if self._record is None:
            # Opened straight onto a scan's text: the record handed in is the
            # one `Esc` comes back to, at the link that leads here.
            self._record = (self._title, self._source, cursor, 0)
        self._raw = request
        self._title = title
        self._source = text
        self._cursor = 0

    def _leave_raw(self) -> None:
        title, content, cursor, top = self._record
        self._raw = None
        self._record = None
        self._title = title
        self._source = content
        self._cursor = cursor
        self._match_index = -1
        self._set_title(title)
        self._set_renderable(content)
        self._top = self._clamp(top)
        self._reveal_cursor()
        self._update_controls()

    def _set_title(self, title: str) -> None:
        try:
            self.query_one(".title", Static).update(f" {title} ")
        except NoMatches:
            pass

    def action_step(self, delta: int) -> None:
        """The previous/next of whatever is showing: a row's record, or a scan.

        In a scan's text it is the other scans of the same subject; on a record
        it is the neighbouring rows. Never one for the other - an arrow that
        swapped nmap's text for a record would be leaving the level unasked.
        """
        if self._raw is not None:
            self._step_scan(delta)
            return
        self._step_row(delta)

    def _step_scan(self, delta: int) -> None:
        if self._on_sibling is None or self._raw is None:
            return
        page = self._on_sibling(self._raw, delta)
        if page is None:
            return
        self._enter_raw(page)
        self._display_raw()

    def _step_row(self, delta: int) -> None:
        """Read the previous/next row's record in place.

        The list is the one that moves - it hands back the row it landed on,
        so the reader and the list underneath can never disagree about which
        entry is being read, and leaving lands on the last one looked at.
        """
        if self._on_step is None:
            return
        payload = self._on_step(delta)
        if payload is None:
            return
        self._show(*payload)

    def _show(self, title: str, renderable: RenderableType, follow: bool) -> None:
        """Swap in another row's record: new title, read from the top.

        An active search survives the move - carrying the term from entry to
        entry is the whole point of stepping through them, so the matches are
        recounted against the new record and the term is left in the box. The
        current-match cursor is dropped rather than moved, so the entry opens
        at its top and `n` goes to its first match, not its second.
        """
        self._title = title
        self._set_title(title)
        self._top = 0
        self._cursor = 0
        self._match_index = -1
        self._follow = follow
        self.update(renderable)

    def action_back(self) -> None:
        box = self.query_one("#search-input", Input)
        if self.focused is box:
            self._clear_search()
            return
        if self._raw is not None and self._record is not None:
            self._leave_raw()
            return
        self.dismiss(None)

    # --- search ----------------------------------------------------------

    def action_search(self) -> None:
        self.query_one("#search-row", Horizontal).add_class("-shown")
        self.query_one("#search-input", Input).focus()

    @on(Input.Changed, "#search-input")
    def _search_changed(self, event: Input.Changed) -> None:
        self._set_term(event.value)

    @on(Input.Submitted, "#search-input")
    def _search_submitted(self, _event: Input.Submitted) -> None:
        # Leave the term and the highlighting in place; only give up the box,
        # so n/N and the scroll keys reach the reader again.
        self._body_widget().focus()

    def _set_term(self, term: str) -> None:
        self._term = term
        self._reapply_search()
        if self._matches:
            self._match_index = self._first_match_from(self._top)
            self._reveal_current_match()
        else:
            self._match_index = -1
            self._paint()
        self._update_controls()

    def _reapply_search(self) -> None:
        """Recompute matches over the current lines - called after every edit
        to the term, and after every content update, so a live scan's new
        output is searched too."""
        self._matches = []
        if not self._term:
            return
        needle = self._term.lower()
        step = max(1, len(needle))
        for i, line in enumerate(self._lines):
            hay = line.plain.lower()
            start = 0
            while (pos := hay.find(needle, start)) != -1:
                self._matches.append((i, pos, pos + len(needle)))
                start = pos + step
        if self._match_index >= len(self._matches):
            self._match_index = len(self._matches) - 1

    def _first_match_from(self, top: int) -> int:
        for i, (line, _s, _e) in enumerate(self._matches):
            if line >= top:
                return i
        return 0

    def _reveal_current_match(self) -> None:
        if not (0 <= self._match_index < len(self._matches)):
            self._paint()
            return
        line, _s, _e = self._matches[self._match_index]
        self._top = self._clamp(line - self._height() // 2)
        if self._has_cursor():
            self._cursor = self._item_at(line)
        self._follow = False
        self._paint()

    def action_freeze(self) -> None:
        if self._on_freeze is not None:
            self._on_freeze()

    def action_next_match(self) -> None:
        self._step_match(1)

    def action_prev_match(self) -> None:
        self._step_match(-1)

    def _step_match(self, direction: int) -> None:
        if not self._matches:
            return
        self._match_index = (self._match_index + direction) % len(self._matches)
        self._reveal_current_match()
        self._update_controls()

    def _clear_search(self) -> None:
        self.query_one("#search-input", Input).value = ""
        self._term = ""
        self._matches = []
        self._match_index = -1
        self.query_one("#search-row", Horizontal).remove_class("-shown")
        self._body_widget().focus()
        self._paint()
        self._update_controls()

    # --- footer ----------------------------------------------------------

    def _update_controls(self) -> None:
        try:
            footer = self.query_one(".controls", Static)
        except NoMatches:
            return
        footer.update(self._controls_text())

    def _controls_text(self) -> str:
        if self._term:
            if self._matches:
                count = len(self._matches)
                plural = "es" if count != 1 else ""
                # No current match yet (a fresh entry stepped onto) - say how
                # many there are rather than claiming to be at "0/N" of them.
                status = (f"/{self._term} — {self._match_index + 1}/{count} match{plural}"
                          if self._match_index >= 0
                          else f"/{self._term} — {count} match{plural}")
            else:
                status = f"/{self._term} — no matches"
            return f"{status}   n next · N prev · / edit · Esc clear · q back"
        if self._raw is not None:
            scans = " · ←/→ other scans" if self._on_sibling is not None else ""
            return f"j/k ↑↓ scroll{scans} · / search · q/Esc back to the record"
        step = " · ←/→ entry" if self._on_step is not None else ""
        move = "j/k ↑↓ line" if self._has_cursor() else "j/k ↑↓ scroll"
        link = " · o open" if self._opens_here() is not None else ""
        return f"{move}{link}{step} · g/G ends · / search · q/Esc back"


def _opening(content: Content, request: rawlog.Request) -> int:
    """Where in a record the link to this request is - where `Esc` lands."""
    if not isinstance(content, list):
        return 0
    for i, line in enumerate(content):
        opens = line.opens
        if opens is not None and _same(opens, request):
            return i
    return 0


def _same(a: rawlog.Request, b: rawlog.Request) -> bool:
    """One scan's text about one subject - by what it is, not by object.

    The pane's record and the reader's fuller one are built separately, so
    their requests are equal without being the same object.
    """
    def port(r: rawlog.Request) -> tuple[int, str] | None:
        return None if r.service is None else (r.service.port, r.service.protocol)
    return (a.entry.scan is b.entry.scan and a.host.address == b.host.address
            and port(a) == port(b))
