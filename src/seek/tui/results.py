"""The result list widget (virtualized, not focusable - the query box keeps focus).

Rows never wrap by default: each row is shortened to a single line, windowed so
the matched characters stay visible. Set ``wrap_results = true`` in the config
to wrap instead. The path and the matched content are drawn in different
colours.
"""

from __future__ import annotations

from rich.text import Text
from textual.widgets import OptionList
from textual.widgets.option_list import Option

from seek.config import Config
from seek.models import MatchKind, Result
from seek.tui.cells import clip_window

_TAB = 4


def _expand_tabs(s: str, tabsize: int = _TAB) -> tuple[str, list[int]]:
    """``s.expandtabs(tabsize)`` plus the column each original character landed on.

    Match spans are computed by the engine against the line *as stored*, but the
    row renders it with tabs expanded. Without a mapping between the two the
    highlight is applied at stored offsets to expanded text, which puts it on the
    wrong characters - visibly wrong on any tab-indented file.
    """
    if "\t" not in s:
        return s, list(range(len(s)))
    out: list[str] = []
    cols: list[int] = []
    col = 0
    for ch in s:
        cols.append(col)
        if ch == "\t":
            width = tabsize - (col % tabsize)
            out.append(" " * width)
            col += width
        else:
            out.append(ch)
            col += 1
    return "".join(out), cols


_MARKER_STYLE = {
    MatchKind.FILENAME: "marker_filename",
    MatchKind.DIRNAME: "marker_dirname",
    MatchKind.CONTENT: "marker_content",
}
_PREFIX_CELLS = 4  # "● " + "c "


class ResultsList(OptionList):
    can_focus = False
    DEFAULT_CSS = """
    ResultsList { height: 1fr; border: none; padding: 0; }
    """

    def __init__(self, config: Config) -> None:
        super().__init__()
        self._config = config
        self._wrap = config.wrap_results
        self._last_w = 0
        # `results` is in display order: worst match first (top), best last
        # (bottom, next to the query box). The cursor starts on the best match.
        self.results: list[Result] = []
        self.marked: set[tuple[str, int | None]] = set()

    # --- population -------------------------------------------------------------

    def set_results(self, ranked: list[Result], *, preserve: bool = False) -> None:
        """`ranked` is best-first (engine order); displayed bottom-up.

        ``preserve`` keeps the cursor on the same result (by identity) instead
        of snapping it to the best match - used for progressive/streaming
        updates so navigation is not yanked away mid-scan.
        """
        keep = self.current().identity() if (preserve and self.current()) else None
        self.results = list(reversed(ranked))
        self.marked &= {r.identity() for r in self.results}
        self.clear_options()
        self.add_options([self._render_row(r) for r in self.results])
        if not self.results:
            return
        target = len(self.results) - 1  # best match, at the bottom
        if keep is not None:
            for i, r in enumerate(self.results):
                if r.identity() == keep:
                    target = i
                    break
        self.highlighted = target
        self.scroll_to_highlight()

    def ranked(self) -> list[Result]:
        """Best-first order, for exports."""
        return list(reversed(self.results))

    def on_resize(self, _event) -> None:
        w = self._budget()
        if not self._wrap and self.results and w != self._last_w:
            self._last_w = w
            self._rerender_rows()

    def _rerender_rows(self) -> None:
        for i, r in enumerate(self.results):
            self.replace_option_prompt_at_index(i, self._render_row(r).prompt)

    # --- row rendering -------------------------------------------------------

    def _budget(self) -> int:
        w = self.scrollable_content_region.width or self.size.width or 120
        return max(24, w - 1)

    def _t(self, key: str) -> str:
        return self._config.theme.get(key, "")

    def _render_row(self, r: Result) -> Option:
        text = Text(no_wrap=not self._wrap, overflow="fold" if self._wrap else "crop")
        text.append("● " if r.identity() in self.marked else "  ", style=self._t("selected"))
        text.append(f"{r.kind.marker} ", style=self._t(_MARKER_STYLE[r.kind]))
        rem = max(8, self._budget() - _PREFIX_CELLS)

        if r.kind is MatchKind.CONTENT:
            self._render_content_row(text, r, rem)
        else:
            self._render_name_row(text, r, rem)
        return Option(text, id=self._oid(r))

    def _render_name_row(self, text: Text, r: Result, rem: int) -> None:
        rel = r.rel
        # The engine scores a name result against the *basename* (`cand.name`),
        # so its spans are basename-relative, while the row draws the whole
        # relative path. Shift them onto the text being rendered before anything
        # clips it - otherwise `main` in `src/main.py` lights up `src/`.
        base_at = rel.rfind("/") + 1
        spans = [p + base_at for p in r.spans if 0 <= p + base_at < len(rel)]
        if not self._wrap:
            rel, spans = clip_window(rel, spans, rem, anchor="tail")
        start = len(text.plain)
        cut = rel.rfind("/") + 1
        if cut:
            text.append(rel[:cut], style=self._t("path"))
        text.append(rel[cut:], style=self._t("basename"))
        self._highlight(text, start, spans)

    def _render_content_row(self, text: Text, r: Result, rem: int) -> None:
        prefix = f"{r.rel}:{r.line_no}: "
        prefix_budget = max(14, rem // 2)
        if not self._wrap and len(prefix) > prefix_budget:
            prefix, _ = clip_window(prefix, [], prefix_budget, anchor="tail")
        text.append(prefix, style=self._t("path"))

        raw, cols = _expand_tabs(r.line_text or "")
        stripped = raw.strip()
        lead = len(raw) - len(raw.lstrip())
        # `r.spans` index the stored line; `stripped` is the expanded line with
        # its indent removed. Move each span through both steps rather than
        # assuming the three strings share a coordinate system.
        spans = []
        for p in r.spans:
            if 0 <= p < len(cols):
                shifted = cols[p] - lead
                if 0 <= shifted < len(stripped):
                    spans.append(shifted)
        line_budget = max(8, rem - len(prefix))
        if not self._wrap:
            stripped, spans = clip_window(stripped, spans, line_budget, anchor="match")
        start = len(text.plain)
        text.append(stripped, style=self._t("content"))
        self._highlight(text, start, spans)

    def _highlight(self, text: Text, start: int, spans: list[int]) -> None:
        """Apply the match style to ``spans`` (offsets from ``start``)."""
        style = self._t("match")
        end = len(text.plain)
        for pos in spans:
            p = start + pos
            if start <= p < end:
                text.stylize(style, p, p + 1)

    @staticmethod
    def _oid(r: Result) -> str:
        return f"{r.path}\x00{r.view_line or r.line_no}"

    # --- selection -----------------------------------------------------------

    def current(self) -> Result | None:
        if self.highlighted is None or not self.results:
            return None
        return self.results[self.highlighted]

    def selected_results(self) -> list[Result]:
        if not self.marked:
            return []
        return [r for r in self.ranked() if r.identity() in self.marked]

    def toggle_mark(self) -> None:
        cur = self.current()
        if cur is None:
            return
        self.marked.symmetric_difference_update({cur.identity()})
        self.replace_option_prompt_at_index(self.highlighted, self._render_row(cur).prompt)

    def clear_marks(self) -> None:
        if not self.marked:
            return
        self.marked.clear()
        self._rerender_rows()

    # --- navigation (called by the app; focus stays on the query) -----------

    def nav(self, delta: int) -> None:
        if not self.results:
            return
        cur = self.highlighted or 0
        self.highlighted = max(0, min(len(self.results) - 1, cur + delta))
        self.scroll_to_highlight()
