"""Build preview renderables for a result (side glance or full detail).

For file previews the visible window is syntax-highlighted *and* every place the
current query matches within a line is highlighted on top of that. The side
preview centres the matched line inside the visible pane so the result is
always in view.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Group, RenderableType
from rich.syntax import Syntax
from rich.text import Text

from seek.config import Config
from seek.engine.content import ContentCache
from seek.engine.format import format_lines
from seek.engine.query import ParsedQuery
from seek.engine.score import match_spans
from seek.models import MatchKind, Result
from seek.tui.tree import render_tree

_SNIFF = 8192
_TAB = 4
_MAX_SYNTAX_LINES = 5000


def _read_capped(path: Path, cap: int) -> tuple[str | None, bool, bool]:
    """Return (text, truncated, is_binary)."""
    try:
        with path.open("rb") as fh:
            raw = fh.read(cap + 1)
    except OSError:
        return None, False, False
    if b"\x00" in raw[:_SNIFF]:
        return None, False, True
    truncated = len(raw) > cap
    return raw[:cap].decode("utf-8", errors="replace"), truncated, False


@dataclass(slots=True)
class FileView:
    """A file prepared for display: the lines as indexed, plus how to draw them.

    Shared by the side preview and the detail view so both show exactly the text
    that was indexed. The detail view keeps one of these and renders only the
    slice on screen - handing a whole file to a `Static` made Textual lay out
    every line of it, which for a 120k-line file took half a minute.
    """

    lines: list[str] = field(default_factory=list)
    lexer: str = "text"
    target: int | None = None      # the matched line, in indexed coordinates
    truncated: bool = False        # the size cap cut the file short
    formatted: bool = False        # re-indented before indexing
    cap: int = 0
    error: str | None = None       # set instead of `lines` when unreadable

    @property
    def truncation_note(self) -> Text:
        return Text(
            f"\n… truncated at {self.cap // 1024} KiB — open in an editor "
            f"for the whole file",
            style="yellow",
        )


def load_file(
    result: Result, config: Config, *, full: bool, cache: ContentCache | None = None
) -> FileView:
    """Read ``result``'s file and prepare it exactly as the index saw it.

    When ``cache`` already holds the file, its lines are used rather than read
    and re-indented again: the search has just done that work, and repeating it
    cost ~50 ms of the preview's ~50 ms on a multi-megabyte file, once per press
    of an arrow key. It also makes the "preview cannot disagree with the index"
    invariant hold by construction instead of by both sides deriving the same
    thing - these are literally the lines that were searched.

    Only for the side preview, and only when the preview's own cap is no smaller
    than the cache's, so nothing is hidden that the caller asked to see.
    """
    cap = config.detail_size_cap if full else config.preview_size_cap
    if cache is not None and not full and cap >= cache.size_cap:
        got = cache.content(result.path)
        if got is not None:
            return _prepared(result, got[0], got[1], cache.was_truncated(result.path), cap)
    text, truncated, is_binary = _read_capped(result.path, cap)
    if is_binary:
        return FileView(cap=cap, error="<binary file>")
    if text is None:
        return FileView(cap=cap, error="<unreadable>")
    # Re-indent the same way the index did, so what is shown is what was
    # searched and `view_line` addresses the right line.
    file_lines, origin = format_lines(text.splitlines() or [""], result.path, config)
    return _prepared(result, file_lines, origin, truncated, cap)


def _prepared(
    result: Result,
    file_lines: list[str],
    origin: list[int] | None,
    truncated: bool,
    cap: int,
) -> FileView:
    lines = [ln.expandtabs(_TAB) for ln in file_lines]
    # `view_line` addresses the indexed text; it falls back to `line_no`, which
    # is the same thing whenever the file was not reformatted.
    target = (
        (result.view_line or result.line_no)
        if result.kind is MatchKind.CONTENT
        else None
    )
    if target is not None:
        # The preview and the index can be capped at different sizes.
        target = min(target, len(lines)) or None
    return FileView(
        lines=lines, lexer=_lexer_for(result.path), target=target,
        truncated=truncated, formatted=origin is not None, cap=cap,
    )


def build_preview(
    result: Result | None,
    config: Config,
    *,
    full: bool,
    query: ParsedQuery | None = None,
    viewport_lines: int | None = None,
    cache: ContentCache | None = None,
) -> RenderableType:
    if result is None:
        return Text("")

    if result.kind is MatchKind.DIRNAME:
        depth = 6 if full else 3
        return render_tree(
            result.path, config, max_depth=depth, max_entries=2000 if full else 400,
        )

    view = load_file(result, config, full=full, cache=cache)
    if view.error is not None:
        return Text(view.error, style="dim")
    raw_lines, lexer, target, truncated = (
        view.lines, view.lexer, view.target, view.truncated
    )
    _origin = view.formatted or None

    parts: list[RenderableType] = []
    if not full:
        # The header names the real file location, matching the result row, the
        # export format and what an editor is handed - never the position in the
        # reformatted view, whose line numbers are in the gutter.
        loc = f":{result.line_no}" if result.line_no else ""
        header = Text(f"{result.rel}{loc}", style="bold " + config.theme.get("path", "cyan"))
        n = len(raw_lines)
        header.append(f"  ·  {lexer}  ·  {n} line{'s' if n != 1 else ''}", style="dim")
        if _origin is not None:
            header.append("  ·  formatted", style="dim")
        parts.append(header)

    if full:
        start, end = 1, len(raw_lines)
    else:
        vp = viewport_lines or config.preview_window_lines
        vp = max(5, min(vp, config.preview_window_lines) - 1)  # -1 for the header
        start = max(1, target - vp // 2) if target else 1
        end = min(len(raw_lines), start + vp - 1)
        start = max(1, end - vp + 1)  # pull the window up if we hit the end

    parts.append(
        _render_window(
            raw_lines, start, end, target, query,
            config.theme.get("match", "bold yellow"), lexer,
        )
    )
    if truncated:
        parts.append(view.truncation_note)
    return Group(*parts)


def _render_window(
    raw_lines: list[str],
    start: int,
    end: int,
    target: int | None,
    query: ParsedQuery | None,
    match_style: str,
    lexer: str = "text",
) -> RenderableType:
    win = raw_lines[start - 1 : end]
    # Syntax-highlight the window, unless it is so large that tokenising it
    # would stall the UI - then fall back to plain text but keep match spans.
    if len(win) > _MAX_SYNTAX_LINES:
        rich_lines = [Text(ln) for ln in win]
    else:
        try:
            highlighted = Syntax(
                "\n".join(win), lexer, theme="ansi_dark", word_wrap=False
            ).highlight("\n".join(win))
            rich_lines = list(highlighted.split("\n"))
        except Exception:  # noqa: BLE001 - lexer/highlight edge cases
            rich_lines = [Text(ln) for ln in win]
    while len(rich_lines) < len(win):  # pragma: no cover - defensive
        rich_lines.append(Text(""))

    gutter_w = len(str(end)) + 1
    out = Text()
    for i, raw in enumerate(win):
        lineno = start + i
        line = rich_lines[i]
        line.set_length(len(raw))
        if query is not None:
            m = match_spans(query, raw)
            if m is not None:
                for pos in m[1]:
                    if 0 <= pos < len(raw):
                        line.stylize(match_style, pos, pos + 1)
        is_target = lineno == target
        gutter = Text(
            f"{lineno:>{gutter_w}} ",
            style="reverse" if is_target else "dim",
        )
        if is_target:
            line.stylize("bold")
        out.append_text(gutter)
        out.append_text(line)
        out.append("\n")
    return out


def _lexer_for(path: Path) -> str:
    try:
        from pygments.lexers import get_lexer_for_filename

        return get_lexer_for_filename(path.name).aliases[0]
    except Exception:  # noqa: BLE001
        return "text"
