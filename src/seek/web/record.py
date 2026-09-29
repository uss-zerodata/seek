"""A row's record as HTML - the terminal's record, converted, never re-described.

`record.record_lines` builds the record once, as Rich; this renders each line
through a Rich console into styled segments and writes those as HTML. Styles map
by *attribute* - bold, dim, italic, underline, reverse, and the colour - rather
than by a table of the style strings `detail.py` happens to use, so a style
added to the terminal's record can never be dropped here unnoticed. Standard
colours become classes the stylesheet themes for light and dark; any other
colour is kept inline.

A line that opens something becomes a link to that scan's own text for the
record's subject.
"""

from __future__ import annotations

from html import escape
from urllib.parse import urlencode

from rich.console import Console
from rich.style import Style

from seek.gowitness.results import Capture
from seek.nmap import rawlog
from seek.tui.nmap import detail as detail_pane
from seek.web import links

_WIDTH = 160
_STANDARD = {"black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"}


def _color_class(color, prefix: str) -> tuple[str, str]:
    """(class, inline style) for a Rich colour."""
    if color is None or color.is_default:
        return "", ""
    name = color.name.lower().replace("bright_", "b")
    base = name[1:] if name.startswith("b") and name[1:] in _STANDARD else name
    if base in _STANDARD:
        return f"{prefix}-{name}", ""
    triplet = color.get_truecolor()
    prop = "color" if prefix == "c" else "background-color"
    return "", f"{prop}:#{triplet.red:02x}{triplet.green:02x}{triplet.blue:02x}"


def style_attrs(style: Style | None) -> tuple[list[str], list[str]]:
    classes: list[str] = []
    inline: list[str] = []
    if style is None:
        return classes, inline
    for flag, cls in (("bold", "b"), ("dim", "d"), ("italic", "i"),
                      ("underline", "u"), ("reverse", "rv"), ("strike", "s")):
        if getattr(style, flag):
            classes.append(cls)
    for color, prefix in ((style.color, "c"), (style.bgcolor, "bg")):
        cls, css = _color_class(color, prefix)
        if cls:
            classes.append(cls)
        if css:
            inline.append(css)
    return classes, inline


def _html_of(renderable, console: Console) -> str:
    out: list[str] = []
    for line in console.render_lines(renderable, pad=False):
        parts: list[str] = []
        for segment in line:
            if not segment.text:
                continue
            classes, inline = style_attrs(segment.style)
            text = escape(segment.text)
            if classes or inline:
                attrs = f' class="{" ".join(classes)}"' if classes else ""
                attrs += f' style="{";".join(inline)}"' if inline else ""
                text = f"<span{attrs}>{text}</span>"
            parts.append(text)
        out.append("".join(parts))
    return "\n".join(out)


def raw_query(request: rawlog.Request) -> str:
    """Query parameters naming one scan's text about one subject."""
    params = {"scan": str(request.entry.scan.path), "address": request.host.address}
    if request.service is not None:
        params.update(protocol=request.service.protocol, port=str(request.service.port))
    return urlencode(params)


def thumbnail(capture: Capture) -> str:
    """A capture's picture, small, opening its page - the gallery's thumbnail."""
    if capture.shot is None or capture.failed:
        return ""
    return (f'<a class="thumb-inline" href="{links.capture(capture)}" '
            f'title="{escape(capture.url)}"><img src="{links.image(capture)}" '
            f'alt="screenshot of {escape(capture.url)}"></a>')


def lines_html(lines: list[detail_pane.Line], width: int = _WIDTH) -> str:
    """Each line as HTML; a line about something links to it.

    A capture's thumbnail follows the last consecutive line about it - a URL and
    the result under it are one capture, shown once.
    """
    console = Console(width=width, color_system="truecolor", record=False,
                      force_terminal=True, legacy_windows=False)
    out: list[str] = []
    shown: set[int] = set()
    for i, line in enumerate(lines):
        body = _html_of(line.text, console)
        if line.opens is not None:
            body = (f'<a class="opens" href="/raw?{escape(raw_query(line.opens))}" '
                    f'data-raw="{escape(raw_query(line.opens))}">{body}</a>')
        elif (target := links.href(line.to)) is not None:
            body = f'<a class="to" href="{escape(target)}">{body}</a>'
        out.append(f'<div class="ln" data-i="{i}">{body or "&nbsp;"}</div>')
        if isinstance(line.to, Capture) and id(line.to) not in shown:
            following = lines[i + 1].to if i + 1 < len(lines) else None
            if following is not line.to:
                shown.add(id(line.to))
                picture = thumbnail(line.to)
                if picture:
                    out.append(f'<div class="shot">{picture}</div>')
    return "\n".join(out)
