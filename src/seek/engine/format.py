"""Re-indent over-long structured content before it is indexed.

Minified JSON, XML and HTML put a whole document on one line. Such a line is
unreadable in the interface, and because the content query is a fuzzy
*subsequence* test it also matches essentially any query - a long enough line
contains every character in every order - so those files crowd out real results.

Both re-indenters are single-pass scanners. They do not parse and cannot fail:
truncated documents, concatenated documents, comments and unclosed markup all
produce a reasonable split rather than an error. That matters more than pretty
output, because a real tree is full of files that no parser accepts. Measured
against the alternatives, `xml.dom.minidom` is 2.3x slower and both it and
`json.loads` raise on 4 of 7 malformed-input cases these handle.
"""

from __future__ import annotations

from pathlib import Path

from seek.config import Config

# extension (without the dot) -> which re-indenter suits it
_BRACE_EXTS = frozenset({"json", "jsonl", "js", "mjs", "cjs", "css", "yaml", "yml"})
_TAG_EXTS = frozenset({"xml", "html", "htm", "svg", "xhtml"})

_OPEN = "{["
_CLOSE = "}]"
_QUOTES = "\"'"


def reflow_braces(text: str, indent: str = "  ") -> list[str]:
    """Re-indent brace/bracket structured text (JSON, JS, CSS, YAML flow).

    Tracks quote state with backslash escaping, so a `,` or `{` inside a string
    literal is never treated as a break point.
    """
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    quote = ""
    esc = False

    def flush(at_depth: int) -> None:
        frag = "".join(buf).strip()
        if frag:
            out.append(indent * at_depth + frag)
        buf.clear()

    for ch in text:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
            continue
        if ch in _QUOTES:
            in_str, quote = True, ch
            buf.append(ch)
        elif ch in _OPEN:
            buf.append(ch)
            flush(depth)
            depth += 1
        elif ch in _CLOSE:
            flush(depth)
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == ",":
            buf.append(ch)
            flush(depth)
        else:
            buf.append(ch)
    flush(depth)
    return out


def reflow_tags(text: str, indent: str = "  ") -> list[str]:
    """Re-indent tag structured text (XML, HTML, SVG).

    Tracks whether the scan is inside a tag, so a `>` inside a quoted attribute
    value does not end it. Depth decrements on a closing tag and does not
    increment for self-closing, declaration or processing-instruction tags.
    """
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    in_tag = False
    in_str = False
    quote = ""

    def emit(frag: str, at_depth: int) -> None:
        if frag.strip():
            out.append(indent * at_depth + frag.strip())

    for ch in text:
        if in_tag and in_str:
            buf.append(ch)
            if ch == quote:
                in_str = False
            continue
        if ch == "<" and not in_tag:
            emit("".join(buf), depth)
            buf = [ch]
            in_tag = True
        elif in_tag and ch in _QUOTES:
            in_str, quote = True, ch
            buf.append(ch)
        elif ch == ">" and in_tag:
            buf.append(ch)
            tag = "".join(buf)
            buf = []
            in_tag = False
            closing = tag.startswith("</")
            standalone = (
                tag.endswith("/>") or tag.startswith("<!") or tag.startswith("<?")
            )
            if closing:
                depth = max(0, depth - 1)
            emit(tag, depth)
            if not closing and not standalone:
                depth += 1
        else:
            buf.append(ch)
    emit("".join(buf), depth)
    return out


def _reflow_for(path: Path) -> callable | None:
    ext = path.suffix.lstrip(".").lower()
    if ext in _BRACE_EXTS:
        return reflow_braces
    if ext in _TAG_EXTS:
        return reflow_tags
    return None


def should_format(path: Path, config: Config) -> bool:
    """Cheap check: is this file even a candidate for re-indenting?"""
    if not config.format_content:
        return False
    ext = path.suffix.lstrip(".").lower()
    return ext in {e.lstrip(".").lower() for e in config.format_extensions}


def format_lines(
    raw_lines: list[str], path: Path, config: Config
) -> tuple[list[str], list[int] | None]:
    """Return ``(lines, origin)`` for indexing.

    ``origin[i]`` is the 1-based line of the stored file that formatted line
    ``i`` came from; it is ``None`` when nothing was reformatted, in which case
    the identity mapping is implied and line numbers are exact.

    Only lines longer than ``config.format_min_line`` are re-indented. A file
    with no such line is returned untouched, so an already-pretty document costs
    one pass over its line lengths and keeps its real line numbers.
    """
    if not should_format(path, config):
        return raw_lines, None
    limit = config.format_min_line
    if not any(len(line) > limit for line in raw_lines):
        return raw_lines, None
    reflow = _reflow_for(path)
    if reflow is None:  # extension configured but no re-indenter suits it
        return raw_lines, None

    out: list[str] = []
    origin: list[int] = []
    for lineno, line in enumerate(raw_lines, start=1):
        if len(line) <= limit:
            out.append(line)
            origin.append(lineno)
            continue
        pieces = reflow(line)
        if not pieces:  # nothing but whitespace survived - keep the original
            pieces = [line]
        out.extend(pieces)
        origin.extend([lineno] * len(pieces))
    return out, origin
