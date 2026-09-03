"""Trimming text to a width measured in terminal cells.

A terminal budget is in cells, not characters: CJK, most emoji and the box
glyphs occupy two cells each, so a row measured with ``len()`` can be twice as
wide as the space it was given. In the result list that overflows the pane; in
the scan viewer's ``DataTable``, whose columns have fixed widths, it overruns
the column and pushes the ones beside it.

ASCII is the overwhelmingly common case and needs none of this, so both helpers
take the arithmetic shortcut when the string has no wide characters at all and
only walk the string when it does.
"""

from __future__ import annotations

from rich.cells import cell_len, get_character_cell_size

ELLIPSIS = "…"


def width_of(text: str) -> int:
    """How many cells ``text`` occupies, on the same shortcut as the rest.

    `rich.cells.cell_len` walks the string; the scan viewer budgets its columns
    by measuring every cell of every row, which is two hundred thousand calls
    for a projection that yields fifty thousand rows - a sixth of a second on
    the event loop, and an address, a port number or a service name is ASCII
    every time.
    """
    return len(text) if text.isascii() else cell_len(text)


def fit_forward(s: str, start: int, budget: int) -> int:
    """The largest ``end`` with ``cell_len(s[start:end]) <= budget``."""
    if s.isascii():
        return min(len(s), start + max(0, budget))
    used = 0
    end = start
    for i in range(start, len(s)):
        width = get_character_cell_size(s[i])
        if used + width > budget:
            break
        used += width
        end = i + 1
    return end


def fit_back(s: str, end: int, budget: int) -> int:
    """The smallest ``start`` with ``cell_len(s[start:end]) <= budget``."""
    if s.isascii():
        return max(0, end - max(0, budget))
    used = 0
    start = end
    for i in range(end - 1, -1, -1):
        width = get_character_cell_size(s[i])
        if used + width > budget:
            break
        used += width
        start = i
    return start


def clip_cells(text: str, width: int, ellipsis: str = ELLIPSIS) -> str:
    """Trim ``text`` to ``width`` cells, marking that something was removed."""
    if width <= 0 or cell_len(text) <= width:
        return text
    keep = max(1, width - cell_len(ellipsis))
    return text[: fit_forward(text, 0, keep)] + ellipsis


def clip_window(
    s: str, spans: list[int], budget: int, anchor: str
) -> tuple[str, list[int]]:
    """Shorten ``s`` to at most ``budget`` cells, keeping ``spans`` visible.

    ``anchor``: 'match' windows around the first span, 'tail' keeps the end,
    'head' keeps the start. Returns the visible text and the span positions
    remapped onto it - character indices, since that is what Rich styles by.
    """
    if cell_len(s) <= budget:
        return s, spans
    inner = max(4, budget - 2)  # leave room for the ellipses, one cell each
    max_start = fit_back(s, len(s), inner)
    if anchor == "tail":
        start = max_start
    elif anchor == "match" and spans:
        start = min(max(0, min(spans) - inner // 4), max_start)
    else:
        start = 0
    end = fit_forward(s, start, inner)
    pre = ELLIPSIS if start > 0 else ""
    suf = ELLIPSIS if end < len(s) else ""
    out = pre + s[start:end] + suf
    off = len(pre) - start
    return out, [p + off for p in spans if start <= p < end]
