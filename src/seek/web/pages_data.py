"""Records and raw output: shared by the JSON API and the page fragments."""

from __future__ import annotations

import io
from collections import OrderedDict
from pathlib import Path

from rich.console import Console

from seek.nmap import rawlog
from seek.nmap.session import Session
from seek.tui.nmap import detail as detail_pane
from seek.tui.nmap import record as record_mod
from seek.web import schemas as s
from seek.web.record import lines_html, raw_query
from seek.web.views import Unresolved, ViewCache, step_of

_FILES_KEPT = 4
_files: OrderedDict[Path, str | None] = OrderedDict()


def _plain(lines: list[detail_pane.Line]) -> str:
    console = Console(width=160, record=True, file=io.StringIO())
    console.print(detail_pane.as_group(lines))
    return console.export_text()


def record(session: Session, cache: ViewCache, tab: str, path: list[str], step: str,
           report_mode: str = "condensed", full: bool = True) -> s.RecordOut:
    place = cache.resolve(session, tab, path)
    row = next((r for r in place.view.rows(session.scans)
                if not r.heading and step_of(r) == step), None)
    if row is None:
        raise Unresolved(f"nothing called {step} in {place.view.title}")
    # A running run's log grows by the hundred lines a second and the page
    # reloads it every 400 ms: the whole of it - up to 20 000 lines through
    # Rich to HTML and to text, in the process the terminal runs in - is the
    # pane's tail until the run ends. `/runs/{id}/log` has every line.
    if getattr(row.target, "running", False):
        full = False
    lines, title = record_mod.record_lines(row, place.view.title, session,
                                           report_mode, full=full)
    return s.RecordOut(title=title, html=lines_html(lines), text=_plain(lines))


def _text_of(path: Path | None) -> str | None:
    """A scan's `.nmap` text, a few kept - stepping must not re-read."""
    if path is None:
        return None
    if path in _files:
        _files.move_to_end(path)
        return _files[path]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = None
    _files[path] = text
    while len(_files) > _FILES_KEPT:
        _files.popitem(last=False)
    return text


def raw(session: Session, scan: str, address: str, protocol: str | None = None,
        port: int | None = None) -> s.RawOut:
    host = next((h for h in session.scans.hosts if h.address == address), None)
    if host is None:
        raise Unresolved(f"no host {address}")
    service = None
    if port is not None:
        service = next((sv for sv in host.services
                        if sv.port == port and sv.protocol == (protocol or "tcp")), None)
        if service is None:
            raise Unresolved(f"no port {port}/{protocol} on {address}")
    entries = session.scanned().entries(host, service)
    here = next((i for i, e in enumerate(entries) if str(e.scan.path) == scan), -1)
    if here < 0:
        raise Unresolved(f"{scan} did not record {address}")
    request = rawlog.Request(entries[here], host, service)
    excerpt = rawlog.read(request, source=_text_of(entries[here].path))
    lines = detail_pane.raw_record(request, excerpt, at=(here + 1, len(entries)))

    def query(i: int) -> str:
        if not 0 <= i < len(entries):
            return ""
        return raw_query(rawlog.Request(entries[i], host, service))

    return s.RawOut(title=f"{request.entry.label} · {request.subject}",
                    subject=request.subject, scan=request.entry.label,
                    position=here + 1, total=len(entries), previous=query(here - 1),
                    next=query(here + 1), reconstructed=excerpt.reconstructed,
                    problem=excerpt.problem, html=lines_html(lines), text=excerpt.text)
