"""Every overview and drill-down, addressed by URL.

A browser's position is its URL: the tab, the drill-down path, and the
current level's filter, sort, toggles and selected row. Going back is the
browser's own history, so each level comes back with the filter, sort and row it
was left with - the terminal's rule, with no server-side client state, and two
windows independent by construction.

A drill step is named by what its row *is* - `h:10.0.0.5`, `s:tcp/443/https/
nginx/1.25`, `b:port/443/tcp` - never by its position, so a URL still resolves
after a scan has grown the model. Steps are resolved by rebuilding the parent
view and finding the row with the same name, which is exactly how the terminal
re-finds a row after a rebuild.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from seek.nmap import filtering
from seek.nmap import inventory as inv_mod
from seek.nmap.models import Host, Service
from seek.nmap.runner import ScanRun
from seek.nmap.session import Session
from seek.nmap.timeline import Scan
from seek.nmap.views import ServiceGroup
from seek.runner import Run
from seek.tui.nmap import tabs
from seek.tui.nmap import views as vdefs
from seek.vulndb import match as vmatch

SEP = "|"                         # between steps in `path=`


class Unresolved(LookupError):
    """A step that names no row of its parent view any more."""


def step_of(row: vdefs.Row) -> str:
    """A row's name, stable across rebuilds of the same model and growth of it."""
    t = row.target
    if isinstance(t, Host):
        return f"h:{t.address}"
    if isinstance(t, ServiceGroup):
        return f"s:{t.protocol}/{t.port}/{t.name or ''}/{t.product or ''}/{t.version or ''}"
    if isinstance(t, Service) and row.host is not None:
        return f"p:{row.host.address}/{t.protocol}/{t.port}"
    if isinstance(t, vdefs.Grouping):
        return f"b:{t.key}/{t.label}"
    if isinstance(t, vmatch.Affected):
        return f"c:{t.finding.id}/{t.entry.key if t.entry else ''}/{t.version or ''}"
    if isinstance(t, inv_mod.Entry):
        # Product *and* version: the tab lists nginx 1.16.1 and nginx apart.
        return f"i:{t.key}/{t.version or ''}"
    if isinstance(t, Scan):
        return f"f:{t.path or t.label}"
    if isinstance(t, Run):
        return f"r:{id(t):x}"
    return f"k:{row.section}/{row.cells[0] if row.cells else ''}"


@dataclass
class Level:
    """One level of a path: its view, and the row of its parent it came from."""

    view: vdefs.View
    step: str = ""


@dataclass
class Place:
    """Where a URL points: the tab, the levels down to the current one."""

    tab: str
    levels: list[Level] = field(default_factory=list)

    @property
    def view(self) -> vdefs.View:
        return self.levels[-1].view

    @property
    def marked_tab(self) -> str:
        """The tab whose subject is on screen - the topmost view that claims one."""
        return next((lv.view.tab for lv in reversed(self.levels) if lv.view.tab), self.tab)


def resolve(session: Session, tab: str, path: list[str], only_up: bool = False,
            only_ports: bool = False, only_open: bool = False) -> Place:
    if tab not in dict(tabs.TABS):
        raise Unresolved(f"no tab {tab}")
    place = Place(tab, [Level(tabs.tab_view(tab, session, only_up, only_ports))])
    for step in path:
        rows = place.view.rows(session.scans)
        row = next((r for r in rows if not r.heading and step_of(r) == step), None)
        if row is None:
            raise Unresolved(f"nothing called {step} in {place.view.title}")
        # `only_open` applies to a host's own port list, the level it opens.
        child = vdefs.open_row(row, session.scans.hosts, only_open)
        if child is None:
            raise Unresolved(f"{step} opens nothing")
        place.levels.append(Level(child, step))
    return place


@dataclass
class Listing:
    columns: tuple[str, ...]
    rows: list[vdefs.Row]
    total: int                     # rows before the filter, headings excluded
    sort: int
    desc: bool
    loose: int = 0                 # scattered-letter matches left out


def listing(session: Session, view: vdefs.View, q: str = "",
            sort: int | None = None, desc: bool | None = None) -> Listing:
    """The view's rows, filtered and sorted exactly as `NmapApp._narrow` does."""
    rows = view.rows(session.scans)
    col, down = view.default_sort
    if sort is not None:
        col, down = sort, bool(desc)
    col = min(max(col, 0), max(0, len(view.columns) - 1))
    spec = filtering.parse_filter(q.strip()) if q.strip() else filtering.FilterSpec()
    unfiltered = sum(1 for r in rows if not r.heading)
    loose = 0
    if not spec.is_empty:
        rows = [r for r in rows if r.heading
                or filtering.matches(spec, session.row_text(r), r.addresses, r.records)]
        rows, loose = filtering.prefer_firm(spec, rows, session.row_text)
        live = {r.section for r in rows if not r.heading}
        rows = [r for r in rows if not r.heading or r.section in live]
    rows = sorted(rows, key=lambda r: vdefs.key_at(r, col), reverse=down)
    rows.sort(key=lambda r: (r.section_rank, 0 if r.heading else 1))
    return Listing(view.columns, rows, unfiltered, col, down, loose)


def mark_state(session: Session, row: vdefs.Row) -> str:
    """`all`, `some` or `` - the terminal's `●` and `◐`."""
    if not session.marks or not row.records:
        return ""
    marked = sum(1 for r in row.records if r.identity in session.marks)
    if not marked:
        return ""
    return "all" if marked == len(row.records) else "some"


def run_of(row: vdefs.Row) -> ScanRun | Run | None:
    return row.target if isinstance(row.target, Run) else None


class ViewCache:
    """One view object per place, so its rows are projected once per model.

    A view keeps its rows keyed on the `ScanSet` it built them from, so reusing
    the object is all the caching there is; a new model rebuilds on next use.
    Bounded: drill-downs are cheap and plentiful, overviews are few.
    """

    LIMIT = 128

    def __init__(self) -> None:
        self._places: dict[tuple, Place] = {}

    def resolve(self, session: Session, tab: str, path: list[str], only_up: bool = False,
                only_ports: bool = False, only_open: bool = False) -> Place:
        key = (tab, tuple(path), only_up, only_ports, only_open)
        if tab in ("inventory", "findings"):
            # Its levels are built from entries that captures change without
            # the model changing; a new capture generation is a new place.
            key += (session.shots.generation, session.vulndb().generation)
        place = self._places.get(key)
        if place is None or place.levels[0].view.kind == "scans":
            place = resolve(session, tab, path, only_up, only_ports, only_open)
            if len(self._places) >= self.LIMIT:
                self._places.pop(next(iter(self._places)))
            self._places[key] = place
        return place


def _opens(row: vdefs.Row) -> bool:
    """Whether opening a row goes anywhere - without building where it goes."""
    target = row.drill if row.drill is not None else row.target
    return isinstance(target, (vdefs.View, ServiceGroup, vdefs.Grouping, inv_mod.Entry,
                               vmatch.Affected, Host, Service))


_SHOTS_PER_ROW = 3


def row_shots(model, row: vdefs.Row):
    """A row's captures, by what it stands for: a port its own, a host all of
    its ports', a bucket every member's - the first few, and how many."""
    from seek.web import schemas as s

    if model is None or not model.captures or not row.records:
        return [], 0
    seen: dict[str, object] = {}
    for record in row.records:
        found = (model.captures_of(record.host, record.service) if record.service
                 else model.captures_of_host(record.host))
        for placed in found:
            seen.setdefault(placed.id, placed)
    picked = list(seen.values())
    refs = [s.ShotRef(id=p.id, url=p.capture.url, status=p.capture.status,
                      image=None if p.capture.failed or p.capture.shot is None
                      else f"/media/shot/{p.id}")
            for p in picked[:_SHOTS_PER_ROW]]
    return refs, len(picked)


def overview(session: Session, cache: ViewCache, tab: str, path: list[str], q: str = "",
             sort: int | None = None, desc: bool | None = None, up: bool = False,
             ports: bool = False, only_open: bool = False, offset: int = 0,
             limit: int = 500, model=None):
    """Everything a list page or `GET /api/v1/views/{tab}` shows."""
    from seek.web import schemas as s

    place = cache.resolve(session, tab, path, up, ports, only_open)
    shown = listing(session, place.view, q, sort, desc)
    limit = max(1, min(limit, 5000))
    offset = max(0, offset)
    crumbs = [s.Crumb(title=lv.view.title, path=SEP.join(path[:i]))
              for i, lv in enumerate(place.levels)]
    return s.ViewOut(
        tab=tab, kind=place.view.kind, marked_tab=place.marked_tab, title=place.view.title,
        subtitle=place.view.subtitle, path=SEP.join(path), crumbs=crumbs,
        columns=list(shown.columns), sort=shown.sort, desc=shown.desc,
        total=shown.total, count=sum(1 for r in shown.rows if not r.heading),
        offset=offset, limit=limit, marks=len(session.marks),
        understood=filtering.explain(filtering.parse_filter(q)) if q.strip() else [],
        loose=shown.loose,
        rows=[_row_out(session, model, r) for r in shown.rows[offset:offset + limit]])


def _row_out(session: Session, model, r: vdefs.Row):
    from seek.web import schemas as s

    shots, total = ([], 0) if r.heading else row_shots(model, r)
    return s.RowOut(step=step_of(r) if not r.heading else "", cells=list(r.cells),
                    tones=list(r.tones),
                    heading=r.heading, section=r.section, mark=mark_state(session, r),
                    opens=_opens(r) and not r.heading, shots=shots, shots_total=total)
