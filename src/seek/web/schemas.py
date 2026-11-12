"""The shapes the API returns and the pages render.

One set for both: a page is a template over the same object the API sends as
JSON, so the two cannot describe a host differently. Built from the model by
the `out_*` functions here and nowhere else.
"""

from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from seek.nmap import names as name_mod
from seek.nmap import vulns
from seek.nmap.models import Host, Service, Vulnerability
from seek.nmap.views import ServiceGroup
from seek.web.source import Placed, WebModel

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int
    loose: int = 0                   # scattered-letter matches left out (`~` shows them)


class CaptureSummary(BaseModel):
    id: str
    url: str
    final_url: str = ""
    redirected: bool = False
    status: int | None = None
    title: str = ""
    failed: bool = False
    failure: str = ""
    database: str = ""
    address: str | None = None
    protocol: str | None = None
    port: int | None = None
    image: str | None = None            # the media route, when there is a picture
    # How many captures this one's service has - more than one is worth a link
    # to see them together. 0 when it belongs to no service.
    siblings: int = 0


class CaptureOut(CaptureSummary):
    reason: str = ""
    http_protocol: str = ""
    probed_at: str = ""
    content_length: int | None = None
    technologies: list[str] = []
    headers: list[tuple[str, str]] = []
    cookies: list[tuple[str, str]] = []
    console: list[tuple[str, str]] = []
    network: list[tuple[str, str]] = []
    tls: str = ""
    sans: list[str] = []


class VulnOut(BaseModel):
    id: str
    title: str | None = None
    state: str | None = None
    severity: str | None = None
    ids: list[str] = []
    refs: list[str] = []


class PortOut(BaseModel):
    protocol: str
    port: int
    state: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    vulnerabilities: list[VulnOut] = []
    captures: list[CaptureSummary] = []


class HostSummary(BaseModel):
    address: str
    names: list[str] = []
    os: str | None = None
    up: bool = False
    state: str | None = None
    open_ports: list[str] = []
    captures: int = 0


class HostOut(HostSummary):
    reason: str | None = None
    sources: list[str] = []
    ports: list[PortOut] = []
    vulnerabilities: list[VulnOut] = []


class ServiceSummary(BaseModel):
    protocol: str
    port: int
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    hosts: int = 0
    vulnerabilities: int = 0


class ServiceHost(BaseModel):
    address: str
    names: list[str] = []
    version: str | None = None
    extrainfo: str | None = None
    captures: list[CaptureSummary] = []


class ServiceOut(ServiceSummary):
    members: list[ServiceHost] = []


class ErrorOut(BaseModel):
    detail: str


# --- from the model -------------------------------------------------------------


def _names(host: Host) -> list[str]:
    return [name for name, _ in name_mod.host_names(host)]


def out_capture(placed: Placed, full: bool = False, siblings: int = 0) -> CaptureSummary:
    c = placed.capture
    common = dict(
        id=placed.id, url=c.url, final_url=c.final_url, redirected=c.redirected,
        status=c.status, title=c.title, failed=c.failed, failure=c.failure,
        database=str(c.database or ""),
        address=placed.host.address if placed.host else None,
        protocol=placed.service.protocol if placed.service else None,
        port=placed.service.port if placed.service else None,
        image=f"/media/shot/{placed.id}" if c.shot is not None and not c.failed else None,
        siblings=siblings,
    )
    if not full:
        return CaptureSummary(**common)
    return CaptureOut(
        **common, reason=c.reason, http_protocol=c.protocol, probed_at=c.probed_at,
        content_length=c.content_length, technologies=c.technologies,
        headers=c.headers, cookies=c.cookies, console=c.console, network=c.network,
        tls=c.tls, sans=c.sans)


def out_vuln(v: Vulnerability) -> VulnOut:
    return VulnOut(id=v.id, title=v.title, state=v.state, severity=v.severity,
                   ids=v.ids, refs=v.refs)


def out_port(model: WebModel, host: Host, svc: Service) -> PortOut:
    return PortOut(
        protocol=svc.protocol, port=svc.port, state=svc.state, service=svc.name,
        product=svc.product, version=svc.version, extrainfo=svc.extrainfo,
        vulnerabilities=[out_vuln(v) for v in svc.vulnerabilities],
        captures=[out_capture(p) for p in model.captures_of(host, svc)])


def out_host_summary(model: WebModel, host: Host) -> HostSummary:
    return HostSummary(
        address=host.address, names=_names(host), os=host.os, up=host.up,
        state=host.state,
        open_ports=[f"{s.port}/{s.protocol}" for s in host.open_services],
        captures=len(model.captures_of_host(host)))


def out_host(model: WebModel, host: Host) -> HostOut:
    summary = out_host_summary(model, host)
    return HostOut(
        **summary.model_dump(), reason=host.reason, sources=host.sources,
        ports=[out_port(model, host, s) for s in host.services],
        vulnerabilities=[out_vuln(v) for v in vulns.host_vulnerabilities(host)])


def out_service_summary(group: ServiceGroup) -> ServiceSummary:
    return ServiceSummary(
        protocol=group.protocol, port=group.port, name=group.name,
        product=group.product, version=group.version, extrainfo=group.extrainfo,
        hosts=group.host_count, vulnerabilities=group.vulnerability_count)


def out_service(model: WebModel, group: ServiceGroup) -> ServiceOut:
    return ServiceOut(
        **out_service_summary(group).model_dump(),
        members=[ServiceHost(address=h.address, names=_names(h), version=s.version,
                             extrainfo=s.extrainfo,
                             captures=[out_capture(p) for p in model.captures_of(h, s)])
                 for h, s in group.members])


# --- overviews and drill-downs ------------------------------------------------------


class Crumb(BaseModel):
    title: str
    path: str                        # the `path=` that shows this level


class ShotRef(BaseModel):
    """A capture, as small as a list row needs it."""

    id: str
    url: str
    image: str | None = None         # absent for a failure: nothing to show
    status: int | None = None


class RowOut(BaseModel):
    step: str                        # append to `path=` to open this row
    cells: list[str]
    heading: bool = False
    section: str = ""
    mark: str = ""                   # "all", "some" or ""
    opens: bool = False              # whether opening it goes anywhere
    shots: list[ShotRef] = []        # the row's captures, the first few
    shots_total: int = 0             # how many it has in all
    tones: list[str] = []            # per cell: "ok", "warn", "bad", "dim" or ""


class ViewOut(BaseModel):
    tab: str
    kind: str = ""                   # the view's kind: hosts, host-detail, services ...
    marked_tab: str
    title: str
    subtitle: str = ""
    path: str = ""
    crumbs: list[Crumb] = []
    columns: list[str]
    sort: int
    desc: bool
    total: int                       # before the filter
    count: int                       # after it
    offset: int = 0
    limit: int = 0
    rows: list[RowOut] = []
    marks: int = 0
    understood: list[str] = []       # what the filter was read as, in words
    loose: int = 0                   # scattered-letter matches left out (`~` shows them)


# --- records and nmap's own text -----------------------------------------------------


class RecordOut(BaseModel):
    title: str
    html: str                        # the terminal's record, as HTML lines
    text: str                        # the same, plain


class RawOut(BaseModel):
    title: str
    subject: str
    scan: str
    position: int                    # 1-based, of `total` scans of this subject
    total: int
    previous: str = ""               # query string of the previous scan's text
    next: str = ""
    reconstructed: bool = False
    problem: str = ""
    html: str
    text: str


# --- marks and export ----------------------------------------------------------------


class RowRef(BaseModel):
    """A row of a view, by the same names the page uses."""

    tab: str
    path: str = ""
    step: str


class MarkOut(BaseModel):
    address: str
    protocol: str | None = None
    port: int | None = None
    label: str


class MarksOut(BaseModel):
    count: int
    marked: bool | None = None       # the toggled row, after a toggle
    marks: list[MarkOut] = []


class Choice(BaseModel):
    key: str
    label: str
    disabled: str = ""               # the reason, when it cannot be chosen


class ExportOptions(BaseModel):
    source: str                      # "3 marked record(s)" / "the 12 record(s) listed"
    count: int
    recipes: list[Choice]
    fields: list[str]
    formats: list[Choice]
    fixed_format: list[str]          # recipes whose format is always text
    capture: str = ""                # why a capture cannot run; empty when it can
    scan: str = ""                   # why a scan cannot run; empty when it can


# --- runs, scans and captures -----------------------------------------------------


class RunOut(BaseModel):
    id: str
    tool: str                        # "nmap" or "gowitness"
    label: str
    scope: str = ""
    state: str
    running: bool
    elapsed: float
    result: str = ""
    lines: int = 0                   # how many log lines there are, for `since`


class LogOut(BaseModel):
    run: RunOut
    since: int
    lines: list[str]


class PresetOut(BaseModel):
    name: str
    args: str
    needs_root: bool


class ScanPlanIn(BaseModel):
    preset: str
    targets: list[str] = []
    command: str | None = None       # the edited command; the preset's when absent
    # Arguments to draft from instead of a preset - an earlier command or the
    # builder's; `preset` then only names the output files.
    args: str | None = None
    # This run's notification; the configured default when absent, "" for none.
    notify_url: str | None = None
    notify_progress: bool | None = None


class ScanPlanOut(BaseModel):
    preset: str
    command: str                     # what the user may edit
    note: str
    argv: list[str] = []
    targets: list[str] = []
    out_base: str = ""
    elevated: bool = False
    privilege: str = ""               # what needs root, as the terminal says it
    via: str = ""                    # "", "sudo" or "capabilities" - how it gets root
    error: str = ""                  # why this command would not be run
    blocked: str = ""                # why it cannot start here; it can still be copied
    warning: str = ""                # what starting now costs - another scan running
    copy_local: str | None = None    # the argv as one shell line; None without nmap here
    copy_remote: str = ""            # the snippet for a machine with only nmap
    notify_url: str = ""             # the configured default, for the review to show
    notify_progress: bool = False


class CapturePlanOut(BaseModel):
    argv: list[str]
    urls: list[str]
    where: str
    backend: str = ""
    blocked: str = ""
    copy_local: str | None = None
    copy_remote: str = ""
    notify_url: str = ""
    notify_progress: bool = False


class CaptureIn(BaseModel):
    tab: str = ""
    path: str = ""
    q: str = ""
    notify_url: str | None = None    # as on ScanPlanIn
    notify_progress: bool | None = None


# --- the search across everything -------------------------------------------------------


class Hit(BaseModel):
    title: str
    subtitle: str = ""
    href: str
    image: str | None = None          # a screenshot, when the hit has one


class HitGroup(BaseModel):
    kind: str                         # hosts, services, names, screenshots
    label: str
    total: int
    more: str                         # where every hit of this kind is listed
    loose: int = 0                    # fuzzy-only matches left out for the firm ones
    hits: list[Hit] = []


class SearchOut(BaseModel):
    q: str
    understood: list[str] = []        # what the query was read as, in words
    groups: list[HitGroup] = []


# --- the gallery, grouped ---------------------------------------------------------------


class CaptureGroup(BaseModel):
    key: str
    label: str
    count: int
    more: str                        # query string: the gallery narrowed to this group
    items: list[CaptureSummary] = []  # the first few


class Stack(BaseModel):
    """Every screenshot of one host:port, shown as one card until opened."""

    key: str
    label: str                       # "10.0.0.5:443/tcp https" or "name:8080 (not in the scans)"
    count: int
    first: CaptureSummary            # the front card: first in the gallery's order
    rest: list[CaptureSummary] = []  # the others, up to a page's worth
    more: str                        # query string: the gallery narrowed to this port


class StackPage(BaseModel):
    stacks: list[Stack]
    total: int                       # stacks (host:port combinations) in all
    captures: int                    # screenshots in them
    offset: int = 0
    limit: int = 100
    loose: int = 0


class GroupPage(BaseModel):
    by: str
    groups: list[CaptureGroup]
    total: int                       # groups in all
    captures: int                    # captures in them
    offset: int = 0
    limit: int = 100
    loose: int = 0


# --- the software inventory (`/api/v1/inventory`) -------------------------------
# The same document the JSON export writes - `export.inventory_document` - so a
# consumer of either reads one shape. Version 1; see `export.INVENTORY_VERSION`.


class InventoryObservation(BaseModel):
    source: str
    product: str
    version: str | None = None
    detail: str = ""


class InventorySupport(BaseModel):
    status: str
    cycle: str | None = None
    eol_date: str | None = None
    latest: str | None = None
    ending_soon: bool = False
    reason: str | None = None


class InventoryFinding(BaseModel):
    id: str
    sources: list[str] = []
    severity: str | None = None
    score: float | None = None
    vector: str | None = None
    url: str | None = None
    summary: str | None = None
    undecided: bool = False
    tested: bool = False
    state: str | None = None
    releases_known: int | None = None
    releases_affected: int | None = None


class InventoryEntry(BaseModel):
    address: str
    names: list[str] = []
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    product: str
    version: str | None = None
    kind: str
    cpe22: list[str] = []
    cpe23: list[str] = []
    cpe_origin: str | None = None
    confidence: str
    conflicting: bool = False
    observations: list[InventoryObservation] = []
    support: InventorySupport | None = None
    findings: list[InventoryFinding] = []


class InventoryDocument(BaseModel):
    # `schema` shadows a BaseModel attribute, so the field carries an alias.
    model_config = ConfigDict(populate_by_name=True)

    schema_: str = Field(alias="schema")
    version: int
    generated_from: list[str] = []
    unplaced_captures: int = 0
    vulndb_date: str | None = None
    entries: list[InventoryEntry] = []


# --- the vulnerability database (`/api/v1/vulndb`, `/api/v1/findings`) ------------


class VulndbOut(BaseModel):
    label: str
    missing: bool
    age_days: float | None = None
    stale: bool = True
    updating: bool = False
    progress: str = ""
    path: str = ""


class FindingPlace(BaseModel):
    address: str
    protocol: str | None = None
    port: int | None = None


class FindingOut(BaseModel):
    id: str
    severity: str | None = None
    score: float | None = None
    summary: str | None = None
    url: str | None = None
    sources: list[str] = []
    tested: bool = False             # nmap ran a check and reported it
    state: str | None = None
    likely: bool = False             # a candidate for a version family, not a finding
    releases_known: int | None = None
    releases_affected: int | None = None
    product: str | None = None
    version: str | None = None
    support: str | None = None
    places: list[FindingPlace] = []


# --- the command builder -------------------------------------------------------------------


class BuilderStepOut(BaseModel):
    key: str
    title: str
    number: int
    status: str                      # done, current, ahead, skipped


class BuilderChoiceOut(BaseModel):
    key: str
    label: str
    adds: str
    gain: str
    cost: str
    recommended: bool = False
    selected: bool = False


class BuilderRowOut(BaseModel):
    name: str
    about: str
    flag: bool
    hint: str = ""                   # the value's form
    value: str | None = None
    on: bool = False
    source: str = ""
    owner: str = ""                  # why seek sets it - not settable


class BuilderGroupOut(BaseModel):
    group: str
    rows: list[BuilderRowOut]


class BuilderCommandOut(BaseModel):
    profile: str
    args: list[str]
    text: str
    misses: list[str] = []
    notes: list[str] = []


class BuilderOut(BaseModel):
    state: str                       # the state to send back, as JSON
    step: str
    question: str
    steps: list[BuilderStepOut]
    choices: list[BuilderChoiceOut] = []
    groups: list[BuilderGroupOut] = []
    commands: list[BuilderCommandOut]
    measured: list[list] = []        # [host, ms] pairs taken now


class BuilderMeasureIn(BaseModel):
    targets: list[str]
    confirmed: bool = False


class BuilderMeasureOut(BaseModel):
    what: str                        # what was sent
    measured: list[list]             # [host, ms]
    note: str


class EarlierOut(BaseModel):
    args: str
    where: str
    last: float | None = None
    count: int = 1


class EarlierListsOut(BaseModel):
    recent: list[EarlierOut]
    frequent: list[EarlierOut]


# --- tags --------------------------------------------------------------------------


class IssueIn(BaseModel):
    title: str
    severity: str
    description: str = ""
    references: list[str] = []


class TagOut(BaseModel):
    name: str
    description: str = ""
    issues: list[IssueIn] = []
    sources: list[str] = []
    hosts: int = 0
    services: int = 0
    uncertain: int = 0
    notes: list[str] = []


class ProblemOut(BaseModel):
    level: str
    message: str
    where: str = ""
    tag: str | None = None


class TagsOut(BaseModel):
    """Every tag, its counts and sources, and what is wrong with the tag files."""
    ready: bool
    tags: list[TagOut]
    problems: list[ProblemOut]
    unmatched_entries: int = 0
    files: list[str] = []
    home: str | None = None


class TagEntriesIn(BaseModel):
    """Add or take off a manual tag: on these rows, or on the marks when none."""
    tag: str
    add: bool = True
    rows: list[RowRef] = []


class DefinitionIn(BaseModel):
    description: str = ""
    issues: list[IssueIn] = []


class TagChangeOut(BaseModel):
    saved: list[str]
    errors: list[str]
    summary: str = ""


class FactIO(BaseModel):
    """One fact of the rule builder, as shown and as sent back. `ports` is the
    scope as typed (`80,8000-8999`, empty for any port); `fixed` facts carry the
    condition as written, in JSON, in `value`."""
    kind: str
    protocol: str | None = None
    ports: str = ""
    value: str = ""
    mode: str = "equals"
    case: bool = False
    label: str = ""
    group: str = ""


class DraftFactIO(BaseModel):
    fact: FactIO
    state: str = "ignore"


class DraftIO(BaseModel):
    """What the user has chosen: the selection, each fact's state, same port, and
    the ports the selection was limited to when services were picked."""
    selection: list[str]
    facts: list[DraftFactIO] = []
    same_port: bool = True
    limit: list[str] | None = None


class ProposalOut(BaseModel):
    fact: FactIO
    selected: int
    others: int
    excludes: int = 0
    assumed_on: list[str] = []


class CombinationOut(BaseModel):
    facts: list[FactIO]
    excludes: int
    remaining: int


class FactRowOut(BaseModel):
    fact: FactIO
    state: str
    selected: int
    others: int


class MatchOut(BaseModel):
    address: str
    ports: str
    title: str
    matched: bool
    assumed: bool = False


class AssessOut(BaseModel):
    of_selection: int
    rows: list[FactRowOut]
    selection: list[MatchOut]
    others: list[MatchOut]
    matched: int
    selected_matched: int
    other_count: int
    assumed: list[str]
    exclusions: list[ProposalOut] = []
    combination: CombinationOut | None = None
    rule: list[dict] = []
    notes: list[str] = []
    confirm: str = ""


class BenchView(BaseModel):
    """The rows in view, when the rule is built from them."""
    tab: str
    path: str = ""
    q: str = ""


class BenchIn(BaseModel):
    rows: list[RowRef] = []
    view: BenchView | None = None


class BenchOut(BaseModel):
    draft: DraftIO
    assessment: AssessOut
    rule_name: str = ""
    grant: str = "host"
    replaces: dict | None = None


class AssessIn(BaseModel):
    draft: DraftIO


class RefineIn(BaseModel):
    draft: DraftIO
    fact: FactIO


class RefineOut(BaseModel):
    fact: FactIO
    selected: int
    of_selection: int
    others: int
    dropped: list[str]


class RuleIn(BaseModel):
    """A draft as a rule, to hand to the tag editor."""
    draft: DraftIO
    rule_name: str
    grant: str = "host"


class RuleRawOut(BaseModel):
    raw: dict


class RuleOpenIn(BaseModel):
    """A rule of the tag editor, opened in the builder."""
    tag: str
    raw: dict
    origin: int | None = None          # the loaded rule it came from, by index


class EditRuleIO(BaseModel):
    raw: dict
    origin: int | None = None          # index among the tag's rules as loaded
    deleted: bool = False
    name: str = ""
    where: str = ""
    changed: bool = False
    editable: bool = True
    reason: str = ""


class TagEditIO(BaseModel):
    original: str | None = None
    name: str
    description: str = ""
    issues: list[IssueIn] = []
    rules: list[EditRuleIO] = []
    manual_hosts: int = 0
    manual_services: int = 0
    confirm_overwrite: bool = False
