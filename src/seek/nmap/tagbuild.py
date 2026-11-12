"""The rule builder: from a few hosts, a draft rule that the user shapes on one screen.

Pure. A `Builder` holds one model (the prepared index, the tags, the files'
coverage); a `Draft` is what the user has chosen (the selection, each fact
ignored, required or excluded, same port or not). `assess` says everything a
front end shows about a draft, and counts it with the tagging evaluator itself
over exactly the conditions `draft_rule` saves - so a count shown is the count
the saved rule gives. Nothing here writes; a draft is saved by the session like
any other tag change.

Facts are proposed as found: a text value `equals` the value (case ignored),
facts that most of the selection shares come with their "k/N", and broader ones
are offered next to them - a value found on different ports as a port list, a
common beginning or end, and words every value contains. Any of them can be
edited (`fact_from`), and `refine` counts an edit before it is taken.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
from dataclasses import dataclass, field, replace
from enum import StrEnum

from seek.nmap import tagging
from seek.nmap import tagrules as tr
from seek.nmap.coverage import Ranges, merge_ranges
from seek.nmap.models import Host, ScanFile

# A common beginning, end or word shorter than this says little about a device;
# four characters is "Zebra", "RICOH", "- READY" and still not "the", "1.0".
MIN_PARTIAL = 4
# Words every differing value contains: at most this many per field, longest first.
MAX_WORDS = 3
# Exclusions are offered alone, or as the best combination of at most this many.
MAX_COMBINED = 3
# How many proposals of each kind are shown; the rest are noise.
MAX_SHOWN = 40
# Candidate facts counted per selection, the most widely shared first.
MAX_COUNTED = 120
# Exclusions other than open ports: found in this many unwanted hosts, and the
# most frequent this many counted exactly over all of them.
SAMPLE = 2000
COUNTED = 60
# Unselected matches listed (all are counted).
MAX_OTHERS = 200
# Ports listed per host in the match list.
MAX_PORTS_SHOWN = 8


class Kind(StrEnum):
    OPEN = "open"
    SERVICE = "service"
    PRODUCT = "product"
    VERSION = "version"
    TITLE = "title"
    CERT_ISSUER = "cert_issuer"
    HEADER = "header"
    OS = "os"
    TAG = "tag"
    ADDRESS = "address"
    FIXED = "fixed"          # a condition of an opened rule the builder keeps as written


class Mode(StrEnum):
    EQUALS = "equals"
    CONTAINS = "contains"
    START = "start"
    END = "end"
    REGEX = "regex"


class State(StrEnum):
    IGNORE = "ignore"
    REQUIRE = "require"
    EXCLUDE = "exclude"


TEXT_KINDS = (Kind.SERVICE, Kind.PRODUCT, Kind.VERSION, Kind.TITLE, Kind.CERT_ISSUER,
              Kind.HEADER)
PORT_KINDS = (Kind.OPEN, *TEXT_KINDS)
# Shown first among facts as rare as each other: the cheapest to keep true.
_KIND_ORDER = {k: n for n, k in enumerate(Kind)}
_MODE_TEXT = {Mode.EQUALS: "=", Mode.CONTAINS: "contains", Mode.START: "starts with",
              Mode.END: "ends with", Mode.REGEX: "~"}
# The colleague's keys: a rule written with them is edited in its file.
_LEGACY_KEYS = frozenset({"nmap_port", "html_title", "html_body", "html_redirect",
                          "service_match", "has_tag"})


# --- facts ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Fact:
    """One fact about a host, as one condition a rule can hold.

    `ports` None is any port; `protocol` None any protocol. For `FIXED`, `value`
    is the condition as written, in JSON.
    """
    kind: Kind
    protocol: str | None = None
    ports: Ranges | None = None
    value: str = ""
    mode: Mode = Mode.EQUALS
    case: bool = False

    @property
    def has_ports(self) -> bool:
        return self.kind in PORT_KINDS

    @property
    def where(self) -> str:
        if self.ports is None:
            return f"any {self.protocol} port" if self.protocol else "any port"
        return tr.format_ports(self.ports, self.protocol)

    @property
    def group(self) -> str:
        """The heading a front end lists the fact under."""
        return self.where if self.has_ports else "host"

    def _test(self) -> str:
        return (f"{_MODE_TEXT[self.mode]} {self.value!r}"
                + (" (case)" if self.case else ""))

    @property
    def label(self) -> str:
        if self.kind is Kind.OPEN:
            return f"{self.where} open"
        if self.kind is Kind.OS:
            return f"OS {self._test()}"
        if self.kind is Kind.TAG:
            return f"tag {self.value}"
        if self.kind is Kind.ADDRESS:
            return f"address {self.value}"
        if self.kind is Kind.FIXED:
            return f"as written: {self.value}"
        return f"{self.where} {self.kind.value.replace('_', ' ')} {self._test()}"

    def _match(self) -> dict:
        v = self.value
        test: dict = {Mode.EQUALS: {"equals": v}, Mode.CONTAINS: {"literal": v},
                      Mode.START: {"regex": "^" + re.escape(v)},
                      Mode.END: {"regex": re.escape(v) + "$"},
                      Mode.REGEX: {"regex": v}}[self.mode]
        if self.case:
            test["case"] = True
        return test

    def condition(self) -> dict:
        """The fact in seek's own rule form."""
        if self.kind is Kind.TAG:
            return {"tag": self.value}
        if self.kind is Kind.ADDRESS:
            return {"address": self.value}
        if self.kind is Kind.FIXED:
            return json.loads(self.value)
        if self.kind is Kind.OS:
            return {"os": self._match()}
        cond: dict = {}
        if self.ports is not None:
            cond["port"] = tr.written_ports(self.ports, self.protocol)
        elif self.protocol:
            cond["protocol"] = self.protocol
        if self.kind is not Kind.OPEN:
            cond[self.kind.value] = self._match()
        return cond


def parse_ports(text: str) -> tuple[Ranges | None, str | None]:
    """A port scope as typed: empty or `any` is any port, else `"80,8000-8999/tcp"`.
    Raises `tr.RuleError` naming what is wrong."""
    text = text.strip()
    if not text or text.lower() == "any":
        return None, None
    if text.lower().startswith("any/"):
        return None, tr._protocol(text[4:], None)
    return tr._port(text, None)


def fact_from(kind: Kind | str, *, protocol: str | None = None, ports=None,
              value: str = "", mode: Mode | str = Mode.EQUALS, case: bool = False) -> Fact:
    """A fact as a front end sends it, checked the way a rule file is: raises
    `tr.RuleError` with the reason. `ports` is a typed scope or ranges."""
    kind, mode = Kind(kind), Mode(mode)
    if isinstance(ports, str):
        ranges, typed_proto = parse_ports(ports)
        protocol = typed_proto or protocol
    else:
        ranges = merge_ranges(tuple(p) for p in ports) if ports else None
    if protocol is not None:
        protocol = tr._protocol(protocol, None)
    if kind not in PORT_KINDS:
        ranges, protocol = None, None
    fact = Fact(kind, protocol, ranges, value if kind is not Kind.OPEN else "",
                mode, bool(case))
    if kind is Kind.OPEN and ranges is None:
        raise tr.RuleError("an open port needs a port: give one, a list or a range")
    if kind in (*TEXT_KINDS, Kind.OS, Kind.TAG, Kind.ADDRESS, Kind.FIXED) and not value:
        raise tr.RuleError(f"{kind.value.replace('_', ' ')} needs a value")
    if kind is Kind.FIXED:
        try:
            json.loads(value)
        except ValueError:
            raise tr.RuleError("a fixed condition is not valid JSON") from None
    tr.condition(fact.condition())
    return fact


# --- drafts --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Draft:
    """What the user has chosen. Facts left ignored but edited stay listed."""
    selection: tuple[str, ...]
    facts: tuple[tuple[Fact, State], ...] = ()
    same_port: bool = True

    def state_of(self, fact: Fact) -> State:
        return next((s for f, s in self.facts if f == fact), State.IGNORE)

    def with_state(self, fact: Fact, state: State) -> Draft:
        if any(f == fact for f, _ in self.facts):
            facts = tuple((f, state if f == fact else s) for f, s in self.facts)
        else:
            facts = (*self.facts, (fact, state))
        return replace(self, facts=facts)

    def replace_fact(self, old: Fact, new: Fact) -> Draft:
        """An edit: the new fact takes the old one's state; the old one is dropped
        from the draft (it stays among the proposals)."""
        state = self.state_of(old)
        facts = tuple((f, s) for f, s in self.facts if f not in (old, new))
        return replace(self, facts=((new, State.REQUIRE if state is State.IGNORE else state),
                                    *facts))

    def add(self, address: str) -> Draft:
        if address in self.selection:
            return self
        return replace(self, selection=(*self.selection, address))

    def drop(self, address: str) -> Draft:
        return replace(self, selection=tuple(a for a in self.selection if a != address))

    @property
    def changed(self) -> bool:
        return any(s is not State.IGNORE for _f, s in self.facts)


def draft_when(draft: Draft) -> list[dict]:
    """The conditions of the draft, in seek's own form. With `same_port`, required
    port facts with one scope are one condition, which holds on one port; a field
    that two facts test twice stays two conditions. Exclusions are never merged:
    "not (A and B)" is not "not A and not B"."""
    required = [f for f, s in draft.facts if s is State.REQUIRE]
    excluded = [f for f, s in draft.facts if s is State.EXCLUDE]
    when: list[dict] = []
    merged: dict[tuple, dict] = {}
    for fact in required:
        cond = fact.condition()
        if not (draft.same_port and fact.has_ports):
            when.append(cond)
            continue
        key = (fact.protocol, fact.ports)
        into = merged.get(key)
        if into is None:
            merged[key] = cond
            when.append(cond)
        elif all(into.get(k, v) == v for k, v in cond.items()):
            into.update(cond)
        else:
            when.append(cond)
    when += [{"not": f.condition()} for f in excluded]
    return when


def draft_rule(draft: Draft, name: str, grant: tr.Grant = tr.Grant.HOST) -> dict:
    """The rule in seek's own form, as `Session.plan_rule` saves it."""
    return {"name": name, "grant": tr.Grant(grant).value, "when": draft_when(draft)}


# --- the builder ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Proposal:
    fact: Fact
    selected: int                 # selected hosts with it
    others: int                   # unselected hosts with it
    excludes: int = 0             # for an exclusion: unwanted matches it removes
    # For an exclusion: selected hosts on which it is only an assumption.
    assumed_on: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Combination:
    facts: tuple[Fact, ...]
    excludes: int
    remaining: int                # unwanted matches still left after all of them


@dataclass(slots=True)
class Builder:
    """One builder over one model: the prepared index, the tags, the files'
    coverage, and the selection it was started with."""
    index: object                 # tagging._Index
    files: list[ScanFile]
    tags: tagging.TagSet | None
    initial: tuple[str, ...]
    # Set when services were selected: facts of those ports only.
    limit: frozenset[tuple[str, int]] | None = None
    notes: list[str] = field(default_factory=list)
    _position: dict[str, int] | None = None
    _sids: dict[int, list[int]] | None = None
    _holders: dict[Fact, frozenset[int]] = field(default_factory=dict)
    _proposals: dict[tuple, tuple[Proposal, ...]] = field(default_factory=dict)
    _facts: dict[tuple, dict[Fact, str]] = field(default_factory=dict)

    @property
    def hosts(self) -> list[Host]:
        return self.index.hosts

    def position(self, address: str) -> int | None:
        if self._position is None:
            self._position = {h.address: n for n, h in enumerate(self.hosts)}
        return self._position.get(address)

    def sids_of(self, h: int) -> list[int]:
        if self._sids is None:
            self._sids = {}
            for sid, owner in enumerate(self.index.host_of):
                self._sids.setdefault(owner, []).append(sid)
        return self._sids.get(h, [])

    def addresses(self, numbers) -> tuple[str, ...]:
        return tuple(sorted((self.hosts[h].address for h in numbers), key=_address_key))

    def holders(self, fact: Fact) -> frozenset[int]:
        """Every host the fact holds for, certain or assumed - counted once."""
        found = self._holders.get(fact)
        if found is None:
            out = tagging.evaluate(self.index, tr.condition(fact.condition()), self.tags)
            found = self._holders[fact] = frozenset(out.certain | out.assumed.keys())
        return found

    def draft(self) -> Draft:
        return Draft(self.initial)

    def limited(self, limit: frozenset[tuple[str, int]] | None) -> Builder:
        """The same builder with other ports - the selected ports, or None for
        whole hosts. The counts made so far are shared: they do not depend on it."""
        return replace(self, limit=limit)

    @property
    def limit_text(self) -> str:
        if self.limit is None:
            return "whole hosts"
        ports = sorted(self.limit, key=lambda k: (k[1], k[0]))
        return "ports " + ", ".join(f"{n}/{p}" for p, n in ports[:4]) + (
            f" +{len(ports) - 4}" if len(ports) > 4 else "")


def _address_key(address: str):
    try:
        a = ipaddress.ip_address(address)
        return (0, a.version, int(a))
    except ValueError:
        return (1, 0, address)


def start(index, files: list[ScanFile], tags: tagging.TagSet | None, records) -> Builder:
    """A builder for these records (hosts, or services of hosts)."""
    position = {h.address: n for n, h in enumerate(index.hosts)}
    chosen: dict[str, None] = {}
    ports: set[tuple[str, int]] = set()
    vanished = 0
    any_service = False
    for record in records:
        if record.host.address not in position:
            vanished += 1
            continue
        chosen.setdefault(record.host.address)
        if record.service is not None:
            any_service = True
            ports.add((record.service.protocol, record.service.port))
    b = Builder(index, list(files), tags, tuple(chosen),
                frozenset(ports) if any_service else None, _position=position)
    if vanished:
        b.notes.append(f"{vanished} selected record(s) are no longer in the scans and were "
                       "left out")
    if len(chosen) == 1:
        b.notes.append("one host is selected: everything about it is shared, so a rule from "
                       "it may fit that host alone - prefer the rarest facts")
    return b


# --- proposals -------------------------------------------------------------------


def _one(port: int) -> Ranges:
    return ((port, port),)


def _facts_of(b: Builder, h: int, limit=None) -> dict[Fact, str]:
    """Every fact of one host, with the raw value of text facts - built once per
    host: the exclusions look at the same sample of hosts on every change."""
    key = (h, limit)
    found = b._facts.get(key)
    if found is None:
        found = b._facts[key] = _build_facts(b, h, limit)
    return found


def _build_facts(b: Builder, h: int, limit) -> dict[Fact, str]:
    host = b.hosts[h]
    found: dict[Fact, str] = {}
    caps_of = ({b.index.key_of[s]: b.index.caps(s) for s in b.sids_of(h)}
               if b.index.with_caps else {})
    for svc in host.open_services:
        key = (svc.protocol, svc.port)
        if limit is not None and key not in limit:
            continue
        p, ports = svc.protocol, _one(svc.port)
        found[Fact(Kind.OPEN, p, ports)] = ""
        caps = caps_of.get(key, [])
        for kind, values in (
                (Kind.SERVICE, [svc.name] if svc.name else []),
                (Kind.PRODUCT, [svc.product] if svc.product else []),
                (Kind.VERSION, [svc.version] if svc.version else []),
                (Kind.TITLE, [c.title for c in caps if c.title]),
                (Kind.CERT_ISSUER, tagging.service_values(tr.Field.CERT_ISSUER, svc, caps)),
                (Kind.HEADER, [f"{k}: {v}" for c in caps for k, v in c.headers
                               if k.lower() == "server"])):
            for v in values:
                found[Fact(kind, p, ports, v)] = v
    if host.os:
        found[Fact(Kind.OS, value=host.os)] = host.os
    if b.tags is not None:
        for name in b.tags.names(host.address):
            found[Fact(Kind.TAG, value=name)] = name
    return found


def _common(values: list[str], end: bool) -> str:
    seqs = [v[::-1] for v in values] if end else values
    out = []
    for chars in zip(*seqs, strict=False):
        if len(set(chars)) != 1:
            break
        out.append(chars[0])
    common = "".join(out)
    return common[::-1] if end else common


def _words(values: list[str], skip: set[str]) -> list[str]:
    """Words of at least MIN_PARTIAL characters that every value contains, as
    written in the first value, longest first."""
    sets = [{w.casefold() for w in re.split(r"\W+", v) if len(w) >= MIN_PARTIAL}
            for v in values]
    shared = set.intersection(*sets) if sets else set()
    shared -= {s.casefold() for s in skip}
    first = {w.casefold(): w for w in re.split(r"\W+", values[0])}
    return sorted((first[w] for w in shared if w in first),
                  key=lambda w: (-len(w), w))[:MAX_WORDS]


def _threshold(n: int) -> int:
    """How many selected hosts a fact needs to be proposed: half, at least two."""
    return n if n <= 1 else max(2, math.ceil(n / 2))


def proposals(b: Builder, selected: list[int]) -> tuple[Proposal, ...]:
    """What the selection shares - every host first, rarest first, then what most
    of it shares, then broader facts - cached per selection."""
    key = (tuple(sorted(selected)), b.limit)
    cached = b._proposals.get(key)
    if cached is not None:
        return cached
    n = len(selected)
    if not n:
        return ()
    need = _threshold(n)
    per_host = [_facts_of(b, h, b.limit) for h in selected]
    freq: dict[Fact, int] = {}
    for facts in per_host:
        for f in facts:
            freq[f] = freq.get(f, 0) + 1
    candidates = [f for f, k in freq.items() if k >= need]
    candidates.sort(key=lambda f: (-freq[f], _KIND_ORDER[f.kind]))
    candidates = candidates[:MAX_COUNTED]
    # Broader: a value on several ports, a common start or end, shared words.
    broader: list[Fact] = []
    across: dict[tuple, tuple[set[int], set[int]]] = {}
    slots: dict[tuple, list[str]] = {}
    for k, facts in enumerate(per_host):
        seen: dict[tuple, str] = {}
        for f, raw in facts.items():
            if f.kind not in TEXT_KINDS:
                continue
            hosts, ports = across.setdefault((f.kind, f.protocol, raw), (set(), set()))
            hosts.add(k)
            ports.add(f.ports[0])
            seen.setdefault((f.kind, f.protocol, f.ports), raw)
        for slot, raw in seen.items():
            slots.setdefault(slot, []).append(raw)
    for (kind, proto, raw), (hosts, ports) in across.items():
        if len(hosts) >= need and len(ports) > 1:
            broader.append(Fact(kind, proto, merge_ranges(ports), raw))
    for (kind, proto, ports), values in slots.items():
        if len(values) < need or len(set(values)) == 1:
            continue
        parts = set()
        for mode in (Mode.START, Mode.END):
            part = _common(values, mode is Mode.END).strip()
            if len(part) >= MIN_PARTIAL:
                parts.add(part)
                broader.append(Fact(kind, proto, ports, part, mode))
        for word in _words(values, parts):
            broader.append(Fact(kind, proto, ports, word, Mode.CONTAINS))
    chosen = set(selected)
    out = []
    for fact in dict.fromkeys(candidates + broader):
        holders = b.holders(fact)
        k = len(holders & chosen)
        if k >= need:
            out.append(Proposal(fact, k, len(holders - chosen)))
    out.sort(key=lambda p: (p.selected != n, -p.selected, p.others,
                            _KIND_ORDER[p.fact.kind], p.fact.label))
    result = tuple(out[:MAX_SHOWN * 2])
    b._proposals[key] = result
    return result


# --- exclusions ------------------------------------------------------------------


def _probed(b: Builder, h: int, fact: Fact) -> bool:
    if not fact.has_ports or fact.ports is None:
        return True
    return not b.index.unprobed(h, fact.ports, fact.protocol)


def exclusions(b: Builder, selected: list[int], unwanted: set[int],
               taken: set[Fact]) -> tuple[tuple[Proposal, ...], Combination | None]:
    """Facts that no selected host has, ranked by how many of the unwanted
    matches each one removes, and the best combination when none removes all."""
    if not unwanted:
        return (), None
    theirs: set[Fact] = set().union(*(_facts_of(b, h) for h in selected)) | taken
    counts: dict[Fact, set[int]] = {}
    # Open ports, the usual exclusion, straight from the index: one set
    # intersection per port, whatever the number of hosts.
    for (proto, number, state), _sids in b.index.by_port.items():
        if state != "open":
            continue
        fact = Fact(Kind.OPEN, proto, _one(number))
        if fact in theirs:
            continue
        hit = b.index._port_hosts(tr.PortClause(_one(number), proto)) & unwanted
        if hit:
            counts[fact] = hit
    # Everything else is found in a sample of the unwanted hosts, then counted
    # exactly - expanding every fact of twenty thousand hosts was half a second;
    # the sample only decides which facts are counted.
    seen: dict[Fact, int] = {}
    for h in sorted(unwanted)[:SAMPLE]:
        for fact in _facts_of(b, h):
            if fact.kind in (Kind.SERVICE, Kind.PRODUCT, Kind.TITLE, Kind.OS,
                             Kind.TAG) and fact not in theirs:
                seen[fact] = seen.get(fact, 0) + 1
    for fact, _n in sorted(seen.items(), key=lambda kv: -kv[1])[:COUNTED]:
        hit = set(b.holders(fact)) & unwanted
        if hit:
            counts[fact] = hit
    singles = []
    for fact, hosts in counts.items():
        assumed_on = tuple(b.hosts[h].address for h in selected if not _probed(b, h, fact))
        singles.append(Proposal(fact, 0, len(hosts), len(hosts), assumed_on))
    singles.sort(key=lambda p: (-p.excludes, _KIND_ORDER[p.fact.kind], p.fact.label))
    combination = None
    if singles and singles[0].excludes < len(unwanted):
        left = set(unwanted)
        picked: list[Fact] = []
        for _ in range(MAX_COMBINED):
            best = max(counts.items(), key=lambda kv: len(kv[1] & left), default=None)
            if best is None or not best[1] & left:
                break
            picked.append(best[0])
            left -= best[1]
            if not left:
                break
        combination = Combination(tuple(picked), len(unwanted) - len(left), len(left))
    return tuple(singles[:MAX_SHOWN]), combination


# --- the assessment --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Row:
    """One fact as listed: its state and how many selected and other hosts have it."""
    fact: Fact
    state: State
    selected: int
    others: int


@dataclass(frozen=True, slots=True)
class Match:
    """A host in the selection or among the matches."""
    address: str
    ports: str
    title: str
    matched: bool
    assumed: bool = False


@dataclass(frozen=True, slots=True)
class Assessment:
    of_selection: int
    rows: tuple[Row, ...]
    selection: tuple[Match, ...]
    others: tuple[Match, ...]            # the first MAX_OTHERS unselected matches
    matched: int                         # every host the draft matches
    selected_matched: int
    other_count: int
    assumed: tuple[str, ...]
    exclusions: tuple[Proposal, ...] = ()
    combination: Combination | None = None
    rule: tuple[dict, ...] = ()          # the conditions counted - what is saved
    notes: tuple[str, ...] = ()
    confirm: str = ""                    # why saving needs a confirmation, if it does


def _match(b: Builder, h: int, matched: bool, assumed: bool) -> Match:
    host = b.hosts[h]
    ports = [f"{s.port}" + ("" if s.protocol == "tcp" else f"/{s.protocol}")
             for s in host.open_services]
    shown = ",".join(ports[:MAX_PORTS_SHOWN]) + ("…" if len(ports) > MAX_PORTS_SHOWN else "")
    title = ""
    if b.index.with_caps:
        title = next((c.title for s in b.sids_of(h) for c in b.index.caps(s) if c.title), "")
    return Match(host.address, shown, title, matched, assumed)


def _positions(b: Builder, draft: Draft) -> tuple[list[int], list[str]]:
    found, gone = [], []
    for address in draft.selection:
        h = b.position(address)
        (gone if h is None else found).append(address if h is None else h)
    return found, gone


def assess(b: Builder, draft: Draft) -> Assessment:
    """Everything a front end shows about the draft."""
    selected, gone = _positions(b, draft)
    chosen = set(selected)
    notes = list(b.notes)
    if gone:
        notes.append(f"{len(gone)} selected host(s) are no longer in the scans")
    if not selected:
        notes.append("nothing selected that is in the scans")
    offered = proposals(b, selected)
    in_draft = {f for f, _s in draft.facts}
    rows: list[Row] = []
    for fact, state in draft.facts:
        if fact not in {p.fact for p in offered}:
            holders = b.holders(fact)
            rows.append(Row(fact, state, len(holders & chosen), len(holders - chosen)))
    rows += [Row(p.fact, draft.state_of(p.fact), p.selected, p.others) for p in offered]
    order = list(dict.fromkeys(r.fact.group for r in rows))
    rows.sort(key=lambda r: order.index(r.fact.group))
    if not offered and selected and not draft.facts:
        notes.append("the selected hosts share no fact - try a smaller selection")
    when = draft_when(draft)
    if not when:
        return Assessment(len(selected), tuple(rows),
                          tuple(_match(b, h, False, False) for h in selected), (), 0, 0, 0,
                          (), notes=tuple(notes))
    out = tagging.evaluate(b.index, tr.condition({"all": when}), b.tags)
    hosts = out.certain | out.assumed.keys()
    unwanted = hosts - chosen
    singles, combination = exclusions(b, selected, unwanted, in_draft)
    # The model keeps hosts in address order, so the first by number are the
    # first by address; only those are sorted exactly.
    picked = sorted(sorted(unwanted)[:MAX_OTHERS], key=lambda h: _address_key(b.hosts[h].address))
    in_selection = len(hosts & chosen)
    confirm = "the rule matches none of the selected hosts" if selected and not in_selection \
        else ""
    if any(f.has_ports and f.ports is None for f, s in draft.facts if s is not State.IGNORE):
        notes.append("a fact on any port is tested against every port - it is slower")
    return Assessment(
        len(selected), tuple(rows),
        tuple(_match(b, h, h in hosts, h in out.assumed) for h in selected),
        tuple(_match(b, h, True, h in out.assumed) for h in picked),
        len(hosts), in_selection, len(unwanted), b.addresses(out.assumed),
        singles, combination, tuple(when), tuple(notes), confirm)


@dataclass(frozen=True, slots=True)
class Refined:
    """An edited fact counted before it is taken."""
    selected: int
    of_selection: int
    others: int
    dropped: tuple[str, ...]             # selected hosts the edit no longer holds for


def refine(b: Builder, draft: Draft, fact: Fact) -> Refined:
    selected, _gone = _positions(b, draft)
    holders = b.holders(fact)
    chosen = set(selected)
    return Refined(len(holders & chosen), len(selected), len(holders - chosen),
                   b.addresses(chosen - holders))


# --- opening a saved rule ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Opened:
    facts: tuple[tuple[Fact, State], ...]
    same_port: bool
    name: str
    grant: tr.Grant


def _text_test(value) -> tuple[str, Mode, bool] | None:
    """A text test as written, as a value and a mode; None if the builder cannot
    show it as one."""
    if isinstance(value, str):
        return value, Mode.REGEX, False
    if not isinstance(value, dict):
        return None
    case = value.get("case", False) is True
    if "equals" in value:
        return str(value["equals"]), Mode.EQUALS, case
    if "literal" in value:
        return str(value["literal"]), Mode.CONTAINS, case
    if "regex" in value:
        rx = str(value["regex"])
        for mode, body in ((Mode.START, rx[1:] if rx.startswith("^") else None),
                           (Mode.END, rx[:-1] if rx.endswith("$") else None)):
            if body:
                plain = re.sub(r"\\(.)", r"\1", body)
                if re.escape(plain) == body:
                    return plain, mode, case
        return rx, Mode.REGEX, case
    return None


def _facts_of_condition(cond: dict) -> list[Fact] | None:
    """One condition as builder facts; None when it is kept as written."""
    keys = set(cond)
    if keys == {"tag"} and isinstance(cond["tag"], str):
        return [Fact(Kind.TAG, value=cond["tag"])]
    if keys == {"address"} and isinstance(cond["address"], str):
        try:
            ipaddress.ip_address(cond["address"])
        except ValueError:
            return None
        return [Fact(Kind.ADDRESS, value=cond["address"])]
    if keys == {"os"}:
        test = _text_test(cond["os"])
        return None if test is None else [Fact(Kind.OS, None, None, *test)]
    text_keys = {k.value for k in TEXT_KINDS}
    if not keys <= {"port", "protocol"} | text_keys:
        return None
    try:
        ports, proto = tr._port(cond["port"], None) if "port" in cond else (None, None)
        if "protocol" in cond:
            proto = tr._protocol(cond["protocol"], None)
    except tr.RuleError:
        return None
    texts = sorted(keys & text_keys)
    if not texts:
        return None if ports is None else [Fact(Kind.OPEN, proto, ports)]
    facts = []
    for k in texts:
        test = _text_test(cond[k])
        if test is None:
            return None
        facts.append(Fact(Kind(k), proto, ports, *test))
    return facts


def _has_legacy(value) -> bool:
    if isinstance(value, dict):
        return bool(_LEGACY_KEYS & set(value)) or any(_has_legacy(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_legacy(v) for v in value)
    return False


def from_rule(rule: tr.Rule) -> Opened | str:
    """A saved rule as builder facts, or why the builder cannot edit it."""
    where = f"{rule.source}: "
    when = rule.raw.get("when")
    if _has_legacy(when):
        return where + ("the rule is written in categorize_systems' format - edit it in "
                        "the file")
    if isinstance(when, dict) and set(when) == {"all"}:
        when = when["all"]
    items = when if isinstance(when, list) else [when]
    facts: list[tuple[Fact, State]] = []
    joined = split = False
    scopes: set[tuple] = set()
    for item in items:
        if not isinstance(item, dict):
            return where + "the builder cannot read this rule - edit it in the file"
        if set(item) & {"all", "any"}:
            return where + "the builder cannot edit a rule with `any:` or nested groups - " \
                           "edit it in the file"
        state = State.REQUIRE
        cond = item
        if set(item) == {"not"}:
            state, cond = State.EXCLUDE, item["not"]
            if not isinstance(cond, dict) or set(cond) & {"all", "any"}:
                return where + "the builder cannot edit a negated group - edit it in the file"
        found = _facts_of_condition(cond)
        if found is None or (state is State.EXCLUDE and len(found) > 1):
            found = [Fact(Kind.FIXED, value=json.dumps(tr.plain(cond), sort_keys=True))]
        if state is State.REQUIRE and found[0].has_ports:
            scope = (found[0].protocol, found[0].ports)
            split |= scope in scopes
            scopes.add(scope)
            joined |= len(found) > 1
        facts += [(f, state) for f in found]
    if joined and split:
        return where + ("the rule tests one port in one condition and the same ports in "
                        "another - the builder cannot keep both apart; edit it in the file")
    return Opened(tuple(facts), not split, rule.name, rule.grant)
