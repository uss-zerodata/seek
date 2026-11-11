"""The rule builder: from a few marked hosts, the facts that make a rule for them.

Pure, and counted with the tagging evaluator itself (`tagging.evaluate` over a
prepared index), so a count shown here is the count the saved rule will give.
It proposes; the user chooses. It writes nothing - a chosen draft is saved by
the session like any other tag change.

Values are proposed exactly as found, as literals, except a service name, which
is anchored at both ends (`http` must not match `https`), and the common
beginning or end of differing values, which is offered as an anchored partial
match (design D11).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

from seek.nmap import tagging
from seek.nmap import tagrules as tr
from seek.nmap.coverage import Coverage
from seek.nmap.models import Host, ScanFile

# A common beginning or end shorter than this says little about a device; four
# characters is "- READY", "Zebra", "RICOH" and still not "the", "1.0".
MIN_PARTIAL = 4
# Exclusions are offered alone, or as the best combination of at most this many.
MAX_COMBINED = 3
# How many proposals of each kind a front end is given; the rest are noise.
MAX_SHOWN = 40
# Exclusions other than open ports: found in this many unwanted hosts, and the
# most frequent this many counted exactly over all of them.
SAMPLE = 2000
COUNTED = 60


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


# Shown first among facts as rare as each other: the cheapest to keep true.
_KIND_ORDER = {k: n for n, k in enumerate(Kind)}
_TEXT_KINDS = (Kind.SERVICE, Kind.PRODUCT, Kind.VERSION, Kind.TITLE, Kind.CERT_ISSUER,
               Kind.HEADER)


@dataclass(frozen=True, slots=True)
class Fact:
    """One fact about a host, as a condition a rule can hold."""
    kind: Kind
    protocol: str | None = None
    port: int | None = None
    value: str = ""
    partial: str = ""          # "" exact; "start" or "end" for a common part

    @property
    def where(self) -> str:
        return f"{self.port}/{self.protocol}" if self.port is not None else ""

    @property
    def label(self) -> str:
        if self.kind is Kind.OPEN:
            return f"{self.where} open"
        if self.kind is Kind.OS:
            return f"OS {self.value}"
        if self.kind is Kind.TAG:
            return f"tag {self.value}"
        name = self.kind.value.replace("_", " ")
        if self.partial == "start":
            return f"{self.where} {name} starts with {self.value!r}"
        if self.partial == "end":
            return f"{self.where} {name} ends with {self.value!r}"
        return f"{self.where} {name} {self.value!r}"

    def condition(self) -> dict:
        """The fact in seek's own rule form."""
        if self.kind is Kind.TAG:
            return {"tag": self.value}
        if self.kind is Kind.OS:
            return {"os": {"literal": self.value}}
        cond: dict = {"port": self.where}
        if self.kind is Kind.OPEN:
            return cond
        if self.partial == "start":
            text: object = {"regex": "^" + re.escape(self.value), "case": True}
        elif self.partial == "end":
            text = {"regex": re.escape(self.value) + "$", "case": True}
        elif self.kind is Kind.SERVICE:
            text = {"regex": "^" + re.escape(self.value) + "$"}
        else:
            text = {"literal": self.value}
        cond[self.kind.value] = text
        return cond


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


@dataclass(frozen=True, slots=True)
class Shared:
    selected: tuple[str, ...]
    facts: tuple[Proposal, ...] = ()
    partial: tuple[Proposal, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Exclusions:
    matched: int                  # hosts the chosen facts hold for
    unwanted: int                 # of them, not selected
    single: tuple[Proposal, ...] = ()
    combination: Combination | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Preview:
    matched: tuple[str, ...]
    selected: int                 # of the selection, how many it matches
    assumed: tuple[str, ...]      # matched only on an assumption
    of_selection: int             # how many hosts were selected
    confirm: str = ""             # why saving needs a confirmation, if it does


@dataclass(slots=True)
class Builder:
    """One builder session over one model: the prepared index, the tags, the
    files' coverage, and the hosts the user selected."""
    index: object                 # tagging._Index
    files: list[ScanFile]
    tags: tagging.TagSet | None
    selected_hosts: list[int]
    ports: frozenset[tuple[str, int]] | None   # set when services were selected
    notes: list[str] = field(default_factory=list)
    _coverage: Coverage | None = None
    _sids: dict[int, list[int]] | None = None

    def sids_of(self, h: int) -> list[int]:
        """A host's service ids - indexed once, not looked up by a pass over
        every service of the model per host."""
        if self._sids is None:
            self._sids = {}
            for sid, owner in enumerate(self.index.host_of):
                self._sids.setdefault(owner, []).append(sid)
        return self._sids.get(h, [])

    @property
    def hosts(self) -> list[Host]:
        return self.index.hosts

    def addresses(self, numbers) -> tuple[str, ...]:
        return tuple(sorted((self.hosts[h].address for h in numbers),
                            key=_address_key))

    def count(self, fact: Fact) -> set[int]:
        out = tagging.evaluate(self.index, _node(fact.condition()), self.tags)
        return out.certain | out.assumed.keys()


def _address_key(address: str):
    import ipaddress
    try:
        a = ipaddress.ip_address(address)
        return (0, a.version, int(a))
    except ValueError:
        return (1, 0, address)


def _node(cond: dict) -> tr.Node:
    return tr.condition(cond)


def start(index, files: list[ScanFile], tags: tagging.TagSet | None, records) -> Builder:
    """A builder for these records (hosts, or services of hosts)."""
    position = {h.address: n for n, h in enumerate(index.hosts)}
    chosen: dict[int, None] = {}
    ports: set[tuple[str, int]] = set()
    vanished = 0
    any_service = False
    for record in records:
        n = position.get(record.host.address)
        if n is None:
            vanished += 1
            continue
        chosen.setdefault(n)
        if record.service is not None:
            any_service = True
            ports.add((record.service.protocol, record.service.port))
    b = Builder(index, list(files), tags, list(chosen),
                frozenset(ports) if any_service else None)
    if vanished:
        b.notes.append(f"{vanished} selected record(s) are no longer in the scans and were "
                       "left out")
    if len(chosen) == 1:
        b.notes.append("one host is selected: everything about it is shared, so a rule from "
                       "it may fit that host alone - prefer the rarest facts")
    return b


# --- facts --------------------------------------------------------------------


def _facts_of(b: Builder, h: int) -> dict[Fact, str]:
    """Every fact of one host, keyed by fact, with the raw value for partials."""
    host = b.hosts[h]
    found: dict[Fact, str] = {}
    caps_of = ({b.index.key_of[s]: b.index.caps(s) for s in b.sids_of(h)}
               if b.index.with_caps else {})
    for svc in host.open_services:
        key = (svc.protocol, svc.port)
        if b.ports is not None and key not in b.ports:
            continue
        p, n = key
        found[Fact(Kind.OPEN, p, n)] = ""
        caps = caps_of.get(key, [])
        for kind, values in (
                (Kind.SERVICE, [svc.name] if svc.name else []),
                (Kind.PRODUCT, [svc.product] if svc.product else []),
                (Kind.VERSION, [svc.version] if svc.version else []),
                (Kind.TITLE, [c.title for c in caps if c.title]),
                (Kind.CERT_ISSUER, tagging.service_values(tr.Field.CERT_ISSUER, svc, caps)),
                (Kind.HEADER, [f"server: {v}" for c in caps for k, v in c.headers
                               if k.lower() == "server"])):
            for v in values:
                found[Fact(kind, p, n, v)] = v
    if host.os:
        found[Fact(Kind.OS, value=host.os)] = host.os
    if b.tags is not None:
        for name in b.tags.names(host.address):
            found[Fact(Kind.TAG, value=name)] = name
    return found


def _common(values: list[str], end: bool) -> str:
    if not values:
        return ""
    seqs = [v[::-1] for v in values] if end else values
    out = []
    for chars in zip(*seqs, strict=False):
        if len(set(chars)) != 1:
            break
        out.append(chars[0])
    common = "".join(out)
    return common[::-1] if end else common


def shared(b: Builder) -> Shared:
    """The facts every selected host has, rarest first, and the partial ones."""
    selected = b.addresses(b.selected_hosts)
    if not b.selected_hosts:
        return Shared((), notes=("nothing selected that is in the scans",))
    per_host = [_facts_of(b, h) for h in b.selected_hosts]
    common = set(per_host[0]).intersection(*per_host[1:])
    chosen = set(b.selected_hosts)
    facts = []
    for fact in common:
        holders = b.count(fact)
        facts.append(Proposal(fact, len(holders & chosen), len(holders - chosen)))
    facts.sort(key=lambda p: (p.others, _KIND_ORDER[p.fact.kind], p.fact.label))
    # Partial: a text fact on one port that every selected host has, with values
    # that differ but share a beginning or an end.
    partial = []
    if len(per_host) > 1:
        slots: dict[tuple, list[list[str]]] = {}
        for facts_of in per_host:
            seen: dict[tuple, list[str]] = {}
            for f, raw in facts_of.items():
                if f.kind in _TEXT_KINDS:
                    seen.setdefault((f.kind, f.protocol, f.port), []).append(raw)
            for slot, values in seen.items():
                slots.setdefault(slot, []).append(values)
        for (kind, proto, port), lists in slots.items():
            if len(lists) != len(per_host):
                continue                     # not every selected host has the field
            values = [v[0] for v in lists]
            if len(set(values)) == 1:
                continue                     # the same everywhere: an exact fact already
            for side in ("start", "end"):
                part = _common(values, side == "end").strip()
                if len(part) >= MIN_PARTIAL:
                    fact = Fact(kind, proto, port, part, side)
                    holders = b.count(fact)
                    partial.append(Proposal(fact, len(holders & chosen),
                                            len(holders - chosen)))
        partial.sort(key=lambda p: (p.others, p.fact.label))
    notes = list(b.notes)
    if not facts and not partial:
        notes.append("the selected hosts share no fact - no rule can be proposed for all "
                     "of them; try a smaller selection")
    return Shared(selected, tuple(facts[:MAX_SHOWN]), tuple(partial[:MAX_SHOWN]),
                  tuple(notes))


# --- exclusions ------------------------------------------------------------------


def _all(conds: list[dict]) -> tr.Node:
    return tr.condition({"all": conds}) if len(conds) > 1 else tr.condition(conds[0])


def _matched(b: Builder, conds: list[dict]) -> set[int]:
    if not conds:
        return set(b.index.all_hosts)
    out = tagging.evaluate(b.index, _all(conds), b.tags)
    return out.certain | out.assumed.keys()


def _probed(b: Builder, h: int, fact: Fact) -> bool:
    if fact.port is None:
        return True
    host = b.hosts[h]
    if any(s.port == fact.port and s.protocol == fact.protocol for s in host.services):
        return True
    if b._coverage is None:
        b._coverage = Coverage(b.files)
    return b._coverage.of(host).covers(fact.port, fact.protocol)


def exclusions(b: Builder, chosen: list[Fact]) -> Exclusions:
    """Facts that none of the selected hosts has, ranked by how many of the
    unwanted matches of `chosen` each one removes."""
    conds = [f.condition() for f in chosen]
    matched = _matched(b, conds)
    selected = set(b.selected_hosts)
    unwanted = matched - selected
    if not unwanted:
        return Exclusions(len(matched), 0, notes=("the chosen facts match the selection "
                                                  "only - nothing to exclude",))
    # Facts of the selected hosts are never exclusions. Ports apply to every
    # port here: an exclusion is about the host, even when services were
    # selected.
    ports, b.ports = b.ports, None
    try:
        theirs: set[Fact] = set().union(*(_facts_of(b, h) for h in b.selected_hosts))
        counts: dict[Fact, set[int]] = {}
        # Open ports, the usual exclusion, straight from the index: one set
        # intersection per port, whatever the number of hosts.
        for (proto, number, state), _sids in b.index.by_port.items():
            if state != "open":
                continue
            fact = Fact(Kind.OPEN, proto, number)
            if fact in theirs:
                continue
            hit = b.index._port_hosts(tr.PortClause(number, proto)) & unwanted
            if hit:
                counts[fact] = hit
        # Everything else is found in a sample of the unwanted hosts, then
        # counted exactly - expanding every fact of twenty thousand hosts was
        # half a second; the sample only decides which facts are counted.
        seen: dict[Fact, int] = {}
        for h in sorted(unwanted)[:SAMPLE]:
            for fact in _facts_of(b, h):
                if fact.kind in (Kind.SERVICE, Kind.PRODUCT, Kind.TITLE, Kind.OS,
                                 Kind.TAG) and fact not in theirs:
                    seen[fact] = seen.get(fact, 0) + 1
        for fact, _n in sorted(seen.items(), key=lambda kv: -kv[1])[:COUNTED]:
            hit = b.count(fact) & unwanted
            if hit:
                counts[fact] = hit
    finally:
        b.ports = ports
    singles = []
    for fact, hosts in counts.items():
        assumed_on = tuple(b.hosts[h].address for h in b.selected_hosts
                           if not _probed(b, h, fact))
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
    return Exclusions(len(matched), len(unwanted), tuple(singles[:MAX_SHOWN]), combination)


# --- preview and the draft -------------------------------------------------------


def preview(b: Builder, positive: list[Fact], negative: list[Fact]) -> Preview:
    conds = [f.condition() for f in positive] + [{"not": f.condition()} for f in negative]
    if not conds:
        return Preview((), 0, (), len(b.selected_hosts), "choose at least one fact")
    out = tagging.evaluate(b.index, _all(conds), b.tags)
    hosts = out.certain | out.assumed.keys()
    selected = len(hosts & set(b.selected_hosts))
    confirm = ("the rule matches none of the selected hosts" if selected == 0
               and b.selected_hosts else "")
    return Preview(b.addresses(hosts), selected, b.addresses(out.assumed),
                   len(b.selected_hosts), confirm)


def draft(name: str, positive: list[Fact], negative: list[Fact],
          grant: tr.Grant = tr.Grant.HOST) -> dict:
    """The rule in seek's own form, as `Session.plan_rule` saves it."""
    return {"name": name, "grant": grant.value,
            "when": [f.condition() for f in positive]
            + [{"not": f.condition()} for f in negative]}
