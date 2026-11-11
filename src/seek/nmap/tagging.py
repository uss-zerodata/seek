"""Tag rules run over the model: which host and which port carries which tag, and why.

A projection, like the inventory (design D4): it reads the hosts, the scan
files' coverage, the captures and the loaded tag files, and returns an
immutable `TagSet`. It writes nothing and reads no file itself - page bodies
come through a `BodySource`, whose default asks the capture database's owner.

Three values, not two (design D5): a clause holds, fails, or holds on an
assumption. Only a negation can assume - "22/tcp is not open" where no scan
probed 22/tcp. Missing data for a positive test is simply a failure.
"""

from __future__ import annotations

import ipaddress
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from seek.gowitness import results as gw_results
from seek.nmap import tagrules as tr
from seek.nmap.coverage import Coverage
from seek.nmap.models import Host, ScanFile, Service
from seek.nmap.progress import TAGS, Report, counted
from seek.nmap.tagfiles import Loaded

ServiceKey = tuple[str, int]                 # (protocol, port) within one host
# How many body verdicts the session keeps between rebuilds: a manual tag must
# not make every body be read again, and a verdict is a few dozen bytes.
BODY_CACHE_SIZE = 50_000


# --- results -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Grant:
    """Why a host or a port carries a tag. No evidence means certain."""
    sources: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()

    @property
    def uncertain(self) -> bool:
        return bool(self.evidence)

    def join(self, other: Grant) -> Grant:
        sources = tuple(dict.fromkeys(self.sources + other.sources))
        if not self.uncertain or not other.uncertain:
            return Grant(sources, ())        # one certain reason is enough
        shorter = min((self, other), key=lambda g: len(g.evidence))
        return Grant(sources, shorter.evidence)


@dataclass(frozen=True, slots=True)
class TagCount:
    hosts: int = 0
    services: int = 0
    uncertain: int = 0


@dataclass(frozen=True, slots=True)
class TagSet:
    hosts: dict[str, dict[str, Grant]] = field(default_factory=dict)
    services: dict[tuple[str, str, int], dict[str, Grant]] = field(default_factory=dict)
    defs: dict[str, tr.TagDef] = field(default_factory=dict)
    problems: tuple[tr.Problem, ...] = ()
    counts: dict[str, TagCount] = field(default_factory=dict)
    # Notes per tag that are not problems: "slow: no port".
    notes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    unmatched_entries: int = 0

    def of_host(self, address: str) -> dict[str, Grant]:
        return self.hosts.get(address, {})

    def of_service(self, address: str, protocol: str, port: int) -> dict[str, Grant]:
        return self.services.get((address, protocol, port), {})

    def names(self, address: str, protocol: str | None = None,
              port: int | None = None) -> frozenset[str]:
        """The tags a host carries, and with a port those of that port too - what
        the `tag:` filter term tests."""
        found = set(self.of_host(address))
        if port is not None and protocol is not None:
            found |= set(self.of_service(address, protocol, port))
        return frozenset(found)

    def issues(self, tags: Iterable[str]) -> list[tuple[str, tr.Issue]]:
        return [(t, i) for t in sorted(tags) for i in (self.defs[t].issues if t in self.defs
                                                        else ())]

    @property
    def tag_names(self) -> list[str]:
        return sorted(set(self.defs) | set(self.counts))


EMPTY_TAGS = TagSet()


# --- page bodies -----------------------------------------------------------------


class BodySource:
    """Answers "does this capture's body match" in batches, with a bounded cache.

    Verdicts are cached on the database file's identity (path, mtime, size), the
    row and the pattern, so a recomputation after a manual tag reads nothing.
    """

    def __init__(self, cap: int = gw_results.BODY_CAP, size: int = BODY_CACHE_SIZE) -> None:
        self.cap = cap
        self.size = size
        self._cache: OrderedDict[tuple, bool | None] = OrderedDict()

    def _stamp(self, db: Path) -> tuple:
        try:
            st = db.stat()
            return (str(db), st.st_mtime_ns, st.st_size)
        except OSError:
            return (str(db), 0, -1)

    def resolve(self, wanted: Mapping[Path, Mapping[int, set[tr.TextMatch]]]
                ) -> tuple[dict[tuple, bool | None], list[str]]:
        """Verdicts for `{database: {row_id: patterns}}`: True, False, or None when
        the body is not there. Also the databases that could not be read."""
        out: dict[tuple, bool | None] = {}
        failed: list[str] = []
        for db, rows in wanted.items():
            stamp = self._stamp(db)
            todo: dict[int, set[tr.TextMatch]] = {}
            for rid, patterns in rows.items():
                for m in patterns:
                    key = (stamp, rid, m.key())
                    if key in self._cache:
                        self._cache.move_to_end(key)
                        out[(db, rid, m.key())] = self._cache[key]
                    else:
                        todo.setdefault(rid, set()).add(m)
            if not todo:
                continue
            try:
                for rid, body in gw_results.read_bodies(db, todo, self.cap):
                    for m in todo[rid]:
                        verdict = None if body is None else m.search(body)
                        out[(db, rid, m.key())] = verdict
                        self._remember((stamp, rid, m.key()), verdict)
            except gw_results.BodiesUnavailable as exc:
                failed.append(str(exc))
                for rid, patterns in todo.items():
                    for m in patterns:
                        out[(db, rid, m.key())] = None
        return out, failed

    def _remember(self, key: tuple, verdict: bool | None) -> None:
        self._cache[key] = verdict
        if len(self._cache) > self.size:
            self._cache.popitem(last=False)


# --- field values ----------------------------------------------------------------


def _dn(table) -> str:
    """An `ssl-cert` subject or issuer table as nmap writes it: `commonName=x/...`."""
    if isinstance(table, dict):
        return "/".join(f"{k}={v}" for k, v in table.items() if isinstance(v, str))
    return ""


def _cert(svc: Service, which: str) -> list[str]:
    out = []
    for script in svc.scripts:
        if script.id != "ssl-cert":
            continue
        if isinstance(script.data, dict) and which in script.data:
            out.append(_dn(script.data[which]))
        elif script.output:
            label = "Subject:" if which == "subject" else "Issuer:"
            out += [line.split(":", 1)[1].strip() for line in script.output.splitlines()
                    if line.strip().startswith(label)]
    return [v for v in out if v]


def service_values(field_: tr.Field, svc: Service, captures: list) -> list[str]:
    """Every value a port has for a field - several captures, several CPEs."""
    f = tr.Field
    if field_ is f.SERVICE:
        return [svc.name] if svc.name else []
    if field_ is f.PRODUCT:
        return [svc.product] if svc.product else []
    if field_ is f.VERSION:
        return [svc.version] if svc.version else []
    if field_ is f.EXTRAINFO:
        return [svc.extrainfo] if svc.extrainfo else []
    if field_ is f.CPE:
        return list(svc.cpes)
    if field_ is f.TUNNEL:
        return [svc.tunnel] if svc.tunnel else []
    if field_ is f.CERT_SUBJECT:
        return _cert(svc, "subject") + [c.tls_subject for c in captures if c.tls_subject]
    if field_ is f.CERT_ISSUER:
        return _cert(svc, "issuer") + [c.tls_issuer for c in captures if c.tls_issuer]
    if field_ is f.TITLE:
        return [c.title for c in captures if c.title]
    if field_ is f.REDIRECT:
        return [c.final_url for c in captures if c.final_url]
    if field_ is f.HEADER:
        return [f"{k}: {v}" for c in captures for k, v in c.headers]
    if field_ is f.TECHNOLOGY:
        return [t for c in captures for t in c.technologies]
    if field_ is f.NETWORK_LOG:
        return [url for c in captures for url, _ in c.network]
    return []                                 # BODY is read in batches, never here


def host_values(field_: tr.HostField, host: Host) -> list[str]:
    hf = tr.HostField
    if field_ is hf.ADDRESS:
        return [host.address]
    if field_ is hf.HOSTNAME:
        names = list(host.hostnames)
        names += [n for s in host.services for n, _ in s.names]
        return names
    if field_ is hf.OS:
        return [host.os] if host.os else []
    if field_ is hf.HOST_SCRIPT:
        return [s.output for s in host.scripts if s.output]
    return []




# --- evaluation ---------------------------------------------------------------------
#
# Clause by clause over every host at once, not host by host over every rule.
# Measured on the 24 200-host corpus with 200 rules, the per-host walk spent
# 13.6 s matching the same few dozen product strings against nineteen thousand
# services per clause; here a text test runs once per distinct value, a clause is
# a set of service ids, and a rule is set arithmetic over hosts.

Evidence = tuple[str, ...]


@dataclass(slots=True)
class Outcome:
    """Which hosts a node holds for: for certain, on an assumption (with the
    evidence missing), and the services its positive port tests matched."""
    certain: set[int]
    assumed: dict[int, Evidence]
    sids: set[int] = field(default_factory=set)

    def hosts(self) -> set[int]:
        return self.certain | self.assumed.keys()


@dataclass(slots=True)
class _ClauseResult:
    matched: set[int]                     # service ids satisfying the clause
    hosts: set[int]                       # the hosts of those services
    unknown: dict[int, str]               # service ids that could not be told, and why
    blind: int = 0                        # of those, how many for want of a page body


class _Index:
    """Every service of every host, numbered and indexed for clause tests.

    Depends on the model and the captures only - not on the rules - so the
    session keeps one per model and capture generation (`prepare`), and a
    manual tag or a rule edit does not pay for it again.
    """

    def __init__(self, hosts: list[Host], captures: Mapping,
                 coverage: Coverage | None) -> None:
        self.hosts = hosts
        self.coverage = coverage
        self.bodies: Mapping = {}
        host_of: list[int] = []
        key_of: list[ServiceKey] = []
        svc: list[Service] = []
        caps: dict[int, list] = {}
        by_port: dict[tuple[str, int, str], list[int]] = {}
        add_host, add_key, add_svc = host_of.append, key_of.append, svc.append
        sid = 0
        for h, host in enumerate(hosts):
            address = host.address
            for s in host.services:
                key = (s.protocol, s.port)
                add_host(h)
                add_key(key)
                add_svc(s)
                group = by_port.get((s.protocol, s.port, s.state or ""))
                if group is None:
                    by_port[(s.protocol, s.port, s.state or "")] = [sid]
                else:
                    group.append(sid)
                if captures:
                    found = captures.get((address, s.protocol, s.port))
                    if found:
                        caps[sid] = found
                sid += 1
        self.host_of, self.key_of, self.svc, self._caps = host_of, key_of, svc, caps
        self.by_port = {k: set(v) for k, v in by_port.items()}
        self.with_caps = set(caps)
        self.protocols = {k[0] for k in self.by_port}
        self.all_hosts = set(range(len(hosts)))
        self._by_state: dict[str, set[int]] = {}
        self._recorded: dict[ServiceKey, set[int]] | None = None
        self._values: dict[tr.Field, dict[str, set[int]]] = {}
        self._tests: dict[tuple, set[int]] = {}
        self._host_clauses: dict[tr.HostClause, set[int]] = {}
        self._probed: dict[tuple[int, str | None], set[int]] = {}
        self._group_hosts: dict[tuple[str, int, str], set[int]] = {}
        # Keyed by the clause itself, a frozen value: identical clauses in two
        # rules share one result, and a temporary clause cannot alias another
        # by a recycled `id`. Cleared per build: body verdicts change.
        self._clauses: dict[tr.PortClause, _ClauseResult] = {}

    def caps(self, sid: int) -> list:
        return self._caps.get(sid, [])

    def hosts_of(self, sids: Iterable[int]) -> set[int]:
        host_of = self.host_of
        return {host_of[s] for s in sids}

    def candidates(self, clause: tr.PortClause) -> set[int]:
        if clause.port is None:
            found = self._by_state.get(clause.state)
            if found is None:
                found = set().union(*(sids for (_p, _n, st), sids in self.by_port.items()
                                      if st == clause.state))
                self._by_state[clause.state] = found
            return found
        protos = (clause.protocol,) if clause.protocol else tuple(self.protocols)
        found: set[int] = set()
        for p in protos:
            found |= self.by_port.get((p, clause.port, clause.state), set())
        return found

    def _port_hosts(self, clause: tr.PortClause) -> set[int]:
        protos = (clause.protocol,) if clause.protocol else tuple(self.protocols)
        found: set[int] = set()
        for p in protos:
            key = (p, clause.port, clause.state)
            hosts = self._group_hosts.get(key)
            if hosts is None:
                hosts = self._group_hosts[key] = self.hosts_of(self.by_port.get(key, ()))
            found |= hosts
        return found

    def field_matches(self, fld: tr.Field, match: tr.TextMatch) -> set[int]:
        """Service ids with a value of `fld` that `match` finds - tested once per
        distinct value."""
        key = (fld, match.key())
        found = self._tests.get(key)
        if found is None:
            values = self._values.get(fld)
            if values is None:
                values = {}
                for sid, svc in enumerate(self.svc):
                    for v in service_values(fld, svc, self._caps.get(sid, ())):
                        values.setdefault(v, set()).add(sid)
                self._values[fld] = values
            found = set()
            for value, sids in values.items():
                if match.search(value):
                    found |= sids
            self._tests[key] = found
        return found

    def probed(self, port: int, protocol: str | None) -> set[int]:
        """Hosts on which `port` was recorded or some scan probed it."""
        key = (port, protocol)
        found = self._probed.get(key)
        if found is None:
            if self._recorded is None:
                self._recorded = {}
                for (proto, number, _state), sids in self.by_port.items():
                    self._recorded.setdefault((proto, number), set()).update(
                        self.host_of[s] for s in sids)
            protos = (protocol,) if protocol else tuple(self.protocols)
            found = set()
            for p in protos:
                found |= self._recorded.get((p, port), set())
            if self.coverage is not None:
                for h, host in enumerate(self.hosts):
                    if h not in found and self.coverage.of(host).covers(port, protocol):
                        found.add(h)
            self._probed[key] = found
        return found

    def clause(self, clause: tr.PortClause) -> _ClauseResult:
        """The services satisfying a positive port clause, computed once."""
        cached = self._clauses.get(clause)
        if cached is not None:
            return cached
        sids = set(self.candidates(clause))
        for t in clause.scripts:
            sids = {s for s in sids if any(x.id == t.id and (t.output is None
                                                              or t.output.search(x.output))
                                           for x in self.svc[s].scripts)}
        unknown: dict[int, str] = {}
        capture_fields = [(f, m) for f, m in clause.fields if f.from_capture]
        for fld, match in clause.fields:
            if not fld.from_capture:
                sids &= self.field_matches(fld, match)
        blind = 0
        if capture_fields:
            for s in sids - self.with_caps:
                proto_port = self.key_of[s]
                unknown[s] = f"no capture of {proto_port[1]}/{proto_port[0]}"
            sids &= self.with_caps
            for fld, match in capture_fields:
                if fld is tr.Field.BODY:
                    kept = set()
                    for s in sids:
                        verdicts = [self.bodies.get((c.database, c.row_id, match.key()))
                                    for c in self.caps(s)
                                    if c.database is not None and c.row_id is not None]
                        if any(v is True for v in verdicts):
                            kept.add(s)
                        elif not verdicts or all(v is None for v in verdicts):
                            proto_port = self.key_of[s]
                            unknown[s] = f"no page body for {proto_port[1]}/{proto_port[0]}"
                            blind += 1
                    sids = kept
                else:
                    sids &= self.field_matches(fld, match)
        if not clause.fields and not clause.scripts and clause.port is not None:
            hosts = self._port_hosts(clause)     # a bare port: the group's hosts
        else:
            hosts = self.hosts_of(sids)
        result = _ClauseResult(sids, hosts, unknown, blind)
        self._clauses[clause] = result
        return result


def _host_clause_hosts(index: _Index, clause: tr.HostClause) -> set[int]:
    found = index._host_clauses.get(clause)
    if found is None:
        found = set()
        for h, host in enumerate(index.hosts):
            if clause.networks:
                try:
                    address = ipaddress.ip_address(host.address)
                except ValueError:
                    continue
                if not any(address.version == n.version and address in n
                           for n in clause.networks):
                    continue
            if all(any(m.search(v) for v in host_values(f, host)) for f, m in clause.fields):
                found.add(h)
        index._host_clauses[clause] = found
    return found


class _Eval:
    """Rules over all hosts, with tags so far and the body-blind count."""

    def __init__(self, index: _Index) -> None:
        self.index = index
        # Every tag a host carries so far - host tags and tags of its services,
        # rules and manual entries alike: certain, or assumed with evidence.
        self.tag_certain: dict[str, set[int]] = {}
        self.tag_assumed: dict[str, dict[int, Evidence]] = {}
        self.blind = 0

    def carried(self, tag: str) -> tuple[set[int], dict[int, Evidence]]:
        return self.tag_certain.get(tag, set()), self.tag_assumed.get(tag, {})

    def node(self, node: tr.Node, within: set[int]) -> Outcome:
        """The outcome over the hosts in `within` - the hosts still in question."""
        index = self.index
        if isinstance(node, tr.PortClause):
            got = index.clause(node)
            self.blind += got.blind
            return Outcome(got.hosts & within, {}, got.matched)
        if isinstance(node, tr.HostClause):
            return Outcome(_host_clause_hosts(index, node) & within, {})
        if isinstance(node, tr.TagClause):
            certain, assumed = self.carried(node.tag)
            return Outcome(certain & within, {h: e for h, e in assumed.items() if h in within})
        if isinstance(node, tr.Not):
            return self.negation(node.clause, within)
        if isinstance(node, tr.All):
            # Hosts stay certain while every child is certain for them; a child
            # that only assumes moves them to `assumed`, adding its evidence; a
            # child that fails drops them. Set operations, so the Python work is
            # in proportion to the assumed hosts, which are few.
            certain = set(within)
            assumed: dict[int, list[str]] = {}
            sids: set[int] = set()
            for child in node.children:
                got = self.node(child, certain | assumed.keys())
                moved = certain & got.assumed.keys()
                certain &= got.certain
                for h in list(assumed):
                    if h in got.certain:
                        continue
                    if h in got.assumed:
                        assumed[h] += [e for e in got.assumed[h] if e not in assumed[h]]
                    else:
                        del assumed[h]
                for h in moved:
                    assumed[h] = list(got.assumed[h])
                sids |= got.sids
                if not certain and not assumed:
                    break
            return Outcome(certain, {h: tuple(e) for h, e in assumed.items()}, sids)
        if isinstance(node, tr.Any):
            certain: set[int] = set()
            assumed: dict[int, Evidence] = {}
            sids: set[int] = set()
            for child in node.children:
                got = self.node(child, within)
                certain |= got.certain
                sids |= got.sids
                for h, ev in got.assumed.items():
                    if h not in assumed or len(ev) < len(assumed[h]):
                        assumed[h] = ev
            return Outcome(certain, {h: e for h, e in assumed.items() if h not in certain}, sids)
        raise TypeError(f"not a rule node: {node!r}")

    def negation(self, clause, within: set[int]) -> Outcome:
        index = self.index
        if isinstance(clause, tr.HostClause):
            return Outcome(within - _host_clause_hosts(index, clause), {})
        if isinstance(clause, tr.TagClause):
            # The assumption is followed consistently: a tag held on an
            # assumption makes its negation fail, so no host is granted both.
            certain, assumed = self.carried(clause.tag)
            return Outcome(within - certain - assumed.keys(), {})
        got = index.clause(clause)
        self.blind += got.blind
        rest = within - got.hosts
        evidence: dict[int, list[str]] = {}
        for s, why in got.unknown.items():
            h = index.host_of[s]
            if h in rest:
                evidence.setdefault(h, [])
                if why not in evidence[h]:
                    evidence[h].append(why)
        if clause.port is not None:
            where = f"{clause.port}/{clause.protocol}" if clause.protocol else str(clause.port)
            for h in rest - index.probed(clause.port, clause.protocol):
                evidence.setdefault(h, []).insert(0, f"{where} not scanned")
        return Outcome(rest - evidence.keys(), {h: tuple(e) for h, e in evidence.items()})


# --- the build -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Compiled:
    rule: tr.Rule
    reads_bodies: bool
    no_port: bool
    label: str


def _top(node: tr.Node) -> tuple[tr.Node, ...]:
    return node.children if isinstance(node, tr.All) else (node,)


def _cost(node: tr.Node) -> int:
    """Narrowest first: a port with a fixed number shrinks the hosts in question
    before anything that has to look at every one."""
    if isinstance(node, tr.PortClause):
        if node.reads_bodies:
            return 6
        return (2 if node.reads_captures else 1) + (3 if node.port is None else 0)
    if isinstance(node, tr.TagClause):
        return 2
    if isinstance(node, tr.HostClause):
        return 3
    return 5


def _walk(node: tr.Node):
    yield node
    if isinstance(node, (tr.All, tr.Any)):
        for child in node.children:
            yield from _walk(child)
    elif isinstance(node, tr.Not):
        yield node.clause


def compile_rule(rule: tr.Rule) -> _Compiled:
    children = tuple(sorted(_top(rule.when), key=_cost))
    when = tr.All(children) if isinstance(rule.when, tr.All) else rule.when
    nodes = list(_walk(rule.when))
    reads_bodies = any(isinstance(n, tr.PortClause) and n.reads_bodies for n in nodes)
    no_port = any(isinstance(n, tr.PortClause) and n.port is None for n in nodes)
    return _Compiled(tr.Rule(rule.tag, rule.name, rule.grant, when, rule.source, rule.raw),
                     reads_bodies, no_port, f"{rule.source} {rule.name}")


def _body_wants(index: _Index, compiled: list[_Compiled]
                ) -> dict[Path, dict[int, set[tr.TextMatch]]]:
    """Which bodies to read: for each body test, the captures of the ports that
    pass the clause's other tests - never every body of every capture."""
    wanted: dict[Path, dict[int, set[tr.TextMatch]]] = {}
    for c in compiled:
        if not c.reads_bodies:
            continue
        for clause in (n for n in _walk(c.rule.when)
                       if isinstance(n, tr.PortClause) and n.reads_bodies):
            rest = tr.PortClause(clause.port, clause.protocol, clause.state,
                                 tuple(fm for fm in clause.fields if fm[0] is not tr.Field.BODY),
                                 clause.scripts)
            for s in index.clause(rest).matched & index.with_caps:
                for cap in index.caps(s):
                    if cap.database is None or cap.row_id is None:
                        continue
                    for fld, match in clause.fields:
                        if fld is tr.Field.BODY:
                            wanted.setdefault(cap.database, {}).setdefault(
                                cap.row_id, set()).add(match)
    return wanted


def prepare(hosts: list[Host], files: list[ScanFile],
            captures: Mapping[tuple[str, str, int], list] | None = None) -> _Index:
    """The rule-independent part of a build: worth keeping while the model and
    the captures stay the same."""
    return _Index(hosts, captures or {}, Coverage(files) if files else None)


def build(hosts: list[Host], files: list[ScanFile], loaded: Loaded,
          captures: Mapping[tuple[str, str, int], list] | None = None,
          bodies: BodySource | None = None, report: Report | None = None,
          prepared: _Index | None = None) -> TagSet:
    """Every tag on every host and port. Pure apart from `bodies`. `prepared`
    must come from `prepare` over the same hosts, files and captures."""
    problems: list[tr.Problem] = list(loaded.problems)
    for f in files:
        for proto in sorted(f.coverage_unknown):
            problems.append(tr.Problem(
                f"the {proto} port list of {f.name} could not be read; a rule that excludes "
                f"a {proto} port treats its hosts as not scanned there",
                tr.Source(str(f.path)), tr.Level.WARNING))

    by_tag: dict[str, list[_Compiled]] = {}
    notes: dict[str, list[str]] = {}
    for name in loaded.order:
        for rule in loaded.tags[name].rules:
            c = compile_rule(rule)
            by_tag.setdefault(name, []).append(c)
            if c.no_port and "slow: no port" not in notes.get(name, []):
                notes.setdefault(name, []).append("slow: no port")

    index = prepared if prepared is not None else prepare(hosts, files, captures)
    index._clauses.clear()
    index.bodies = {}
    if bodies is not None:
        verdicts, failed = bodies.resolve(_body_wants(index, [c for cs in by_tag.values()
                                                               for c in cs]))
        index.bodies = verdicts
        index._clauses.clear()             # the body-free passes above are not answers
        for reason in failed:
            problems.append(tr.Problem(f"page bodies could not be read ({reason}); body "
                                       "rules were not evaluated there - they are tried again "
                                       "when the captures change", None, tr.Level.WARNING))

    ev = _Eval(index)
    host_grants: dict[str, dict[int, Grant]] = {}
    service_grants: dict[str, dict[int, Grant]] = {}     # by service id

    # Manual entries first: a rule may ask about a tag a person gave.
    position = {h.address: n for n, h in enumerate(hosts)}
    sid_of = {(index.host_of[s], *index.key_of[s]): s for s in range(len(index.svc))}
    unmatched = 0
    for path, entries in loaded.entries.items():
        grant = Grant((f"manual ({path})",))
        for e in entries:
            h = position.get(e.host)
            if h is None:
                unmatched += 1
                continue
            if e.port is None:
                per = host_grants.setdefault(e.tag, {})
            else:
                s = sid_of.get((h, e.protocol, e.port))
                if s is None:
                    unmatched += 1
                    continue
                per = service_grants.setdefault(e.tag, {})
                h = s
            per[h] = per[h].join(grant) if h in per else grant
    for tag in set(host_grants) | set(service_grants):
        ev.tag_certain.setdefault(tag, set()).update(host_grants.get(tag, {}))
        ev.tag_certain[tag].update(index.host_of[s] for s in service_grants.get(tag, {}))

    blind: dict[str, int] = {}
    tags_done = counted(loaded.order, report, TAGS) if report else loaded.order
    for name in tags_done:
        hosts_out = host_grants.setdefault(name, {})
        assumed: dict[int, Grant] = {}
        service_hits: dict[int, list[tuple[str, Evidence]]] = {}
        for c in by_tag.get(name, ()):
            before = ev.blind
            got = ev.node(c.rule.when, index.all_hosts)
            if ev.blind > before:
                blind[name] = blind.get(name, 0) + (ev.blind - before)
            if not got.certain and not got.assumed:
                continue
            if c.rule.grant in (tr.Grant.HOST, tr.Grant.BOTH):
                # One Grant object shared by every host the rule holds for:
                # `dict.fromkeys` does the bulk in C; only hosts that another
                # rule of the same tag already holds for are joined one by one.
                grant = Grant((c.label,))
                overlap = got.certain & hosts_out.keys()
                hosts_out.update(dict.fromkeys(got.certain - overlap, grant))
                for h in overlap:
                    hosts_out[h] = hosts_out[h].join(grant)
                for h, e in got.assumed.items():
                    g = Grant((c.label,), e)
                    if h not in assumed or len(e) < len(assumed[h].evidence):
                        assumed[h] = g
            if c.rule.grant in (tr.Grant.SERVICE, tr.Grant.BOTH):
                holding = got.certain | got.assumed.keys()
                for s in got.sids:
                    h = index.host_of[s]
                    if h in holding:
                        service_hits.setdefault(s, []).append(
                            (c.label, () if h in got.certain else got.assumed[h]))
        for h, g in assumed.items():
            if h in hosts_out and not hosts_out[h].uncertain:
                continue
            hosts_out[h] = hosts_out[h].join(g) if h in hosts_out else g
        services_out = service_grants.setdefault(name, {})
        for s, hits in service_hits.items():
            sure = [lab for lab, e in hits if not e]
            g = (Grant(tuple(dict.fromkeys(sure))) if sure
                 else min((Grant((lab,), e) for lab, e in hits), key=lambda x: len(x.evidence)))
            services_out[s] = services_out[s].join(g) if s in services_out else g
        # What later tags see: every host carrying this tag, on a host or a port.
        sure_hosts = {h for h, g in hosts_out.items() if not g.uncertain}
        sure_hosts |= {index.host_of[s] for s, g in services_out.items() if not g.uncertain}
        maybe: dict[int, Evidence] = {}
        for h, g in hosts_out.items():
            if g.uncertain and h not in sure_hosts:
                maybe[h] = g.evidence
        for s, g in services_out.items():
            h = index.host_of[s]
            if g.uncertain and h not in sure_hosts and h not in maybe:
                maybe[h] = g.evidence
        ev.tag_certain[name] = sure_hosts
        ev.tag_assumed[name] = maybe

    for name, count in sorted(blind.items()):
        problems.append(tr.Problem(
            f"tag {name!r}: {count} service(s) could not be evaluated - their captures hold "
            "no page body (captured without bodies, or gowitness kept none)", None,
            tr.Level.WARNING, name))

    host_tags: dict[str, dict[str, Grant]] = {}
    service_tags: dict[tuple[str, str, int], dict[str, Grant]] = {}
    counts: dict[str, TagCount] = {}
    for name in sorted(set(host_grants) | set(service_grants)):
        per_host = host_grants.get(name, {})
        per_service = service_grants.get(name, {})
        if not per_host and not per_service:
            continue
        uncertain_hosts = {h for h, g in per_host.items() if g.uncertain}
        uncertain_hosts |= {index.host_of[s] for s, g in per_service.items() if g.uncertain}
        for h, g in per_host.items():
            host_tags.setdefault(hosts[h].address, {})[name] = g
        for s, g in per_service.items():
            proto, port = index.key_of[s]
            service_tags.setdefault((hosts[index.host_of[s]].address, proto, port), {})[name] = g
        counts[name] = TagCount(len(per_host), len(per_service), len(uncertain_hosts))
    return TagSet(host_tags, service_tags, dict(loaded.tags), tuple(problems), counts,
                  {n: tuple(v) for n, v in notes.items()}, unmatched)
