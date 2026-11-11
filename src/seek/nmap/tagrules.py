"""The tag rule language: what a rule file says, read into immutable definitions.

Owns the YAML document format (both the colleague's `categorize_systems`
dialect and seek's own `tags:` section), the text matcher, validation with a
file and line for every problem, and the order tags must be evaluated in. It
reads no file - `tagfiles` hands it text - and it evaluates nothing: `tagging`
runs the definitions over hosts.

A problem never stops the load. It disables the smallest unit it concerns - an
issue, a rule, a tag or a whole document - and is returned beside the
definitions, so the viewer can show it where tags are shown.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum

import yaml

FORMAT_VERSION = 1
# A rule file is a page of text a person writes. Anything bigger is a mistake
# or an attack; refusing it bounds both the parse and the walk below.
MAX_FILE_BYTES = 2 * 1024 * 1024
# Aliases are shared by PyYAML rather than copied, but walking a document that
# reuses one node a million times still visits it a million times.
MAX_NODES = 100_000
# Python's `re` has no timeout; a short pattern is a cheap guard against the
# worst of catastrophic backtracking, which needs nesting to be written.
MAX_PATTERN = 1000
TAG_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PROTOCOLS = frozenset({"tcp", "udp", "sctp"})
STATES = frozenset({"open", "closed", "filtered", "unfiltered", "open|filtered",
                    "closed|filtered"})


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Grant(StrEnum):
    """Who a matching rule tags: the host, the ports that matched, or both."""
    HOST = "host"
    SERVICE = "service"
    BOTH = "both"


class Level(StrEnum):
    ERROR = "error"          # something was disabled
    WARNING = "warning"      # everything still applies, but look


class Field(StrEnum):
    """A text field of a port that a condition can test."""
    SERVICE = "service"
    PRODUCT = "product"
    VERSION = "version"
    EXTRAINFO = "extrainfo"
    CPE = "cpe"
    TUNNEL = "tunnel"
    CERT_SUBJECT = "cert_subject"
    CERT_ISSUER = "cert_issuer"
    TITLE = "title"
    BODY = "body"
    REDIRECT = "redirect"
    HEADER = "header"
    TECHNOLOGY = "technology"
    NETWORK_LOG = "network_log"

    @property
    def from_capture(self) -> bool:
        return self in _CAPTURE_FIELDS


_CAPTURE_FIELDS = frozenset({Field.TITLE, Field.BODY, Field.REDIRECT, Field.HEADER,
                             Field.TECHNOLOGY, Field.NETWORK_LOG})


class HostField(StrEnum):
    ADDRESS = "address"
    HOSTNAME = "hostname"
    OS = "os"
    HOST_SCRIPT = "host_script"


# --- results -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Source:
    """Where a definition or a problem was written."""
    path: str
    line: int | None = None

    def __str__(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass(frozen=True, slots=True)
class Problem:
    message: str
    source: Source | None = None
    level: Level = Level.ERROR
    tag: str | None = None

    def __str__(self) -> str:
        where = f"{self.source}: " if self.source else ""
        return f"{where}{self.message}"


@dataclass(frozen=True, slots=True)
class TextMatch:
    """A text test: an expression searched anywhere, ignoring case, by default."""
    pattern: re.Pattern
    written: str
    literal: bool = False
    case: bool = False

    def search(self, value: str | None) -> bool:
        return bool(value) and self.pattern.search(value) is not None

    def key(self) -> tuple:
        return (self.written, self.literal, self.case)


@dataclass(frozen=True, slots=True)
class ScriptTest:
    """A script by its exact id, with an optional test of its output."""
    id: str
    output: TextMatch | None = None


@dataclass(frozen=True, slots=True)
class PortClause:
    """Facts about one port: every test must hold for the same port.

    `port` None means any port - legal, and noted as slow, because nothing
    narrows it down.
    """
    port: int | None = None
    protocol: str | None = None
    state: str = "open"
    fields: tuple[tuple[Field, TextMatch], ...] = ()
    scripts: tuple[ScriptTest, ...] = ()

    @property
    def reads_captures(self) -> bool:
        return any(f.from_capture for f, _ in self.fields)

    @property
    def reads_bodies(self) -> bool:
        return any(f is Field.BODY for f, _ in self.fields)


@dataclass(frozen=True, slots=True)
class HostClause:
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    fields: tuple[tuple[HostField, TextMatch], ...] = ()


@dataclass(frozen=True, slots=True)
class TagClause:
    tag: str


@dataclass(frozen=True, slots=True)
class Not:
    """Exactly one clause, negated. Never a group: an assumption under a double
    negation would have no clear meaning (design D1)."""
    clause: PortClause | HostClause | TagClause


@dataclass(frozen=True, slots=True)
class All:
    children: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Any:
    children: tuple[Node, ...]


Node = PortClause | HostClause | TagClause | Not | All | Any


@dataclass(frozen=True, slots=True)
class Rule:
    tag: str
    name: str
    grant: Grant
    when: Node
    source: Source
    # The rule as written, in seek's own form (`name`, `grant`, `when`) - what a
    # copy to another file writes. Plain data, ready for YAML.
    raw: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def canonical(self) -> str:
        """What the rule tests and grants, for telling a copy from a difference."""
        return _canonical({"grant": self.grant.value, "when": self.raw.get("when")})


@dataclass(frozen=True, slots=True)
class Issue:
    title: str
    severity: Severity
    description: str = ""
    references: tuple[str, ...] = ()
    source: Source | None = None

    def key(self) -> tuple:
        return (self.title.casefold(), self.severity, self.description, self.references)


@dataclass(frozen=True, slots=True)
class TagDef:
    name: str
    description: str = ""
    issues: tuple[Issue, ...] = ()
    rules: tuple[Rule, ...] = ()
    sources: tuple[Source, ...] = ()

    def canonical(self) -> tuple:
        """What the definition says, without where it was said."""
        return (self.description, tuple(sorted(i.key() for i in self.issues)),
                tuple(sorted(r.canonical for r in self.rules)))

    @property
    def highest(self) -> Severity | None:
        return max((i.severity for i in self.issues), key=lambda s: s.rank, default=None)


@dataclass(frozen=True, slots=True)
class FileDefs:
    """What one document defines. Precedence between files is `tagfiles`'s job."""
    tags: dict[str, TagDef] = field(default_factory=dict)
    problems: tuple[Problem, ...] = ()


class RuleError(ValueError):
    """One unit of a rule file is wrong; carries the line it was written on."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


# --- reading the YAML --------------------------------------------------------------


class _Mapping(dict):
    """A mapping that remembers the line it started on (1-based)."""
    line: int | None = None


class _List(list):
    line: int | None = None


_BASE = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _LineLoader(_BASE):  # type: ignore[misc, valid-type]
    """Safe loading only - no tag constructs an object - with lines kept."""

    def construct_mapping(self, node, deep=False) -> _Mapping:
        out = _Mapping(super().construct_mapping(node, deep=True))
        out.line = node.start_mark.line + 1
        return out

    def construct_sequence(self, node, deep=False) -> _List:
        out = _List(super().construct_sequence(node, deep=True))
        out.line = node.start_mark.line + 1
        return out


_LineLoader.add_constructor("tag:yaml.org,2002:map", _LineLoader.construct_mapping)
_LineLoader.add_constructor("tag:yaml.org,2002:seq", _LineLoader.construct_sequence)


def _count_nodes(value, budget: list[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0:
        raise RuleError(f"more than {MAX_NODES} entries")
    if isinstance(value, dict):
        for v in value.values():
            _count_nodes(v, budget)
    elif isinstance(value, list):
        for v in value:
            _count_nodes(v, budget)


def parse_document(text: str, path: str) -> tuple[dict | None, list[Problem]]:
    """The YAML of one rule or tag file, or None and why not."""
    where = Source(path)
    if len(text.encode("utf-8", "surrogatepass")) > MAX_FILE_BYTES:
        size = MAX_FILE_BYTES // (1024 * 1024)
        return None, [Problem(f"larger than {size} MiB; not read", where)]
    try:
        doc = yaml.load(text, Loader=_LineLoader)  # noqa: S506 - a safe loader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        reason = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        return None, [Problem(f"not valid YAML: {reason}",
                              Source(path, mark.line + 1 if mark else None))]
    if doc is None:
        return {}, []
    if not isinstance(doc, dict):
        found = "list" if isinstance(doc, list) else type(doc).__name__
        return None, [Problem("expected a mapping with `rules:` and/or `tags:` at the top, "
                              f"found a {found}", where)]
    try:
        _count_nodes(doc, [MAX_NODES])
    except RuleError as exc:
        return None, [Problem(f"{exc}; not read", where)]
    version = doc.get("seek", FORMAT_VERSION)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return None, [Problem("`seek:` must be a format number such as 1",
                              Source(path, _line(doc)))]
    if version > FORMAT_VERSION:
        return None, [Problem(f"written for format {version}; this seek reads format "
                              f"{FORMAT_VERSION} - update seek", Source(path, _line(doc)))]
    return doc, []


def _line(value, default: int | None = None) -> int | None:
    return getattr(value, "line", None) or default


# --- values -----------------------------------------------------------------------


def _text(value, what: str, line: int | None) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)) or value is None:
        # YAML 1.1 reads `no` as false, `1.10` as 1.1 and `22:30` as 1350.
        shown = "empty" if value is None else repr(value)
        raise RuleError(f"{what} must be text, but YAML read it as {shown}; write it in quotes",
                        line)
    raise RuleError(f"{what} must be text, found a {type(value).__name__}", line)


def tag_name(value, line: int | None = None) -> str:
    """A valid tag name in its shown form (lowercase), or RuleError."""
    name = _text(value, "a tag name", line).strip().lower()
    if not TAG_NAME.fullmatch(name):
        raise RuleError(f"{name!r} is not a tag name: 1 to 64 lowercase letters, digits, "
                        "`.`, `_` or `-`, starting with a letter or digit", line)
    return name


def text_match(value, what: str, line: int | None, *, full: bool = False) -> TextMatch:
    """A text test from `"expr"`, `{regex: expr, case: true}` or `{literal: text}`.

    `full` anchors an expression at both ends - the colleague's `service`
    compared names with `!=`, and `http` must not match `https` there.
    """
    literal, case = False, False
    if isinstance(value, dict):
        line = _line(value, line)
        _only(value, {"regex", "literal", "case"}, what, line)
        if ("regex" in value) == ("literal" in value):
            raise RuleError(f"{what}: give exactly one of `regex:` or `literal:`", line)
        case = value.get("case", False)
        if not isinstance(case, bool):
            raise RuleError(f"{what}: `case:` must be true or false", line)
        literal = "literal" in value
        written = _text(value["literal" if literal else "regex"], what, line)
    else:
        written = _text(value, what, line)
    if not written:
        raise RuleError(f"{what} is empty", line)
    if len(written) > MAX_PATTERN:
        raise RuleError(f"{what} is longer than {MAX_PATTERN} characters", line)
    source = re.escape(written) if literal else written
    if full:
        source = rf"\A(?:{source})\Z"
    try:
        pattern = re.compile(source, 0 if case else re.IGNORECASE)
    except re.error as exc:
        raise RuleError(f"{what}: {written!r} is not a valid expression ({exc})", line) from None
    return TextMatch(pattern, written, literal, case)


def _port(value, line: int | None) -> tuple[int, str | None]:
    """`443`, `"443/tcp"` - a port and maybe its protocol."""
    if isinstance(value, bool):
        raise RuleError("a port must be a number such as 443 or text such as \"443/tcp\"", line)
    if isinstance(value, int):
        number, proto = value, None
    elif isinstance(value, str):
        num, _, proto_text = value.strip().partition("/")
        if not num.isdigit():
            raise RuleError(f"{value!r} is not a port such as 443 or 443/tcp", line)
        number, proto = int(num), (_protocol(proto_text, line) if proto_text else None)
    else:
        raise RuleError(f"a port must be a number, found a {type(value).__name__}", line)
    if not 1 <= number <= 65535:
        raise RuleError(f"port {number} is outside 1-65535", line)
    return number, proto


def _protocol(value, line: int | None) -> str:
    proto = _text(value, "a protocol", line).lower()
    if proto not in PROTOCOLS:
        raise RuleError(f"protocol {proto!r} is not one of {', '.join(sorted(PROTOCOLS))}", line)
    return proto


def _state(value, line: int | None) -> str:
    state = _text(value, "a port state", line).lower()
    if state not in STATES:
        raise RuleError(f"state {state!r} is not one of {', '.join(sorted(STATES))}", line)
    return state


def _only(mapping: dict, allowed: Iterable[str], what: str, line: int | None) -> None:
    unknown = [str(k) for k in mapping if k not in set(allowed)]
    if unknown:
        raise RuleError(f"{what}: unknown key {', '.join(repr(k) for k in unknown)}", line)


# --- conditions --------------------------------------------------------------------

_PORT_KEYS = {"port", "protocol", "state", "script"} | {f.value for f in Field}
_HOST_KEYS = {f.value for f in HostField}
# The colleague's spellings, read as seek's own.
_ALIASES = {"cert:issuer": "cert_issuer", "cert:subject": "cert_subject"}


def _scripts(value, line: int | None) -> tuple[ScriptTest, ...]:
    items = value if isinstance(value, list) else [value]
    out = []
    for item in items:
        ln = _line(item, line)
        if isinstance(item, str):
            out.append(ScriptTest(item))
            continue
        if not isinstance(item, dict):
            raise RuleError("`script:` takes an id or `{id: ..., output: ...}`", ln)
        _only(item, {"id", "output"}, "script", ln)
        if "id" not in item:
            raise RuleError("script: `id:` is required", ln)
        output = text_match(item["output"], "script output", ln) if "output" in item else None
        out.append(ScriptTest(_text(item["id"], "a script id", ln), output))
    return tuple(out)


def _port_clause(data: dict, line: int | None, *, legacy_service: bool = False,
                 port_required: bool = False) -> PortClause:
    port, proto = None, None
    if "port" in data:
        port, proto = _port(data["port"], line)
    elif port_required:
        raise RuleError("`port:` is required", line)
    if "protocol" in data:
        proto = _protocol(data["protocol"], line)
    state = _state(data["state"], line) if "state" in data else "open"
    fields = []
    for key in sorted(k for k in data if k in {f.value for f in Field}):
        fields.append((Field(key), text_match(data[key], key, line,
                                              full=legacy_service and key == "service")))
    scripts = _scripts(data["script"], line) if "script" in data else ()
    return PortClause(port, proto, state, tuple(fields), scripts)


def _host_clause(data: dict, line: int | None) -> HostClause:
    networks, fields = [], []
    for key in sorted(k for k in data if k in _HOST_KEYS):
        value = data[key]
        if key == HostField.ADDRESS and isinstance(value, str) and _network(value):
            networks.append(_network(value))
            continue
        fields.append((HostField(key), text_match(value, key, line)))
    return HostClause(tuple(networks), tuple(fields))


def _network(text: str):
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError:
        return None


def _clause_from_keys(data: dict, line: int | None) -> Node:
    """A mapping of port and/or host keys: one port clause, one host clause, or both
    (as `All`, the way `service_match`'s `hostname` is a host test)."""
    data = {_ALIASES.get(k, k): v for k, v in data.items()}
    _only(data, _PORT_KEYS | _HOST_KEYS, "condition", line)
    port_part = {k: v for k, v in data.items() if k in _PORT_KEYS}
    host_part = {k: v for k, v in data.items() if k in _HOST_KEYS}
    parts: list[Node] = []
    if port_part:
        parts.append(_port_clause(port_part, line))
    if host_part:
        parts.append(_host_clause(host_part, line))
    if not parts:
        raise RuleError("a condition must test something", line)
    return parts[0] if len(parts) == 1 else All(tuple(parts))


def condition(value, line: int | None = None) -> Node:
    """One condition, in either dialect."""
    if not isinstance(value, dict) or not value:
        raise RuleError("a condition must be a mapping such as `{port: 443}`", line)
    line = _line(value, line)
    keys = set(value)
    if len(keys) == 1:
        (key,) = keys
        arg = value[key]
        if key in ("all", "any"):
            if not isinstance(arg, list) or not arg:
                raise RuleError(f"`{key}:` takes a list of conditions", line)
            children = tuple(condition(c, _line(c, line)) for c in arg)
            return All(children) if key == "all" else Any(children)
        if key == "not":
            inner = condition(arg, _line(arg, line))
            if not isinstance(inner, (PortClause, HostClause, TagClause)):
                raise RuleError("`not:` takes one condition, not a group - write each "
                                "excluded fact as its own `not:`", line)
            return Not(inner)
        if key == "tag":
            return TagClause(tag_name(arg, line))
        if key == "has_tag":
            if not isinstance(arg, dict):
                raise RuleError("`has_tag:` takes `{tag: name}`", line)
            _only(arg, {"tag"}, "has_tag", line)
            return TagClause(tag_name(arg.get("tag"), line))
        if key == "nmap_port":
            if not isinstance(arg, dict):
                raise RuleError("`nmap_port:` takes a mapping", line)
            _only(arg, {"port", "state", "protocol", "service", "product"}, "nmap_port", line)
            return _port_clause(arg, _line(arg, line), legacy_service=True, port_required=True)
        if key in ("html_title", "html_body", "html_redirect"):
            if not isinstance(arg, dict):
                raise RuleError(f"`{key}:` takes `{{regex: ...}}`", line)
            _only(arg, {"regex"}, key, line)
            if "regex" not in arg:
                raise RuleError(f"{key}: `regex:` is required", line)
            fld = {"html_title": Field.TITLE, "html_body": Field.BODY,
                   "html_redirect": Field.REDIRECT}[key]
            return PortClause(fields=((fld, text_match(arg["regex"], key, line)),))
        if key == "service_match":
            if not isinstance(arg, dict):
                raise RuleError("`service_match:` takes a mapping", line)
            data = {_ALIASES.get(k, k): v for k, v in arg.items()}
            _only(data, {"port", "state", "protocol", "service", "product", "title", "body",
                         "redirect", "cert_subject", "cert_issuer", "hostname", "network_log"},
                  "service_match", line)
            port_part = {k: v for k, v in data.items() if k != "hostname"}
            clause = _port_clause(port_part, line, legacy_service=True, port_required=True)
            if "hostname" in data:
                return All((clause, _host_clause({"hostname": data["hostname"]}, line)))
            return clause
    return _clause_from_keys(value, line)


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def plain(value: object) -> object:
    """The loader's line-carrying mappings and lists as plain ones, for writing."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


# --- definitions -------------------------------------------------------------------


def _issue(value, path: str, line: int | None) -> Issue:
    if not isinstance(value, dict):
        raise RuleError("an issue must be a mapping with `title:` and `severity:`", line)
    line = _line(value, line)
    _only(value, {"title", "severity", "description", "references"}, "issue", line)
    if "title" not in value or "severity" not in value:
        raise RuleError("an issue needs `title:` and `severity:`", line)
    title = _text(value["title"], "an issue title", line).strip()
    severity_text = _text(value["severity"], "a severity", line).strip().lower()
    if severity_text not in {s.value for s in Severity}:
        raise RuleError(f"severity {severity_text!r} is not one of "
                        f"{', '.join(s.value for s in Severity)}", line)
    refs = value.get("references", [])
    if not isinstance(refs, list):
        raise RuleError("`references:` takes a list", line)
    return Issue(title, Severity(severity_text),
                 _text(value.get("description", ""), "a description", line),
                 tuple(_text(r, "a reference", line) for r in refs), Source(path, line))


def _native_rule(tag: str, value, path: str, line: int | None, index: int) -> Rule:
    if not isinstance(value, dict):
        raise RuleError("a rule must be a mapping with `when:`", line)
    line = _line(value, line)
    _only(value, {"name", "grant", "when"}, "rule", line)
    name = _text(value.get("name", f"rule {index}"), "a rule name", line)
    grant_text = _text(value.get("grant", Grant.HOST.value), "grant", line).lower()
    if grant_text not in {g.value for g in Grant}:
        raise RuleError(f"grant {grant_text!r} is not host, service or both", line)
    when = value.get("when")
    if when is None or (isinstance(when, list) and not when):
        raise RuleError("a rule needs at least one condition under `when:` - an empty "
                        "rule would match every host", line)
    node = (All(tuple(condition(c, _line(c, line)) for c in when)) if isinstance(when, list)
            else condition(when, line))
    return Rule(tag, name, Grant(grant_text), node, Source(path, line),
                {"name": name, "grant": grant_text, "when": plain(when)})


def _legacy_rules(value, path: str, line: int | None) -> list[Rule]:
    """One rule of the colleague's list: one `Rule` per tag it grants."""
    if not isinstance(value, dict):
        raise RuleError("a rule must be a mapping with `pattern:`", line)
    line = _line(value, line)
    _only(value, {"name", "pattern", "host_tags", "service_tags"}, "rule", line)
    name = _text(value.get("name", "unnamed rule"), "a rule name", line)
    if "pattern" not in value:
        raise RuleError(f"rule {name!r} has no `pattern:`", line)
    node = condition(value["pattern"], _line(value["pattern"], line))
    grants: dict[str, set[Grant]] = {}
    for key, grant in (("host_tags", Grant.HOST), ("service_tags", Grant.SERVICE)):
        tags = value.get(key, [])
        if not isinstance(tags, list):
            raise RuleError(f"`{key}:` takes a list of tag names", line)
        for t in tags:
            grants.setdefault(tag_name(t, line), set()).add(grant)
    if not grants:
        raise RuleError(f"rule {name!r} grants no tag", line)
    rules = []
    for t, g in grants.items():
        grant = Grant.BOTH if len(g) == 2 else next(iter(g))
        # seek reads the colleague's patterns anywhere a condition goes, so the
        # pattern is the `when:` of the same rule in seek's own form.
        rules.append(Rule(t, name, grant, node, Source(path, line),
                          {"name": name, "grant": grant.value, "when": plain(value["pattern"])}))
    return rules


def definitions(doc: dict, path: str) -> FileDefs:
    """Everything a parsed document defines, with a problem for each part that was
    not taken - never an exception."""
    problems: list[Problem] = []
    rules: dict[str, list[Rule]] = {}
    described: dict[str, dict] = {}

    for key in doc:
        if key not in ("seek", "rules", "tags", "entries"):
            problems.append(Problem(f"unknown section {key!r} ignored", Source(path, _line(doc)),
                                    Level.WARNING))

    legacy = doc.get("rules", [])
    if legacy and not isinstance(legacy, list):
        problems.append(Problem("`rules:` must be a list", Source(path, _line(doc))))
        legacy = []
    for item in legacy or []:
        try:
            for rule in _legacy_rules(item, path, _line(item, _line(legacy))):
                rules.setdefault(rule.tag, []).append(rule)
        except RuleError as exc:
            problems.append(Problem(f"rule disabled: {exc}", Source(path, exc.line)))

    tags = doc.get("tags", {})
    if tags and not isinstance(tags, dict):
        problems.append(Problem("`tags:` must be a mapping of tag names", Source(path, _line(doc))))
        tags = {}
    for raw_name, body in (tags or {}).items():
        line = _line(body, _line(tags))
        try:
            name = tag_name(raw_name, line)
        except RuleError as exc:
            problems.append(Problem(f"tag disabled: {exc}", Source(path, exc.line)))
            continue
        if body is None:
            body = {}
        if not isinstance(body, dict):
            problems.append(Problem("a tag must be a mapping", Source(path, line), tag=name))
            continue
        try:
            _only(body, {"description", "issues", "rules"}, f"tag {name}", line)
            desc = _text(body.get("description", ""), "a description", line)
        except RuleError as exc:
            problems.append(Problem(f"tag disabled: {exc}", Source(path, exc.line), tag=name))
            continue
        issues: list[Issue] = []
        raw_issues = body.get("issues", [])
        for item in raw_issues if isinstance(raw_issues, list) else [raw_issues]:
            try:
                issues.append(_issue(item, path, _line(item, line)))
            except RuleError as exc:
                problems.append(Problem(f"issue left out: {exc}", Source(path, exc.line),
                                        tag=name))
        raw_rules = body.get("rules", [])
        for index, item in enumerate(raw_rules if isinstance(raw_rules, list) else [raw_rules], 1):
            try:
                rules.setdefault(name, []).append(
                    _native_rule(name, item, path, _line(item, line), index))
            except RuleError as exc:
                problems.append(Problem(f"rule disabled: {exc}", Source(path, exc.line),
                                        tag=name))
        described[name] = {"description": desc, "issues": tuple(issues),
                           "source": Source(path, line)}

    out: dict[str, TagDef] = {}
    for name in sorted(set(rules) | set(described)):
        d = described.get(name, {})
        sources = [d["source"]] if d else []
        sources += [r.source for r in rules.get(name, [])]
        out[name] = TagDef(name, d.get("description", ""), d.get("issues", ()),
                           tuple(rules.get(name, ())), tuple(dict.fromkeys(sources)))
    return FileDefs(out, tuple(problems))


def load(text: str, path: str) -> tuple[dict | None, FileDefs]:
    """Parse and read one document: its raw mapping (for `entries:`) and definitions."""
    doc, problems = parse_document(text, path)
    if doc is None:
        return None, FileDefs({}, tuple(problems))
    defs = definitions(doc, path)
    return doc, FileDefs(defs.tags, tuple(problems) + defs.problems)


# --- dependency order --------------------------------------------------------------


def tags_used(node: Node) -> set[str]:
    if isinstance(node, TagClause):
        return {node.tag}
    if isinstance(node, Not):
        return tags_used(node.clause)
    if isinstance(node, (All, Any)):
        return set().union(*(tags_used(c) for c in node.children))
    return set()


def order(tags: dict[str, TagDef]) -> tuple[tuple[str, ...], dict[str, Problem]]:
    """Evaluation order: every tag after the tags its rules ask about.

    Tags in a cycle (including a tag that asks about itself) are disabled, with
    one problem naming every tag in the cycle; the rest keep their order. A tag
    that is asked about but has no rules is a leaf - manual entries grant it.
    """
    deps = {name: set().union(*(tags_used(r.when) for r in d.rules)) & set(tags)
            for name, d in tags.items()}
    # Tarjan's strongly connected components, iteratively: rule sets can be long
    # chains, and recursion depth would be the limit.
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[list[str]] = []
    counter = 0
    for start in sorted(deps):
        if start in index:
            continue
        work = [(start, iter(sorted(deps[start])))]
        index[start] = low[start] = counter
        counter += 1
        stack.append(start)
        on_stack.add(start)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(deps[child]))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[node])
            if low[node] == index[node]:
                comp = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    comp.append(member)
                    if member == node:
                        break
                components.append(comp)
    disabled: dict[str, Problem] = {}
    ordered: list[str] = []
    # Tarjan emits components dependencies-first: exactly the evaluation order.
    for comp in components:
        cyclic = len(comp) > 1 or comp[0] in deps[comp[0]]
        if cyclic:
            names = sorted(comp)
            first = tags[names[0]].sources[0] if tags[names[0]].sources else None
            problem = Problem(f"tags disabled, they depend on each other in a cycle: "
                              f"{', '.join(names)}", first)
            for n in names:
                disabled[n] = problem
        else:
            ordered.extend(comp)
    return tuple(ordered), disabled
