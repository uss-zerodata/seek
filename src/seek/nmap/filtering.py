"""Filter rows by fuzzy text and by address range, in one expression.

A token in CIDR notation (`10.10.10.32/26`) is understood as a network and
tested against the addresses a row belongs to; every other token is left to the
ordinary fuzzy query. The two compose, so `10.10.10.0/24 apache !ssl` means
"in that network, fuzzy-matching apache, not matching ssl".

Ranges combine as a union and the fuzzy terms as an AND: `10.0.0.0/8
192.168.0.0/16 apache` is "in either network, and matching apache". A negated
range subtracts from whatever the positive ones admitted.

A complete address is a *beginning*: `10.10.10.1` finds `.1`, then `.10`-`.19`
and `.100`-`.199`, so the list narrows smoothly as it is typed instead of
jumping to one host at the last digit. `=10.10.10.1` or `10.10.10.1/32` is that
host alone. An incomplete one (`10.10.10`) stays a fuzzy term.

Ports are written as nmap and URLs write them: `:443`, `443/tcp`, `53/udp` (or
`port:443`) is a port with that number, whatever its state; `10.10.10.10:8080`
is that host with that port. `open:`/`closed:` still ask for the state as well.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace

from seek.engine.query import ParsedQuery, parse_query
from seek.engine.score import match_score

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def _as_network(token: str) -> Network | None:
    """The network a token denotes, or None if it is not one.

    Either an explicit prefix (`10.10.10.32/26`) or a complete address, which is
    its own single-host network (`10.10.10.5` -> `10.10.10.5/32`).
    """
    try:
        if "/" in token:
            return ipaddress.ip_network(token, strict=False)
        return ipaddress.ip_network(ipaddress.ip_address(token))
    except ValueError:
        return None


@dataclass(slots=True)
class FilterSpec:
    # For highlighting, always; for matching only on the plain path.
    query: ParsedQuery | None = None
    include: list[Network] = field(default_factory=list)
    exclude: list[Network] = field(default_factory=list)
    # Complete addresses as typed: beginnings. In the same union as `include`.
    prefixes: list[str] = field(default_factory=list)
    exclude_prefixes: list[str] = field(default_factory=list)
    # Set only when the filter uses field terms, operators or parentheses; the
    # plain path above is then not consulted for matching (see `parse_filter`).
    expr: Node | None = None
    ignored: list[str] = field(default_factory=list)
    # One query per positive fuzzy term, for a structured filter: under OR a
    # cell matches one alternative, and highlighting with all of them ANDed
    # would mark nothing at all.
    highlights: tuple[ParsedQuery, ...] = ()
    # `~` in the filter: list the scattered-letter matches too, rather than
    # only the rows that contain the words (`prefer_firm`).
    loose: bool = False

    @property
    def is_empty(self) -> bool:
        return (self.expr is None and self.query is None and not self.include
                and not self.exclude and not self.prefixes and not self.exclude_prefixes)

    @property
    def networks(self) -> list[Network]:
        return [*self.include, *self.exclude]


def parse_filter(text: str) -> FilterSpec:
    """Split a filter into its network terms and its fuzzy remainder.

    Two paths, chosen by the text. A filter with no field term, no operator and
    no parenthesis is built exactly as it always was - that path is tuned for
    tens of thousands of rows a keystroke, and its "several ranges are a union"
    rule is behaviour people rely on, so it is kept rather than re-derived. Any
    of the new syntax builds an expression tree instead (`_parse_expr`).
    """
    loose = "~" in text.split()
    if loose:
        text = " ".join(t for t in text.split() if t != "~")
    spec = _parse(text)
    spec.loose = loose
    return spec


def _parse(text: str) -> FilterSpec:
    tokens = _tokens(text)
    if any(_is_structured(t) or _is_port_term(t) for t in tokens):
        return _parse_expr(tokens)
    include: list[Network] = []
    exclude: list[Network] = []
    prefixes: list[str] = []
    exclude_prefixes: list[str] = []
    rest: list[str] = []
    for token in text.split():
        negated = token.startswith("!")
        body = token[1:] if negated else token
        exact = body.startswith("=") and _complete_address(body[1:])
        if exact or "/" in body:
            network = _as_network(body[1:] if exact else body)
            if network is None:
                rest.append(token)
            else:
                (exclude if negated else include).append(network)
        elif _complete_address(body):
            (exclude_prefixes if negated else prefixes).append(body)
        else:
            rest.append(token)
    remainder = " ".join(rest).strip()
    query = parse_query(remainder) if remainder else None
    if query is not None and query.is_empty:
        query = None
    return FilterSpec(query=query, include=include, exclude=exclude, prefixes=prefixes,
                      exclude_prefixes=exclude_prefixes)


def _in(network: Network, addresses: tuple[str, ...]) -> bool:
    for addr in addresses:
        try:
            if ipaddress.ip_address(addr) in network:
                return True
        except ValueError:
            continue
    return False


def matches(spec: FilterSpec, text: str, addresses: tuple[str, ...] = (),
            records: tuple = (), tags=None) -> bool:
    """Does a row pass? Network terms gate; the fuzzy query scores.

    `records` are the row's `(host, service)` records, which field terms are
    tested against; the plain path never looks at them. `tags` is the session's
    `TagSet`, which `tag:` terms read - give a spec `without_tags` first when
    there is none yet.
    """
    if spec.is_empty:
        return True
    if spec.expr is not None:
        return _Row(text, addresses, records, tags).eval(spec.expr)
    # Several positive ranges are a *union*: `10.0.0.0/8 192.168.0.0/16` is the
    # two networks people actually mean, the way a target list reads. Requiring
    # every one of them, as this used to, asks for an address in both at once -
    # which for two distinct networks is nothing at all, so a second range could
    # only ever empty the list.
    if (spec.include or spec.prefixes) and not (
            any(_in(n, addresses) for n in spec.include)
            or any(a.startswith(p) for p in spec.prefixes for a in addresses)):
        return False
    for network in spec.exclude:
        if _in(network, addresses):
            return False
    if any(a.startswith(p) for p in spec.exclude_prefixes for a in addresses):
        return False
    if spec.query is not None and match_score(spec.query, text) is None:
        return False
    return True


def describe(spec: FilterSpec) -> str:
    """Short human summary, for the status line."""
    if spec.expr is not None or spec.ignored:
        shown = _show(spec.expr) if spec.expr is not None else ""
        if spec.ignored:
            shown += ("  ·  " if shown else "") + "ignored: " + ", ".join(spec.ignored)
        return shown
    union = [str(n) for n in spec.include] + [f"{p}…" for p in spec.prefixes]
    bits = [" or ".join(union)] if union else []
    bits += [f"!{n}" for n in spec.exclude] + [f"!{p}…" for p in spec.exclude_prefixes]
    if spec.query is not None:
        bits.append(spec.query.raw.strip())
    return " ".join(b for b in bits if b)


# --- structured filters -------------------------------------------------------
#
# Field terms (`open:22`, `closed:443/tcp`, `service:ssh`, `product:nginx`),
# uppercase AND / OR / NOT, `|`, `!` and parentheses. Grammar, lowest first:
#
#     or      := and ( ("OR" | "|") and )*
#     and     := unary ( ["AND"] unary )*        adjacency is AND
#     unary   := ("NOT" | "!") unary | primary
#     primary := "(" or ")" | field | range | fuzzy
#
# Two semantic rules make it read the way a review asks its questions: field
# terms joined by AND describe *one* port (`service:http product:nginx` is an
# http port served by nginx, not http here and nginx there), and NOT is "none
# of the row's ports" (`NOT service:ssh` is a host without ssh - negating per
# port would match any host that has some other service).
#
# It is evaluated on every keystroke, so a half-typed query is the normal case:
# a missing `)` is implied, a dangling operator or an empty field is dropped
# and named in `FilterSpec.ignored`, and nothing half-typed empties the list.

FIELDS = frozenset({"open", "closed", "port", "service", "product", "tag"})
_OPERATORS = frozenset({"AND", "OR", "NOT", "|", "!", "(", ")"})


@dataclass(frozen=True, slots=True)
class Fuzzy:
    """One term of the search grammar (`'x`, `^x`, `x$`, `!x`), against the row text."""
    query: ParsedQuery
    token: str


@dataclass(frozen=True, slots=True)
class Range:
    """Address ranges and beginnings; several side by side in one AND are a
    union, as always - `10.0.0.1 10.0.0.9` is either host, not both."""
    networks: tuple[Network, ...] = ()
    prefixes: tuple[str, ...] = ()        # complete addresses, as typed: a beginning


@dataclass(frozen=True, slots=True)
class Field:
    """A fact about one port: its state, its service name, its product, or a tag
    it carries - its own or its host's."""
    key: str
    value: str
    port: int | None = None
    proto: str | None = None
    text: str = ""
    start: bool = False                 # `^value`
    end: bool = False                   # `value$`

    def _text_test(self, have: str) -> bool:
        if self.start and self.end:
            return have == self.text
        if self.start:
            return have.startswith(self.text)
        if self.end:
            return have.endswith(self.text)
        return self.text in have

    def test(self, svc, tags: frozenset[str] = frozenset()) -> bool:
        """`svc` None is a host with no ports at all: only its tags can match."""
        if self.key == "tag":
            return any(self._text_test(t) for t in tags)
        if svc is None:
            return False
        if self.key == "port":
            # Any port a scan recorded with this number - whatever its state.
            return svc.port == self.port and (not self.proto or svc.protocol == self.proto)
        if self.key in ("open", "closed"):
            if svc.port != self.port or (self.proto and svc.protocol != self.proto):
                return False
            if self.key == "open":
                return svc.state == "open"
            # Recorded, and not open: closed, filtered, open|filtered. A port no
            # scan recorded is not here at all, so it matches neither key.
            return bool(svc.state) and svc.state != "open"
        have = ((svc.name if self.key == "service" else svc.product) or "").lower()
        return self._text_test(have)


@dataclass(frozen=True, slots=True)
class Not:
    child: Node


@dataclass(frozen=True, slots=True)
class And:
    children: tuple[Node, ...]


@dataclass(frozen=True, slots=True)
class Or:
    children: tuple[Node, ...]


Node = Fuzzy | Range | Field | Not | And | Or


def _tokens(text: str) -> list[str]:
    """Whitespace-separated, with parentheses always tokens of their own.

    `!(` is therefore NOT and a group, while `!ssh` stays one token - the fuzzy
    grammar's own negation, which is exactly what it meant before.
    """
    out: list[str] = []
    for chunk in text.split():
        word = ""
        for ch in chunk:
            if ch in "()":
                if word:
                    out.append(word)
                    word = ""
                out.append(ch)
            else:
                word += ch
        if word:
            out.append(word)
    return out


def _field_key(body: str) -> str | None:
    key, sep, _ = body.partition(":")
    key = key.lower()
    return key if sep and key in FIELDS else None


def _is_structured(token: str) -> bool:
    if token in _OPERATORS:
        return True
    return _field_key(token[1:] if token.startswith("!") else token) is not None


_PROTOCOLS = ("tcp", "udp", "sctp")


def _port_of(token: str) -> Field | None:
    """`:443`, `443/tcp`, `53/udp` - a port as nmap and URLs write it."""
    if token.startswith(":"):
        return _field("port", token[1:])
    number, slash, proto = token.partition("/")
    if slash and number.isdigit() and proto.lower() in _PROTOCOLS:
        return _field("port", token)
    return None


def _complete_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _address_port(token: str) -> tuple[str, str] | None:
    """`10.10.10.10:8080` - an IPv4 address with a port after it."""
    address, colon, port = token.rpartition(":")
    if colon and port.isdigit() and address.count(".") == 3 and _complete_address(address):
        return address, port
    return None


def _is_port_term(token: str) -> bool:
    """A port, or a host with a port - what the plain path cannot express."""
    body = token[1:] if token.startswith("!") else token
    return _port_of(body) is not None or _address_port(body) is not None


def _prune_tags(node):
    """The expression without its `tag:` terms; None when nothing is left. A NOT
    whose child goes goes with it - "none of nothing" would empty the list."""
    if isinstance(node, Field):
        return None if node.key == "tag" else node
    if isinstance(node, Not):
        child = _prune_tags(node.child)
        return None if child is None else Not(child)
    if isinstance(node, (And, Or)):
        kids = [k for k in (_prune_tags(c) for c in node.children) if k is not None]
        if not kids:
            return None
        return kids[0] if len(kids) == 1 else type(node)(tuple(kids))
    return node


def _tag_terms(node) -> list[str]:
    if isinstance(node, Field):
        return [f"tag:{node.value}"] if node.key == "tag" else []
    if isinstance(node, Not):
        return _tag_terms(node.child)
    if isinstance(node, (And, Or)):
        return [t for c in node.children for t in _tag_terms(c)]
    return []


def uses_tags(spec: FilterSpec) -> bool:
    return spec.expr is not None and bool(_tag_terms(spec.expr))


def without_tags(spec: FilterSpec, reason: str = "tags not ready") -> FilterSpec:
    """The spec for a moment with no tags yet: its `tag:` terms named as ignored
    rather than tested, so a half-built projection never empties the list."""
    if not uses_tags(spec):
        return spec
    terms = _tag_terms(spec.expr)
    pruned = _prune_tags(spec.expr)
    return replace(spec, expr=pruned,
                   ignored=[*spec.ignored, *(f"{t} ({reason})" for t in terms)])


def _field(key: str, value: str) -> Field | None:
    """A field term, or None when its value cannot be used (yet)."""
    if not value:
        return None
    if key in ("open", "closed", "port"):
        port, _, proto = value.partition("/")
        if not port.isdigit():
            return None
        return Field(key, value, port=int(port), proto=proto.lower() or None)
    folded = value.lower()
    start = folded.startswith("^")
    end = folded.endswith("$")
    text = folded[1 if start else 0:len(folded) - 1 if end else len(folded)]
    if not text:
        return None
    return Field(key, value, text=text, start=start, end=end)


def _and(parts: list[Node]) -> Node | None:
    """Join as AND, folding the positive ranges among them into one union."""
    ranges = [p for p in parts if isinstance(p, Range)]
    if len(ranges) > 1:
        first = parts.index(ranges[0])
        rest = [p for p in parts if not isinstance(p, Range)]
        rest.insert(first, Range(tuple(n for r in ranges for n in r.networks),
                                 tuple(p for r in ranges for p in r.prefixes)))
        parts = rest
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else And(tuple(parts))


def _or(parts: list[Node]) -> Node | None:
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else Or(tuple(parts))


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.at = 0
        self.ignored: list[str] = []

    def peek(self) -> str | None:
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def take(self) -> str | None:
        token = self.peek()
        self.at += 1
        return token

    def parse(self) -> Node | None:
        node = self.or_()
        while self.peek() is not None:          # a `)` with nothing to close
            self.ignored.append(self.take())
            node = _and([n for n in (node, self.or_()) if n is not None])
        return node

    def or_(self) -> Node | None:
        parts: list[Node] = []
        first = self.and_()
        if first is not None:
            parts.append(first)
        while self.peek() in ("OR", "|"):
            op = self.take()
            right = self.and_()
            if right is None or not parts:
                self.ignored.append(op)         # `ssh OR`, `OR ssh`
            if right is not None:
                parts.append(right)
        return _or(parts)

    def and_(self) -> Node | None:
        parts: list[Node] = []
        while True:
            token = self.peek()
            if token is None or token in (")", "OR", "|"):
                break
            if token == "AND":
                self.take()
                if self.peek() in (None, ")", "OR", "|", "AND") or not parts:
                    self.ignored.append(token)
                continue
            node = self.unary()
            if node is not None:
                parts.append(node)
        return _and(parts)

    def unary(self) -> Node | None:
        token = self.peek()
        if token in ("NOT", "!"):
            self.take()
            if self.peek() in (None, ")", "OR", "|", "AND"):
                self.ignored.append(token)
                return None
            child = self.unary()
            return Not(child) if child is not None else None
        return self.primary()

    def primary(self) -> Node | None:
        token = self.take()
        if token == "(":
            node = self.or_()
            if self.peek() == ")":
                self.take()
            # else: implied at the end - the query is still being typed
            if node is None:
                self.ignored.append("()")
            return node
        return self.term(token)

    def term(self, token: str) -> Node | None:
        negated = token.startswith("!") and len(token) > 1
        body = token[1:] if negated else token
        key = _field_key(body)
        if key is not None:
            node: Node | None = _field(key, body.partition(":")[2])
            if node is None:
                self.ignored.append(token)
                return None
            return Not(node) if negated else node
        node = _address_term(body)
        if node is not None:
            return Not(node) if negated else node
        query = parse_query(token)
        if query.is_empty:
            return None
        return Fuzzy(query, token)


def _address_term(body: str) -> Node | None:
    """Ports, `host:port`, `=host`, ranges and address beginnings - or None."""
    port = _port_of(body)
    if port is not None:
        return port
    pair = _address_port(body)
    if pair is not None:
        address, number = pair
        port = _field("port", number)
        exact = Range((ipaddress.ip_network(ipaddress.ip_address(address)),))
        return And((exact, port)) if port is not None else exact
    if body.startswith("=") and _complete_address(body[1:]):
        return Range((ipaddress.ip_network(ipaddress.ip_address(body[1:])),))
    if "/" in body:
        network = _as_network(body)
        return Range((network,)) if network is not None else None
    if _complete_address(body):
        return Range(prefixes=(body,))
    return None


def _positive_fuzzy(node: Node | None, negated: bool = False) -> list[str]:
    """The fuzzy terms a match can be highlighted by: those not under a NOT."""
    if node is None:
        return []
    if isinstance(node, Fuzzy):
        return [] if negated else [node.token]
    if isinstance(node, Not):
        return _positive_fuzzy(node.child, not negated)
    if isinstance(node, (And, Or)):
        return [t for c in node.children for t in _positive_fuzzy(c, negated)]
    return []


def _parse_expr(tokens: list[str]) -> FilterSpec:
    parser = _Parser(tokens)
    expr = parser.parse()
    highlight = " ".join(_positive_fuzzy(expr))
    query = parse_query(highlight) if highlight else None
    if query is not None and query.is_empty:
        query = None
    highlights = tuple(q for q in (parse_query(t) for t in _positive_fuzzy(expr))
                       if not q.is_empty)
    return FilterSpec(query=query, expr=expr, ignored=parser.ignored,
                      highlights=highlights)


# A service overview row stands for every host running that service - twenty
# thousand pairs at engagement scale, 342 557 across the tab - and walking them
# all on every keystroke was 150-250 ms of a 36-row list. A field term reads
# only a port's number, protocol, state, name and product, which within one
# such row repeat almost entirely, so one port per distinct combination answers
# every term exactly. Kept per records tuple (rows are cached with the model,
# so the tuple is the same object keystroke after keystroke); the tuple is held
# beside its answer so a recycled `id` can never be mistaken for it.
_SAMPLES: dict[int, tuple[tuple, list, object]] = {}
_SAMPLES_MAX = 4096


def _names(tags, host, svc) -> frozenset[str]:
    if tags is None:
        return frozenset()
    if svc is None:
        return tags.names(host.address)
    return tags.names(host.address, svc.protocol, svc.port)


def _ports(record, tags) -> list[tuple]:
    """A record's `(service, tag names)` pairs: its own service, or every port
    of its host - and a host with no ports at all as one portless sample, so
    its tags can still be asked about."""
    svc = getattr(record, "service", None)
    services = [svc] if svc is not None else record.host.services
    if not services:
        return [(None, _names(tags, record.host, None))]
    return [(each, _names(tags, record.host, each)) for each in services]


def _representatives(records: tuple, tags=None) -> list:
    # The tag set is part of the key, held beside it like the records: a
    # re-tag must not be answered from the samples of the tags before it.
    hit = _SAMPLES.get(id(records))
    if hit is not None and hit[0] is records and hit[2] is tags:
        return hit[1]
    seen: dict[tuple, tuple] = {}
    for record in records:
        for each, names in _ports(record, tags):
            key = ((each.port, each.protocol, each.state, each.name, each.product)
                   if each is not None else None, names)
            seen.setdefault(key, (each, names))
    if len(_SAMPLES) >= _SAMPLES_MAX:
        _SAMPLES.clear()                    # a new model; the old rows are gone
    found = list(seen.values())
    _SAMPLES[id(records)] = (records, found, tags)
    return found


class _Row:
    """One row under evaluation; its ports are gathered once, when first asked."""

    __slots__ = ("text", "addresses", "records", "tags", "_services")

    def __init__(self, text: str, addresses: tuple[str, ...], records: tuple,
                 tags=None) -> None:
        self.text = text
        self.addresses = addresses
        self.records = records
        self.tags = tags
        self._services: list | None = None

    def services(self) -> list:
        """`(service, tag names)` for a record's own service, or for every port
        of its host - closed and filtered included, or `closed:` could never
        match a host row."""
        if self._services is None:
            records = self.records
            if len(records) == 1:
                self._services = _ports(records[0], self.tags)
            else:
                self._services = _representatives(records, self.tags)
        return self._services

    def eval(self, node: Node) -> bool:
        if isinstance(node, Fuzzy):
            return match_score(node.query, self.text) is not None
        if isinstance(node, Range):
            return (any(_in(n, self.addresses) for n in node.networks)
                    or any(a.startswith(p) for p in node.prefixes for a in self.addresses))
        if isinstance(node, Field):
            return any(node.test(s, names) for s, names in self.services())
        if isinstance(node, Not):
            return not self.eval(node.child)            # "none of the ports"
        if isinstance(node, Or):
            return any(self.eval(c) for c in node.children)
        # AND: the field terms directly under it are one clause, satisfied by
        # a single port; everything else is a condition on the row.
        fields = [c for c in node.children if isinstance(c, Field)]
        if fields and not any(all(f.test(s, names) for f in fields)
                              for s, names in self.services()):
            return False
        return all(self.eval(c) for c in node.children if not isinstance(c, Field))


def _show(node: Node, inside: type | None = None) -> str:
    """The tree back as text, every operator and grouping spelled out."""
    if isinstance(node, Fuzzy):
        return node.token
    if isinstance(node, Field):
        return f"{node.key}:{node.value}"
    if isinstance(node, Range):
        items = [str(n) for n in node.networks] + [f"{p}…" for p in node.prefixes]
        if len(items) == 1:
            return items[0]
        return "(" + " OR ".join(items) + ")"
    if isinstance(node, Not):
        child = _show(node.child, Not)
        return f"NOT {child}"
    joiner = " AND " if isinstance(node, And) else " OR "
    text = joiner.join(_show(c, type(node)) for c in node.children)
    # Parenthesised wherever the reading depends on precedence: a group under
    # a NOT, and an OR inside an AND (or the reverse, for clarity).
    return f"({text})" if inside is not None and inside is not type(node) else text


# --- saying what a filter was understood as -------------------------------------


def explain(spec: FilterSpec) -> list[str]:
    """What a filter will do, in words - shown under the box as it is typed.

    One phrase per condition, top-level ANDs listed side by side; anything
    ignored because it is half-typed is said too, so a filter that "does
    nothing" says why.
    """
    if spec.is_empty:
        return ([f"ignored while incomplete: {' '.join(spec.ignored)}"]
                if spec.ignored else [])
    if spec.loose:
        return [*explain(FilterSpec(spec.query, spec.include, spec.exclude, spec.prefixes,
                                    spec.exclude_prefixes, spec.expr, spec.ignored,
                                    spec.highlights)), "looser matches included (~)"]
    if spec.expr is None:
        parts = []
        if spec.include or spec.prefixes:
            parts.append(_say(Range(tuple(spec.include), tuple(spec.prefixes))))
        parts += [f"not: {_say(Range((n,)))}" for n in spec.exclude]
        parts += [f"not: address beginning {p}" for p in spec.exclude_prefixes]
        if spec.query is not None:
            parts += [_say_term(t) for t in spec.query.terms]
        return parts
    nodes = spec.expr.children if isinstance(spec.expr, And) else (spec.expr,)
    parts = [_say(n) for n in nodes]
    if spec.ignored:
        parts.append("ignored while incomplete: " + " ".join(spec.ignored))
    return parts


def _say_term(term) -> str:
    kind = term.type.value
    text = term.text
    said = {"fuzzy": f"text like “{text}”", "exact": f"text containing “{text}”",
            "prefix": f"text starting “{text}”", "suffix": f"text ending “{text}”",
            "equal": f"text exactly “{text}”"}.get(kind, text)
    return f"not {said}" if term.negated else said


def _say(node: Node) -> str:
    if isinstance(node, Fuzzy):
        return " and ".join(_say_term(t) for t in node.query.terms)
    if isinstance(node, Range):
        said = []
        for n in node.networks:
            text = str(n)
            said.append("host " + text.rsplit("/", 1)[0]
                        if n.num_addresses == 1 else f"address in {text}")
        said += [f"address beginning {p}" for p in node.prefixes]
        return " or ".join(said)
    if isinstance(node, Field):
        port = f"{node.port}/{node.proto}" if node.proto else f"{node.port}"
        return {"port": f"port {port} (any state)", "open": f"port {port} open",
                "closed": f"port {port} not open (closed or filtered)",
                "service": f"a service named like “{node.value}”",
                "product": f"a product like “{node.value}”",
                "tag": f"a tag like “{node.value}”"}[node.key]
    if isinstance(node, Not):
        return "not: " + _say(node.child)
    joiner = " and " if isinstance(node, And) else " or "
    return "(" + joiner.join(_say(c) for c in node.children) + ")"


def strong(spec: FilterSpec, text: str) -> bool:
    """Whether every plain word of the filter occurs in `text` as written.

    The fuzzy grammar lets `401` match "4…0…1" scattered through a long line,
    which is right for narrowing a list while typing and wrong for "where is
    X": a search ranks the rows that contain its words above the ones that only
    contain their letters, and drops the latter when there are any of the
    former. Terms that are not plain words - exact, prefix, negated, fields,
    ranges - decide membership already and are not second-guessed here.
    """
    if spec.query is None:
        return True
    folded = text.lower()
    for term in spec.query.terms:
        if term.negated or term.type.value != "fuzzy":
            continue
        if term.text.lower() not in folded:
            return False
    return True


def prefer_firm(spec: FilterSpec, rows: list, text_of) -> tuple[list, int]:
    """The rows that contain the filter's words, when any do - and how many
    matched only by scattered letters and were left out.

    A filter narrows by the fuzzy grammar; this is the second step both front
    ends take so that `synology` lists the host whose page says Synology and not
    the ones that merely contain s…y…n…o…l…o…g…y. With no firm match the fuzzy
    rows stand, so a typo still finds something. `~` in the filter turns it off.
    Heading rows are kept for the caller to prune.
    """
    if spec.loose or spec.query is None:
        return rows, 0
    firm = [r for r in rows if getattr(r, "heading", False) or strong(spec, text_of(r))]
    body = sum(1 for r in rows if not getattr(r, "heading", False))
    kept = sum(1 for r in firm if not getattr(r, "heading", False))
    if not kept or kept == body:
        return rows, 0
    return firm, body - kept
