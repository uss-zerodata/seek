"""Filter rows by fuzzy text and by address range, in one expression.

A token in CIDR notation (`10.10.10.32/26`) is understood as a network and
tested against the addresses a row belongs to; every other token is left to the
ordinary fuzzy query. The two compose, so `10.10.10.0/24 apache !ssl` means
"in that network, fuzzy-matching apache, not matching ssl".

Ranges combine as a union and the fuzzy terms as an AND: `10.0.0.0/8
192.168.0.0/16 apache` is "in either network, and matching apache". A negated
range subtracts from whatever the positive ones admitted.

A complete address counts as a range of one: `10.10.10.5` means `10.10.10.5/32`.
An *incomplete* one does not - `10.10.10` is not a valid address, so it stays a
fuzzy term and still finds `.5`, `.21` and `.250` while you are typing. The
switch from "finds many" to "finds exactly one" therefore happens at the moment
the address becomes complete.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

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
    query: ParsedQuery | None = None
    include: list[Network] = field(default_factory=list)
    exclude: list[Network] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return self.query is None and not self.include and not self.exclude

    @property
    def networks(self) -> list[Network]:
        return [*self.include, *self.exclude]


def parse_filter(text: str) -> FilterSpec:
    """Split a filter into its network terms and its fuzzy remainder."""
    include: list[Network] = []
    exclude: list[Network] = []
    rest: list[str] = []
    for token in text.split():
        negated = token.startswith("!")
        body = token[1:] if negated else token
        network = _as_network(body)
        if network is None:
            rest.append(token)
        elif negated:
            exclude.append(network)
        else:
            include.append(network)
    remainder = " ".join(rest).strip()
    query = parse_query(remainder) if remainder else None
    if query is not None and query.is_empty:
        query = None
    return FilterSpec(query=query, include=include, exclude=exclude)


def _in(network: Network, addresses: tuple[str, ...]) -> bool:
    for addr in addresses:
        try:
            if ipaddress.ip_address(addr) in network:
                return True
        except ValueError:
            continue
    return False


def matches(spec: FilterSpec, text: str, addresses: tuple[str, ...] = ()) -> bool:
    """Does a row pass? Network terms gate; the fuzzy query scores."""
    if spec.is_empty:
        return True
    # Several positive ranges are a *union*: `10.0.0.0/8 192.168.0.0/16` is the
    # two networks people actually mean, the way a target list reads. Requiring
    # every one of them, as this used to, asks for an address in both at once -
    # which for two distinct networks is nothing at all, so a second range could
    # only ever empty the list.
    if spec.include and not any(_in(n, addresses) for n in spec.include):
        return False
    for network in spec.exclude:
        if _in(network, addresses):
            return False
    if spec.query is not None and match_score(spec.query, text) is None:
        return False
    return True


def describe(spec: FilterSpec) -> str:
    """Short human summary, for the status line."""
    bits = [" or ".join(str(n) for n in spec.include)] if spec.include else []
    bits += [f"!{n}" for n in spec.exclude]
    if spec.query is not None:
        bits.append(spec.query.raw.strip())
    return " ".join(b for b in bits if b)
