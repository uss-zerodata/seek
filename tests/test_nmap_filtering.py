"""CIDR terms and fuzzy terms compose in one filter expression."""

from __future__ import annotations

import pytest

from seek.nmap.filtering import describe, matches, parse_filter


def _spec(text):
    return parse_filter(text)


# --- what counts as a network ----------------------------------------------


def test_a_prefix_makes_a_token_a_network():
    spec = _spec("10.10.10.32/26")
    assert [str(n) for n in spec.include] == ["10.10.10.0/26"]
    assert spec.query is None


def test_a_complete_address_is_a_beginning():
    """`10.10.10.5` finds `.5` and `.50`-`.59`: the list narrows as it is typed,
    rather than jumping to one host at the last digit."""
    spec = _spec("10.10.10.5")
    assert spec.prefixes == ["10.10.10.5"] and spec.include == []
    assert spec.query is None
    assert matches(spec, "x", ("10.10.10.5",)) is True
    assert matches(spec, "x", ("10.10.10.50",)) is True
    assert matches(spec, "x", ("10.10.10.6",)) is False


def test_equals_or_slash_32_is_exactly_that_host():
    for text in ("=10.10.10.5", "10.10.10.5/32"):
        spec = _spec(text)
        assert [str(n) for n in spec.include] == ["10.10.10.5/32"], text
        assert matches(spec, "x", ("10.10.10.5",)) is True
        assert matches(spec, "x", ("10.10.10.50",)) is False


def test_an_incomplete_address_stays_a_fuzzy_term():
    """Typing towards an address must still match while it is unfinished."""
    spec = _spec("10.10.10")
    assert spec.include == []
    assert spec.query is not None
    assert matches(spec, "10.10.10.5", ("10.10.10.5",)) is True
    assert matches(spec, "10.10.10.50", ("10.10.10.50",)) is True


def test_an_invalid_address_stays_a_fuzzy_term():
    spec = _spec("999.1.1.1")
    assert spec.include == []
    assert spec.query is not None


def test_a_complete_ipv6_address_is_a_beginning_too():
    spec = _spec("2001:db8::1")
    assert spec.prefixes == ["2001:db8::1"]
    assert matches(spec, "x", ("2001:db8::1",)) is True
    assert matches(spec, "x", ("2001:db8::2",)) is False
    assert [str(n) for n in _spec("=2001:db8::1").include] == ["2001:db8::1/128"]


def test_an_address_composes_with_fuzzy_terms():
    spec = _spec("10.10.10.5 http")
    assert spec.prefixes == ["10.10.10.5"]
    assert matches(spec, "nginx http", ("10.10.10.5",)) is True
    assert matches(spec, "ssh", ("10.10.10.5",)) is False


def test_an_exact_address_can_be_negated():
    spec = _spec("!10.10.10.5")
    assert matches(spec, "x", ("10.10.10.5",)) is False
    assert matches(spec, "x", ("10.10.10.6",)) is True


def test_a_path_like_token_is_not_a_network():
    spec = _spec("src/main")
    assert spec.include == [] and spec.exclude == []
    assert spec.query.raw == "src/main"


def test_nonsense_prefix_falls_back_to_fuzzy():
    spec = _spec("10.10.10.0/99")
    assert spec.include == []
    assert spec.query is not None


# --- membership -------------------------------------------------------------


@pytest.mark.parametrize(
    "addr,inside",
    [("10.10.10.0", True), ("10.10.10.32", True), ("10.10.10.63", True),
     ("10.10.10.64", False), ("10.10.10.95", False), ("10.10.11.1", False)],
)
def test_membership_of_a_slash_26(addr, inside):
    assert matches(_spec("10.10.10.32/26"), addr, (addr,)) is inside


def test_a_row_with_no_address_fails_a_network_term():
    assert matches(_spec("10.0.0.0/8"), "some text", ()) is False


def test_a_row_matches_if_any_of_its_addresses_is_inside():
    spec = _spec("10.10.10.0/24")
    assert matches(spec, "group", ("192.0.2.9", "10.10.10.5")) is True


def test_negated_network_excludes():
    spec = _spec("!10.10.10.0/28")
    assert matches(spec, "x", ("10.10.10.5",)) is False
    assert matches(spec, "x", ("10.10.10.20",)) is True


# --- composition with the fuzzy query --------------------------------------


def test_network_and_fuzzy_terms_both_apply():
    spec = _spec("10.10.10.0/24 prox")
    assert [str(n) for n in spec.include] == ["10.10.10.0/24"]
    assert spec.query.raw.strip() == "prox"
    assert matches(spec, "10.10.10.21 Proxmox", ("10.10.10.21",)) is True
    assert matches(spec, "10.10.10.21 nginx", ("10.10.10.21",)) is False
    assert matches(spec, "192.0.2.1 Proxmox", ("192.0.2.1",)) is False


def test_the_fuzzy_grammar_still_works_alongside_a_network():
    spec = _spec("10.0.0.0/8 'http !ssl")
    assert matches(spec, "10.1.2.3 http server", ("10.1.2.3",)) is True
    assert matches(spec, "10.1.2.3 http ssl", ("10.1.2.3",)) is False
    assert matches(spec, "10.1.2.3 ftp", ("10.1.2.3",)) is False


def test_several_networks_are_a_union_not_an_intersection():
    """Two ranges mean "either", the way a target list reads.

    They used to be ANDed, which asks for an address in both networks at once -
    for two disjoint networks that is nothing at all, so adding a second range
    could only ever empty the list.
    """
    spec = _spec("10.0.0.0/8 192.168.0.0/16")
    assert matches(spec, "x", ("10.1.2.3",)) is True
    assert matches(spec, "x", ("192.168.1.1",)) is True
    assert matches(spec, "x", ("172.16.0.1",)) is False


def test_a_nested_second_range_widens_rather_than_narrows():
    spec = _spec("10.0.0.0/8 10.10.0.0/16")
    assert matches(spec, "x", ("10.10.1.1",)) is True
    assert matches(spec, "x", ("10.20.1.1",)) is True, "still inside the /8"
    assert matches(spec, "x", ("11.0.0.1",)) is False


def test_a_negated_range_subtracts_from_the_union():
    spec = _spec("10.0.0.0/8 192.168.0.0/16 !10.1.0.0/16")
    assert matches(spec, "x", ("10.2.0.1",)) is True
    assert matches(spec, "x", ("192.168.5.5",)) is True
    assert matches(spec, "x", ("10.1.0.1",)) is False


def test_fuzzy_terms_still_and_on_top_of_a_union():
    spec = _spec("10.0.0.0/8 192.168.0.0/16 apache")
    assert matches(spec, "apache 2.4", ("10.1.1.1",)) is True
    assert matches(spec, "nginx", ("10.1.1.1",)) is False
    assert matches(spec, "apache 2.4", ("172.16.0.1",)) is False


def test_describe_spells_a_union_as_or():
    assert describe(_spec("10.0.0.0/8 192.168.0.0/16")) == "10.0.0.0/8 or 192.168.0.0/16"
    assert describe(_spec("!10.0.0.0/8")) == "!10.0.0.0/8"


def test_an_empty_filter_matches_everything():
    assert _spec("").is_empty
    assert matches(_spec(""), "anything", ()) is True


def test_describe_names_the_resolved_range():
    assert describe(_spec("10.10.10.32/26 web")) == "10.10.10.0/26 web"


def test_ipv6_networks_are_supported():
    spec = _spec("2001:db8::/32")
    assert matches(spec, "x", ("2001:db8::1",)) is True
    assert matches(spec, "x", ("2001:dead::1",)) is False


# --- ports, as nmap and URLs write them -------------------------------------------


class _Svc:
    def __init__(self, port, protocol="tcp", state="open"):
        self.port, self.protocol, self.state = port, protocol, state
        self.name = self.product = None


class _Host:
    def __init__(self, address, *services):
        self.address, self.services = address, list(services)


class _Rec:
    def __init__(self, host, service=None):
        self.host, self.service = host, service


def _row(address, *services):
    host = _Host(address, *services)
    return ("text", (address,), (_Rec(host),))


@pytest.mark.parametrize("text, port, proto", [
    (":443", 443, None), ("443/tcp", 443, "tcp"), ("53/udp", 53, "udp"),
    ("port:8080", 8080, None), ("port:80/tcp", 80, "tcp"),
])
def test_a_port_is_a_port_whatever_its_state(text, port, proto):
    spec = _spec(text)
    for state in ("open", "closed", "filtered"):
        assert matches(spec, *_row("10.0.0.1", _Svc(port, proto or "tcp", state))), state
    assert not matches(spec, *_row("10.0.0.1", _Svc(port + 1)))
    if proto:
        other = "udp" if proto == "tcp" else "tcp"
        assert not matches(spec, *_row("10.0.0.1", _Svc(port, other)))


def test_a_host_with_a_port_is_that_host_and_that_port():
    spec = _spec("10.10.10.10:8080")
    assert matches(spec, *_row("10.10.10.10", _Svc(8080)))
    assert not matches(spec, *_row("10.10.10.10", _Svc(80))), "the port too"
    assert not matches(spec, *_row("10.10.10.100", _Svc(8080))), "that host, exactly"


def test_open_and_closed_still_ask_for_the_state():
    assert matches(_spec("open:80/udp"), *_row("h", _Svc(80, "udp", "open")))
    assert not matches(_spec("open:80/udp"), *_row("h", _Svc(80, "udp", "closed")))
    assert matches(_spec("closed:8080"), *_row("h", _Svc(8080, "tcp", "filtered")))


def test_what_a_filter_was_understood_as_is_said():
    from seek.nmap.filtering import explain

    assert explain(_spec(":443 nginx")) == ["port 443 (any state)", "text like “nginx”"]
    assert explain(_spec("10.10.10.1")) == ["address beginning 10.10.10.1"]
    assert explain(_spec("=10.10.10.1")) == ["host 10.10.10.1"]
    assert explain(_spec("10.0.0.0/8 !ssh")) == ["address in 10.0.0.0/8", "not text like “ssh”"]
    assert explain(_spec("open:")) == ["ignored while incomplete: open:"]
