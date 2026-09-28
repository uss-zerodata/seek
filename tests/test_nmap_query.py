"""Structured filters: field terms, AND / OR / NOT, grouping.

`basic` holds 192.0.2.1 (22 ssh/OpenSSH open, 80 http/nginx open, 443 https
closed), 192.0.2.2 (80 http/nginx open, 22 filtered) and 192.0.2.3 (down).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap import filtering
from seek.nmap.filtering import And, Field, Fuzzy, Not, Or, Range, describe, parse_filter
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import views as vdefs

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _rows(*names):
    return vdefs.hosts_view().rows(prepare(load([FIX / f"{n}.xml" for n in names])))


def _hosts(query: str, *names: str) -> list[str]:
    spec = parse_filter(query)
    return [r.cells[0] for r in _rows(*(names or ("basic",)))
            if filtering.matches(spec, r.text, r.addresses, r.records)]


def _forced(query: str) -> filtering.FilterSpec:
    """The same text, through the tree whether or not it needs one."""
    return filtering._parse_expr(filtering._tokens(query))


# --- parsing ----------------------------------------------------------------


def test_plain_filters_keep_the_plain_path():
    for query in ("apache", "'http !443", "10.0.0.0/8 192.168.0.0/16 apache",
                  "rock and roll", "http://intranet", "a:b"):
        spec = parse_filter(query)
        assert spec.expr is None and not spec.ignored, query


@pytest.mark.parametrize("query", ["open:22", "SERVICE:ssh", "!product:x", "a OR b",
                                   "a | b", "NOT a", "(a)", "a AND b"])
def test_any_new_syntax_builds_a_tree(query):
    assert parse_filter(query).expr is not None


def test_precedence_is_not_then_and_then_or():
    expr = parse_filter("a b OR NOT c d").expr
    assert isinstance(expr, Or)
    left, right = expr.children
    assert isinstance(left, And) and isinstance(right, And)
    assert isinstance(right.children[0], Not)


def test_symbols_and_words_are_the_same_operators():
    assert describe(parse_filter("a | b")) == describe(parse_filter("a OR b"))
    assert describe(parse_filter("!(open:22)")) == describe(parse_filter("NOT open:22"))
    assert describe(parse_filter("a AND b open:1")) == describe(parse_filter("a b open:1"))


def test_grouping_is_shown_explicitly():
    assert describe(parse_filter("service:http AND NOT (product:apache | product:iis)")) \
        == "service:http AND NOT (product:apache OR product:iis)"
    assert describe(parse_filter("a b OR c d")) == "(a AND b) OR (c AND d)"


def test_field_values():
    port = parse_filter("open:80/TCP").expr
    assert isinstance(port, Field) and (port.port, port.proto) == (80, "tcp")
    exact = parse_filter("service:^HTTP$").expr
    assert isinstance(exact, Field) and (exact.text, exact.start, exact.end) == ("http", True, True)


def test_a_negated_fuzzy_term_keeps_the_search_grammar():
    """`!ssh` meant "not matching ssh" before; it still does, as one term."""
    expr = parse_filter("open:22 !ssh").expr
    assert isinstance(expr, And)
    assert any(isinstance(c, Fuzzy) and c.token == "!ssh" for c in expr.children)


@pytest.mark.parametrize(("query", "ignored"), [
    ("service:", ["service:"]),
    ("open:web", ["open:web"]),
    ("ssh OR", ["OR"]),
    ("OR ssh", ["OR"]),
    ("ssh AND", ["AND"]),
    ("NOT", ["NOT"]),
    ("()", ["()"]),
    (") ssh", [")"]),
])
def test_what_cannot_be_used_is_ignored_and_named(query, ignored):
    spec = parse_filter(query)
    assert spec.ignored == ignored
    assert "ignored: " in describe(spec)


def test_an_unclosed_group_is_closed_at_the_end():
    spec = parse_filter("service:ssh OR (open:80 service:http")
    assert spec.ignored == []
    assert describe(spec) == "service:ssh OR (open:80 AND service:http)"


def test_nothing_half_typed_empties_the_list():
    for query in ("service:", "open:", "(", "NOT", "open:web"):
        assert len(_hosts(query)) == 3, query


def test_positive_ranges_side_by_side_stay_a_union():
    expr = parse_filter("10.0.0.0/8 192.168.0.0/16 open:22").expr
    assert isinstance(expr, And)
    assert any(isinstance(c, Range) and len(c.networks) == 2 for c in expr.children)


def test_highlighting_uses_the_positive_fuzzy_terms():
    spec = parse_filter("apache OR (nginx NOT alpha) open:80")
    assert spec.query is not None
    assert [t.text for t in spec.query.terms] == ["apache", "nginx"]


# --- evaluation -------------------------------------------------------------


def test_open_is_the_port_found_open_not_the_text():
    assert _hosts("open:22") == ["192.0.2.1"], ".2 has 22 filtered"
    assert _hosts("open:80/tcp") == ["192.0.2.1", "192.0.2.2"]
    assert _hosts("open:80/udp") == []


def test_closed_is_recorded_and_not_open():
    assert _hosts("closed:22") == ["192.0.2.2"], "filtered counts as not open"
    assert _hosts("closed:443/tcp") == ["192.0.2.1"]
    assert _hosts("closed:8080") == [], "never scanned is neither"


def test_open_filtered_is_closed(tmp_path):
    scan = tmp_path / "udp.xml"
    scan.write_text(
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap -sU -oX udp.xml '
        '192.0.2.9" start="1756000000" version="7.94" xmloutputversion="1.05">\n'
        '<host><status state="up" reason="echo-reply" reason_ttl="64"/>'
        '<address addr="192.0.2.9" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="53"><state state="open|filtered" reason="no-response" '
        'reason_ttl="0"/><service name="domain" method="table" conf="3"/></port>'
        '</ports></host>\n</nmaprun>\n')
    rows = vdefs.hosts_view().rows(prepare(load([scan])))
    for query, want in (("closed:53/udp", True), ("open:53", False)):
        spec = parse_filter(query)
        assert filtering.matches(spec, rows[0].text, rows[0].addresses, rows[0].records) is want


def test_service_and_product():
    assert _hosts("service:ssh") == ["192.0.2.1"]
    assert _hosts("product:NGINX") == ["192.0.2.1", "192.0.2.2"], "case-insensitive"
    assert _hosts("service:http") == ["192.0.2.1", "192.0.2.2"], ".1's https contains http too"
    assert _hosts("service:^http$ closed:443") == [], "443 is https, not exactly http"


def test_and_ties_field_terms_to_one_port():
    assert _hosts("service:http AND product:openssh") == [], "ssh is OpenSSH, http is not"
    assert _hosts("service:ssh AND product:openssh") == ["192.0.2.1"]
    assert _hosts("open:22 AND service:http") == [], "22 is not the http port"


def test_or():
    assert _hosts("service:ssh OR open:80") == ["192.0.2.1", "192.0.2.2"]
    assert _hosts("service:telnet | service:ssh") == ["192.0.2.1"]


def test_not_means_none_of_the_ports():
    assert _hosts("NOT service:ssh") == ["192.0.2.2", "192.0.2.3"]
    assert _hosts("!open:22") == ["192.0.2.2", "192.0.2.3"]


def test_grouping():
    assert _hosts("service:http AND NOT (product:openssh | closed:443)") == ["192.0.2.2"]


def test_structured_and_plain_terms_together():
    assert _hosts("192.0.2.0/24 open:80 !alpha") == ["192.0.2.2"], ".1 is alpha.example"
    assert _hosts("192.0.2.1 192.0.2.2 NOT open:22") == ["192.0.2.2"], "ranges stay a union"


def test_a_port_row_is_judged_by_its_own_port():
    scans = prepare(load([FIX / "basic.xml"]))
    host = next(h for h in scans.hosts if h.address == "192.0.2.1")
    rows = vdefs.host_detail(host).rows(scans)
    spec = parse_filter("service:ssh OR open:80")
    assert [r.cells[0] for r in rows
            if filtering.matches(spec, r.text, r.addresses, r.records)] == ["22/tcp", "80/tcp"]


def test_a_service_group_matches_by_its_members():
    rows = vdefs.services_view().rows(prepare(load([FIX / "basic.xml"])))
    spec = parse_filter("open:22")
    assert [r.cells[0] for r in rows
            if filtering.matches(spec, r.text, r.addresses, r.records)] == ["22"]


# --- the two paths agree ----------------------------------------------------


@pytest.mark.parametrize("query", [
    "nginx", "'http !443", "^192.0.2.1", "example$", "alpha !beta", "!alpha",
    "192.0.2.0/24", "192.0.2.0/24 nginx", "!192.0.2.1", "192.0.2.1 192.0.2.2",
    "192.0.2.1 192.0.2.2 !192.0.2.2", "ssh http", "OpenSSH",
])
def test_a_plain_query_gives_the_same_rows_through_the_tree(query):
    rows = _rows("basic", "vuln", "vhosts")
    plain, tree = parse_filter(query), _forced(query)
    assert plain.expr is None and tree.expr is not None
    got = [[r.cells[0] for r in rows
            if filtering.matches(spec, r.text, r.addresses, r.records)]
           for spec in (plain, tree)]
    assert got[0] == got[1]
