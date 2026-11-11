"""The tag rule language: values, validation with lines, both dialects, the order."""

from __future__ import annotations

from pathlib import Path

import pytest

from seek.nmap import tagrules as tr

FIXTURES = Path(__file__).parent / "fixtures" / "tagging"


def _load(text: str) -> tr.FileDefs:
    return tr.load(text, "seek-rules.yaml")[1]


def _errors(defs: tr.FileDefs) -> list[str]:
    return [str(p) for p in defs.problems if p.level is tr.Level.ERROR]


# --- 2.1 text matching ---------------------------------------------------------------


def test_text_matches_anywhere_ignoring_case_by_default():
    m = tr.text_match("openresty", "product", 1)
    assert m.search("OpenResty web app server")
    assert not m.search(None) and not m.search("")


def test_case_can_be_required():
    m = tr.text_match({"regex": "READY", "case": True}, "title", 1)
    assert m.search("D2J201900995 - READY") and not m.search("ready")


def test_a_literal_keeps_its_special_characters():
    m = tr.text_match({"literal": "Jetty(i-jetty g2p5_0.08)"}, "product", 1)
    assert m.search("Jetty(i-jetty g2p5_0.08)")
    assert not m.search("Jettyi-jetty g2p5_0x08"), "parentheses and dots are not special"


def test_a_full_match_does_not_match_a_longer_name():
    m = tr.text_match("http", "service", 1, full=True)
    assert m.search("HTTP") and not m.search("https")


@pytest.mark.parametrize("value, fragment", [
    ("Jetty(i-jetty", "not a valid expression"),
    ("x" * 1001, "longer than 1000"),
    ("", "is empty"),
    ({"regex": "a", "literal": "b"}, "exactly one"),
    ({"regex": "a", "case": "yes"}, "true or false"),
])
def test_a_bad_text_value_is_refused(value, fragment):
    with pytest.raises(tr.RuleError, match=fragment):
        tr.text_match(value, "product", 7)


# --- 2.2 names, severities, issues ------------------------------------------------


@pytest.mark.parametrize("name", ["Printer", "zebra-zd420", "a.b_c-1", "9100"])
def test_valid_tag_names_are_lowercased(name):
    assert tr.tag_name(name) == name.lower()


@pytest.mark.parametrize("name", ["my printer", "-lead", "x" * 65, "a:b", ""])
def test_invalid_tag_names_are_refused(name):
    with pytest.raises(tr.RuleError, match="not a tag name"):
        tr.tag_name(name, 3)


def test_an_invalid_tag_disables_that_tag_only():
    defs = _load('tags:\n  "my printer": {description: x}\n  printer: {description: y}\n')
    assert set(defs.tags) == {"printer"}
    assert any("seek-rules.yaml:2" in e and "not a tag name" in e for e in _errors(defs))


def test_an_unknown_severity_drops_the_issue_and_keeps_the_tag():
    defs = _load("tags:\n  zebra-zd420:\n    issues:\n"
                 "      - {title: PIN only, severity: medium}\n"
                 "      - {title: Other, severity: severe}\n")
    assert [i.title for i in defs.tags["zebra-zd420"].issues] == ["PIN only"]
    (err,) = _errors(defs)
    assert "severe" in err and "info, low, medium, high, critical" in err and ":5:" in err


def test_names_are_one_tag_whatever_their_case():
    defs = _load("rules:\n"
                 "  - {name: a, pattern: {nmap_port: {port: 1}}, host_tags: [Printer]}\n"
                 "  - {name: b, pattern: {nmap_port: {port: 2}}, host_tags: [printer]}\n")
    assert list(defs.tags) == ["printer"] and len(defs.tags["printer"].rules) == 2


def test_the_loaded_types_cannot_be_changed():
    tag = _load("tags:\n  x: {description: d}\n").tags["x"]
    with pytest.raises(AttributeError):
        tag.description = "changed"  # type: ignore[misc]


# --- 2.3 the YAML: lines, limits, versions, coercion ------------------------------


def test_invalid_yaml_names_file_and_line():
    defs = _load("tags:\n  a: {description: [unclosed\n")
    (err,) = _errors(defs)
    assert err.startswith("seek-rules.yaml:") and "not valid YAML" in err


def test_a_list_at_the_top_is_not_a_rule_file():
    (err,) = _errors(_load("- a\n- b\n"))
    assert "expected a mapping" in err and "list" in err


def test_an_empty_file_defines_nothing_and_is_fine():
    assert _load("") == tr.FileDefs({}, ())


def test_a_newer_format_is_refused_whole():
    (err,) = _errors(_load("seek: 2\ntags:\n  a: {}\n"))
    assert "format 2" in err and "update seek" in err


def test_too_large_a_file_is_not_read():
    (err,) = _errors(_load("# " + "x" * (tr.MAX_FILE_BYTES + 1)))
    assert "larger than 2 MiB" in err


def test_alias_reuse_beyond_the_node_limit_is_not_read():
    lines = ["a: &a [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"]
    for n in range(1, 7):     # each level holds ten of the one before: 10^7 entries
        prev = "a" if n == 1 else f"l{n - 1}"
        lines.append(f"l{n}: &l{n} [" + ", ".join(f"*{prev}" for _ in range(10)) + "]")
    (err,) = _errors(_load("\n".join(lines) + "\n"))
    assert "more than 100000 entries" in err


@pytest.mark.parametrize("value, shown", [("no", "False"), ("1.10", "1.1"), ("22:30", "1350")])
def test_yaml_coercions_ask_for_quotes(value, shown):
    defs = _load(f"tags:\n  x:\n    rules:\n      - when: [{{port: 80, product: {value}}}]\n")
    (err,) = _errors(defs)
    assert "write it in quotes" in err and shown in err and ":4:" in err


def test_a_tag_named_no_needs_quotes():
    (err,) = _errors(_load("tags:\n  no: {description: x}\n"))
    assert "YAML read it as False" in err


@pytest.mark.parametrize("port", ["0", "65536", "true", "'web'", "'443/icmp'"])
def test_a_bad_port_disables_the_rule(port):
    defs = _load(f"tags:\n  x:\n    rules:\n      - when: [{{port: {port}}}]\n")
    assert "rule disabled" in _errors(defs)[0]
    assert defs.tags["x"].rules == ()


def test_unknown_sections_warn_and_the_rest_loads():
    defs = _load("rules: []\nextras: 1\ntags:\n  x: {}\n")
    assert "x" in defs.tags
    assert [p.level for p in defs.problems] == [tr.Level.WARNING]


# --- 2.4 the colleague's dialect -----------------------------------------------------


def test_every_pattern_type_of_the_colleague_loads():
    defs = tr.load((FIXTURES / "categorize_rules.yaml").read_text(), "categorize_rules.yaml")[1]
    assert not defs.problems
    assert {"switch", "printer", "ricoh", "ricoh-web-ui", "zebra", "appliance", "cctv",
            "hikvision", "hikvision-web-ui", "axis"} <= set(defs.tags)


def test_nmap_port_means_open_without_a_state_and_its_service_is_exact():
    defs = _load("rules:\n  - name: r\n    pattern: {nmap_port: {port: 80, service: http}}\n"
                 "    host_tags: [web]\n")
    clause = defs.tags["web"].rules[0].when
    assert isinstance(clause, tr.PortClause) and clause.state == "open" and clause.port == 80
    (field, match), = clause.fields
    assert field is tr.Field.SERVICE and match.search("http") and not match.search("https")


def test_a_gowitness_pattern_has_no_port():
    defs = _load("rules:\n  - {name: r, pattern: {html_title: {regex: Monitor}}, host_tags: [p]}\n")
    clause = defs.tags["p"].rules[0].when
    assert clause.port is None and clause.fields[0][0] is tr.Field.TITLE


def test_service_match_reads_colon_keys_and_tests_the_hostname_on_the_host():
    defs = tr.load((FIXTURES / "categorize_rules.yaml").read_text(), "f")[1]
    node = defs.tags["hikvision"].rules[0].when
    assert isinstance(node, tr.All)
    port, host = node.children
    assert {f for f, _ in port.fields} == {tr.Field.TITLE, tr.Field.CERT_ISSUER,
                                            tr.Field.CERT_SUBJECT, tr.Field.NETWORK_LOG}
    assert host.fields[0][0] is tr.HostField.HOSTNAME


def test_host_and_service_tags_of_one_rule():
    defs = tr.load((FIXTURES / "categorize_rules.yaml").read_text(), "f")[1]
    assert defs.tags["ricoh-web-ui"].rules[0].grant is tr.Grant.SERVICE
    assert defs.tags["ricoh"].rules[0].grant is tr.Grant.HOST
    both = _load("rules:\n  - {name: r, pattern: {nmap_port: {port: 1}}, host_tags: [a], "
                 "service_tags: [a]}\n")
    assert both.tags["a"].rules[0].grant is tr.Grant.BOTH


def test_a_colleague_rule_with_a_typo_is_disabled_alone():
    defs = _load("rules:\n"
                 "  - {name: bad, pattern: {nmap_prot: {port: 1}}, host_tags: [a]}\n"
                 "  - {name: ok, pattern: {nmap_port: {port: 1}}, host_tags: [b]}\n")
    assert set(defs.tags) == {"b"} and "nmap_prot" in _errors(defs)[0]


# --- 2.5 seek's own section ----------------------------------------------------------


def test_both_formats_in_one_file_combine():
    defs = _load("rules:\n  - {name: r, pattern: {nmap_port: {port: 9100}}, host_tags: [printer]}\n"
                 "tags:\n  printer:\n    description: Any printer\n"
                 "    issues: [{title: Unauthenticated raw printing, severity: low}]\n")
    tag = defs.tags["printer"]
    assert tag.description == "Any printer" and len(tag.rules) == 1 and tag.issues


def test_a_misspelt_key_disables_its_rule_and_names_the_key():
    defs = _load("tags:\n  x:\n    rules:\n      - when: [{port: 80, prodcut: nginx}]\n"
                 "      - when: [{port: 81}]\n")
    assert len(defs.tags["x"].rules) == 1
    assert "'prodcut'" in _errors(defs)[0]


def test_a_rule_without_conditions_is_refused():
    defs = _load("tags:\n  x:\n    rules:\n      - {name: everything, when: []}\n")
    assert "match every host" in _errors(defs)[0]


def test_not_takes_one_clause_and_negations_parse():
    defs = _load("tags:\n  x:\n    rules:\n      - when:\n          - {port: 80/tcp}\n"
                 "          - not: {port: 22/tcp}\n          - not: {tag: ricoh}\n")
    node = defs.tags["x"].rules[0].when
    nots = [c for c in node.children if isinstance(c, tr.Not)]
    assert isinstance(nots[0].clause, tr.PortClause) and nots[0].clause.protocol == "tcp"
    assert isinstance(nots[1].clause, tr.TagClause)
    bad = _load("tags:\n  y:\n    rules:\n      - when: [{not: {any: [{port: 1}]}}]\n")
    assert "not a group" in _errors(bad)[0]


def test_a_port_and_a_host_test_in_one_mapping_are_both_required():
    defs = _load("tags:\n  x:\n    rules:\n      - when: [{port: 443, hostname: 'cam'}]\n")
    node = defs.tags["x"].rules[0].when.children[0]
    assert isinstance(node, tr.All)


def test_an_address_condition_reads_a_network():
    defs = _load("tags:\n  x:\n    rules:\n      - when: [{address: 10.20.0.0/16}]\n")
    clause = defs.tags["x"].rules[0].when.children[0]
    assert str(clause.networks[0]) == "10.20.0.0/16"


def test_the_canonical_form_ignores_where_it_was_written():
    a = _load("tags:\n  x:\n    description: d\n    rules: [{when: [{port: 1}]}]\n").tags["x"]
    b = tr.load("\n\ntags:\n  x: {rules: [{when: [{port: 1}]}], description: d}\n",
                "other.yaml")[1].tags["x"]
    assert a.canonical() == b.canonical() and a.sources != b.sources


# --- 2.6 dependency order --------------------------------------------------------


def test_tags_are_ordered_after_the_tags_they_ask_about():
    defs = _load("tags:\n"
                 "  ricoh:\n    rules: [{when: [{tag: printer}, {title: Monitor}]}]\n"
                 "  printer:\n    rules: [{when: [{port: 9100}]}]\n")
    ordered, disabled = tr.order(defs.tags)
    assert ordered.index("printer") < ordered.index("ricoh") and not disabled


def test_a_cycle_disables_exactly_its_tags_with_one_problem():
    defs = _load("tags:\n"
                 "  a:\n    rules: [{when: [{tag: b}]}]\n"
                 "  b:\n    rules: [{when: [{not: {tag: a}}]}]\n"
                 "  c:\n    rules: [{when: [{port: 1}]}]\n"
                 "  self:\n    rules: [{when: [{tag: self}]}]\n")
    ordered, disabled = tr.order(defs.tags)
    assert ordered == ("c",)
    assert set(disabled) == {"a", "b", "self"}
    assert disabled["a"] is disabled["b"] and "a, b" in disabled["a"].message


def test_a_tag_only_asked_about_is_a_leaf():
    defs = _load("tags:\n  ricoh:\n    rules: [{when: [{tag: explored}]}]\n")
    assert tr.order(defs.tags) == (("ricoh",), {})


# --- 2.7 the documented examples ---------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent


def test_the_example_rule_file_loads_without_problems():
    defs = tr.load((ROOT / "examples" / "seek-rules.yaml").read_text(), "seek-rules.yaml")[1]
    assert not defs.problems, [str(p) for p in defs.problems]
    assert defs.tags["zebra-zd420"].issues[0].severity is tr.Severity.MEDIUM


def test_every_yaml_block_in_the_readme_loads_without_problems():
    import re

    blocks = re.findall(r"^```yaml\n(.*?)^```", (ROOT / "README.md").read_text(), re.S | re.M)
    assert blocks, "the README shows the rule format"
    for block in blocks:
        defs = tr.load(block, "README.md")[1]
        assert not defs.problems, [str(p) for p in defs.problems]
