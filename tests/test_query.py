from seek.engine.query import TermType, parse_query
from seek.engine.score import match_spans


def test_and_terms():
    q = parse_query("main test")
    assert len(q.terms) == 2
    assert q.matches("main_test_file")
    assert not q.matches("main_only")


def test_negation():
    q = parse_query("config !test")
    assert q.matches("config_prod.py")
    assert not q.matches("config_test.py")


def test_prefix_suffix_equal():
    assert parse_query("^src").terms[0].type is TermType.PREFIX
    assert parse_query("log$").terms[0].type is TermType.SUFFIX
    assert parse_query("^main$").terms[0].type is TermType.EQUAL
    assert match_spans(parse_query("^src"), "src/app.py")
    assert match_spans(parse_query("^src"), "lib/src.py") is None
    assert match_spans(parse_query("py$"), "app.py")
    assert match_spans(parse_query("py$"), "py.app") is None


def test_exact_term():
    q = parse_query("'readme")
    assert q.terms[0].type is TermType.EXACT
    assert match_spans(q, "the_readme_file")
    assert match_spans(q, "the_reidme_file") is None


def test_smart_case():
    assert match_spans(parse_query("readme"), "README") is not None
    assert match_spans(parse_query("Readme"), "readme") is None
    assert match_spans(parse_query("Readme"), "Readme") is not None


def test_fuzzy_non_contiguous():
    res = match_spans(parse_query("mnf"), "main_function.py")
    assert res is not None
    _, spans = res
    assert spans == sorted(spans)


def test_contiguous_outranks_scattered():
    contig = match_spans(parse_query("main"), "main.py")
    scattered = match_spans(parse_query("main"), "m_a_i_n.py")
    assert contig[0] > scattered[0]


def test_empty_query():
    assert parse_query("").is_empty
    assert parse_query("   ").is_empty
    assert match_spans(parse_query(""), "anything") is None


def test_content_query_len():
    assert parse_query("a").content_query_len == 1
    assert parse_query("abc de").content_query_len == 3
    assert parse_query("!ab").content_query_len == 0
