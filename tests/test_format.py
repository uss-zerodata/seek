"""The re-indenters: never lose content, never raise, never split inside a string."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from seek.config import Config
from seek.engine.format import (
    format_lines,
    reflow_braces,
    reflow_tags,
    should_format,
)


def _dense(s: str) -> str:
    """Everything but whitespace, for the content-preservation invariant."""
    return re.sub(r"\s+", "", s)


# --- content preservation ---------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"a":{"b":[1,2,3],"c":"x"},"d":[0,1,2]}',
        '{"s":"a,b{c}d","n":1}',
        '[{"k":"v"},{"k":"w"}]',
        '{"esc":"he said \\"hi\\", then {left}","n":2}',
        '{"a": [1,2,3',
        "",
        "no structure at all",
    ],
)
def test_reflow_braces_preserves_every_non_space_character(text):
    assert _dense("".join(reflow_braces(text))) == _dense(text)


@pytest.mark.parametrize(
    "text",
    [
        "<root><item id='1'><n>a</n></item></root>",
        '<a title="a>b">t</a>',
        "<div><p>hello<br><span>x",
        "<?xml version='1.0'?><r><c/></r>",
        "",
        "plain text",
    ],
)
def test_reflow_tags_preserves_every_non_space_character(text):
    assert _dense("".join(reflow_tags(text))) == _dense(text)


# --- the specific traps -----------------------------------------------------


def test_structural_characters_inside_a_string_are_not_break_points():
    out = reflow_braces('{"s":"a,b{c}d","n":1}')
    assert any('"s":"a,b{c}d",' == line.strip() for line in out), out


def test_escaped_quote_does_not_end_the_string():
    out = reflow_braces('{"s":"he said \\"a,b\\" ok","n":1}')
    joined = "".join(out)
    assert '\\"a,b\\"' in joined


def test_gt_inside_an_attribute_does_not_end_the_tag():
    out = reflow_tags('<a title="a>b">t</a>')
    assert '<a title="a>b">' in out[0]


def test_closing_tags_reduce_depth():
    out = reflow_tags("<root><a><b>x</b></a></root>")
    indents = [len(line) - len(line.lstrip()) for line in out]
    assert indents[0] == 0
    assert max(indents) > 0
    assert out[-1].strip() == "</root>"
    assert indents[-1] == 0


def test_self_closing_and_declaration_tags_do_not_nest():
    out = reflow_tags("<?xml version='1.0'?><r><c/><c/></r>")
    assert out[-1].strip() == "</r>"
    assert (len(out[-1]) - len(out[-1].lstrip())) == 0


# --- error resistance -------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        '{"a": [1,2,3',            # truncated
        '{"a":1} // trailing',     # comment
        '{"a":1}\n{"a":2}',        # jsonl
        '{"unterminated": "abc',   # unterminated string
        "<div><p>hello<br>",       # unclosed markup
        "}]}]}]",                  # only closers
        "\x00\x01binary-ish",
        "",
    ],
)
def test_malformed_input_never_raises(text):
    assert isinstance(reflow_braces(text), list)
    assert isinstance(reflow_tags(text), list)


def test_json_and_minidom_would_have_raised_where_we_do_not():
    """Documents why parsing was rejected: these are ordinary tree contents."""
    import xml.dom.minidom

    for bad in ('{"a": [1,2,3', "<div><p>x"):
        with pytest.raises(Exception):  # noqa: B017, PT011
            json.loads(bad)
        with pytest.raises(Exception):  # noqa: B017, PT011
            xml.dom.minidom.parseString(bad)
        assert reflow_braces(bad)
        assert reflow_tags(bad)


# --- the gate and the origin map -------------------------------------------


def _cfg(**kw) -> Config:
    return Config(**kw)


def test_minified_json_is_broken_up():
    blob = json.dumps({"users": [{"id": i, "n": f"u{i}"} for i in range(60)]})
    assert len(blob) > 500
    lines, origin = format_lines([blob], Path("d.json"), _cfg())
    assert len(lines) > 50
    assert max(len(x) for x in lines) < 100
    assert origin == [1] * len(lines)


def test_short_lines_pass_through_untouched_and_map_to_themselves():
    raw = ['{"a": 1}', '{"b": 2}']
    lines, origin = format_lines(raw, Path("d.json"), _cfg())
    assert lines == raw
    assert origin is None  # nothing was reformatted, line numbers are exact


def test_mixed_file_keeps_short_lines_and_maps_the_long_one():
    long = json.dumps({"k": ["v" * 40 for _ in range(40)]})
    raw = ["first", long, "last"]
    lines, origin = format_lines(raw, Path("d.json"), _cfg())
    assert lines[0] == "first"
    assert lines[-1] == "last"
    assert origin[0] == 1
    assert origin[-1] == 3
    assert set(origin[1:-1]) == {2}, "every piece maps back to the long line"
    assert len(origin) == len(lines)


def test_unlisted_extension_is_untouched():
    long_line = "x" * 5000
    lines, origin = format_lines([long_line], Path("code.py"), _cfg())
    assert lines == [long_line]
    assert origin is None


def test_disabled_by_config():
    blob = json.dumps({"a": ["b" * 40 for _ in range(40)]})
    lines, origin = format_lines([blob], Path("d.json"), _cfg(format_content=False))
    assert lines == [blob]
    assert origin is None


def test_threshold_is_respected():
    line = "[" + ",".join(str(i) for i in range(100)) + "]"
    assert 200 < len(line) < 500
    untouched, o1 = format_lines([line], Path("d.json"), _cfg())
    assert untouched == [line] and o1 is None
    split, o2 = format_lines([line], Path("d.json"), _cfg(format_min_line=100))
    assert len(split) > 1 and o2 is not None


def test_extension_set_is_configurable():
    long_line = "{" + ",".join(f'"k{i}":{i}' for i in range(200)) + "}"
    assert not should_format(Path("a.conf"), _cfg())
    cfg = _cfg(format_extensions=["conf"])
    assert should_format(Path("a.conf"), cfg)
    # ...but there is no re-indenter for `.conf`, so it is still left alone
    lines, origin = format_lines([long_line], Path("a.conf"), cfg)
    assert lines == [long_line] and origin is None


def test_xml_file_uses_the_tag_reindenter():
    doc = "<root>" + "".join(f"<i id='{i}'>v{i}</i>" for i in range(80)) + "</root>"
    lines, origin = format_lines([doc], Path("d.xml"), _cfg())
    assert len(lines) > 80
    assert lines[0].strip() == "<root>"
    assert origin == [1] * len(lines)


def test_origin_length_always_matches_lines():
    doc = "<a>" + "".join(f"<b>{i}</b>" for i in range(100)) + "</a>"
    lines, origin = format_lines(["short", doc], Path("d.html"), _cfg())
    assert origin is not None
    assert len(origin) == len(lines)
    assert all(1 <= o <= 2 for o in origin)
