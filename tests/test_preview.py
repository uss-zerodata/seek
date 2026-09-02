from rich.console import Console

from seek.config import Config
from seek.engine.content import ContentCache
from seek.engine.query import parse_query
from seek.models import MatchKind, Result
from seek.tui.preview import _render_window, build_preview, load_file


def _render(renderable, width=100) -> str:
    con = Console(width=width, file=open("/dev/null", "w"), record=True)
    con.print(renderable)
    return con.export_text()


def _r(kind, path, line=None):
    return Result(kind=kind, path=path, rel=path.name, score=1, line_no=line)


def test_large_file_truncated_in_side_preview(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("\n".join(f"line {i}" for i in range(200_000)))
    cfg = Config(preview_size_cap=4096)
    out = _render(build_preview(_r(MatchKind.FILENAME, big), cfg, full=False))
    assert "truncated" in out


def test_large_file_truncated_in_detail_view(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x\n" * 4_000_000)  # ~8MB
    cfg = Config(detail_size_cap=1_000_000)
    out = _render(build_preview(_r(MatchKind.FILENAME, big), cfg, full=True))
    assert "truncated" in out


def test_binary_file_preview(tmp_path):
    b = tmp_path / "x.bin"
    b.write_bytes(b"\x00\x01\x02rubbish")
    out = _render(build_preview(_r(MatchKind.FILENAME, b), Config(), full=False))
    assert "binary" in out


def test_content_preview_windows_on_line(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("\n".join(f"row{i}" for i in range(1000)))
    cfg = Config(preview_window_lines=20)
    out = _render(build_preview(_r(MatchKind.CONTENT, f, 500), cfg, full=False))
    assert "row500" in out
    assert "row0" not in out


def test_query_match_highlighted_in_preview(tmp_path):
    f = tmp_path / "code.py"
    f.write_text("first line\nsecond needle line\nthird\nanother needle\n")
    win = _render_window(
        f.read_text().splitlines(), 1, 4, target=2,
        query=parse_query("needle"), match_style="bold yellow",
    )
    styled_text = "".join(
        seg.text
        for seg in win.render(Console())
        if seg.style and "yellow" in str(seg.style)
    )
    # every occurrence of the query on visible lines is highlighted
    assert styled_text == "needle" * 2


def test_directory_preview_is_a_tree(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("hi")
    out = _render(build_preview(_r(MatchKind.DIRNAME, tmp_path), Config(), full=False))
    assert "a.txt" in out


# --- the preview reads what the index read -----------------------------------


def _content_result(path, line_no=1):
    return Result(kind=MatchKind.CONTENT, path=path, rel=path.name, score=1,
                  line_no=line_no, line_text="x", view_line=line_no)


def test_preview_reuses_the_content_cache_when_it_has_the_file(tmp_path):
    """The search has already read and re-indented the file; do not redo it.

    On a multi-megabyte file that repeated work was essentially the whole cost
    of building a preview, paid again on every press of an arrow key.
    """
    f = tmp_path / "f.py"
    f.write_text("\n".join(f"line {i}" for i in range(500)))
    cfg = Config()
    cache = ContentCache(1 << 24, cfg.content_size_cap, cfg)
    cache.content(f)  # as a content search would have

    assert (
        load_file(_content_result(f, 10), cfg, full=False, cache=cache).lines
        == load_file(_content_result(f, 10), cfg, full=False).lines
    )


def test_preview_falls_back_to_disk_on_a_cache_miss(tmp_path):
    f = tmp_path / "f.py"
    f.write_text("hello\nworld\n")
    cfg = Config()
    empty = ContentCache(1 << 24, cfg.content_size_cap, cfg)
    assert load_file(_content_result(f), cfg, full=False, cache=empty).lines == [
        "hello", "world"
    ]


def test_a_capped_preview_never_shows_a_half_line(tmp_path):
    """At the size cap the index drops the trailing fragment; the preview must too.

    Reading independently, the preview kept the partial line the cap landed in
    the middle of and displayed it as if it were a real line of the file.
    """
    f = tmp_path / "big.txt"
    f.write_text("\n".join(f"line number {i:06}" for i in range(4000)))
    cfg = Config(content_size_cap=4096, preview_size_cap=4096)
    cache = ContentCache(1 << 24, 4096, cfg)
    indexed, _origin = cache.content(f)

    view = load_file(_content_result(f), cfg, full=False, cache=cache)
    assert view.lines == indexed, "the preview shows exactly the indexed text"
    assert view.truncated, "and still says it was cut short"
    assert "truncated at 4 KiB" in view.truncation_note.plain
