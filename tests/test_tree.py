from rich.console import Console
from rich.text import Text

from seek.config import Config
from seek.tui.tree import render_tree


def _spans(text: Text) -> dict[str, str]:
    """word -> style string, from the rendered spans."""
    out = {}
    for span in text.spans:
        frag = text.plain[span.start : span.end].strip("/\n ")
        if frag:
            out[frag] = str(span.style)
    return out


def test_render_tree_is_styled_text(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("x\n")
    (tmp_path / "notes.md").write_text("y\n")
    (tmp_path / "data.bin").write_bytes(b"\x00")
    tree = render_tree(tmp_path, Config())
    assert isinstance(tree, Text)
    plain = tree.plain
    assert "src/" in plain and "app.py" in plain and "notes.md" in plain

    styles = _spans(tree)
    # directory coloured with the tree_dir style
    assert "blue" in styles.get("src", "")
    # python file gets the .py colour (green), markdown a different one
    assert styles.get("app.py") != styles.get("notes.md")
    assert "green" in styles.get("app.py", "")


def test_render_tree_prunes_and_truncates(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("x")
    (tmp_path / "node_modules").mkdir()
    for i in range(30):
        (tmp_path / f"f{i}.txt").write_text("x")
    tree = render_tree(tmp_path, Config(), max_entries=5)
    plain = tree.plain
    assert ".git" not in plain
    assert "node_modules" not in plain
    assert "truncated" in plain


def test_render_tree_renders_without_error(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.py").write_text("x\n")
    con = Console(width=40, file=open("/dev/null", "w"))
    con.print(render_tree(tmp_path, Config()))  # must not raise


def test_tree_honours_gitignore_when_the_heading_says_it_does(tmp_path):
    """The heading above this tree states the walk semantics in effect.

    The tree used to prune only `noise_dirs` - not `.gitignore`, not
    `exclude_globs` - so with `--gitignore` on it displayed files that a search
    from the same root would never return.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x")
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "artifact.js").write_text("x")
    (tmp_path / "run.log").write_text("x")
    (tmp_path / ".gitignore").write_text("build/\n*.log\n")

    shown = render_tree(tmp_path, Config(honor_gitignore=True)).plain
    assert "src/" in shown
    assert "build/" not in shown
    assert "run.log" not in shown

    ignored_off = render_tree(tmp_path, Config()).plain
    assert "build/" in ignored_off, "off by default, as the walk is"
    assert "run.log" in ignored_off


def test_tree_applies_exclude_globs(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "v.txt").write_text("x")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("x")

    shown = render_tree(tmp_path, Config(exclude_globs=["vendor"])).plain
    assert "vendor" not in shown
    assert "src/" in shown


def test_tree_does_not_enumerate_a_huge_directory_in_full(tmp_path):
    """Sorting the raw `scandir` iterator read every entry to display forty."""
    big = tmp_path / "many"
    big.mkdir()
    for i in range(6000):
        (big / f"f{i:05}.txt").write_text("")

    shown = render_tree(tmp_path, Config(), max_entries=40).plain
    assert shown.count("\n") < 60, "bounded by max_entries, not by the directory"
    assert "truncated" in shown
