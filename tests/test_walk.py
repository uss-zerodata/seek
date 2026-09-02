from pathlib import Path

from seek.config import Config
from seek.scope import build_scope
from seek.walk import walk


def _rels(root: Path, config: Config, scope=None) -> set[str]:
    scope = scope or build_scope([], regex=False)
    return {c.rel for c in walk(root, config, scope)}


def test_hidden_included_git_and_noise_excluded(tree):
    rels = _rels(tree, Config())
    assert ".hidden" in rels
    assert not any(r.startswith(".git/") or r == ".git" for r in rels)
    assert not any(r.startswith("node_modules") for r in rels)


def test_gitignore_not_applied_by_default(tree):
    rels = _rels(tree, Config())
    assert "build/artifact.js" in rels
    assert "run.log" in rels


def test_gitignore_applied_when_enabled(tree):
    rels = _rels(tree, Config(honor_gitignore=True))
    assert "build/artifact.js" not in rels
    assert "run.log" not in rels
    assert "src/main.py" in rels


def test_noise_dir_walked_when_disabled(tree):
    rels = _rels(tree, Config(apply_noise_excludes=False))
    assert "node_modules/pkg.js" in rels


def test_exclude_glob(tree):
    rels = _rels(tree, Config(exclude_globs=["*.txt"]))
    assert "notes.txt" not in rels
    assert "src/main.py" in rels


def test_symlink_loop_terminates(symlink_loop):
    rels = _rels(symlink_loop, Config())
    assert "a/file.txt" in rels
    assert not any("loop/a/loop" in r for r in rels)


def test_scope_basename_glob(tree):
    rels = _rels(tree, Config(), build_scope(["*.py"], regex=False))
    assert rels == {"src/main.py", "src/helper.py"}


def test_scope_path_glob(tree):
    rels = _rels(tree, Config(), build_scope(["src/*.py"], regex=False))
    assert rels == {"src/main.py", "src/helper.py"}


def test_scope_regex(tree):
    rels = _rels(tree, Config(), build_scope([r"README"], regex=True))
    assert "docs/README.md" in rels
    assert "src/main.py" not in rels


def test_unreadable_dir_skipped(tmp_path):
    import os
    import sys

    if sys.platform == "win32" or os.geteuid() == 0:
        return
    bad = tmp_path / "locked"
    bad.mkdir()
    (bad / "inside.txt").write_text("x")
    (tmp_path / "ok.txt").write_text("y")
    bad.chmod(0o000)
    try:
        rels = _rels(tmp_path, Config())
        assert "ok.txt" in rels
    finally:
        bad.chmod(0o755)


def test_gitignore_does_not_leak_into_a_sibling_directory(tmp_path):
    """A `.gitignore` governs its own subtree and nothing else.

    The layer stack used to be popped by the slash count of each layer's path,
    which never dropped a sibling at the same depth - so rules from the
    directory walked first suppressed files in the one walked after it. The
    walk pops in reverse-alphabetical order, so `zz` is visited before `aa`.
    """
    (tmp_path / "zz").mkdir()
    (tmp_path / "aa").mkdir()
    (tmp_path / "zz" / ".gitignore").write_text("secret.txt\n")
    (tmp_path / "zz" / "secret.txt").write_text("x")
    (tmp_path / "aa" / "secret.txt").write_text("x")

    rels = _rels(tmp_path, Config(honor_gitignore=True))
    assert "zz/secret.txt" not in rels, "the rule must apply where it was written"
    assert "aa/secret.txt" in rels, "a sibling has no rules of its own"


def test_gitignore_does_not_leak_between_cousins(tmp_path):
    """Nor does a nested layer reach a directory beside its parent."""
    (tmp_path / "zz" / "deep").mkdir(parents=True)
    (tmp_path / "aa" / "deep").mkdir(parents=True)
    (tmp_path / "zz" / "deep" / ".gitignore").write_text("k.txt\n")
    (tmp_path / "zz" / "deep" / "k.txt").write_text("x")
    (tmp_path / "aa" / "deep" / "k.txt").write_text("x")

    rels = _rels(tmp_path, Config(honor_gitignore=True))
    assert "zz/deep/k.txt" not in rels
    assert "aa/deep/k.txt" in rels


def test_gitignore_layers_still_nest(tmp_path):
    """The root layer keeps applying below it, and a nested one adds to it."""
    (tmp_path / "a" / "deep").mkdir(parents=True)
    (tmp_path / ".gitignore").write_text("*.log\n")
    (tmp_path / "a" / ".gitignore").write_text("*.tmp\n")
    (tmp_path / "a" / "deep" / "x.tmp").write_text("x")
    (tmp_path / "a" / "deep" / "y.log").write_text("x")
    (tmp_path / "a" / "deep" / "z.txt").write_text("x")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "w.tmp").write_text("x")

    rels = _rels(tmp_path, Config(honor_gitignore=True))
    assert "a/deep/x.tmp" not in rels, "the nested layer applies below itself"
    assert "a/deep/y.log" not in rels, "the root layer still applies"
    assert "a/deep/z.txt" in rels
    assert "b/w.tmp" in rels, "the nested layer does not reach a sibling"
