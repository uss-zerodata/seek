"""`rebase()` re-expresses a completed walk as if rooted elsewhere."""

from __future__ import annotations

from pathlib import Path

from seek.config import Config
from seek.models import Candidate
from seek.scope import build_scope
from seek.walk import rebase, walk


def _c(rel: str, is_dir: bool = False) -> Candidate:
    return Candidate(path=Path("/r") / rel, is_dir=is_dir, rel=rel)



def test_rebase_empty_root_returns_everything():
    base = [_c("a"), _c("b/c")]
    assert [x.rel for x in rebase(base, "")] == ["a", "b/c"]


def test_rebase_strips_the_prefix_and_drops_outsiders():
    base = [_c("src", True), _c("src/main.py"), _c("src/lib/u.py"), _c("docs/x.md")]
    out = rebase(base, "src")
    assert [x.rel for x in out] == ["main.py", "lib/u.py"]
    # the new root itself is not one of its own candidates
    assert all(x.rel for x in out)


def test_rebase_keeps_path_and_kind_and_recomputes_name():
    base = [_c("src/lib/util.py"), _c("src/pkg", True)]
    out = rebase(base, "src")
    assert out[0].path == _c("src/lib/util.py").path
    assert out[0].name == "util.py"
    assert out[1].is_dir is True


def test_rebase_does_not_match_a_partial_directory_name():
    base = [_c("src/a.py"), _c("srcextra/b.py")]
    assert [x.rel for x in rebase(base, "src")] == ["a.py"]


def test_rebase_matches_a_real_walk(tmp_path):
    (tmp_path / "src" / "lib").mkdir(parents=True)
    (tmp_path / "src" / "main.py").write_text("x\n")
    (tmp_path / "src" / "lib" / "u.py").write_text("y\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "r.md").write_text("z\n")
    cfg, scope = Config(), build_scope([], regex=False)

    base = list(walk(tmp_path, cfg, scope))
    fresh = list(walk(tmp_path / "src", cfg, scope))
    assert sorted(x.rel for x in rebase(base, "src")) == sorted(x.rel for x in fresh)


