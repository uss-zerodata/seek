"""A single huge file must not be read into memory in full."""

from __future__ import annotations

from pathlib import Path

from seek.config import Config
from seek.engine.content import ContentCache


def test_oversized_text_file_is_read_only_up_to_the_cap(tmp_path):
    p = tmp_path / "big.log"
    p.write_text("".join(f"line {i}\n" for i in range(200_000)))
    assert p.stat().st_size > 100_000

    cache = ContentCache(10_000_000, size_cap=20_000)
    lines = cache.lines(p)
    assert lines is not None
    total = sum(len(x) + 1 for x in lines)
    assert total <= 20_000
    assert lines[0] == "line 0"


def test_truncation_drops_the_partial_final_line(tmp_path):
    p = tmp_path / "big.txt"
    # 40 chars per line; a 1,000-byte cap lands mid-line
    p.write_text("".join(f"{'x' * 38}{i:02d}\n" for i in range(100)))
    cache = ContentCache(10_000_000, size_cap=1_001)
    lines = cache.lines(p)
    assert lines
    # every returned line is whole
    assert all(len(x) == 40 for x in lines)


def test_a_cap_landing_on_a_newline_keeps_the_whole_line(tmp_path):
    p = tmp_path / "exact.txt"
    p.write_text("".join(f"{'y' * 9}\n" for i in range(100)))  # 10 bytes per line
    cache = ContentCache(10_000_000, size_cap=9_000 + 8192)
    lines = cache.lines(p)
    assert all(x == "y" * 9 for x in lines)


def test_large_binary_is_rejected_after_the_header_read(tmp_path, monkeypatch):
    p = tmp_path / "blob.bin"
    p.write_bytes(b"\x00" * 4 + b"z" * 5_000_000)

    reads: list[int] = []
    real_open = Path.open

    class CountingFile:
        def __init__(self, fh):
            self._fh = fh

        def read(self, n=-1):
            data = self._fh.read(n)
            reads.append(len(data))
            return data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._fh.close()
            return False

    def fake_open(self, *args, **kwargs):
        return CountingFile(real_open(self, *args, **kwargs))

    monkeypatch.setattr(Path, "open", fake_open)
    cache = ContentCache(10_000_000)
    assert cache.lines(p) is None
    # exactly one read, of the sniff header - never the 5 MB body
    assert len(reads) == 1
    assert reads[0] <= 8192


def test_normal_file_is_unaffected(tmp_path):
    p = tmp_path / "small.py"
    p.write_text("import os\nvalue = 1\n")
    cache = ContentCache(10_000_000, size_cap=Config().content_size_cap)
    assert cache.lines(p) == ["import os", "value = 1"]


def test_config_default_and_override():
    assert Config().content_size_cap == 5 * 1024 * 1024
    assert Config(content_size_cap=1024).content_size_cap == 1024
