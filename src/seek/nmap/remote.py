"""A planned command as text, for a person to paste - here or on another machine.

The command box is not a shell, and nothing seek *executes* is ever joined into
a string. This module is the other direction: text a person copies into a shell
of their own, so `shlex.join` is the correct tool here and nowhere else.

The remote form is built by the same argv builders the local run uses, with the
program named bare, the paths relative and no container wrapper, so the two
forms cannot disagree about a flag. Nothing of this machine - its paths, its
user, its scan directory - is in it.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from seek.gowitness import capture as gw_capture
from seek.gowitness.detect import Probe
from seek.gowitness.results import canonical_url
from seek.nmap import presets

URLS_END = "SEEK_URLS"
"""The heredoc delimiter. A URL never is this bare word, so it cannot end the
list early."""


def local_text(argv: list[str]) -> str:
    """The exact argv this machine would run, as one shell line."""
    return shlex.join(argv)


def nmap_snippet(scan_args: list[str], targets: list[str], out_name: str) -> str:
    """The scan for a machine with only nmap: bare program, relative `-oA`, and
    an interactive `sudo` when the flags need root - whoever runs seek here."""
    argv = presets.build_argv("nmap", scan_args, targets, out_name)
    if presets.needs_root(scan_args):
        argv = ["sudo", *argv]
    return shlex.join(argv) + "\n"


def capture_snippet(urls: list[str], *, collect_all: bool = True,
                    settle_ms: int = 2000, settle_cap_ms: int = 20000) -> str:
    """The capture for a machine with only gowitness: it writes its own URL list
    and puts everything under `gowitness/`, the directory discovery looks for."""
    paths = gw_capture.Paths(Path(gw_capture.CAPTURE_DIRNAME))
    argv = gw_capture.scan_argv(Probe(backend="native", path="gowitness"), paths,
                                collect_all=collect_all, settle_ms=settle_ms,
                                settle_cap_ms=settle_cap_ms)
    written = list(dict.fromkeys(canonical_url(u) for u in urls))
    return "\n".join([
        f"mkdir -p {shlex.quote(str(paths.shots))}",
        f"cat > {shlex.quote(str(paths.urls))} <<'{URLS_END}'",
        *written,
        URLS_END,
        shlex.join(argv),
    ]) + "\n"
