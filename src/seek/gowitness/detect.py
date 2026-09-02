"""Is gowitness here, and which way.

Mirrors `nmap/presets.py:probe()` in shape and in rule: look once at startup,
never raise, absence is an answer. The difference is that gowitness has two
ways of being present, and which one is in use is worth saying out loud - a
containerised run starts slower, and writes files owned by root.

**A docker client is not a docker backend.** `shutil.which("docker")` finding
the binary says nothing about whether the daemon is running, and a dead daemon
is the common broken case. Availability therefore means `docker info` answering,
which is the same question the first capture would ask, asked early enough to
disable the feature instead of failing at the keystroke.

The image is deliberately **not** pulled here: it is a several-hundred-megabyte
download, and doing it during startup detection would hang the viewer with no
way to report why. The first capture pulls it, where the progress can be
streamed into the run log like any other output.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_IMAGE = "ghcr.io/sensepost/gowitness"
MODES = ("auto", "docker", "native")

_PROBE_TIMEOUT = 5.0


@dataclass(slots=True)
class Probe:
    """What was found when we looked for gowitness."""

    backend: str | None = None       # "docker" | "native"
    path: str | None = None          # the docker binary, or the gowitness binary
    image: str | None = None         # only for the docker backend
    reason: str | None = None        # why it is unavailable, when it is

    @property
    def available(self) -> bool:
        return self.backend is not None

    def label(self) -> str:
        """One line for the status bar - a symbol and words, never colour alone."""
        if self.available:
            return f"◉ gowitness {self.backend}"
        return "◉ gowitness not found"


def _docker_usable(docker: str) -> str | None:
    """`None` when the daemon answers, otherwise why it does not."""
    try:
        done = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=_PROBE_TIMEOUT, check=False,
        )
    except OSError as exc:
        return f"{docker} could not be run: {exc.strerror or exc}"
    except subprocess.SubprocessError:
        return f"{docker} info did not answer in {_PROBE_TIMEOUT:.0f}s"
    if done.returncode != 0:
        first = (done.stderr or done.stdout).strip().splitlines()
        return first[0][:120] if first else "the docker daemon did not answer"
    return None


def _try_docker(image: str, docker_path: str = "docker") -> Probe:
    docker = shutil.which(docker_path)
    if docker is None:
        return Probe(reason="docker is not on PATH")
    failure = _docker_usable(docker)
    if failure is not None:
        return Probe(reason=failure)
    return Probe(backend="docker", path=docker, image=image)


def _try_native(program: str) -> Probe:
    path = shutil.which(program)
    if path is None:
        return Probe(reason=f"{program} is not on PATH")
    return Probe(backend="native", path=path)


def probe(mode: str = "auto", program: str = "gowitness",
          image: str = DEFAULT_IMAGE) -> Probe:
    """Look for gowitness once, at startup.

    `auto` prefers docker and falls back to the native binary. A pinned mode
    never falls back: silently running the other backend would hide the very
    thing the setting was used to express.
    """
    if mode == "docker":
        found = _try_docker(image)
        if not found.available:
            found.reason = f"docker was pinned, but {found.reason}"
        return found
    if mode == "native":
        found = _try_native(program)
        if not found.available:
            found.reason = f"native was pinned, but {found.reason}"
        return found

    docker = _try_docker(image)
    if docker.available:
        return docker
    native = _try_native(program)
    if native.available:
        return native
    return Probe(reason=f"{docker.reason}, and {native.reason}")
