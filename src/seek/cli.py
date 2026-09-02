"""Command-line entry point.

``seek [options] [patterns...]`` launches the interactive session.
``seek init <bash|zsh>`` prints shell-integration code.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from seek.config import ConfigError, load_config
from seek.engine.engine import Modes
from seek.paths import config_file
from seek.scope import ScopeError, build_scope
from seek.session import SessionConfig
from seek.shell import SUPPORTED_SHELLS, render_init

app = typer.Typer(
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Interactive terminal search for files, directories, and file contents.",
)

_KNOWN_SUBCOMMANDS = {"search", "init", "nmap"}


@app.command()
def init(
    shell: Annotated[str, typer.Argument(help="Target shell: bash or zsh")],
) -> None:
    """Print shell-integration code for ``eval "$(seek init <shell>)"``."""
    key = shell.strip().lower()
    if key not in SUPPORTED_SHELLS:
        supported = ", ".join(sorted(SUPPORTED_SHELLS))
        typer.echo(f"seek: unsupported shell {shell!r}; supported: {supported}", err=True)
        raise typer.Exit(code=2)
    typer.echo(render_init(key))


@app.command()
def nmap(
    paths: Annotated[
        list[Path] | None,
        typer.Argument(help="nmap XML files, or directories containing them."),
    ] = None,
) -> None:
    """Browse one or more nmap XML scans, consolidated.

    Stateless: the files given are read straight into memory for this run, with
    no import step and nothing written.
    """
    from seek.nmap.merge import load
    from seek.nmap.views import prepare

    if not paths:
        typer.echo(
            "seek nmap: give one or more nmap XML files, or a directory of them.\n"
            "  seek nmap scan.xml\n"
            "  seek nmap scans/\n"
            "  seek nmap discovery.xml services.xml",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        config = load_config()
    except ConfigError as exc:
        # Surface it, exactly as `search` does: a typo in the config must not be
        # swallowed into a silent fall-back to defaults, which reads to the user
        # as "my edits are being ignored".
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None
    scans = prepare(load(list(paths)))
    for name, message in scans.failures:
        typer.echo(f"seek: skipped {name}: {message}", err=True)

    # A directory with nothing in it yet is the case for *starting* a scan, so
    # it is only an error when no scan can be started.
    from seek.nmap.presets import probe

    nmap = probe(config.nmap_path)
    if not scans.hosts and not scans.sources and not nmap.available:
        typer.echo("seek: no readable nmap output in the given paths", err=True)
        typer.echo(f"seek: and no scan can be started here ({nmap.reason})", err=True)
        raise typer.Exit(code=1)

    if not _stdout_is_usable():
        typer.echo("seek: requires an interactive terminal", err=True)
        raise typer.Exit(code=1)

    from seek.tui.nmap.app import run_viewer

    first = Path(paths[0])
    scan_dir = first if first.is_dir() else Path.cwd()
    # The paths given are the sources: a directory keeps covering whatever a
    # scan writes into it, so a finished run needs no special case.
    raise typer.Exit(code=run_viewer(scans, config, sources=[Path(p) for p in paths],
                                     scan_dir=scan_dir))


_OTHER_COMMANDS = (
    "Other commands (run `seek <command> --help`):\n"
    "  seek nmap <files|dir>   browse or run nmap scans\n"
    "  seek init <bash|zsh>    print shell-integration code"
)


@app.command(epilog=_OTHER_COMMANDS)
def search(
    patterns: Annotated[
        list[str] | None,
        typer.Argument(help="Glob (or regex with -r) patterns scoping the walk."),
    ] = None,
    file: Annotated[bool, typer.Option("-f", "--file", help="Search filenames.")] = False,
    directory: Annotated[
        bool, typer.Option("-d", "--directory", help="Search directory names.")
    ] = False,
    content: Annotated[
        bool, typer.Option("-c", "--content", help="Search file contents.")
    ] = False,
    regex: Annotated[
        bool, typer.Option("-r", "--regex", help="Treat patterns as regexes.")
    ] = False,
    gitignore: Annotated[
        bool | None,
        typer.Option("--gitignore/--no-gitignore", help="Honor .gitignore/.ignore."),
    ] = None,
    config_path: Annotated[
        bool, typer.Option("--config-path", help="Print the config file path and exit.")
    ] = False,
    init_config: Annotated[
        bool,
        typer.Option(
            "--init-config",
            help="Write a starter config to the config path (won't overwrite an "
            "existing one) and exit.",
        ),
    ] = False,
) -> None:
    """Launch the interactive search session (default command)."""
    if config_path:
        typer.echo(str(config_file()))
        raise typer.Exit()
    if init_config:
        raise typer.Exit(code=_write_starter_config())

    try:
        cfg = load_config()
    except ConfigError as exc:
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None
    cfg = cfg.with_overrides(honor_gitignore=gitignore)

    try:
        scope = build_scope(patterns or [], regex=regex)
    except ScopeError as exc:
        typer.echo(f"seek: {exc}", err=True)
        raise typer.Exit(code=2) from None

    modes = Modes.resolve((file, directory, content))

    if not _stdout_is_usable():
        typer.echo("seek: requires an interactive terminal", err=True)
        raise typer.Exit(code=1)

    session = SessionConfig(
        root=Path.cwd(),
        modes=modes,
        scope=scope,
        config=cfg,
        regex=regex,
        patterns=list(patterns or []),
    )
    from seek.tui.app import run_session

    raise typer.Exit(code=run_session(session))


def _write_starter_config() -> int:
    """Install a starter config at the standard path, without clobbering one.

    The shipped `config.example.toml` is only a template inside the package -
    editing it changes nothing, because the app reads the per-user path below.
    This writes that template where the app will actually read it.
    """
    from seek.config import example_toml

    dest = config_file()
    if dest.exists():
        typer.echo(f"seek: a config already exists at {dest}", err=True)
        typer.echo("seek: edit it, or delete it and run --init-config again", err=True)
        return 1
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(example_toml(), encoding="utf-8")
    except OSError as exc:
        typer.echo(f"seek: could not write {dest}: {exc.strerror or exc}", err=True)
        return 1
    typer.echo(f"seek: wrote a starter config to {dest}")
    typer.echo("seek: edit it and run seek again to pick up the changes")
    return 0


def _stdout_is_usable() -> bool:
    """The interactive UI needs a real terminal on stdout (and stdin)."""
    return sys.stdout.isatty() and sys.stdin.isatty()


def main() -> None:
    # `search` is the default command; anything that is not another subcommand is
    # handed to it - including a bare `-h`/`--help`, so the main help screen is
    # the search command's own (every option visible) rather than a bare list of
    # subcommands that hides them. The other commands are named in search's
    # epilog, so nothing is lost.
    argv = sys.argv[1:]
    if not argv or argv[0] not in _KNOWN_SUBCOMMANDS:
        argv = ["search", *argv]
    app(argv)
