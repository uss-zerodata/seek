"""Finding nmap, deriving privilege, reading a command, and reading a scope.

Nothing here runs a scan. The one thing that executes anything is `probe`,
which is pointed at stub scripts written into a temporary directory.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from seek.nmap import presets


def _stub(tmp_path: Path, name: str, body: str, mode: int = 0o755) -> Path:
    script = tmp_path / name
    script.write_text(body)
    script.chmod(mode)
    return script


# --- is nmap here -----------------------------------------------------------


def test_probe_reports_the_version_it_found(tmp_path, monkeypatch):
    _stub(tmp_path, "nmap", "#!/bin/sh\necho 'Nmap version 7.94 ( https://nmap.org )'\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    found = presets.probe()
    assert found.available and found.version == "7.94"
    assert found.label() == "⌁ nmap 7.94"


def test_probe_reports_absence_rather_than_raising(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))       # an empty directory
    found = presets.probe()
    assert not found.available
    assert "not on PATH" in found.reason
    assert found.label() == "⌁ nmap not found"


def test_probe_reports_a_program_that_cannot_be_executed(tmp_path, monkeypatch):
    _stub(tmp_path, "nmap", "#!/bin/sh\nexit 0\n", mode=0o644)
    monkeypatch.setenv("PATH", str(tmp_path))
    found = presets.probe()
    assert not found.available, "not executable is not available"


def test_probe_reports_a_failing_version_call(tmp_path, monkeypatch):
    _stub(tmp_path, "nmap", "#!/bin/sh\necho 'boom' >&2\nexit 3\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    found = presets.probe()
    assert not found.available and "boom" in found.reason


def test_probe_keeps_a_program_that_answers_with_nonsense(tmp_path, monkeypatch):
    """It is on the path and it runs; say what was odd rather than hiding it."""
    _stub(tmp_path, "nmap", "#!/bin/sh\necho 'hello'\n")
    monkeypatch.setenv("PATH", str(tmp_path))
    found = presets.probe()
    assert found.available and found.version is None
    assert "did not report an nmap version" in found.reason


# --- privileges -------------------------------------------------------------


@pytest.mark.parametrize("args,expected", [
    ("-sV --version-light -T4", False),
    ("-p- -sV -T4", False),
    ("--script vuln -sV", False),
    ("-sS -T4", True),
    ("-sU --top-ports 100", True),
    ("-sSU", True),
    ("-A", True),
    ("-O -sV", True),
    ("--traceroute", True),
    ("-sV --privileged", True),
    # host-discovery probes: raw ICMP/IP/UDP need root, connect()-based ones do not
    ("-sn -PE -PP", True),
    ("-sn -PU53,123", True),
    ("-sn -PO", True),
    ("-sn -PS22,80,445 -PA80", False),
    ("-Pn -sV", False),
    # `--script` says nothing on its own: most NSE scripts are ordinary
    # connections. Only the ones that build their own packets need root.
    ("-sV --script ssl-cert,http-title", False),
    ("-p{ports} --script auth", False),
    ("-p139,445 --script smb-vuln* --script-args smbuser=u,smbpass=p", False),
    ("--script broadcast-dhcp-discover", True),
    ("--script broadcast", True),
    ("--script ssh-hostkey,ipv6-ra-flood", True),
    # the `=` spelling is the same flag, and must classify the same way
    ("--script=vuln -sV", False),
    ("-p80 --script=broadcast-ping", True),
    ("--traceroute=x", True),
])
def test_privilege_is_derived_from_the_flags(args, expected):
    assert presets.needs_root(presets.parse_args(args)) is expected


def test_the_flags_that_made_it_privileged_can_be_named():
    args = presets.parse_args("-sS -O -T4")
    assert presets.privileged_labels(args) == "-sS, -O"
    pings = presets.parse_args("-sn -PE -PP -PS22 -PU53")
    assert presets.privileged_labels(pings) == "-PE, -PP, -PU53"
    scripted = presets.parse_args("-sV --script http-title,broadcast-ping")
    assert presets.privileged_labels(scripted) == "--script broadcast-ping"


def test_every_shipped_preset_parses():
    for name, args in presets.DEFAULT_PRESETS.items():
        parsed = presets.parse_args(args.replace(presets.PORTS_PLACEHOLDER, "22,80"))
        assert parsed, name


def test_no_shipped_preset_asks_for_root_just_because_it_runs_scripts():
    """`sudo -n` never prompts, so a needless elevation is a failed scan.

    The NSE presets that ship here - crt.sh lookups, vhost brute force, auth -
    are ordinary connections, and on a machine without passwordless sudo they
    must still run.
    """
    for name, args in presets.DEFAULT_PRESETS.items():
        parsed = presets.parse_args(args.replace(presets.PORTS_PLACEHOLDER, "22,80"))
        assert "--script" not in presets.privileged_labels(parsed), name


# --- the command ------------------------------------------------------------


def test_a_command_becomes_its_arguments():
    assert presets.parse_command("nmap -sV -T4") == ["-sV", "-T4"]
    assert presets.parse_command("  nmap   -p-   ") == ["-p-"]
    assert presets.parse_command("/usr/bin/nmap -sV") == ["-sV"]


@pytest.mark.parametrize("text,expected", [
    ("nmap -sV | tee out.txt", "|"),
    ("nmap -sV > out.txt", ">"),
    ("nmap -sV && echo done", "&"),
    ("nmap -sV; rm -rf /", ";"),
    ("nmap -sV $(whoami)", "$"),
    ("nmap -sV `id`", "`"),
])
def test_shell_metacharacters_are_refused_by_name(text, expected):
    """There is no shell, so passing these through would be silently wrong."""
    with pytest.raises(presets.CommandError) as caught:
        presets.parse_command(text)
    assert expected in str(caught.value)


def test_a_glob_is_not_refused():
    """`--script http-*` is meaningful to nmap and harmless without a shell."""
    assert "http-*" in presets.parse_command("nmap --script http-*")


def test_only_nmap_can_be_started():
    with pytest.raises(presets.CommandError) as caught:
        presets.parse_command("curl https://example.test")
    assert "only 'nmap'" in str(caught.value)


@pytest.mark.parametrize("flag", ["-oA out", "-oX out.xml", "-oN out.txt", "-oG out.gnmap"])
def test_output_flags_belong_to_the_app(flag):
    with pytest.raises(presets.CommandError) as caught:
        presets.parse_command(f"nmap -sV {flag}")
    assert "handled for you" in str(caught.value)


def test_an_unbalanced_quote_is_explained():
    with pytest.raises(presets.CommandError) as caught:
        presets.parse_command('nmap --script "vuln')
    assert "could not be read" in str(caught.value)


def test_an_empty_command_is_refused():
    with pytest.raises(presets.CommandError):
        presets.parse_command("   ")


# --- argv and output --------------------------------------------------------


def test_argv_is_the_command_the_review_screen_shows():
    argv = presets.build_argv("nmap", ["-sV"], ["10.0.0.1", "10.0.0.2"], "/scans/base")
    assert argv == ["nmap", "-sV", "-oA", "/scans/base", "10.0.0.1", "10.0.0.2"]


def test_elevation_is_non_interactive_and_wraps_the_command():
    argv = presets.build_argv("nmap", ["-sS"], ["10.0.0.1"], "/scans/base", elevate=True)
    assert argv[:3] == ["sudo", "-n", "nmap"], "-n never prompts for a password"


def test_the_output_base_names_the_preset_and_the_time():
    when = datetime(2026, 9, 3, 9, 43, 37)
    base = presets.output_base(Path("/scans"), "03 · Details, full TCP (-p-)", when)
    assert base == Path("/scans/nmap_03-details-full-tcp_2026-09-03_09-43-37")


def test_the_stamp_is_local_time():
    """It matches `date +%Y-%m-%d_%H-%M-%S`, so these filenames sort beside the
    ones a shell produced without anyone converting a timezone by eye."""
    when = datetime(2026, 9, 3, 9, 43, 37, tzinfo=UTC)
    base = presets.output_base(Path("/scans"), "quick", when)
    expected = when.astimezone().strftime("%Y-%m-%d_%H-%M-%S")
    assert base.name == f"nmap_quick_{expected}"


def test_a_parenthetical_is_left_out_of_the_slug():
    """A preset's brackets carry the flags and the caveats, which the name has
    already said - they make a filename longer without making it clearer."""
    assert presets.slug("03 · Details, full TCP (-p-)") == "03-details-full-tcp"
    assert presets.slug("Quick TCP (top 1000, versions)") == "quick-tcp"
    assert presets.slug("04 · Vuln, SMB shares (edit the credentials first)") == (
        "04-vuln-smb-shares")


def test_a_name_that_is_only_a_parenthetical_still_yields_a_stem():
    assert presets.slug("(-p-)") == "scan"
    assert presets.slug("") == "scan"


def test_the_stem_carries_no_characters_a_shell_would_argue_with():
    for name in ("03 · Details, full TCP (-p-)", "a/b\\c", "x  y", "«odd»"):
        stem = presets.slug(name)
        assert stem and all(c.isalnum() or c == "-" for c in stem), stem


def test_an_unwritable_directory_is_reported_before_anything_runs(tmp_path):
    assert presets.writable(tmp_path) is None
    assert "does not exist" in presets.writable(tmp_path / "nope")
    file_path = tmp_path / "a-file"
    file_path.touch()
    assert "not a directory" in presets.writable(file_path)
    if os.geteuid() != 0:                       # root can write anywhere
        locked = tmp_path / "locked"
        locked.mkdir(mode=0o500)
        assert "not writable" in presets.writable(locked)


# --- targets ----------------------------------------------------------------


def test_blank_lines_and_comments_are_not_targets():
    assert presets.parse_target("") is None
    assert presets.parse_target("   ") is None
    assert presets.parse_target("# staging is out of scope") is None


@pytest.mark.parametrize("line,kind,value,addresses", [
    ("10.0.0.5", "address", "10.0.0.5", 1),
    ("2001:db8::1", "address", "2001:db8::1", 1),
    ("10.0.0.0/24", "network", "10.0.0.0/24", 256),
    ("10.0.0.5/32", "network", "10.0.0.5/32", 1),
    ("10.0.0.1-20", "range", "10.0.0.1-20", 20),
    ("example.test", "host", "example.test", 1),
    ("sub.example.test.", "host", "sub.example.test.", 1),
])
def test_the_forms_a_scope_accepts(line, kind, value, addresses):
    target = presets.parse_target(line)
    assert (target.kind, target.value, target.addresses) == (kind, value, addresses)
    assert target.ok


def test_a_url_contributes_its_host_and_port():
    target = presets.parse_target("https://app.example.test:8443/admin")
    assert (target.kind, target.value, target.port) == ("url", "app.example.test", 8443)
    assert "8443" in target.note()


def test_a_url_without_a_port_still_gives_a_host():
    target = presets.parse_target("http://example.test/path")
    assert target.value == "example.test" and target.port is None


@pytest.mark.parametrize("line", [
    "10.0.0.300",
    "10.0.0.0/33",
    "not a host!",
    "10.0.0.20-1",
    "https://",
])
def test_a_line_that_is_not_a_target_is_marked_not_fatal(line):
    target = presets.parse_target(line)
    assert not target.ok and target.error


def test_a_scope_counts_what_it_can_use_and_keeps_what_it_cannot():
    scope = presets.Scope.parse(
        "10.0.0.0/24\n"
        "192.168.1.10\n"
        "example.test\n"
        "https://app.example.test:8443\n"
        "10.0.0.300\n"
        "# a comment\n"
        "\n"
    )
    assert len(scope.valid) == 4 and len(scope.invalid) == 1
    assert scope.addresses == 259
    assert scope.values() == ["10.0.0.0/24", "192.168.1.10", "example.test",
                              "app.example.test"]
    assert scope.ports == [8443]
    assert "1 invalid line(s)" in scope.summary()


def test_a_scope_of_nothing_has_no_targets():
    scope = presets.Scope.parse("\n# only comments\n")
    assert scope.valid == [] and scope.addresses == 0
