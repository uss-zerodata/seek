"""What to run, and whether it can be run.

Everything a scan needs before a process exists: is nmap here, what does a
preset expand to, does it need root, what does the user's edited command parse
to, where does the output go, and what is a target.

Pure: no Textual, no process supervision (that is `runner.py`). The one thing it
does execute is `nmap --version`, which is how "is nmap here" is answered.

**The command text is never given to a shell.** It is split with shell-like word
rules and executed as an argument vector, so an edited command is an argument
list, not a script. Text that would only mean something to a shell is refused by
name rather than passed through - see `parse_command`.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import shutil
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

# --- is nmap here -----------------------------------------------------------


@dataclass(slots=True)
class Probe:
    """What was found when we looked for nmap."""

    path: str | None = None
    version: str | None = None
    reason: str | None = None
    # The binary has the file capabilities for raw sockets: a privileged scan
    # runs as the user with `--privileged`, and needs no sudo.
    capable: bool = False

    @property
    def available(self) -> bool:
        return self.path is not None

    def label(self) -> str:
        """One line for the status bar - a symbol and words, never colour alone."""
        if self.available:
            return f"⌁ nmap {self.version}" if self.version else "⌁ nmap"
        return "⌁ nmap not found"


_VERSION = re.compile(r"\bversion\s+(\S+)", re.I)


def probe(program: str = "nmap") -> Probe:
    """Look for nmap once, at startup. Never raises: absence is an answer."""
    path = shutil.which(program)
    if path is None:
        return Probe(reason=f"{program} is not on PATH")
    try:
        done = subprocess.run(  # noqa: S603 - a fixed argv, no shell
            [path, "--version"], capture_output=True, text=True, timeout=5, check=False
        )
    except OSError as exc:
        return Probe(reason=f"{path} could not be run: {exc.strerror or exc}")
    except subprocess.SubprocessError as exc:
        return Probe(reason=f"{path} did not answer --version: {exc}")
    if done.returncode != 0:
        first = (done.stderr or done.stdout).strip().splitlines()
        detail = first[0] if first else f"exit {done.returncode}"
        return Probe(reason=f"{path} --version failed: {detail}")
    match = _VERSION.search(done.stdout)
    # A program that answers --version with something else is still not nmap we
    # can reason about, but it is on the path and runnable - say what we saw.
    return Probe(path=path, version=match.group(1) if match else None,
                 reason=None if match else f"{path} did not report an nmap version",
                 capable=raw_capable(path))


_CAP_NET_ADMIN, _CAP_NET_RAW = 12, 13
_VFS_CAP_FLAGS_EFFECTIVE = 0x1


def raw_capable(path: str) -> bool:
    """Does this binary carry `cap_net_raw` and `cap_net_admin`, permitted and
    effective - what `setcap cap_net_raw,cap_net_admin,...+eip` gives it?

    Read from the `security.capability` attribute (`struct vfs_cap_data`: a
    little-endian magic word whose low bit is "effective", then the low 32
    permitted bits). Only Linux has it; anywhere else, or without the
    attribute, the answer is no.
    """
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return False
    try:
        data = getxattr(path, "security.capability")
    except OSError:
        return False
    if len(data) < 8:
        return False
    magic, permitted = struct.unpack_from("<II", data)
    needed = (1 << _CAP_NET_ADMIN) | (1 << _CAP_NET_RAW)
    if not magic & _VFS_CAP_FLAGS_EFFECTIVE or permitted & needed != needed:
        return False
    # A capability outside this process's bounding set makes the exec itself
    # fail (EPERM) - a container without NET_ADMIN, measured. Then sudo it is.
    return _bounding() & needed == needed


def _bounding() -> int:
    """This process's capability bounding set; all bits when it cannot be read."""
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                if line.startswith("CapBnd:"):
                    return int(line.split()[1], 16)
    except (OSError, ValueError):
        pass
    return ~0


# --- privileges -------------------------------------------------------------

# The scan types that actually need raw sockets, plus the extras that imply
# them. Derived from the flags rather than declared per preset: a command the
# user pastes is then classified as correctly as a shipped one, and no table
# has to be kept in step with nmap.
_ROOT_LETTERS = set("SAWMNFXUYZOI")
# Host-discovery probes that need raw sockets. `-PS`/`-PA` are deliberately
# absent: unprivileged, nmap sends those with connect(), so requiring sudo for
# them would ask for elevation that is not needed. `-Pn` is not a probe at all.
_ROOT_PINGS = set("EPMOUYR")
# The raw-packet evasion options: fragmenting, decoys, a spoofed source or MAC,
# IP options, a set TTL and bad checksums all shape packets a connect() scan
# never builds. `seek.nmap.options` marks the same set `root=True`, and a test
# holds the two together.
_ROOT_FLAGS = {"-O", "-A", "--traceroute", "--privileged", "-f", "--mtu", "-D", "-S",
               "--spoof-mac", "--ip-options", "--ttl", "--badsum"}

# The NSE scripts that build their own packets. `--script` on its own says
# nothing about privilege: an http, smb or ssl script is an ordinary
# connection, so elevating for the flag itself would put `sudo -n` in front of
# half the presets that ship here - `auth`, `brute`, `hostmap-crtsh`,
# `http-vhosts` - and fail them outright wherever passwordless sudo is not set
# up. The `broadcast` and `ipv6` families are taken whole; the rest are named.
_ROOT_SCRIPT_FAMILIES = ("broadcast-", "ipv6-", "targets-ipv6-")
_ROOT_SCRIPTS = {"broadcast", "firewalk", "ipidseq", "sniffer-detect",
                 "path-mtu", "qscan", "ip-forwarding"}
# A `--script` value is a list of names, categories, `+`-forced entries, globs
# and the occasional `and`/`or` expression. Split on everything that separates
# them and look at the parts; a glob matches on the text before the `*`.
_SCRIPT_SPLIT = re.compile(r"[,\s()]+")


def _root_script(spec: str) -> str | None:
    """The first script in a `--script` value that needs raw sockets, if any."""
    for entry in _SCRIPT_SPLIT.split(spec):
        name = entry.strip().lstrip("+").lower()
        if not name:
            continue
        if name in _ROOT_SCRIPTS or name.rstrip("*").startswith(_ROOT_SCRIPT_FAMILIES):
            return entry.strip()
    return None


def _is_privileged(token: str) -> bool:
    # `--flag=value` and `--flag value` are the same flag to nmap, so the name
    # is taken before the `=` - as `parse_args` does for the output flags.
    if token.partition("=")[0] in _ROOT_FLAGS or re.fullmatch(r"-f+", token):
        return True
    # -sS, -sU, -sSU ... but not -sV (a version probe is unprivileged) and not
    # -sn (host discovery only - lower case, and the letters are checked as
    # written).
    if len(token) > 2 and token[:2] == "-s" and set(token[2:]) & _ROOT_LETTERS:
        return True
    # -PE, -PP, -PU53,123 ... raw ICMP, IP-protocol and UDP pings.
    return len(token) > 2 and token[:2] == "-P" and token[2] in _ROOT_PINGS


def _privileged_tokens(args: list[str]) -> list[str]:
    """What in this argument list asks for raw sockets, in order, once each."""
    found: dict[str, None] = {}
    for index, token in enumerate(args):
        flag, sep, value = token.partition("=")
        if flag == "--script":                      # `--script`, not `--script-args`
            spec = value if sep else (args[index + 1] if index + 1 < len(args) else "")
            script = _root_script(spec)
            if script is not None:
                found[f"--script {script}"] = None
        elif _is_privileged(token):
            found[token] = None
    return list(found)


def needs_root(args: list[str]) -> bool:
    """Does this argument list require raw sockets?"""
    return bool(_privileged_tokens(args))


def privileged_labels(args: list[str]) -> str:
    """The flags that made `needs_root` true, for saying *why* in the UI."""
    return ", ".join(_privileged_tokens(args))


# --- the command ------------------------------------------------------------


class CommandError(ValueError):
    """The edited command cannot be run, and why."""


# Refused because they only mean something to a shell, and there is no shell:
# passing them through would be silently wrong. `*` and `?` are *not* refused -
# they are meaningful to nmap itself (`--script "http-*"`) and harmless without
# a shell to expand them.
_SHELL_CHARS = ("|", "&", ";", "<", ">", "`", "$")
_OUTPUT_FLAGS = ("-oA", "-oX", "-oN", "-oG", "-oS")


def parse_args(text: str) -> list[str]:
    """Arguments alone (a preset's value), split and checked."""
    stripped = text.strip()
    for char in _SHELL_CHARS:
        if char in stripped:
            raise CommandError(
                f"{char!r} is only meaningful to a shell, and the command is not "
                "run in one - remove it, or run that pipeline outside seek"
            )
    try:
        tokens = shlex.split(stripped)
    except ValueError as exc:                       # an unbalanced quote
        raise CommandError(f"the command could not be read: {exc}") from exc
    for token in tokens:
        if token.split("=")[0] in _OUTPUT_FLAGS:
            raise CommandError(
                f"{token} is handled for you - output goes to the scan directory "
                "as -oA, so that a scan run here leaves what an external one leaves"
            )
    return tokens


def parse_command(text: str, program: str = "nmap") -> list[str]:
    """The edited command as an argument list, or an explanation of why not.

    Returns the arguments *after* the program name; the caller adds the targets
    and the output flags, which it owns.
    """
    if not text.strip():
        raise CommandError("the command is empty")
    tokens = parse_args(text)
    if not tokens:
        raise CommandError("the command is empty")
    first = tokens[0]
    if Path(first).name != Path(program).name:
        raise CommandError(
            f"this runs {Path(first).name!r}; only {Path(program).name!r} can be "
            "started from here"
        )
    return tokens[1:]


def build_argv(program: str, args: list[str], targets: list[str], out_base: str,
               elevate: bool = False) -> list[str]:
    """The exact argument vector, in the order the review screen shows it.

    `-oA` is ours: it is what makes a scan started here indistinguishable from
    one run outside, and `parse_command` refuses a command that brings its own.
    """
    argv = ["sudo", "-n"] if elevate else []
    argv += [program, *args, "-oA", out_base, *targets]
    return argv


def slug(name: str) -> str:
    """A filename-safe stem for a preset name.

    Anything in brackets is dropped first: a preset is named for a reader, and
    the parenthetical is where the flags and caveats live - "03 · Details, full
    TCP (-p-)" is about full TCP, and `-p-` in the filename says nothing the
    name has not already said while making it longer and harder to read.
    """
    name = re.sub(r"\([^)]*\)", " ", name)
    cleaned = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return cleaned or "scan"


def output_base(directory: Path, preset_name: str, when: datetime | None = None) -> Path:
    """`<dir>/nmap_<preset>_<YYYY-MM-DD_HH-MM-SS>` - the base `-oA` extends.

    The time is local, matching `date +%Y-%m-%d_%H-%M-%S`: these filenames are
    read beside the shell history that produced their neighbours, and a UTC
    stamp among local ones is a stamp that has to be converted before two scans
    can be put in order by eye.
    """
    moment = when.astimezone() if when is not None else datetime.now()
    stamp = moment.strftime("%Y-%m-%d_%H-%M-%S")
    base = Path(directory) / f"nmap_{slug(preset_name)}_{stamp}"
    # Scans may run together: a second one of a preset in the same second
    # must not write over the first (nmap creates the XML as it starts).
    n = 1
    while base.with_name(base.name + ".xml").exists():
        n += 1
        base = Path(directory) / f"nmap_{slug(preset_name)}_{stamp}-{n}"
    return base


def writable(directory: Path) -> str | None:
    """Why the scan could not be written here, or None if it could."""
    path = Path(directory)
    if not path.exists():
        return f"{path} does not exist"
    if not path.is_dir():
        return f"{path} is not a directory"
    probe_file = path / ".seek-write-probe"
    try:
        probe_file.touch()
        probe_file.unlink()
    except OSError as exc:
        return f"{path} is not writable: {exc.strerror or exc}"
    return None


# --- targets ----------------------------------------------------------------


@dataclass(slots=True)
class Target:
    """One line of the scope, and what it turned out to be."""

    raw: str
    value: str = ""                 # what nmap is given
    kind: str = ""                  # address | range | network | host | url
    port: int | None = None
    addresses: int = 0
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def note(self) -> str:
        """The annotation shown beside the line."""
        if self.error:
            return self.error
        if self.kind == "network":
            return f"{self.addresses} addresses"
        if self.kind == "range":
            return f"{self.addresses} addresses"
        if self.kind == "url":
            return f"host{f' · port {self.port}' if self.port else ''}"
        if self.kind == "host":
            return "hostname"
        return ""


_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$",
    re.I,
)
_LAST_OCTET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


def parse_target(line: str) -> Target | None:
    """One scope line. `None` for a blank line or a comment - not an error."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    if "://" in text:
        return _url_target(text)
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            return Target(raw=text, error=str(exc).split(" (")[0])
        return Target(raw=text, value=str(network), kind="network",
                      addresses=network.num_addresses)
    match = _LAST_OCTET_RANGE.match(text)
    if match:
        prefix, low, high = match.group(1), int(match.group(2)), int(match.group(3))
        if not (0 <= low <= high <= 255):
            return Target(raw=text, error="that is not an address range")
        try:
            ipaddress.ip_address(f"{prefix}{low}")
        except ValueError:
            return Target(raw=text, error="that is not an address range")
        return Target(raw=text, value=text, kind="range", addresses=high - low + 1)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        return Target(raw=text, value=str(address), kind="address", addresses=1)
    if _HOSTNAME.match(text) and not _looks_numeric(text):
        return Target(raw=text, value=text, kind="host", addresses=1)
    return Target(raw=text, error="not an address, range, hostname or URL")


def is_hostname(text: str) -> bool:
    """Is this a name something could resolve? Not an address, not a wildcard."""
    candidate = text.strip().rstrip(".")
    if not candidate or candidate.startswith("*"):
        return False
    return bool(_HOSTNAME.match(candidate)) and not _looks_numeric(candidate)


def _looks_numeric(text: str) -> bool:
    """`10.0.0.300` is a botched address, not a hostname.

    It matches the hostname grammar - digits and dots are legal there - and
    accepting it would send nmap off to resolve it. A hostname's last label is
    never all digits (RFC 1123), which is exactly the rule that separates the
    two.
    """
    last = text.rstrip(".").rsplit(".", 1)[-1]
    return last.isdigit()


def _url_target(text: str) -> Target:
    parts = urlsplit(text)
    if not parts.hostname:
        return Target(raw=text, error="that URL has no host")
    try:
        port = parts.port
    except ValueError:
        return Target(raw=text, error="that URL has an invalid port")
    return Target(raw=text, value=parts.hostname, kind="url", port=port, addresses=1)


@dataclass(slots=True)
class Scope:
    """A parsed scope: what nmap will be given, and what could not be read."""

    targets: list[Target]

    @classmethod
    def parse(cls, text: str) -> Scope:
        found = [parse_target(line) for line in text.splitlines()]
        return cls([t for t in found if t is not None])

    @property
    def valid(self) -> list[Target]:
        return [t for t in self.targets if t.ok]

    @property
    def invalid(self) -> list[Target]:
        return [t for t in self.targets if not t.ok]

    @property
    def addresses(self) -> int:
        return sum(t.addresses for t in self.valid)

    @property
    def ports(self) -> list[int]:
        """Ports named by URL targets - worth carrying into the command."""
        return sorted({t.port for t in self.valid if t.port})

    def values(self) -> list[str]:
        return list(dict.fromkeys(t.value for t in self.valid))

    def summary(self) -> str:
        bits = [f"{len(self.valid)} valid target(s)"]
        if self.invalid:
            bits.append(f"{len(self.invalid)} invalid line(s)")
        bits.append(f"{self.addresses} address(es) in scope")
        return " · ".join(bits)


# Derived from the documented workflow in the project's nmap reference: the
# phases are numbered as its output files are (01 discovery, 02 services,
# 03 service-specific), so the list reads in the order the work is done.
#
# Targets, `-iL` and `-oA` are absent on purpose - the app supplies the scope
# and owns the output flags. `sudo` is absent too: whether a preset needs root
# is derived from its flags and the elevation is added at launch.
#
# `{ports}` expands to the open ports already in the model, which is the step
# the reference does with grep between the top-1000 scan and the version scan.
DEFAULT_PRESETS: dict[str, str] = {
    # ============================================================
    # 00 · LOOKUP
    # ============================================================

    # Forward DNS lookup without reverse lookups.
    "00 · Lookup · Forward DNS": "-v -sL -n --host-timeout 2m",

    # Reverse DNS lookup for all targets.
    "00 · Lookup · Reverse DNS": "-v -sL -R --host-timeout 2m",


    # ============================================================
    # 01 · HOST DISCOVERY
    # ============================================================

    # Complete: broad TCP SYN, TCP ACK and UDP discovery probes,
    # including the original port selections.
    "01 · Discovery · Complete (broad TCP/UDP probes)": (
        "-v -T3 -n -sn -PE -PP "
        "-PS20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,443,445,500,514,520,631,993,995,1434,1723,1900,3306,3389,4500,5900,8080,49152 "
        "-PA80 "
        "-PU20,21,22,23,25,53,67,68,69,80,110,111,123,135,137,138,139,143,161,162,443,445,500,514,520,631,993,995,1434,1723,1900,3306,3389,4500,5900,8080,49152,31347 "
        "--initial-rtt-timeout 500ms --max-rtt-timeout 3s --host-timeout 2m"
    ),

    # Fast: original common discovery probes.
    "01 · Discovery · Fast (original common probes)": (
        "-v -T4 -n -sn -PE -PP "
        "-PS22,80,445 -PA80 -PU53,123,161,500,31347 "
        "--initial-rtt-timeout 400ms --max-rtt-timeout 1500ms "
        "--host-timeout 45s"
    ),

    # Very fast: original common TCP/UDP ports with tighter timeouts.
    "01 · Discovery · Very fast (original common probes)": (
        "-v -T4 -n -sn -PE "
        "-PS22,80,445 -PA80 -PU53,123,161,500,31347 "
        "--initial-rtt-timeout 250ms --max-rtt-timeout 1s "
        "--host-timeout 20s"
    ),


    # ============================================================
    # 02 · TCP PORT ENUMERATION
    # ============================================================

    # Complete: all TCP ports.
    "02 · Ports · TCP · Complete (all ports)": (
        "-v -T3 -n -sS -p- --open "
        "--max-retries 3 "
        "--initial-rtt-timeout 500ms --max-rtt-timeout 3s "
        "--host-timeout 15m"
    ),

    # Fast: top 1000 TCP ports.
    "02 · Ports · TCP · Fast (top 1000)": (
        "-v -T4 -n -sS --top-ports 1000 --open "
        "--max-retries 2 "
        "--initial-rtt-timeout 400ms --max-rtt-timeout 1500ms "
        "--host-timeout 4m"
    ),

    # Very fast: top 100 TCP ports.
    "02 · Ports · TCP · Very fast (top 100)": (
        "-v -T4 -n -sS --top-ports 100 --open "
        "--max-retries 1 "
        "--initial-rtt-timeout 250ms --max-rtt-timeout 1s "
        "--host-timeout 90s"
    ),


    # ============================================================
    # 02 · UDP PORT ENUMERATION AND SERVICE DETECTION
    # ============================================================

    # Complete: all UDP ports with maximum version detection intensity.
    "02 · Ports · UDP · Complete (all ports)": (
        "-v -T3 -n -sUV -p- --version-all --open "
        "--max-retries 2 "
        "--initial-rtt-timeout 500ms --max-rtt-timeout 3s "
        "--max-scan-delay 2s --host-timeout 30m"
    ),

    # Fast: top 1000 UDP ports with normal version detection.
    "02 · Ports · UDP · Fast (top 1000)": (
        "-v -T4 -n -sUV --top-ports 1000 --open "
        "--max-retries 2 "
        "--initial-rtt-timeout 400ms --max-rtt-timeout 1500ms "
        "--max-scan-delay 1s --host-timeout 10m"
    ),

    # Very fast: top 100 UDP ports with light version detection.
    "02 · Ports · UDP · Very fast (top 100)": (
        "-v -T4 -n -sUV --version-light --top-ports 100 --open "
        "--max-retries 1 "
        "--initial-rtt-timeout 250ms --max-rtt-timeout 1s "
        "--max-scan-delay 500ms --host-timeout 3m"
    ),


    # ============================================================
    # 03 · TCP SERVICE AND VERSION DETECTION
    # ============================================================

    # Complete: maximum version-detection intensity (9).
    "03 · Details · TCP · Complete (all version probes)": (
        "-v -T3 -n -sS -sV --version-all -p{ports} --open "
        "--max-retries 2 "
        "--initial-rtt-timeout 500ms --max-rtt-timeout 3s "
        "--host-timeout 10m"
    ),

    # Fast: default version-detection intensity (7).
    "03 · Details · TCP · Fast (normal version detection)": (
        "-v -T4 -n -sS -sV -p{ports} --open "
        "--max-retries 2 "
        "--initial-rtt-timeout 400ms --max-rtt-timeout 1500ms "
        "--host-timeout 3m"
    ),

    # Very fast: light version-detection intensity (2).
    "03 · Details · TCP · Very fast (light version detection)": (
        "-v -T4 -n -sS -sV --version-light -p{ports} --open "
        "--max-retries 1 "
        "--initial-rtt-timeout 250ms --max-rtt-timeout 1s "
        "--host-timeout 90s"
    ),


    # ============================================================
    # 04 · VULNERABILITY ASSESSMENT
    # ============================================================

    # Complete: all Nmap vulnerability-category scripts.
    "04 · Vuln · Complete (all vuln scripts)": (
        "-v -T3 -n -sS -sV --version-all -p{ports} "
        "--script vuln --script-timeout 90s "
        "--max-retries 2 --max-rtt-timeout 3s "
        "--host-timeout 15m"
    ),

    # Fast: vulnerability scripts categorized as safe.
    "04 · Vuln · Fast (safe vulnerability scripts)": (
        "-v -T4 -n -sS -sV -p{ports} "
        "--script 'vuln and safe' --script-timeout 30s "
        "--max-retries 1 --max-rtt-timeout 1500ms "
        "--host-timeout 5m"
    ),

    # Very fast: safe vulnerability scripts with shorter timeouts.
    "04 · Vuln · Very fast (short safe checks)": (
        "-v -T4 -n -sS -sV --version-light -p{ports} "
        "--script 'vuln and safe' --script-timeout 10s "
        "--max-retries 1 --max-rtt-timeout 1s "
        "--host-timeout 2m"
    ),


    # ============================================================
    # 04 · TARGETED SECURITY CHECKS
    # ============================================================

    # SMB share enumeration using supplied credentials.
    "04 · Vuln · SMB share enumeration": (
        "-v -T3 -n -sS -sV -p139,445 "
        "--script smb-enum-shares "
        "--script-args 'smbusername=USERNAME,smbpassword=PASSWORD' "
        "--script-timeout 30s --host-timeout 3m"
    ),

    # SMB-specific vulnerability checks.
    "04 · Vuln · SMB vulnerability checks (139,445)": (
        "-v -T3 -n -sS -sV -p139,445 "
        "--script smb-vuln* "
        "--script-timeout 45s --host-timeout 5m"
    ),

    # SSH protocol and configuration enumeration.
    "04 · Audit · SSH configuration (22)": (
        "-v -T3 -n -sS -sV -p22 "
        "--script sshv1,ssh2-enum-algos,ssh-hostkey "
        "--script-timeout 30s --host-timeout 3m"
    ),

    # HTTP-specific vulnerability checks.
    "04 · Vuln · HTTP vulnerability checks (80,443)": (
        "-v -T3 -n -sS -sV -p80,443 "
        "--script http-vuln* "
        "--script-timeout 60s --host-timeout 5m"
    ),


    # ============================================================
    # 05 · NAME AND SERVICE ENRICHMENT
    # ============================================================

    # Complete: maximum version detection and all selected metadata scripts.
    "05 · Names · Complete (all metadata scripts)": (
        "-v -T3 -n -sS -sV --version-all -p{ports} "
        "--script ssl-cert,http-title,http-headers,rdp-ntlm-info,"
        "smb-os-discovery,ldap-rootdse,ssl-cert-intaddr "
        "--script-timeout 60s "
        "--max-retries 2 --max-rtt-timeout 3s "
        "--host-timeout 12m"
    ),

    # Fast: normal version detection and metadata collection.
    "05 · Names · Fast (service metadata)": (
        "-v -T4 -n -sS -sV -p{ports} "
        "--script ssl-cert,http-title,http-headers,rdp-ntlm-info,"
        "smb-os-discovery,ldap-rootdse,ssl-cert-intaddr "
        "--script-timeout 30s "
        "--max-retries 1 --max-rtt-timeout 1500ms "
        "--host-timeout 4m"
    ),

    # Very fast: light version detection and a smaller script selection.
    "05 · Names · Very fast (selected metadata)": (
        "-v -T4 -n -sS -sV --version-light -p{ports} "
        "--script ssl-cert,http-title,rdp-ntlm-info,smb-os-discovery "
        "--script-timeout 10s "
        "--max-retries 1 --max-rtt-timeout 1s "
        "--host-timeout 2m"
    ),

    # NetBIOS enumeration on UDP port 137.
    "05 · Names · NetBIOS enumeration (UDP 137)": (
        "-v -T4 -n -sU -sV -p137 "
        "--script nbstat "
        "--script-timeout 15s --host-timeout 2m"
    ),

    # External Certificate Transparency lookup via crt.sh.
    "05 · Names · External CT lookup (crt.sh)": (
        "-v -T3 -n -sS -sV -p{ports} "
        "--script hostmap-crtsh "
        "--script-timeout 60s --host-timeout 5m"
    ),

    # HTTP virtual-host discovery. Generates additional HTTP requests.
    "05 · Names · HTTP virtual hosts (intrusive)": (
        "-v -T3 -n -sS -sV -p80,443,8080,8443 "
        "--script http-vhosts "
        "--script-timeout 45s --host-timeout 3m"
    ),


    # ============================================================
    # 06 · AUTHENTICATION CHECKS
    # ============================================================

    # Complete: all Nmap authentication-category scripts.
    "06 · Auth · Complete (authentication scripts)": (
        "-v -T3 -n -sS -sV -p{ports} "
        "--script auth --script-timeout 60s "
        "--max-retries 2 --host-timeout 10m"
    ),

    # Fast: authentication scripts categorized as safe.
    "06 · Auth · Fast (safe authentication scripts)": (
        "-v -T4 -n -sS -sV -p{ports} "
        "--script 'auth and safe' --script-timeout 30s "
        "--max-retries 1 --host-timeout 4m"
    ),

    # Very fast: safe authentication checks with shorter timeouts.
    "06 · Auth · Very fast (short safe checks)": (
        "-v -T4 -n -sS -sV --version-light -p{ports} "
        "--script 'auth and safe' --script-timeout 10s "
        "--max-retries 1 --host-timeout 2m"
    ),

    # Explicit opt-in password-guessing operation.
    # Apply only to specifically authorized targets and accounts.
    "06 · Creds · Brute force logins (manual opt-in)": (
        "-v -T3 -n -sS -sV -p{ports} "
        "--script brute --script-timeout 15s "
        "--max-retries 1 --host-timeout 3m"
    ),
}

PORTS_PLACEHOLDER = "{ports}"

# The inventory's own scan: version detection at full intensity on exactly the
# open ports nothing has versioned yet, with the scripts whose output the
# inventory reads. Not a chooser entry - its targets and ports come from the
# inventory, not from a scope - but named like one, so its output files sort
# beside the phase-03 scans they complement.
VERSION_GAPS_PRESET = "03 · Versions, unversioned ports"
VERSION_GAPS_ARGS = ("-vv -T4 -n -Pn -sV --version-all "
                     "--script banner,http-server-header,http-generator -p{ports}")
