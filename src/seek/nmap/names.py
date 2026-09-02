"""The names a host answers to, lifted out of what the scan recorded.

There is no way to ask an address which names point at it: DNS resolves names to
addresses, and a `CNAME` is only visible to someone who already knows the alias.
A reverse lookup gives at most the one `PTR` the address owner chose to publish,
which is why a host serving six sites usually looks like it has one name, or
none.

What the *server* reveals is another matter, and a scan can read all of it:

- the certificate a TLS service presents names every host it is valid for, which
  for a multi-site server is the vhost list itself;
- an HTTP service redirecting to its canonical name says that name out loud;
- Windows services (NTLM, SMB, LDAP, NetBIOS) announce their FQDN and domain;
- `hostmap-*` scripts ask a certificate-transparency index for the names issued
  under a domain - an external lookup, so it is its own preset rather than
  something bundled into a service scan.

So this module is to names what `vulns.py` is to findings: a recogniser that
runs once, at `views.prepare`, and attaches what it found - with **where it came
from**, because a name read off a certificate and a name a server redirects to
are different kinds of evidence.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from seek.nmap.models import Host, ScriptResult, Service
from seek.nmap.presets import is_hostname

# `commonName=` appears in the subject line, `DNS:` in the subject-alternative
# names. Both turn up in the free text and in the structured tables.
_CERT_NAME = re.compile(r"(?:commonName=|DNS:)\s*([A-Za-z0-9*._-]+)")
# "Did not follow redirect to https://www.example.test/", "Location: https://…".
# Anchored on the redirect itself rather than matching any URL in the text: a
# `http-vuln-*` script's advisory links are URLs too, and an advisory host is
# not a name this server answers to.
_URL_HOST = re.compile(
    r"(?:redirect(?:ed|s)?\s+to|Location\s*:)\s*https?://([A-Za-z0-9.*_-]+)", re.I)
# `DNS_Computer_Name: host.example.test`, `FQDN: host.example.test`
_IDENTITY = re.compile(
    r"(?:DNS[_ ]?(?:Computer[_ ]?Name|Domain[_ ]?Name|Tree[_ ]?Name)|FQDN|"
    r"dnsHostName|defaultNamingContext|NetBIOS[_ ]?(?:computer[_ ]?)?name)"
    r"\s*[:=]\s*([A-Za-z0-9.*_-]+)",
    re.I,
)
# A bare list of names, which is what a certificate-transparency lookup returns.
_BARE = re.compile(r"[A-Za-z0-9*_-]+(?:\.[A-Za-z0-9*_-]+)+")


def _flatten(data: object) -> str:
    """Every string leaf of a script's structured output, space separated.

    `ssl-cert` puts the subject in `output` but the alternative names *only* in
    its `<table>` entries, so parsing the text alone finds half the names.
    """
    if isinstance(data, dict):
        return " ".join(_flatten(v) for v in data.values())
    if isinstance(data, list):
        return " ".join(_flatten(v) for v in data)
    return str(data) if data is not None else ""


def _text(script: ScriptResult) -> str:
    return f"{script.output or ''} {_flatten(script.data)}"


def _cert(script: ScriptResult) -> bool:
    return script.id.startswith("ssl-") or script.id.endswith("-cert")


def _http(script: ScriptResult) -> bool:
    """Only the scripts that report where a server sends you."""
    return script.id in {"http-title", "http-headers", "http-redirect",
                         "http-server-header", "https-redirect"}


def _hostmap(script: ScriptResult) -> bool:
    return script.id.startswith("hostmap")


def _identity(script: ScriptResult) -> bool:
    return script.id in {
        "rdp-ntlm-info", "smb-os-discovery", "smb2-security-mode", "nbstat",
        "ldap-rootdse", "ms-sql-ntlm-info", "smtp-ntlm-info", "http-ntlm-info",
        "imap-ntlm-info", "pop3-ntlm-info", "telnet-ntlm-info",
    }


# (does this script carry names, how to read them, what to call the source).
# Narrow by design: a loose sweep over every script's text would harvest the
# example.com in a banner as readily as a real vhost.
_SOURCES: list[tuple[Callable[[ScriptResult], bool], re.Pattern, str]] = [
    (_cert, _CERT_NAME, "certificate"),
    (_hostmap, _BARE, "certificate transparency"),
    (_identity, _IDENTITY, "host identity"),
    (_http, _URL_HOST, "redirect"),
]


def service_names(svc: Service) -> list[tuple[str, str]]:
    """Every DNS name this service revealed, each with where it came from.

    Wildcards and addresses are dropped: nothing resolves `*.example.test`, and
    a certificate naming an IP tells you nothing the address column does not.
    """
    found: dict[str, str] = {}
    for script in svc.scripts:
        for matches, pattern, label in _SOURCES:
            if not matches(script):
                continue
            for raw in pattern.findall(_text(script)):
                name = raw.rstrip(".")
                if is_hostname(name) and "." in name:
                    found.setdefault(name, label)
    return list(found.items())


def attach(host: Host) -> None:
    """Fill in `Service.names`. Called once, from `views.prepare`."""
    for svc in host.services:
        svc.names = service_names(svc)


def _evidence(host: Host) -> dict[str, list[tuple[str, str]]]:
    """name -> every (kind, where) that revealed it, in the order found."""
    out: dict[str, list[tuple[str, str]]] = {}
    for name in host.hostnames:
        out.setdefault(name, []).append(("resolved", ""))
    for svc in host.services:
        for name, label in svc.names:
            where = f"{svc.port}/{svc.protocol}"
            found = out.setdefault(name, [])
            if (label, where) not in found:
                found.append((label, where))
    return out


def host_names(host: Host) -> list[tuple[str, str]]:
    """Every name known for a host, each with everything that revealed it.

    All of the evidence, not the first piece of it: a name that is both the
    certificate's subject and where port 80 redirects is better corroborated
    than one seen once, and that is worth showing rather than collapsing.
    """
    return [
        (name, ", ".join(f"{kind} on {where}" if where else kind
                         for kind, where in evidence))
        for name, evidence in _evidence(host).items()
    ]


def names_of(host: Host) -> list[str]:
    """Just the names, resolved ones first."""
    return list(_evidence(host))


def kinds_of(host: Host) -> dict[str, list[str]]:
    """name -> the kinds of evidence behind it, without the ports."""
    return {name: sorted({kind for kind, _ in evidence})
            for name, evidence in _evidence(host).items()}


def sources_of(host: Host) -> list[str]:
    """The kinds of evidence behind a host's names, for a summary column."""
    return sorted({kind for evidence in _evidence(host).values()
                   for kind, _ in evidence})
