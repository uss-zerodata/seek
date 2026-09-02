"""The names a host answers to, lifted out of what the scan recorded.

A scan learns names two ways and only one of them lands in `<hostnames>`: the
reverse lookup fills that, while a TLS service's certificate claims names that
are buried in an `ssl-cert` script result. Both matter - virtual hosting means
the address and the name often serve different things, and a certificate naming
a host you did not know about is a finding in itself.

So this module is to names what `vulns.py` is to findings: a recogniser that
runs once, at `views.prepare`, and attaches what it found to the model, so every
view can show it without re-parsing script text on each keystroke.
"""

from __future__ import annotations

import re

from seek.nmap.models import Host, ScriptResult, Service
from seek.nmap.presets import is_hostname

# `commonName=` appears in the subject line; `DNS:` in the subject-alternative
# names. Both forms turn up in the free text and in the structured tables.
_CERT_NAME = re.compile(r"(?:commonName=|DNS:)\s*([A-Za-z0-9*._-]+)")


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


def _is_cert_script(script: ScriptResult) -> bool:
    return script.id.startswith("ssl-") or script.id.endswith("-cert")


def cert_names(svc: Service) -> list[str]:
    """DNS names this service's certificate claims.

    Wildcards and addresses are dropped: nothing resolves `*.example.test`, and
    a certificate naming an IP tells you nothing the address column does not.
    """
    found: list[str] = []
    for script in svc.scripts:
        if not _is_cert_script(script):
            continue
        found += _CERT_NAME.findall(f"{script.output or ''} {_flatten(script.data)}")
    return [n.rstrip(".") for n in dict.fromkeys(found) if is_hostname(n)]


def attach(host: Host) -> None:
    """Fill in `Service.cert_names`. Called once, from `views.prepare`."""
    for svc in host.services:
        svc.cert_names = cert_names(svc)


def host_names(host: Host) -> list[tuple[str, str]]:
    """Every name known for a host, each with where it came from."""
    out: dict[str, str] = {}
    for name in host.hostnames:
        out.setdefault(name, "resolved")
    for svc in host.services:
        for name in svc.cert_names:
            out.setdefault(name, f"certificate on {svc.port}/{svc.protocol}")
    return list(out.items())


def names_of(host: Host) -> list[str]:
    """Just the names, resolved ones first."""
    return [name for name, _ in host_names(host)]
