"""Lift vulnerability findings out of script results.

Only what a scan reported is surfaced - nothing is assessed or inferred. In
particular the NSE `vuln` library reports a **state** (`VULNERABLE`,
`LIKELY VULNERABLE`, `NOT VULNERABLE`) and no severity at all; mapping a state
onto a severity would be inventing an assessment, so `severity` stays unset
unless a script genuinely scores the finding, as `vulners` does with CVSS.
"""

from __future__ import annotations

import re

from seek.nmap.models import Host, ScriptResult, Vulnerability

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_NOT_VULNERABLE = "NOT VULNERABLE"


def _looks_vulnerability_bearing(script: ScriptResult) -> bool:
    """A script merely *mentioning* a CVE is not a finding.

    Restricted to scripts that are about vulnerabilities, or that explicitly say
    the target is vulnerable - otherwise a changelog quoted in a banner would be
    reported as one.
    """
    if "vuln" in script.id.lower():
        return True
    return "VULNERABLE" in (script.output or "").upper()


def _dates(entry: dict) -> str | None:
    disclosed = entry.get("disclosure")
    if isinstance(disclosed, str) and disclosed:
        return disclosed
    dates = entry.get("dates")
    if isinstance(dates, dict):
        inner = dates.get("disclosure")
        if isinstance(inner, dict):
            y, m, d = inner.get("year"), inner.get("month"), inner.get("day")
            if y and m and d:
                return f"{y}-{m}-{d}"
    return None


def _as_list(value) -> list[str]:
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []


def _from_nse_vuln(script: ScriptResult) -> list[Vulnerability]:
    """NSE `vuln` library: a table keyed by the identifier, holding a state."""
    if not isinstance(script.data, dict):
        return []
    out: list[Vulnerability] = []
    for key, entry in script.data.items():
        if not isinstance(entry, dict) or "state" not in entry:
            continue
        state = entry.get("state")
        if isinstance(state, str) and state.upper().startswith(_NOT_VULNERABLE):
            continue  # the script ran and found the target unaffected
        out.append(Vulnerability(
            id=key,
            title=entry.get("title") if isinstance(entry.get("title"), str) else None,
            state=state if isinstance(state, str) else None,
            ids=_as_list(entry.get("ids")),
            refs=_as_list(entry.get("refs")),
            disclosed=_dates(entry),
            source_script=script.id,
        ))
    return out


def _from_vulners(script: ScriptResult) -> list[Vulnerability]:
    """`vulners`: cpe-keyed tables of entries carrying an id and a CVSS score."""
    if script.id != "vulners" or not isinstance(script.data, dict):
        return []
    out: list[Vulnerability] = []
    for entries in script.data.values():
        items = entries if isinstance(entries, list) else []
        if isinstance(entries, dict):
            items = entries.get("_items", []) if isinstance(entries.get("_items"), list) else []
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                cvss = item.get("cvss")
                out.append(Vulnerability(
                    id=item["id"],
                    severity=cvss if isinstance(cvss, str) and cvss else None,
                    source_script=script.id,
                ))
    return out


def _from_free_text(script: ScriptResult) -> list[Vulnerability]:
    """Last resort: identifiers named in a vulnerability script's plain output."""
    if script.data or not _looks_vulnerability_bearing(script):
        return []
    seen: list[str] = []
    for found in _CVE_RE.findall(script.output or ""):
        upper = found.upper()
        if upper not in seen:
            seen.append(upper)
    return [Vulnerability(id=i, source_script=script.id) for i in seen]


def from_script(script: ScriptResult) -> list[Vulnerability]:
    """Every finding this script reported, in recognition order."""
    if not _looks_vulnerability_bearing(script) and script.id != "vulners":
        return []
    found = _from_nse_vuln(script) or _from_vulners(script) or _from_free_text(script)
    return found


def _dedup(items: list[Vulnerability]) -> list[Vulnerability]:
    seen: set[tuple[str, str | None]] = set()
    out: list[Vulnerability] = []
    for v in items:
        if v.identity() in seen:
            continue
        seen.add(v.identity())
        out.append(v)
    return out


def attach(host: Host) -> None:
    """Populate the vulnerabilities of each of a host's services, in place."""
    for service in host.services:
        service.vulnerabilities = _dedup(
            [v for s in service.scripts for v in from_script(s)]
        )


def host_vulnerabilities(host: Host) -> list[Vulnerability]:
    """A host's distinct findings.

    One script reported against several ports yields one record per service; at
    host level the same finding is counted once.
    """
    from_services = [v for s in host.services for v in s.vulnerabilities]
    from_host = [v for s in host.scripts for v in from_script(s)]
    return _dedup(from_host + from_services)
