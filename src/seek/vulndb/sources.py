"""Where the public data comes from, and how each format is read.

The URL set is fixed: every request an update makes is one of these, built
from nothing but the calendar year and the product slugs in `eol.SLUGS`. That
is what makes "an update reveals nothing about the engagement" true by
construction - no address, name, product or version from a session can reach a
URL, because no session data reaches this module.

Parsers are pure: bytes or dicts in, rows out.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import IO

# --- the fixed URL set ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Urls:
    """Every base the update talks to; tests point these at a local server."""

    nvd: str = "https://nvd.nist.gov/feeds/json/cve/2.0"
    cpe: str = "https://nvd.nist.gov/feeds/json/cpe/2.0"
    osv: str = "https://osv-vulnerabilities.storage.googleapis.com"
    eol: str = "https://endoflife.date/api"

    def nvd_year(self, year: int | str) -> str:
        return f"{self.nvd}/nvdcve-2.0-{year}.json.gz"

    def nvd_meta(self, year: int | str) -> str:
        return f"{self.nvd}/nvdcve-2.0-{year}.meta"

    def cpe_dictionary(self) -> str:
        return f"{self.cpe}/nvdcpe-2.0.tar.gz"

    def cpe_meta(self) -> str:
        return f"{self.cpe}/nvdcpe-2.0.meta"

    def osv_npm(self) -> str:
        return f"{self.osv}/npm/all.zip"

    def eol_full(self) -> str:
        """Every product, its release lines and its identifiers, in one file."""
        return f"{self.eol}/v1/products/full"


NVD_FIRST_YEAR = 2002          # the 2002 feed carries everything older too
NVD_MODIFIED = "modified"      # the rolling last-eight-days feed
NVD_MODIFIED_DAYS = 8

# --- NVD 2.0 --------------------------------------------------------------------

_SEVERITY_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass(slots=True)
class CveRow:
    id: str
    published: str
    modified: str
    summary: str
    severity: str
    score: float | None
    vector: str
    cwe: str
    refs: list[str] = field(default_factory=list)
    # (part, vendor, product, version, update, start_incl, start_excl, end_incl, end_excl)
    criteria: list[tuple[str, ...]] = field(default_factory=list)
    rejected: bool = False


def _split_cpe23(criteria: str) -> list[str]:
    parts = re.split(r"(?<!\\):", criteria)
    return [re.sub(r"\\(.)", r"\1", p) for p in parts]


def _metric(metrics: dict) -> tuple[str, float | None, str]:
    """The primary (NVD's own) metric of the newest CVSS version, else the first."""
    for key in _SEVERITY_ORDER:
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData") or {}
        severity = data.get("baseSeverity") or chosen.get("baseSeverity") or ""
        return str(severity).upper(), data.get("baseScore"), data.get("vectorString") or ""
    return "", None, ""


def _criteria(configurations: list) -> Iterator[tuple[str, ...]]:
    """Every *vulnerable* CPE criterion. A configuration's platform ("X running
    on Linux") is a `vulnerable: false` match under an AND node, so keeping only
    the vulnerable ones is what keeps Linux from inheriting X's CVEs."""
    for config in configurations or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = _split_cpe23(match.get("criteria") or "")
                if len(parts) < 7 or parts[0] != "cpe" or parts[1] != "2.3":
                    continue
                yield (parts[2], parts[3].lower(), parts[4].lower(), parts[5], parts[6],
                       match.get("versionStartIncluding") or "",
                       match.get("versionStartExcluding") or "",
                       match.get("versionEndIncluding") or "",
                       match.get("versionEndExcluding") or "")


def parse_nvd_item(item: dict) -> CveRow | None:
    cve = item.get("cve") or item
    cid = cve.get("id")
    if not cid:
        return None
    summary = next((d.get("value", "") for d in cve.get("descriptions") or []
                    if d.get("lang") == "en"), "")
    severity, score, vector = _metric(cve.get("metrics") or {})
    cwe = next((d.get("value", "") for w in cve.get("weaknesses") or []
                for d in w.get("description") or [] if d.get("value", "").startswith("CWE-")),
               "")
    return CveRow(
        id=cid, published=cve.get("published") or "", modified=cve.get("lastModified") or "",
        summary=" ".join(summary.split()), severity=severity, score=score, vector=vector,
        cwe=cwe, refs=[r["url"] for r in cve.get("references") or [] if r.get("url")][:20],
        criteria=list(dict.fromkeys(_criteria(cve.get("configurations") or []))),
        rejected=(cve.get("vulnStatus") or "").lower() == "rejected",
    )


def iter_json_array(stream: IO[str], key: str, chunk: int = 1 << 20) -> Iterator[dict]:
    """The items of the top-level array `key`, one at a time.

    A yearly NVD feed decompresses to hundreds of megabytes; loading it whole
    would hold all of it as Python objects. This keeps one item and one chunk
    in memory: find `"key": [`, then decode an object at a time with
    `raw_decode`, refilling the buffer when an object runs past its end.
    """
    decoder = json.JSONDecoder()
    buf = ""
    marker = re.compile(r'"' + re.escape(key) + r'"\s*:\s*\[')
    while True:
        found = marker.search(buf)
        if found:
            buf = buf[found.end():]
            break
        more = stream.read(chunk)
        if not more:
            return
        buf = buf[-len(key) - 8:] + more
    pos = 0
    while True:
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos < len(buf):
                break
            more = stream.read(chunk)
            if not more:
                return
            buf, pos = buf[pos:] + more, 0
        if buf[pos] == "]":
            return
        try:
            item, end = decoder.raw_decode(buf, pos)
        except json.JSONDecodeError:
            more = stream.read(chunk)
            if not more:
                raise
            buf, pos = buf[pos:] + more, 0
            continue
        yield item
        pos = end
        if pos > chunk:
            buf, pos = buf[pos:], 0


def parse_nvd_meta(text: str) -> dict[str, str]:
    """`lastModifiedDate:…\\nsha256:…` -> a dict."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


# --- the CPE dictionary ------------------------------------------------------------


def parse_cpe_name(item: dict) -> tuple[str, str, str] | None:
    """(vendor, product, version) of one dictionary entry - a released version
    of an application or an operating system. Hardware, deprecated names and
    names without a concrete version (`-`, `*`) say nothing about releases."""
    cpe = item.get("cpe") or item
    if cpe.get("deprecated"):
        return None
    parts = _split_cpe23(cpe.get("cpeName") or "")
    if len(parts) < 7 or parts[2] not in ("a", "o"):
        return None
    version, update = parts[5], parts[6]
    if version in ("", "*", "-"):
        return None
    if update not in ("", "*", "-"):
        version += update
    return parts[3].lower(), parts[4].lower(), version


# --- OSV ------------------------------------------------------------------------

_OSV_SEVERITY = {"MODERATE": "MEDIUM"}


@dataclass(slots=True)
class OsvRow:
    id: str
    aliases: list[str]
    summary: str
    severity: str
    score: float | None
    modified: str
    url: str
    # (package, introduced, fixed, last_affected, exact)
    ranges: list[tuple[str, str, str, str, str]] = field(default_factory=list)


def parse_osv(record: dict, packages: Iterable[str]) -> OsvRow | None:
    """An advisory, keeping only what it says about the tracked npm packages."""
    wanted = set(packages)
    ranges: list[tuple[str, str, str, str, str]] = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        name = (pkg.get("name") or "").lower()
        if pkg.get("ecosystem") != "npm" or name not in wanted:
            continue
        for r in affected.get("ranges") or []:
            if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            start = ""
            for event in r.get("events") or []:
                if "introduced" in event:
                    start = "" if event["introduced"] == "0" else event["introduced"]
                elif "fixed" in event:
                    ranges.append((name, start, event["fixed"], "", ""))
                    start = None
                elif "last_affected" in event:
                    ranges.append((name, start, "", event["last_affected"], ""))
                    start = None
            if start is not None:
                ranges.append((name, start, "", "", ""))   # introduced, never fixed
        for version in affected.get("versions") or []:
            ranges.append((name, "", "", "", version))
    if not ranges:
        return None
    severity = ""
    for affected in record.get("affected") or []:
        severity = str((affected.get("database_specific") or {}).get("severity") or severity)
    severity = (record.get("database_specific") or {}).get("severity") or severity
    severity = _OSV_SEVERITY.get(str(severity).upper(), str(severity).upper())
    oid = record.get("id") or ""
    url = next((r.get("url") for r in record.get("references") or []
                if r.get("type") == "ADVISORY" and r.get("url")),
               f"https://osv.dev/vulnerability/{oid}")
    return OsvRow(id=oid, aliases=[a for a in record.get("aliases") or [] if a],
                  summary=" ".join((record.get("summary") or record.get("details") or "")
                                   .split())[:300],
                  severity=severity, score=None, modified=record.get("modified") or "",
                  url=url, ranges=list(dict.fromkeys(ranges)))


# --- endoflife.date --------------------------------------------------------------


def _text(value) -> str:
    if value is True:
        return "true"
    if value is False or value is None:
        return "false" if value is False else ""
    return str(value)


def parse_eol_full(doc: dict) -> tuple[list[tuple[str, ...]], list[tuple[str, str]],
                                       set[str]]:
    """The whole catalogue: release lines `(slug, cycle, released, eol, latest,
    latest_date, lts, maintained)`, the CPE `vendor:product` each product
    declares, and every product name.

    `eol` is the end date when one is given, else `true`/`false`: `isEol` is
    computed on the day the file was generated, a date is compared with the
    session's own."""
    lines: list[tuple[str, ...]] = []
    cpes: list[tuple[str, str]] = []
    names: set[str] = set()
    for product in doc.get("result") or []:
        slug = product.get("name")
        if not slug:
            continue
        names.add(slug)
        for ident in product.get("identifiers") or []:
            if ident.get("type") != "cpe":
                continue
            parts = re.split(r"(?<!\\):", ident.get("id") or "")
            if parts[:2] == ["cpe", "2.3"] and len(parts) >= 5:
                cpes.append((f"{parts[3].lower()}:{parts[4].lower()}", slug))
            elif parts[:1] == ["cpe"] and len(parts) >= 4 and parts[1].startswith("/"):
                cpes.append((f"{parts[2].lower()}:{parts[3].lower()}", slug))
        for r in product.get("releases") or []:
            if not isinstance(r, dict) or not r.get("name"):
                continue
            latest = r.get("latest") or {}
            ended = r.get("eolFrom") or ("true" if r.get("isEol") else "false")
            lines.append((slug, str(r["name"]), _text(r.get("releaseDate")), _text(ended),
                          _text(latest.get("name") if isinstance(latest, dict) else latest),
                          _text(latest.get("date") if isinstance(latest, dict) else ""),
                          _text(r.get("isLts")), _text(r.get("isMaintained"))))
    return lines, list(dict.fromkeys(cpes)), names


def parse_eol(slug: str, cycles: list) -> list[tuple[str, ...]]:
    """(slug, cycle, released, eol, latest, latest_date, lts) per cycle."""
    out = []
    for c in cycles or []:
        if not isinstance(c, dict) or c.get("cycle") in (None, ""):
            continue
        out.append((slug, str(c["cycle"]), _text(c.get("releaseDate")), _text(c.get("eol")),
                    _text(c.get("latest")), _text(c.get("latestReleaseDate")),
                    _text(c.get("lts"))))
    return out
