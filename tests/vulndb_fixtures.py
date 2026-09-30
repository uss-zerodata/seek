"""Small, synthetic copies of the public feeds, in their real shapes.

Identifiers are `CVE-2099-*` and `GHSA-test-*` on purpose: the tests are about
the shapes and the matching, and made-up ids cannot be mistaken for real facts.
"""

from __future__ import annotations

import gzip
import hashlib
import http.server
import io
import json
import threading
import zipfile
from contextlib import contextmanager
from pathlib import Path

from seek.vulndb import eol
from seek.vulndb.sources import Urls


def _cve(cid, nodes, score=7.5, severity="HIGH", metric="cvssMetricV31", status="Analyzed",
         summary="A synthetic flaw."):
    data = {"baseScore": score, "vectorString": f"CVSS:3.1/AV:N/{cid}"}
    entry = {"source": "nvd@nist.gov", "type": "Primary", "cvssData": data}
    if metric == "cvssMetricV2":
        entry["baseSeverity"] = severity
    else:
        data["baseSeverity"] = severity
    return {"cve": {
        "id": cid, "published": "2099-01-01T00:00:00", "lastModified": "2099-01-02T00:00:00",
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": summary}, {"lang": "es", "value": "x"}],
        "metrics": {metric: [entry]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
        "configurations": [{"nodes": nodes}] if nodes else [],
        "references": [{"url": f"https://example.test/{cid}"}],
    }}


def _match(criteria, vulnerable=True, **bounds):
    return {"vulnerable": vulnerable, "criteria": criteria, "matchCriteriaId": "x", **bounds}


def nvd_items(year: int) -> list[dict]:
    if year != 2021:
        return []
    return [
        # a range, under NVD's current vendor name for nginx
        _cve("CVE-2099-0001", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionStartIncluding="0.6.18",
            versionEndExcluding="1.20.1")]}], score=7.7),
        # an exact version
        _cve("CVE-2099-0002", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*")]}], score=9.8,
            severity="CRITICAL"),
        # "an app running on Linux": the platform must not inherit it
        _cve("CVE-2099-0003", [
            {"operator": "OR", "cpeMatch": [_match("cpe:2.3:a:example:app:*:*:*:*:*:*:*:*")]},
            {"operator": "OR", "cpeMatch": [_match(
                "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", vulnerable=False)]}]),
        # CVSS v2 only, with the version split into version + update (8.9 / p1)
        _cve("CVE-2099-0004", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*")]}], score=5.0,
            severity="MEDIUM", metric="cvssMetricV2"),
        # also under the old nginx vendor, with a range only a bound decides
        _cve("CVE-2099-0005", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:igor_sysoev:nginx:*:*:*:*:*:*:*:*", versionEndIncluding="1.16.1")]}],
            score=5.3, severity="MEDIUM"),
        # rejected: must not be stored
        _cve("CVE-2099-0006", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")]}], status="Rejected"),
        # jquery in NVD, and in OSV under this CVE alias
        _cve("CVE-2099-0007", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:jquery:jquery:*:*:*:*:*:*:*:*", versionStartIncluding="1.2",
            versionEndExcluding="3.5.0")]}], score=6.1, severity="MEDIUM"),
        # Samba, to check a scan-reported id meets the database's
        _cve("CVE-2099-0008", [{"operator": "OR", "cpeMatch": [_match(
            "cpe:2.3:a:samba:samba:*:*:*:*:*:*:*:*", versionEndExcluding="4.6.4")]}]),
    ]


OSV = [
    {"id": "GHSA-test-jq01", "aliases": ["CVE-2099-0007"], "summary": "jQuery XSS",
     "modified": "2099-01-01T00:00:00Z",
     "affected": [{"package": {"ecosystem": "npm", "name": "jquery"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"},
                                                            {"fixed": "3.5.0"}]}],
                   "database_specific": {"severity": "MODERATE"}}],
     "references": [{"type": "ADVISORY", "url": "https://example.test/GHSA-test-jq01"}]},
    {"id": "GHSA-test-jq02", "aliases": [], "summary": "jQuery prototype pollution",
     "modified": "2099-01-01T00:00:00Z",
     "affected": [{"package": {"ecosystem": "npm", "name": "jquery"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                            {"fixed": "3.4.0"}]}],
                   "database_specific": {"severity": "HIGH"}}]},
    {"id": "GHSA-test-lp01", "summary": "unrelated",
     "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"},
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
]

EOL = {
    "nginx": [
        {"cycle": "1.26", "releaseDate": "2024-04-23", "eol": False, "latest": "1.26.2"},
        {"cycle": "1.24", "releaseDate": "2023-04-11", "eol": "2024-04-23",
         "latest": "1.24.0"},
        {"cycle": "1.16", "releaseDate": "2019-04-23", "eol": "2020-04-21",
         "latest": "1.16.1"},
    ],
    "php": [
        {"cycle": "8.3", "releaseDate": "2023-11-23", "eol": "2027-12-31", "latest": "8.3.12"},
        {"cycle": "7.4", "releaseDate": "2019-11-28", "eol": "2022-11-28", "latest": "7.4.33"},
    ],
    "apache-http-server": [
        {"cycle": "2.4", "releaseDate": "2012-02-21", "eol": False, "latest": "2.4.62"},
    ],
    "tomcat": [
        {"cycle": "9", "releaseDate": "2018-01-18", "eol": "2026-12-01", "latest": "9.0.96"},
    ],
}
# One slug endoflife.date does not list, to prove the update says so.
UNKNOWN_SLUG = "mssqlserver"


def _gz(obj) -> bytes:
    return gzip.compress(json.dumps(obj).encode())


def build(root: Path, years=range(2002, 2027), osv=OSV) -> Path:
    """Write the three sources' files under `root`, laid out like the real sites."""
    (root / "nvd").mkdir(parents=True, exist_ok=True)
    feeds = {str(y): nvd_items(y) for y in years}
    feeds["modified"] = []
    for name, items in feeds.items():
        data = _gz({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": items})
        (root / "nvd" / f"nvdcve-2.0-{name}.json.gz").write_bytes(data)
        sha = hashlib.sha256(gzip.decompress(data)).hexdigest().upper()
        (root / "nvd" / f"nvdcve-2.0-{name}.meta").write_text(
            f"lastModifiedDate:2099-01-02T00:00:00\r\nsize:{len(data)}\r\nsha256:{sha}\r\n")
    (root / "osv" / "npm").mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for record in osv:
            z.writestr(f"{record['id']}.json", json.dumps(record))
    (root / "osv" / "npm" / "all.zip").write_bytes(buf.getvalue())
    (root / "eol").mkdir(parents=True, exist_ok=True)
    known = sorted(set(eol.SLUGS.values()) - {UNKNOWN_SLUG})
    (root / "eol" / "all.json").write_text(json.dumps(known))
    for slug in known:
        (root / "eol" / f"{slug}.json").write_text(json.dumps(EOL.get(slug, [])))
    return root


def set_modified(root: Path, items: list[dict]) -> None:
    """Replace the rolling `modified` feed (what an incremental update reads)."""
    data = _gz({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": items})
    (root / "nvd" / "nvdcve-2.0-modified.json.gz").write_bytes(data)
    sha = hashlib.sha256(gzip.decompress(data)).hexdigest().upper()
    (root / "nvd" / "nvdcve-2.0-modified.meta").write_text(f"sha256:{sha}\r\n")


@contextmanager
def serve(root: Path):
    """The fixture tree over HTTP on a loopback port; yields the `Urls` for it."""
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(root), **kw)

        def log_message(self, *a):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        yield Urls(nvd=f"{base}/nvd", osv=f"{base}/osv", eol=f"{base}/eol")
    finally:
        server.shutdown()
        server.server_close()


def database(root: Path, today=None) -> Path:
    """A built database under `root`, from the fixture feeds over loopback."""
    from datetime import date

    from seek.vulndb import update

    feeds = build(root / "www")
    path = root / "vulndb.sqlite3"
    with serve(feeds) as urls:
        results = update.run(path, urls=urls, today=today or date(2026, 10, 1))
    assert not any(r.error for r in results), results
    return path
