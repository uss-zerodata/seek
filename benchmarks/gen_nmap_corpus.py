"""Generate an engagement-scale corpus of nmap XML, reproducibly.

Every performance figure quoted for the `responsive-large-engagements` change
is measured against a corpus this script writes, so the numbers can be
reproduced rather than remembered::

    uv run python benchmarks/gen_nmap_corpus.py /tmp/engagement
    uv run python benchmarks/gen_nmap_corpus.py /tmp/small --files 6 --hosts 40

The default is the shape the change was measured on: 120 files over a pool of
24 200 addresses, each file naming 500 of them with a dozen ports apiece. That
is roughly 110 MB of XML - a large but ordinary engagement directory, not a
pathological one.

The output is real nmap XML as far as the parser is concerned: `<!DOCTYPE
nmaprun>`, a `<nmaprun>` root, `-Pn` on some runs, service records with and
without `-sV` identification, and a scattering of NSE output (`ssl-cert`,
`vulners`) so that `names.attach` and `vulns.attach` have work to do. Nothing
here is a real host; the addresses are drawn from RFC 5737 documentation space.

Written straight out rather than through ElementTree: a hundred megabytes of
generated text is the point, and building a tree to serialise it would cost
more than the benchmark it feeds.
"""

from __future__ import annotations

import argparse
import random
import time
from pathlib import Path

# RFC 5737 documentation space: 3 x /24 is not enough addresses, so the pool
# spreads over the whole 198.51.100.0/16-worth of the second block by treating
# it as a flat counter. Nothing routes; nothing is ever contacted.
_BASE = (198, 51)

_SERVICES = [
    (22, "tcp", "ssh", "OpenSSH", "8.9p1", "Ubuntu Linux; protocol 2.0"),
    (25, "tcp", "smtp", "Postfix smtpd", "", ""),
    (53, "tcp", "domain", "ISC BIND", "9.18.12", ""),
    (80, "tcp", "http", "nginx", "1.24.0", ""),
    (110, "tcp", "pop3", "Dovecot pop3d", "", ""),
    (139, "tcp", "netbios-ssn", "Samba smbd", "4.6.2", ""),
    (443, "tcp", "https", "Apache httpd", "2.4.57", "(Debian)"),
    (445, "tcp", "microsoft-ds", "Windows Server 2019", "", ""),
    (631, "tcp", "ipp", "CUPS", "2.4", ""),
    (3128, "tcp", "http-proxy", "Squid http proxy", "5.7", ""),
    (3306, "tcp", "mysql", "MySQL", "8.0.33", ""),
    (3389, "tcp", "ms-wbt-server", "Microsoft Terminal Services", "", ""),
    (5432, "tcp", "postgresql", "PostgreSQL DB", "15.3", ""),
    (6379, "tcp", "redis", "Redis key-value store", "7.0.11", ""),
    (8080, "tcp", "http-proxy", "Jetty", "9.4.51", ""),
    (8443, "tcp", "https-alt", "Tomcat", "9.0.75", ""),
    (9200, "tcp", "wap-wsp", "Elasticsearch REST API", "8.7.1", ""),
    (27017, "tcp", "mongod", "MongoDB", "6.0.6", ""),
]

# (name, argument line, `-Pn`, how much the scan established). A real
# engagement is phases, not one big scan: discovery names hosts and no ports,
# a port scan guesses services from nmap's own table, and a version scan
# probes them - which is what makes the merge's probe-over-guess rule matter
# here rather than only in a unit test.
_DISCOVERY, _PORTS, _PROBED = 0, 1, 2
_PHASES = [
    ("01-discovery", "nmap -vv -T4 -n -sn -PE -PS22,80,443 -oA 01-discovery",
     False, _DISCOVERY),
    ("02-services", "nmap -vv -T4 -n -Pn -sS --top-ports 1000 -oA 02-services",
     True, _PORTS),
    ("03-versions", "nmap -vv -T4 -n -Pn -sV --script ssl-cert,vulners -oA 03-versions",
     True, _PROBED),
]


def _address(index: int) -> str:
    """The `index`-th address of the pool, as a dotted quad."""
    return f"{_BASE[0]}.{_BASE[1]}.{(index // 254) % 254}.{index % 254 + 1}"


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def _comment(text: str) -> str:
    """nmap's own escaping for the command it repeats in an XML comment.

    A comment may not contain `--`, and every real preset has a long option in
    it, so nmap writes each dash of a long option as `&#45;`. A fixture that
    quietly dropped the long options would not be exercising the reader on the
    shape it actually meets.
    """
    return _escape(text).replace("-", "&#45;")


def _cert_script(name: str) -> str:
    """An `ssl-cert` result whose SANs `names.attach` will lift out.

    The SANs live in the structured `<table>`, never in the text output, which
    is exactly the trap the real reader has to survive - so the fixture has to
    reproduce it or it tests nothing.
    """
    sans = "".join(f'<elem>DNS:{n}</elem>' for n in (name, f"www.{name}", f"api.{name}"))
    return (
        '<script id="ssl-cert" output="Subject: commonName=' + name + '">'
        '<table key="subject"><elem key="commonName">' + name + '</elem></table>'
        '<table key="extensions"><table>'
        '<elem key="name">X509v3 Subject Alternative Name</elem>'
        '<elem key="value">DNS:' + name + ', DNS:www.' + name + '</elem>'
        '</table></table>'
        '<table key="sans">' + sans + '</table>'
        '</script>'
    )


_VULNERS = (
    '<script id="vulners" output="cpe:/a:openbsd:openssh:8.9p1: CVE-2023-38408 9.8">'
    '<table key="cpe:/a:openbsd:openssh:8.9p1">'
    '<table><elem key="id">CVE-2023-38408</elem><elem key="cvss">9.8</elem>'
    '<elem key="type">cve</elem></table>'
    '<table><elem key="id">CVE-2023-28531</elem><elem key="cvss">9.8</elem>'
    '<elem key="type">cve</elem></table>'
    '</table></script>'
)


def _service_xml(rng: random.Random, spec: tuple, probed: bool, host_no: int) -> str:
    port, proto, name, product, version, extra = spec
    out = [f'<port protocol="{proto}" portid="{port}">'
           f'<state state="open" reason="syn-ack" reason_ttl="64"/>']
    if probed:
        bits = [f'name="{name}"']
        if product:
            bits.append(f'product="{_escape(product)}"')
        if version:
            bits.append(f'version="{version}"')
        if extra:
            bits.append(f'extrainfo="{_escape(extra)}"')
        bits.append('method="probed" conf="10"')
        out.append(f'<service {" ".join(bits)}/>')
    else:
        # No `-sV`: nmap names the port from its own table and says so.
        out.append(f'<service name="{name}" method="table" conf="3"/>')
    if port in (443, 8443) and probed:
        out.append(_cert_script(f"host{host_no}.example.net"))
    if port == 22 and probed and rng.random() < 0.15:
        out.append(_VULNERS)
    out.append('</port>')
    return "".join(out)


def _host_xml(rng: random.Random, index: int, ports: int, depth: int,
              disabled_ping: bool) -> str:
    address = _address(index)
    reason = "user-set" if disabled_ping else "echo-reply"
    probed = depth == _PROBED
    picks = ([] if depth == _DISCOVERY
             else rng.sample(_SERVICES, min(ports, len(_SERVICES))))
    parts = ['<host starttime="1700000000" endtime="1700000300">',
             f'<status state="up" reason="{reason}" reason_ttl="0"/>',
             f'<address addr="{address}" addrtype="ipv4"/>']
    if rng.random() < 0.4:
        parts.append('<hostnames><hostname name="host'
                     f'{index}.example.net" type="PTR"/></hostnames>')
    else:
        parts.append('<hostnames/>')
    parts.append('<ports>')
    parts += [_service_xml(rng, spec, probed, index)
              for spec in sorted(picks, key=lambda s: s[0])]
    parts.append('</ports>')
    if probed and rng.random() < 0.25:
        parts.append('<os><osmatch name="Linux 5.0 - 5.14" accuracy="95">'
                     '<osclass type="general purpose" vendor="Linux" '
                     'osfamily="Linux" osgen="5.X" accuracy="95"/>'
                     '</osmatch></os>')
    parts.append('</host>')
    return "".join(parts)


def write_corpus(out: Path, files: int, hosts: int, ports: int, pool: int,
                 seed: int = 1) -> list[Path]:
    """Write `files` scan files over a pool of `pool` addresses."""
    out.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)
    written: list[Path] = []
    for n in range(files):
        phase, args, disabled_ping, depth = _PHASES[n % len(_PHASES)]
        # Each file names a contiguous slice of the pool, wrapping round, so
        # every address is seen by several scans and the merge has real work.
        start = (n * max(1, hosts // 2)) % pool
        indices = [(start + i) % pool for i in range(hosts)]
        # Phases run in order and the whole engagement repeats, so the recorded
        # start times put the files in a history rather than a heap.
        started = 1700000000 + n * 3600
        body = "".join(_host_xml(rng, i, ports, depth, disabled_ping)
                       for i in indices)
        path = out / f"{phase}-{n:03d}.xml"
        path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE nmaprun>\n'
            f'<!-- Nmap 7.94 scan initiated as: {_comment(args)} -->\n'
            f'<nmaprun scanner="nmap" args="{_escape(args)}" start="{started}" '
            f'version="7.94" xmloutputversion="1.05">\n'
            f'{body}'
            f'<runstats><finished time="{started + 300}" elapsed="300.00"/>'
            f'<hosts up="{len(indices)}" down="0" total="{len(indices)}"/>'
            '</runstats>\n</nmaprun>\n',
            encoding="utf-8")
        written.append(path)
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", type=Path, help="directory to write the corpus into")
    ap.add_argument("--files", type=int, default=120)
    ap.add_argument("--hosts", type=int, default=500, help="host records per file")
    ap.add_argument("--ports", type=int, default=12, help="open ports per host")
    ap.add_argument("--pool", type=int, default=24200, help="distinct addresses")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    began = time.perf_counter()
    written = write_corpus(args.out, args.files, args.hosts, args.ports,
                           args.pool, args.seed)
    size = sum(p.stat().st_size for p in written)
    print(f"{len(written)} files, {size / 1e6:.1f} MB, up to {args.pool} distinct "
          f"hosts, in {time.perf_counter() - began:.1f}s -> {args.out}")


if __name__ == "__main__":
    main()
