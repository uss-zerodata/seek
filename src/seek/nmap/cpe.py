"""CPE identifiers, and the table that names a product the same way everywhere.

nmap writes CPE 2.2 URIs (`cpe:/a:openbsd:openssh:8.2p1`); vulnerability
databases are searched by the CPE 2.3 formatted string
(`cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*`). `Cpe` reads either and writes
both.

`ALIASES` does two jobs with one entry: it makes `Nginx` (a technology
detector), `nginx` (nmap) and `igor_sysoev:nginx` (an nmap CPE) one product, and
it is the *only* way a product nmap did not give a CPE for gets one. A name that
is not in the table has no CPE - the vendor is never guessed from the product
name, because a wrong CPE turns into wrong vulnerabilities downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

# --- the identifier ----------------------------------------------------------

# Characters a 2.3 formatted string carries unescaped; everything else printable
# is quoted with a backslash (NISTIR 7695, 6.2.2.2 - `.`, `-` and `_` are
# unquoted in the formatted-string binding).
_FS_PLAIN = re.compile(r"[A-Za-z0-9._\-]")
# The 2.2 URI binding percent-encodes the same set.
_URI_PLAIN = _FS_PLAIN


def _fs_escape(value: str) -> str:
    if not value:
        return "*"
    return "".join(c if _FS_PLAIN.match(c) else "\\" + c for c in value)


def _uri_escape(value: str) -> str:
    return "".join(c if _URI_PLAIN.match(c) else f"%{ord(c):02x}"
                   for c in value)


def _uri_unescape(value: str) -> str:
    return re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)


def _fs_unescape(value: str) -> str:
    return "" if value in ("*", "-") else re.sub(r"\\(.)", r"\1", value)


@dataclass(frozen=True, slots=True)
class Cpe:
    """The four parts of a CPE this application uses. `part` is `a`
    (application), `o` (operating system) or `h` (hardware)."""

    part: str
    vendor: str
    product: str
    version: str = ""

    @property
    def key(self) -> str:
        """`vendor:product` - what the alias table is keyed by."""
        return f"{self.vendor}:{self.product}"

    def with_version(self, version: str) -> Cpe:
        return Cpe(self.part, self.vendor, self.product, version)

    @property
    def uri(self) -> str:
        """The CPE 2.2 URI form, as nmap writes it; trailing empties dropped."""
        return _uri(self)

    @property
    def fs(self) -> str:
        """The CPE 2.3 formatted string; an absent version is `*` (any)."""
        return _fs(self)


# An engagement holds a handful of distinct CPEs on hundreds of thousands of
# services; binding and parsing each one once is what keeps the inventory's
# build and its tab linear in services rather than in string work.
@lru_cache(maxsize=8192)
def _uri(c: Cpe) -> str:
    parts = [c.vendor, c.product, c.version]
    while parts and not parts[-1]:
        parts.pop()
    return "cpe:/" + ":".join([c.part, *(_uri_escape(p) for p in parts)])


@lru_cache(maxsize=8192)
def _fs(c: Cpe) -> str:
    return ":".join(["cpe:2.3", c.part, _fs_escape(c.vendor), _fs_escape(c.product),
                     _fs_escape(c.version), "*", "*", "*", "*", "*", "*", "*"])


@lru_cache(maxsize=8192)
def parse(text: str) -> Cpe | None:
    """A CPE from either binding, or `None` when `text` is not one."""
    text = text.strip()
    if text.startswith("cpe:2.3:"):
        # Split on colons that are not escaped.
        fields = re.split(r"(?<!\\):", text)[2:]
        if len(fields) < 3:
            return None
        part, vendor, product = fields[0], _fs_unescape(fields[1]), _fs_unescape(fields[2])
        version = _fs_unescape(fields[3]) if len(fields) > 3 else ""
    elif text.startswith("cpe:/"):
        fields = text[5:].split(":")
        if len(fields) < 3:
            return None
        part, vendor, product = fields[0], _uri_unescape(fields[1]), _uri_unescape(fields[2])
        version = _uri_unescape(fields[3]) if len(fields) > 3 else ""
    else:
        return None
    if part not in ("a", "o", "h") or not vendor or not product:
        return None
    return Cpe(part, vendor.lower(), product.lower(), version)


# --- the alias table ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Product:
    """One product, however a source spells it."""

    key: str
    display: str
    kind: str          # "a", "o" or "h" - the CPE part
    vendor: str
    product: str

    def cpe(self, version: str = "") -> Cpe:
        return Cpe(self.kind, self.vendor, self.product, version)


# (key, display, kind, "vendor:product", other CPE vendor:products, spellings)
# Spellings are what nmap's `product`, a technology detector and a header token
# call it; they are matched after `normal()`. A spelling that names something
# *other* than the product's own version does not belong here - `Apache-Coyote`
# is Tomcat's connector with a version of its own, and `pve-api-daemon/3.0` is
# not Proxmox VE 3.0.
_TABLE: tuple[tuple[str, str, str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    # web servers and proxies
    ("nginx", "nginx", "a", "f5:nginx", ("igor_sysoev:nginx", "nginx:nginx"),
     ("nginx",)),
    ("apache-httpd", "Apache HTTP Server", "a", "apache:http_server", (),
     ("apache httpd", "apache http server", "apache", "apache2")),
    ("apache-tomcat", "Apache Tomcat", "a", "apache:tomcat", (),
     ("apache tomcat", "tomcat", "apache tomcat/coyote jsp engine")),
    ("iis", "Microsoft IIS", "a", "microsoft:internet_information_services",
     ("microsoft:iis",), ("microsoft iis httpd", "microsoft-iis", "iis", "microsoft iis")),
    ("lighttpd", "lighttpd", "a", "lighttpd:lighttpd", (), ("lighttpd",)),
    ("caddy", "Caddy", "a", "caddyserver:caddy", (), ("caddy", "caddy httpd")),
    ("traefik", "Traefik", "a", "traefik:traefik", (), ("traefik",)),
    ("haproxy", "HAProxy", "a", "haproxy:haproxy", (), ("haproxy", "haproxy http proxy")),
    ("envoy", "Envoy", "a", "envoyproxy:envoy", (), ("envoy",)),
    ("squid", "Squid", "a", "squid-cache:squid", (), ("squid", "squid http proxy")),
    ("varnish", "Varnish", "a", "varnish-cache:varnish", (),
     ("varnish", "varnish http accelerator")),
    ("openresty", "OpenResty", "a", "openresty:openresty", (),
     ("openresty", "openresty web app server")),
    ("litespeed", "LiteSpeed Web Server", "a", "litespeedtech:litespeed_web_server", (),
     ("litespeed", "litespeed httpd")),
    ("jetty", "Jetty", "a", "eclipse:jetty", ("mortbay:jetty",), ("jetty",)),
    ("gunicorn", "Gunicorn", "a", "gunicorn:gunicorn", (), ("gunicorn",)),
    ("uvicorn", "Uvicorn", "a", "encode:uvicorn", (), ("uvicorn",)),
    ("werkzeug", "Werkzeug", "a", "palletsprojects:werkzeug", (),
     ("werkzeug", "werkzeug httpd")),
    ("webmin", "Webmin", "a", "webmin:webmin", (), ("webmin", "miniserv", "webmin httpd")),
    # runtimes and frameworks
    ("php", "PHP", "a", "php:php", (), ("php",)),
    ("python", "Python", "a", "python:python", (), ("python",)),
    ("nodejs", "Node.js", "a", "nodejs:node.js", (), ("node.js", "nodejs")),
    ("express", "Express", "a", "expressjs:express", (),
     ("express", "node.js express framework")),
    ("aspnet", "ASP.NET", "a", "microsoft:asp.net", (), ("asp.net", "microsoft asp.net")),
    ("django", "Django", "a", "djangoproject:django", (), ("django",)),
    ("rails", "Ruby on Rails", "a", "rubyonrails:rails", (),
     ("ruby on rails", "rails")),
    ("openssl", "OpenSSL", "a", "openssl:openssl", (), ("openssl",)),
    # applications
    ("wordpress", "WordPress", "a", "wordpress:wordpress", (), ("wordpress",)),
    ("drupal", "Drupal", "a", "drupal:drupal", (), ("drupal",)),
    ("typo3", "TYPO3", "a", "typo3:typo3", (), ("typo3", "typo3 cms")),
    ("grafana", "Grafana", "a", "grafana:grafana", (), ("grafana",)),
    ("jenkins", "Jenkins", "a", "jenkins:jenkins", (), ("jenkins",)),
    ("gitlab", "GitLab", "a", "gitlab:gitlab", (), ("gitlab",)),
    ("proxmox-ve", "Proxmox VE", "a", "proxmox:virtual_environment",
     ("proxmox:proxmox_virtual_environment",),
     ("proxmox ve", "proxmox virtual environment")),
    ("synology-dsm", "Synology DiskStation Manager", "a", "synology:diskstation_manager",
     (), ("synology diskstation", "synology dsm", "synology diskstation manager")),
    # client-side libraries
    ("jquery", "jQuery", "a", "jquery:jquery", (), ("jquery",)),
    ("bootstrap", "Bootstrap", "a", "getbootstrap:bootstrap", (), ("bootstrap",)),
    ("lodash", "Lodash", "a", "lodash:lodash", (), ("lodash",)),
    ("vuejs", "Vue.js", "a", "vuejs:vue.js", (), ("vue.js", "vue")),
    ("react", "React", "a", "facebook:react", (), ("react",)),
    ("angularjs", "AngularJS", "a", "angularjs:angular.js", (), ("angularjs",)),
    # remote access and file transfer
    ("openssh", "OpenSSH", "a", "openbsd:openssh", (), ("openssh",)),
    ("dropbear", "Dropbear SSH", "a", "dropbear_ssh_project:dropbear_ssh", (),
     ("dropbear", "dropbear sshd")),
    ("vsftpd", "vsftpd", "a", "beasts:vsftpd", (), ("vsftpd",)),
    ("proftpd", "ProFTPD", "a", "proftpd:proftpd", (), ("proftpd",)),
    ("pure-ftpd", "Pure-FTPd", "a", "pureftpd:pure-ftpd", (), ("pure-ftpd", "pure ftpd")),
    ("filezilla-server", "FileZilla Server", "a", "filezilla-project:filezilla_server",
     (), ("filezilla server", "filezilla ftpd")),
    ("samba", "Samba", "a", "samba:samba", (), ("samba", "samba smbd")),
    # mail
    ("postfix", "Postfix", "a", "postfix:postfix", (), ("postfix", "postfix smtpd")),
    ("exim", "Exim", "a", "exim:exim", (), ("exim", "exim smtpd")),
    ("sendmail", "Sendmail", "a", "sendmail:sendmail", (), ("sendmail",)),
    ("dovecot", "Dovecot", "a", "dovecot:dovecot", (),
     ("dovecot", "dovecot imapd", "dovecot pop3d")),
    ("exchange", "Microsoft Exchange Server", "a", "microsoft:exchange_server", (),
     ("microsoft exchange smtpd", "microsoft exchange server")),
    # databases and caches
    ("mysql", "MySQL", "a", "oracle:mysql", ("mysql:mysql",), ("mysql",)),
    ("mariadb", "MariaDB", "a", "mariadb:mariadb", (), ("mariadb",)),
    ("postgresql", "PostgreSQL", "a", "postgresql:postgresql", (),
     ("postgresql", "postgresql db")),
    ("redis", "Redis", "a", "redis:redis", (), ("redis", "redis key-value store")),
    ("mongodb", "MongoDB", "a", "mongodb:mongodb", (), ("mongodb",)),
    ("elasticsearch", "Elasticsearch", "a", "elastic:elasticsearch",
     ("elasticsearch:elasticsearch",), ("elasticsearch", "elasticsearch rest api")),
    ("memcached", "Memcached", "a", "memcached:memcached", (), ("memcached",)),
    ("mssql", "Microsoft SQL Server", "a", "microsoft:sql_server", (),
     ("microsoft sql server",)),
    # name service
    ("bind", "ISC BIND", "a", "isc:bind", (), ("isc bind", "bind")),
    ("dnsmasq", "dnsmasq", "a", "thekelleys:dnsmasq", (), ("dnsmasq",)),
    ("unbound", "Unbound", "a", "nlnetlabs:unbound", (), ("unbound",)),
    # operating systems
    ("linux", "Linux", "o", "linux:linux_kernel", (), ("linux", "linux kernel")),
    ("windows", "Microsoft Windows", "o", "microsoft:windows", (),
     ("windows", "microsoft windows")),
)


def normal(name: str) -> str:
    """How a name is compared: case-folded, whitespace collapsed."""
    return " ".join(name.casefold().split())


def _build() -> tuple[dict[str, Product], dict[str, Product], dict[str, tuple[str, ...]]]:
    by_name: dict[str, Product] = {}
    by_cpe: dict[str, Product] = {}
    keys: dict[str, tuple[str, ...]] = {}
    for key, display, kind, cpe_key, more_cpes, spellings in _TABLE:
        vendor, product = cpe_key.split(":", 1)
        entry = Product(key, display, kind, vendor, product)
        keys[key] = (cpe_key, *more_cpes)
        for cpe_name in (cpe_key, *more_cpes):
            by_cpe[cpe_name] = entry
        for spelling in (key, display, *spellings):
            by_name[normal(spelling)] = entry
    return by_name, by_cpe, keys


ALIASES, _BY_CPE, _CPE_KEYS = _build()


def cpe_keys(product_key: str) -> tuple[str, ...]:
    """Every `vendor:product` a product is known by - NVD renames vendors
    (`igor_sysoev:nginx` became `f5:nginx`), and records under the old name
    still describe the same software."""
    return _CPE_KEYS.get(product_key, ())


@lru_cache(maxsize=8192)
def lookup(name_or_cpe: str) -> Product | None:
    """The table's entry for a product name or a CPE, or `None`."""
    if name_or_cpe.startswith("cpe:"):
        cpe = parse(name_or_cpe)
        return _BY_CPE.get(cpe.key) if cpe is not None else None
    return ALIASES.get(normal(name_or_cpe))


@lru_cache(maxsize=8192)
def product_key(name: str) -> str:
    """The key a product is grouped by: the table's, or its normalised name."""
    entry = lookup(name)
    return entry.key if entry is not None else normal(name)
