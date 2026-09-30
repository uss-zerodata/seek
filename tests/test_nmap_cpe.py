"""CPE bindings and the alias table."""

from __future__ import annotations

import re

import pytest

from seek.nmap import cpe


def test_a_22_uri_reads_back():
    c = cpe.parse("cpe:/a:openbsd:openssh:8.2p1")
    assert c == cpe.Cpe("a", "openbsd", "openssh", "8.2p1")
    assert c.uri == "cpe:/a:openbsd:openssh:8.2p1"
    assert c.fs == "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*"


def test_an_unversioned_uri_has_any_version_in_23():
    c = cpe.parse("cpe:/a:igor_sysoev:nginx")
    assert c.version == ""
    assert c.uri == "cpe:/a:igor_sysoev:nginx"
    assert c.fs == "cpe:2.3:a:igor_sysoev:nginx:*:*:*:*:*:*:*:*"


def test_23_reads_back_to_the_same_cpe():
    c = cpe.Cpe("a", "microsoft", "asp.net", "4.0.30319")
    assert cpe.parse(c.fs) == c
    assert cpe.parse(c.uri) == c


def test_23_escapes_what_it_must():
    c = cpe.Cpe("a", "vendor", "prod", "1.0:beta*")
    assert c.fs.startswith("cpe:2.3:a:vendor:prod:1.0\\:beta\\*:")
    assert cpe.parse(c.fs) == c
    assert cpe.parse(c.uri) == c


def test_filling_in_a_version():
    c = cpe.parse("cpe:/a:igor_sysoev:nginx").with_version("1.16.1")
    assert c.uri == "cpe:/a:igor_sysoev:nginx:1.16.1"


@pytest.mark.parametrize("text", ["", "nginx", "cpe:/x:a:b", "cpe:/a:onlyvendor"])
def test_not_a_cpe(text):
    assert cpe.parse(text) is None


def test_every_spelling_of_nginx_is_one_product():
    keys = {cpe.product_key(n) for n in ("Nginx", "nginx", "NGINX")}
    keys.add(cpe.lookup("cpe:/a:igor_sysoev:nginx").key)
    keys.add(cpe.lookup("cpe:2.3:a:f5:nginx:1.2:*:*:*:*:*:*:*").key)
    assert keys == {"nginx"}


def test_nmap_and_detector_names_meet():
    assert cpe.product_key("Apache httpd") == cpe.product_key("Apache HTTP Server")
    assert cpe.product_key("Samba smbd") == cpe.product_key("samba")
    assert cpe.product_key("TYPO3 CMS") == "typo3"


def test_an_unknown_name_is_normalised_not_guessed():
    assert cpe.lookup("Synology  Photo  Station") is None
    assert cpe.product_key("Synology  Photo  Station") == "synology photo station"


def test_the_table_is_well_formed():
    keys = [row[0] for row in cpe._TABLE]
    assert len(keys) == len(set(keys)), "duplicate product keys"
    part = re.compile(r"^[a-z0-9_\-.]+:[a-z0-9_\-.]+$")
    seen: dict[str, str] = {}
    for key, _display, kind, cpe_key, more, spellings in cpe._TABLE:
        assert kind in ("a", "o", "h")
        for name in (cpe_key, *more):
            assert part.match(name), name
            assert seen.setdefault(name, key) == key, f"{name} names two products"
        for spelling in spellings:
            assert cpe.lookup(spelling).key == key, f"{spelling!r} is taken by another product"
