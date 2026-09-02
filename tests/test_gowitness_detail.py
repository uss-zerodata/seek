"""Capture results in the record they belong to.

Rendered against real scan data rather than stub hosts: the join between a
capture and a service is made on the URL, and `_service_urls` is what produces
those URLs - a stub that invents them would test the test, not the join.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from seek.gowitness import results as gw
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import detail

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _text(renderable, width: int = 110) -> str:
    console = Console(width=width, record=True, file=open("/dev/null", "w"))
    console.print(renderable)
    return console.export_text()


@pytest.fixture
def http_service():
    """A real host and one of its HTTP services, with the URLs it answers on."""
    scans = prepare(load([FIX / "basic.xml"]))
    for host in scans.hosts:
        for svc in host.open_services:
            urls = detail._service_urls(svc, host)
            if urls:
                return host, svc, urls
    pytest.skip("no HTTP service in the fixture")


# --- a service's URLs are annotated where they already are ---------------


def test_a_captured_url_is_annotated_under_itself(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=200, reason="OK",
                                    title="Home", server="nginx",
                                    technologies=["Cloudflare"])])
    text = _text(detail.service_detail(svc, host, shots))
    assert urls[0] in text
    assert "200 OK" in text
    assert "Home" in text and "nginx" in text and "Cloudflare" in text


def test_an_uncaptured_url_says_nothing_at_all(http_service):
    """Silence, not "not captured" - before any capture has been run that note
    would be on every URL in the project."""
    host, svc, urls = http_service
    text = _text(detail.service_detail(svc, host, gw.Captures()))
    assert urls[0] in text
    assert "not captured" not in text.lower()
    assert "200" not in text.split(urls[0])[-1][:40]


def test_a_record_with_no_captures_gains_no_section(http_service):
    host, _svc, _urls = http_service
    bare = _text(detail.host_detail(host, None))
    empty = _text(detail.host_detail(host, gw.Captures()))
    assert "Captures" not in bare
    assert "Captures" not in empty


def test_a_failed_capture_is_shown_with_its_reason(http_service):
    host, svc, urls = http_service
    shots = gw.Captures()
    shots.add_failures({urls[0]: "page load error net::ERR_CONNECTION_REFUSED"})
    text = _text(detail.service_detail(svc, host, shots))
    assert "✗" in text
    assert "ERR_CONNECTION_REFUSED" in text


def test_tls_is_shown_for_a_tls_capture(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=200, reason="OK",
                                    tls="TLS 1.3 · AES_128_GCM")])
    text = _text(detail.service_detail(svc, host, shots))
    assert "TLS 1.3" in text


def test_a_redirect_is_visible(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=301, reason="Moved",
                                    final_url="https://elsewhere/login")])
    text = _text(detail.service_detail(svc, host, shots))
    assert "https://elsewhere/login" in text


def test_a_status_that_repeats_its_title_is_not_said_twice(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=403, reason="Forbidden",
                                    title="403 Forbidden")])
    text = _text(detail.service_detail(svc, host, shots))
    assert text.count("403 Forbidden") == 1


# --- the host's summary --------------------------------------------------


def test_a_host_summarises_its_captures(http_service):
    host, _svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=200, reason="OK",
                                    title="Home")])
    text = _text(detail.host_detail(host, shots))
    assert "Captures" in text
    assert urls[0] in text and "Home" in text


def test_several_names_on_one_port_are_shown_separately(http_service):
    """Virtual hosting means one port serves several sites - collapsing them
    would hide the difference the capture was run to find."""
    host, _svc, urls = http_service
    if len(urls) < 2:
        pytest.skip("this service answers on only one URL")
    shots = gw.Captures([
        gw.Capture(url=urls[0], status=200, reason="OK", title="First site"),
        gw.Capture(url=urls[1], status=200, reason="OK", title="Second site"),
    ])
    text = _text(detail.host_detail(host, shots))
    assert "First site" in text and "Second site" in text
    assert urls[0] in text and urls[1] in text


def test_the_host_block_counts_what_it_shows(http_service):
    host, _svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=u, status=200, reason="OK")
                         for u in urls[:2]])
    text = _text(detail.host_detail(host, shots))
    assert f"Captures ({min(2, len(urls))})" in text


# --- colour reinforces, never replaces ------------------------------------


@pytest.mark.parametrize(("status", "style"), [
    (200, "green"), (301, "cyan"), (404, "yellow"), (500, "red"),
])
def test_the_status_style_follows_its_class(status, style):
    assert detail._status_style(gw.Capture(url="u", status=status)) == style


def test_a_failure_styles_as_an_error():
    assert detail._status_style(gw.Capture(url="u", failure="boom")) == "red"


def test_the_number_is_printed_whatever_the_colour(http_service):
    """Colour only speeds the scan; a reader who cannot tell the colours apart
    still gets the status code."""
    host, svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=404, reason="Not Found")])
    assert "404" in _text(detail.service_detail(svc, host, shots))
