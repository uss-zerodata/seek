"""Capture results in the record they belong to.

Rendered against real scan data rather than stub hosts: the join between a
capture and a service is made on the URL, and `service_urls` is what produces
those URLs - a stub that invents them would test the test, not the join.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from rich.console import Console

from seek.gowitness import results as gw
from seek.nmap.export import service_urls
from seek.nmap.merge import load
from seek.nmap.views import prepare
from seek.tui.nmap import detail

FIX = Path(__file__).parent / "fixtures" / "nmap"


def _text(renderable, width: int = 110) -> str:
    if isinstance(renderable, list):
        # A record's lines, as the terminal shows them - not the list's repr,
        # which now carries what each line is about (a capture, headers and all).
        renderable = detail.as_group(renderable)
    console = Console(width=width, record=True, file=open("/dev/null", "w"))
    console.print(renderable)
    return console.export_text()


@pytest.fixture
def http_service():
    """A real host and one of its HTTP services, with the URLs it answers on."""
    scans = prepare(load([FIX / "basic.xml"]))
    for host in scans.hosts:
        for svc in host.open_services:
            urls = service_urls(svc, host)
            if urls:
                return host, svc, urls
    pytest.skip("no HTTP service in the fixture")


# --- a service's URLs are annotated where they already are ---------------


def test_a_captured_url_is_annotated_under_itself(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([gw.Capture(url=urls[0], status=200, reason="OK",
                                    title="Home", headers=[("server", "nginx")],
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


# --- two depths ----------------------------------------------------------


def _rich_capture(url: str) -> gw.Capture:
    return gw.Capture(
        url=url, row_id=7, status=200, reason="OK", title="Login",
        protocol="h2", probed_at="2026-09-02 14:17:50", content_length=50,
        perception_group=2, technologies=[],
        headers=[("content-type", "text/html; charset=utf-8"),
                 ("x-powered-by", "authentik"),
                 ("x-frame-options", "DENY"),
                 ("vary", "Accept-Encoding\nAccept-Language")],
        cookies=[("session", "abc")],
        console=[("console.debug", "authentik(early): version 2026.5.6")],
        tls="TLS 1.3 · AES_128_GCM", sans=["sso.example"])


def test_the_pane_summarises_and_the_reader_lays_out(http_service):
    """The reader shows everything the pane shows, and may show more."""
    host, svc, urls = http_service
    shots = gw.Captures([_rich_capture(urls[0])])
    shallow = _text(detail.service_detail(svc, host, shots, full=False))
    deep = _text(detail.service_detail(svc, host, shots, full=True))

    # everything the pane says, the reader says too
    assert "200 OK" in shallow and "200 OK" in deep
    assert "TLS 1.3" in shallow and "TLS 1.3" in deep
    # and the reader says more
    assert "x-powered-by" not in shallow, "a full header list reached the pane"
    assert "x-powered-by" in deep
    assert "authentik(early): version" in deep, "console messages are in the reader"
    assert "authentik(early)" not in shallow


def test_the_pane_counts_headers_without_listing_them(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([_rich_capture(urls[0])])
    shallow = _text(detail.service_detail(svc, host, shots, full=False))
    assert "4 collected" in shallow


def test_a_missing_security_header_is_visible_at_both_depths(http_service):
    """An absence cannot be noticed by reading a list of what is present."""
    host, svc, urls = http_service
    shots = gw.Captures([_rich_capture(urls[0])])
    for full in (False, True):
        text = _text(detail.service_detail(svc, host, shots, full=full))
        assert "hsts" in text and "csp" in text


def test_cookies_and_certificate_names_reach_the_reader(http_service):
    host, svc, urls = http_service
    shots = gw.Captures([_rich_capture(urls[0])])
    deep = _text(detail.service_detail(svc, host, shots, full=True))
    assert "session" in deep
    assert "sso.example" in deep


def test_a_folded_header_value_stays_on_one_line(http_service):
    """`vary` can arrive with a newline in it, which would break the column."""
    host, svc, urls = http_service
    shots = gw.Captures([_rich_capture(urls[0])])
    deep = _text(detail.service_detail(svc, host, shots, full=True))
    line = next(x for x in deep.splitlines() if "Accept-Encoding" in x)
    assert "Accept-Language" in line


def test_a_derived_system_says_where_it_came_from(http_service):
    """The label earns its place when the name comes from somewhere the record
    does not already show - an identifying header that is not `server`."""
    host, svc, urls = http_service
    capture = gw.Capture(url=urls[0], status=200, reason="OK",
                         headers=[("x-authentik-id", "abc123")])
    text = _text(detail.service_detail(svc, host, gw.Captures([capture])))
    assert "abc123" in text
    assert "from x-authentik-id" in text, "a guess must be labelled as one"


def test_a_derived_name_is_not_repeated_beside_the_header_it_came_from(http_service):
    host, svc, urls = http_service
    capture = gw.Capture(url=urls[0], status=200, reason="OK",
                         headers=[("x-powered-by", "authentik")])
    text = _text(detail.service_detail(svc, host, gw.Captures([capture])))
    assert text.count("authentik") == 1, "the same name was printed twice"


def test_a_detected_technology_is_shown_without_a_guess_beside_it(http_service):
    host, svc, urls = http_service
    capture = gw.Capture(url=urls[0], status=200, reason="OK",
                         technologies=["Cloudflare"],
                         headers=[("server", "cloudflare")])
    text = _text(detail.service_detail(svc, host, gw.Captures([capture])))
    assert "Cloudflare" in text
    assert "from server" not in text


def test_a_record_with_no_captures_gains_nothing_at_either_depth(http_service):
    host, svc, _urls = http_service
    for full in (False, True):
        text = _text(detail.service_detail(svc, host, gw.Captures(), full=full))
        assert "headers" not in text.lower().split("scripts")[0]
        assert "Captures" not in _text(detail.host_detail(host, gw.Captures(), full))


def test_a_failed_capture_shows_no_metadata_block(http_service):
    """There is nothing to lay out - it never answered."""
    host, svc, urls = http_service
    shots = gw.Captures()
    shots.add_failures({urls[0]: "connection refused"})
    deep = _text(detail.service_detail(svc, host, shots, full=True))
    assert "connection refused" in deep
    assert "collected" not in deep


# --- every view's record, not only hosts and services --------------------


def _grouped(shots):
    """A by-service style bucket over a real host's services."""
    from seek.tui.nmap.views import Grouping

    scans = prepare(load([FIX / "basic.xml"]))
    members = [(h, s) for h in scans.hosts for s in h.open_services
               if service_urls(s, h)]
    return Grouping(key="service", label="http", members=members), members


def test_a_grouping_record_shows_its_members_captures():
    """by service / by product / by port and the names list are where the next
    thing to look at gets chosen; a bucket that says nothing about what its
    members served is where a capture is least use."""
    grouping, members = _grouped(None)
    url = service_urls(members[0][1], members[0][0])[0]
    shots = gw.Captures([gw.Capture(url=url, status=200, reason="OK", title="Home")])
    text = _text(detail.grouping_detail(grouping, shots))
    assert "Captures" in text
    assert "Home" in text


def test_a_grouping_with_no_captures_gains_nothing():
    grouping, _ = _grouped(None)
    assert "Captures" not in _text(detail.grouping_detail(grouping, gw.Captures()))
    assert "Captures" not in _text(detail.grouping_detail(grouping, None))


def test_a_service_group_record_shows_its_captures():
    from seek.nmap.views import service_groups

    scans = prepare(load([FIX / "basic.xml"]))
    group = next(g for g in service_groups(scans.hosts) if g.members
                 and service_urls(g.members[0][1], g.members[0][0]))
    host, svc = group.members[0]
    url = service_urls(svc, host)[0]
    shots = gw.Captures([gw.Capture(url=url, status=200, reason="OK", title="Home")])
    text = _text(detail.group_detail(group, shots))
    assert "Captures" in text and "Home" in text


def test_a_service_group_with_no_captures_gains_nothing():
    from seek.nmap.views import service_groups

    scans = prepare(load([FIX / "basic.xml"]))
    group = service_groups(scans.hosts)[0]
    assert "Captures" not in _text(detail.group_detail(group, gw.Captures()))
