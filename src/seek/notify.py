"""Telling an ntfy-compatible webhook that a run ended, or how far it has got.

**A message says nothing about the engagement.** It leaves the machine, so it
carries the preset or tool name, the outcome and the elapsed time - never a
target, an address, a name, a URL, a path, or a line the tool printed. The
builders here take those three things and nothing else, so they cannot leak
what they were never given.

ntfy's format is the plainest it accepts: POST to the topic URL, the message as
the body, `Title`, `Tags` and `Priority` as headers. stdlib `urllib`, no client
library: one request per message does not justify a dependency.
"""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit

MILESTONES = (25, 50, 75)
TIMEOUT = 10.0


class NotifyError(ValueError):
    """A notification URL that cannot be used, and why."""


def normalise(url: str) -> str:
    """The URL as it will be called: `https://` added when no scheme is given,
    refused unless http or https with a host. Empty stays empty (off)."""
    url = url.strip()
    if not url:
        return ""
    if "://" not in url:
        url = f"https://{url}"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise NotifyError(f"not an http(s) URL: {url!r}")
    if parts.username is not None or parts.password is not None:
        # No authentication is supported, and a password in the URL would be
        # shown in every review and written into the config file.
        raise NotifyError(f"credentials in the URL are not supported: {parts.hostname}")
    return url


@dataclass(frozen=True, slots=True)
class Message:
    title: str
    body: str
    tags: str
    priority: str = "default"


def duration(seconds: float) -> str:
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}h {minutes:02d}m" if hours else f"{minutes}m {secs:02d}s"


def ended(name: str, state: str, seconds: float) -> Message:
    """The message at the end of a run. `state` is "done", "failed" or
    "cancelled"."""
    verb, tags, priority = {
        "done": ("finished", "white_check_mark", "default"),
        "failed": ("failed", "x", "high"),
        "cancelled": ("was cancelled", "warning", "default"),
    }.get(state, (state, "grey_question", "default"))
    when = "in" if state == "done" else "after"
    return Message(f"seek: {name}", f"{name} {verb} {when} {duration(seconds)}",
                   tags, priority)


def milestone(name: str, percent: int, seconds: float) -> Message:
    return Message(f"seek: {name}", f"{name} is {percent}% done after {duration(seconds)}",
                   "hourglass_flowing_sand", "low")


def crossed(fraction: float | None, reached: int) -> int:
    """The highest milestone `fraction` has reached beyond `reached`, or 0.

    One message for a jump across several milestones would skip the ones in
    between; the caller sends each, so this returns the next one only and is
    asked again until it returns 0."""
    if fraction is None:
        return 0
    for mark in MILESTONES:
        if mark > reached and fraction * 100 >= mark:
            return mark
    return 0


def _header(text: str) -> str:
    # HTTP headers are Latin-1; a preset name may not be.
    return text.encode("ascii", "replace").decode("ascii")


def send(url: str, message: Message) -> None:
    """POST one message. Blocking - call it from a thread. Raises `OSError`
    (including `urllib.error.URLError`) when it does not arrive."""
    request = urllib.request.Request(
        url, data=message.body.encode("utf-8"), method="POST",
        headers={"Title": _header(message.title), "Tags": message.tags,
                 "Priority": message.priority,
                 "Content-Type": "text/plain; charset=utf-8"})
    # urlopen raises `HTTPError` itself for anything but 2xx, and follows 3xx.
    with urllib.request.urlopen(request, timeout=TIMEOUT):  # noqa: S310
        pass
