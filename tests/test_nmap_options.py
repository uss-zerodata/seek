"""The option catalogue: complete against nmap's summary, consistent with the
privilege check, and strict about values."""

from __future__ import annotations

import pytest

from seek.nmap import options, presets
from seek.nmap.options import BY_NAME, GROUPS, OPTIONS, check, expand, get, lookup, tokens

# Every option on nmap's option summary (nmap.org/book/man-briefoptions.html,
# 7.99), as nmap spells them. The summary's slash shorthands are expanded.
SUMMARY = """
-iL -iR --exclude --excludefile
-sL -sn -Pn -PS -PA -PU -PY -PE -PP -PM -PO -n -R --dns-servers --system-dns --traceroute
-sS -sT -sA -sW -sM -sU -sN -sF -sX --scanflags -sI -sY -sZ -sO -b
-p --exclude-ports -F -r --top-ports --port-ratio
-sV --version-intensity --version-light --version-all --version-trace
-sC --script --script-args --script-args-file --script-trace --script-updatedb --script-help
-O --osscan-limit --osscan-guess
-T --min-hostgroup --max-hostgroup --min-parallelism --max-parallelism
--min-rtt-timeout --max-rtt-timeout --initial-rtt-timeout --max-retries --host-timeout
--scan-delay --max-scan-delay --min-rate --max-rate
-f --mtu -D -S -e -g --source-port --proxies --data --data-string --data-length
--ip-options --ttl --spoof-mac --badsum
-oN -oX -oS -oG -oA -v -d --reason --open --packet-trace --iflist --append-output
--resume --noninteractive --stylesheet --webxml --no-stylesheet
-6 -A --datadir --send-eth --send-ip --privileged --unprivileged -V -h
""".split()

# Documented only in the man page sections, not the summary.
MAN_ONLY = """--resolve-all --unique --disable-arp-ping --discovery-ignore-rst -PR --allports
--max-os-tries --script-timeout --defeat-rst-ratelimit --defeat-icmp-ratelimit
--nsock-engine --randomize-hosts --adler32 --stats-every --servicedb --versiondb
--release-memory""".split()


@pytest.mark.parametrize("name", SUMMARY + MAN_ONLY)
def test_every_documented_option_is_catalogued(name):
    assert name in BY_NAME, name


def test_groups_are_nmaps_own_and_all_used():
    assert len(GROUPS) == 11
    assert {o.group for o in OPTIONS} == set(GROUPS)
    assert all(o.source in options.PAGES for o in OPTIONS)


def test_names_are_unique():
    names = [n for o in OPTIONS for n in o.names]
    assert len(names) == len(set(names))


_SAMPLE = {"number": "8", "real": "0.5", "time": "1s", "ports": "22", "portlist": "22",
           "protocols": "1", "list": "a,b", "hosts": "192.0.2.1", "choice": None,
           "hex": "0xff", "text": "x", "script": "vuln", "script-args": "a=b"}


def _sample(option) -> list[str]:
    if option.value is None:
        return tokens(option)
    value = option.value.choices[0] if option.value.form == "choice" \
        else _SAMPLE[option.value.form]
    return tokens(option, value)


@pytest.mark.parametrize("option", [o for o in OPTIONS if o.root], ids=lambda o: o.name)
def test_every_raw_packet_option_is_elevated(option):
    assert presets.needs_root(_sample(option)), option.name


@pytest.mark.parametrize("option", [o for o in OPTIONS if o.root is False],
                         ids=lambda o: o.name)
def test_connect_style_options_are_not_elevated(option):
    assert not presets.needs_root(_sample(option)), option.name


@pytest.mark.parametrize("name, args", presets.DEFAULT_PRESETS.items())
def test_every_shipped_preset_reads_with_no_unknown_option(name, args):
    argv = presets.parse_args(args)
    index = 0
    while index < len(argv):
        token = argv[index]
        for part in expand(token):
            found = lookup(part)
            assert found is not None, f"{name}: {part!r} is not catalogued"
            if found[2]:
                index += 1
        index += 1


@pytest.mark.parametrize("name, good, bad", [
    ("--host-timeout", ["30m", "900", "900s", "500ms", "2h", "1.5h"], ["fast", "30 m", "-1"]),
    ("-p", ["22", "-", "1-1024", "22,80,443", "U:53,T:21-25,80", "ftp,http*", "[-1024]",
            "P:6"], ["70000", "22;80", "a b"]),
    ("-PS", ["", "22,80", "1-1024"], ["T:22", "x"]),
    ("--version-intensity", ["0", "7", "9"], ["10", "-1", "light"]),
    ("--port-ratio", ["0", "0.5", "1"], ["1.5", "x"]),
    ("--mtu", ["8", "24"], ["7", "12", "0"]),
    ("--ttl", ["0", "64", "255"], ["256"]),
    ("-T", ["4", "aggressive"], ["6", "fast"]),
    ("--data", ["0xdeadbeef", "deadbeef", "\\xde\\xad"], ["0xzz", "hello"]),
    ("--exclude", ["192.0.2.1", "192.0.2.0/24,db.example"], ["no such host!"]),
    ("--script", ["vuln", "http-*", "default and not intrusive", "(a or b) and c"],
     ["(unbalanced"]),
    ("--data-string", ["hello"], ["a$b", "a`id`"]),
])
def test_values_are_checked_against_their_documented_form(name, good, bad):
    option = get(name)
    for text in good:
        assert check(option, text) is None, (name, text)
    for text in bad:
        assert check(option, text) is not None, (name, text)


def test_a_shell_character_is_named():
    assert "'$'" in check(get("--script-args"), "user=$USER")


@pytest.mark.parametrize("token, name, value, takes_next", [
    ("-p", "-p", None, True),
    ("-p22,80", "-p", "22,80", False),
    ("-p-", "-p", "-", False),
    ("-T4", "-T", "4", False),
    ("-PS22,80", "-PS", "22,80", False),
    ("-PS", "-PS", None, False),
    ("--script=vuln", "--script", "vuln", False),
    ("--script", "--script", None, True),
    ("-vv", "-v", None, False),
    ("-sS", "-sS", None, False),
    ("-oA", "-oA", None, True),
    ("--source-port", "-g", None, True),
])
def test_tokens_are_read_as_nmap_reads_them(token, name, value, takes_next):
    option, got, takes = lookup(token)
    assert (option.name, got, takes) == (name, value, takes_next)


def test_unknown_tokens_and_targets_are_not_options():
    assert lookup("192.0.2.1") is None
    assert lookup("--no-such-option") is None


def test_combined_scan_letters_expand():
    assert expand("-sUV") == ["-sU", "-sV"]
    assert expand("-sS") == ["-sS"]


def test_tokens_follow_the_attach_rules():
    assert tokens(get("-T"), "4") == ["-T4"]
    assert tokens(get("-PS"), "22,80") == ["-PS22,80"]
    assert tokens(get("-PS")) == ["-PS"]
    assert tokens(get("--max-retries"), "2") == ["--max-retries", "2"]
    assert tokens(get("-v"), count=3) == ["-v", "-v", "-v"]


def test_options_seek_controls_say_why():
    owned = {o.name for o in OPTIONS if o.owner}
    assert {"-oN", "-oX", "-oS", "-oG", "-oA", "--append-output", "-iL", "-iR", "--resume",
            "--iflist", "--script-help", "--script-updatedb", "-V", "-h"} == owned


def test_every_rule_names_catalogued_options_and_a_source():
    for rule in options.RULES:
        for name in rule.left | rule.right:
            assert name in BY_NAME, (rule.message, name)
        assert rule.source in options.PAGES or rule.source == "nmap"
        assert rule.kind in ("exclusive", "ignored", "advice")
