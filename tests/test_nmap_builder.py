"""The guided builder's model: steps, precedence, profiles, conflicts."""

from __future__ import annotations

import pytest

from seek.nmap import builder, presets
from seek.nmap.builder import (
    FAST,
    RELIABLE,
    Facts,
    State,
    advance,
    back,
    both,
    choices,
    jump,
    resolve,
    status,
)
from seek.nmap.recent import text
from seek.nmap.timing import Rtt

LAN = Facts(targets=("192.0.2.1", "192.0.2.2"), tcp_ports="22,80,443",
            up=frozenset({"192.0.2.1"}), rtts=(Rtt("192.0.2.1", 1.2, "earlier scans"),))
NOTHING = Facts(targets=("192.0.2.1",))


def _walk(*answers, facts=LAN) -> State:
    state = State()
    for step, choice in answers:
        state = advance(state, step, choice)
    return state


SERVICES = (("goal", "services"), ("protocol", "tcp"), ("ports", "known"), ("reach", "pn"),
            ("dns", "no"), ("network", "scans"))


@pytest.mark.parametrize("goal, steps", [
    ("live", ["goal", "dns", "network", "tune", "choose"]),
    ("ports", ["goal", "protocol", "ports", "reach", "dns", "network", "tune", "choose"]),
    ("vulns", ["goal", "protocol", "ports", "reach", "dns", "network", "tune", "choose"]),
])
def test_each_goal_asks_only_what_it_needs(goal, steps):
    state = _walk(("goal", goal))
    assert [s.key for s in builder.visible_steps(state)] == steps
    assert state.step == steps[1]


def test_a_discovery_goal_is_a_ping_scan():
    assert "-sn" in resolve(_walk(("goal", "live")), LAN, FAST).args


def test_back_keeps_the_answers():
    state = _walk(*SERVICES[:5])
    assert state.step == "network"
    state = back(back(state))
    assert state.step == "reach" and state.answer("ports") == "known"
    assert status("ports", state) == "done" and status("dns", state) == "done"
    assert status("network", state) == "ahead", "not answered yet"


def test_jumping_ahead_of_the_answers_is_refused():
    state = _walk(("goal", "ports"))
    assert jump(state, "choose") == state
    assert jump(state, "goal").step == "goal"


def test_a_lan_seen_before_gets_the_floor_in_both():
    fast, reliable = both(_walk(*SERVICES), LAN)
    for built in (fast, reliable):
        assert built.settings["--max-rtt-timeout"].value == "100ms"
        assert built.settings["--max-rtt-timeout"].source == "earlier scans"
        assert "raised to the 100 ms floor" in built.settings["--max-rtt-timeout"].why


def test_no_data_and_no_measurement_leaves_the_templates():
    state = _walk(("goal", "ports"), ("protocol", "tcp"), ("ports", "top1000"),
                  ("reach", "ping"), ("dns", "no"), ("network", "internet"), facts=NOTHING)
    fast, reliable = both(state, NOTHING)
    assert "-T4" in fast.args and not any(a.startswith("-T") for a in reliable.args)
    assert not any("rtt" in a for a in fast.args + reliable.args)


def test_udp_service_identification_profiles():
    state = _walk(("goal", "services"), ("protocol", "udp"), ("ports", "top100"))
    fast, reliable = both(state, LAN)
    assert fast.settings["--version-intensity"].value == "0"
    assert fast.settings["--max-retries"].value == "1"
    assert "--version-intensity" not in reliable.settings
    assert "--max-retries" not in reliable.settings
    said = " ".join(fast.misses)
    assert "most likely probe" in said and "open|filtered" in said


def test_a_value_the_user_set_survives_both_profiles():
    state = _walk(*SERVICES).set("--max-retries", "3")
    for built in both(state, LAN):
        assert built.settings["--max-retries"].value == "3"
        assert built.settings["--max-retries"].source == "you"
    assert not any("fewer retries" in m for m in both(state, LAN)[0].misses)


def test_a_user_setting_records_what_it_overrode():
    state = _walk(*SERVICES).set("--max-rtt-timeout", "400ms")
    setting = resolve(state, LAN, FAST).settings["--max-rtt-timeout"]
    assert setting.overrode == ("earlier scans",)
    assert resolve(state.reset("--max-rtt-timeout"), LAN, FAST) \
        .settings["--max-rtt-timeout"].source == "earlier scans"


def test_the_users_latest_choice_wins_an_exclusive_rule():
    state = _walk(*SERVICES).set("-sT", "")
    built = resolve(state, LAN, RELIABLE)
    assert "-sT" in built.args and "-sS" not in built.args
    assert any("one TCP scan type" in n for n in built.notes)


def test_udp_joins_one_tcp_type():
    built = resolve(_walk(*SERVICES).set("-sU", ""), LAN, RELIABLE)
    assert "-sS" in built.args and "-sU" in built.args


def test_turning_an_option_off():
    state = _walk(*SERVICES).set("-Pn", None)
    assert "-Pn" not in resolve(state, LAN, RELIABLE).args


def test_unprivileged_scans_connect():
    facts = Facts(targets=LAN.targets, tcp_ports=LAN.tcp_ports, privileged=False)
    state = _walk(("goal", "os"), ("protocol", "tcp"), ("ports", "top1000"), facts=facts)
    args = resolve(state, facts, RELIABLE).args
    assert "-sT" in args and "-O" not in args


def test_rendering_is_stable_and_valid():
    state = _walk(*SERVICES).set("--data-length", "24").set("-v", "2")
    first = resolve(state, LAN, FAST).args
    assert first == resolve(builder.State.from_json(state.to_json()), LAN, FAST).args
    assert first.count("-v") == 2
    presets.parse_command("nmap " + text(first))


@pytest.mark.parametrize("goal", list(builder.GOALS))
@pytest.mark.parametrize("profile", [FAST, RELIABLE])
def test_every_goal_builds_a_command_nmap_would_take(goal, profile):
    state = State()
    for step in ("goal", "protocol", "ports", "reach", "dns", "network"):
        if builder.applies(step, state):
            pick = builder.recommended(step, state, LAN) or choices(step, state, LAN)[0].key
            state = advance(state, step, pick if step != "goal" else goal)
    args = resolve(state, LAN, profile).args
    assert args
    presets.parse_command("nmap " + text(args))


def test_the_documented_figures_are_quoted():
    ports = {c.key: c for c in choices("ports", _walk(("goal", "ports")), LAN)}
    assert "78 %" in ports["top100"].cost and "39 %" in ports["top100"].cost
    assert "93 %" in ports["top1000"].gain and "49 %" in ports["top1000"].gain
    assert "65 times" in ports["all"].cost


def test_every_step_marks_one_recommendation_in_words():
    state = _walk(*SERVICES)
    for step in ("goal", "protocol", "ports", "reach", "dns", "network", "choose"):
        marked = [c for c in choices(step, state, LAN) if c.recommended]
        assert len(marked) <= 1, step
        for choice in choices(step, state, LAN):
            assert choice.gain and choice.cost, (step, choice.key)


def test_help_names_the_page_and_the_rules():
    lines = builder.help_text("--defeat-rst-ratelimit")
    assert any("filtered" in line for line in lines)
    assert lines[-1].endswith("man-performance.html")
    assert "takes no value" in lines


def test_fine_tune_lists_every_group_and_filters():
    view = builder.tune_view(_walk(*SERVICES), LAN)
    assert len(view.groups) == 11
    filtered = builder.tune_view(_walk(*SERVICES), LAN, query="rtt")
    names = [r.option.name for _g, rows in filtered.groups for r in rows]
    assert "--max-rtt-timeout" in names and "-sS" not in names
