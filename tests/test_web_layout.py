"""The web interface's layout: the shell, the visible actions, density, legibility.

What a browser draws is not run here. These hold the parts that can be read
from the files: the tokens the stylesheet is built on, the controls a page
offers, and that a control and its key are the same action.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from test_web import world  # noqa: F401 - the fixture

WEB = Path(__file__).parents[1] / "src/seek/web"
CSS = (WEB / "static/app.css").read_text()
KEYS_JS = (WEB / "static/js/keys.js").read_text()
ACTIONS_JS = (WEB / "static/js/actions.js").read_text()
VIEWER_JS = (WEB / "static/js/viewer.js").read_text()

# --- tokens ------------------------------------------------------------------------


def _tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})\b", block))


LIGHT = _tokens(CSS.split(":root {", 1)[1].split("\n}", 1)[0])
DARK = {**LIGHT, **_tokens(CSS.split("prefers-color-scheme: dark", 1)[1].split("\n}", 1)[0])}


def _luminance(colour: str) -> float:
    parts = [int(colour[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    r, g, b = (c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in parts)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


# Text, and every surface it is set on.
SURFACES = ("ground", "pane", "inset", "key-tint")
TEXT = ("ink", "ink-2", "ink-3", "key", "open", "filtered", "closed", "mark")
RECORD = tuple(f"c-{bright}{name}" for bright in ("", "b")
               for name in ("black", "red", "green", "yellow", "blue", "magenta", "cyan"))


@pytest.mark.parametrize("theme", [LIGHT, DARK], ids=["light", "dark"])
def test_text_is_legible_on_every_surface(theme):
    low = [(text, on, round(contrast(theme[text], theme[on]), 2))
           for text in TEXT for on in SURFACES if contrast(theme[text], theme[on]) < 4.5]
    assert low == []


@pytest.mark.parametrize("theme", [LIGHT, DARK], ids=["light", "dark"])
def test_every_terminal_colour_is_legible_in_a_record(theme):
    # A record is drawn on the pane; its cursor line on the tint.
    low = [(name, on, round(contrast(theme[name], theme[on]), 2))
           for name in RECORD for on in ("pane", "key-tint")
           if contrast(theme[name], theme[on]) < 4.5]
    assert low == []
    assert all(f".{name} {{ color: var(--{name}); }}" in CSS for name in RECORD)


@pytest.mark.parametrize("theme", [LIGHT, DARK], ids=["light", "dark"])
def test_a_control_s_label_is_legible_on_its_fill(theme):
    assert contrast(theme["on-key"], theme["key"]) >= 4.5, "the primary button"
    assert contrast(theme["on-hit"], theme["hit-now"]) >= 4.5, "the current search hit"
    assert contrast(theme["ink"], theme["hit"]) >= 4.5, "a search hit"


def test_no_colour_outside_the_tokens():
    rules = CSS.split("* { box-sizing", 1)[1]
    literal = re.findall(r"#[0-9a-fA-F]{3,6}\b", rules)
    assert literal == [], "a literal colour reads in one theme only"


def test_rows_are_dense():
    row = int(re.search(r"--row:\s*(\d+)px", CSS).group(1))
    # A 560px pane, less the column headers: at least eighteen rows.
    assert (560 - row) // row >= 18


# --- controls and their keys --------------------------------------------------------

KEY_ACTIONS = set(re.findall(r'\],\s*"(\w+)",', KEYS_JS.split("export function")[0]))


def _templates() -> str:
    return "".join(p.read_text() for p in (WEB / "templates").glob("*.html"))


def test_every_control_is_an_action_with_a_key():
    named = set(re.findall(r'data-action="(\w+)"', _templates()))
    named |= set(re.findall(r'data-key-of="(\w+)"', _templates()))
    assert named and named <= KEY_ACTIONS, named - KEY_ACTIONS
    # ...and the click goes to the table the keys use.
    table = VIEWER_JS.split("const HANDLERS = {")[1].split("};")[0]
    shared = ACTIONS_JS.split("export const handlers = {")[1]
    handled = set(re.findall(r"^  (\w+)(?::|,)", table, re.M))
    handled |= set(re.findall(r"\b(\w+)(?:: \w+)?[,}]", shared))
    assert set(re.findall(r'data-action="(\w+)"', _templates())) <= handled


def test_every_hint_names_a_real_action():
    rows = re.findall(r"^  \[\[(.*?)\]", KEYS_JS.split("HINTS = [")[1], re.M)
    hinted = set(re.findall(r'"(\w+)"', "".join(rows)))
    assert hinted and hinted <= KEY_ACTIONS, hinted - KEY_ACTIONS


def test_the_host_list_offers_its_toggles_and_actions(world):  # noqa: F811
    page = world[3].get("/v/hosts?up=1").text
    tools = page.split('class="controls"')[1].split("</form>")[0]
    assert 'name="up" value="1" checked' in tools and 'name="ports" value="1" >' in tools
    for action in ("mark", "export", "newScan"):
        assert f'data-action="{action}"' in tools, action
    assert tools.count('class="primary"') == 1, "one primary action in a view"


def test_a_toggle_is_offered_only_where_it_applies(world):  # noqa: F811
    client = world[3]
    services = client.get("/v/services").text
    assert 'name="up"' not in services and 'name="open"' not in services
    host = client.get("/v/hosts?path=h:192.0.2.30").text
    assert 'name="open"' in host and 'name="up"' not in host


def test_an_action_that_cannot_run_says_why(world):  # noqa: F811
    # The fixture's nmap does not exist.
    tools = world[3].get("/v/hosts").text.split('class="controls"')[1].split("</form>")[0]
    scan = re.search(r'<button[^>]*data-action="newScan"[^>]*>', tools).group(0)
    assert "disabled" in scan
    assert re.search(r'class="why">scan: [^<]*not on PATH', tools), "readable without hovering"


# --- the shell ------------------------------------------------------------------------


def test_the_viewer_is_a_shell_and_the_gallery_is_a_page(world):  # noqa: F811
    client = world[3]
    assert '<body class="shell">' in client.get("/v/hosts").text
    assert '<body class="">' in client.get("/").text


def test_the_key_bar_has_hints_and_what_is_loaded(world):  # noqa: F811
    scans, _shots, _source, client = world
    page = client.get("/v/hosts").text
    bar = page.split('<footer class="keys">')[1].split("</footer>")[0]
    for key in ("j", "k", "h", "l", "?"):
        assert f"<kbd>{key}</kbd>" in bar, "the navigation keys are there without script"
    loaded = f"{len(scans.files)} scan(s) · {len(scans.hosts)} host(s)"
    assert loaded in bar
    # The fragment carries it too, so the bar follows a model that grew.
    assert f'data-loaded="{loaded}"' in client.get("/v/hosts?fragment=1").text


def test_the_list_states_its_counts(world):  # noqa: F811
    scans, _shots, _source, client = world
    meta = client.get("/v/hosts?q=192.0.2.30&fragment=1").text.split('class="list-scroll"')[0]
    assert f"1 of {len(scans.hosts)} row(s)" in meta


def test_the_record_pane_has_a_header_with_its_actions(world):  # noqa: F811
    page = world[3].get("/v/hosts?sel=h:192.0.2.30").text
    pane = page.split('class="pane-record"')[1]
    head, body = pane.split('id="record"')
    assert re.search(r'<h2 id="record-title">[^<]*192\.0\.2\.30', head)
    assert 'data-action="follow"' in head and 'data-action="full"' in head
    assert 'id="record-q"' in head, "search within the record"
    assert 'class="record"' in body, "the header stays; only the record scrolls"


def test_the_record_s_views_wait_for_more_than_one(world):  # noqa: F811
    # Tabs and the button that steps through them are for a choice; the script
    # shows them once it has found a second view (a scan's own text, a report).
    head = world[3].get("/v/hosts?sel=h:192.0.2.30").text.split('class="record-head"')[1]
    assert re.search(r'id="record-views"[^>]* hidden', head)
    assert re.search(r'id="record-next"[^>]* hidden', head)
    assert "tabs.hidden = next.hidden = all.length < 2" in VIEWER_JS
    # nmap's text is one tab, however many scans have some.
    assert VIEWER_JS.split("function views()")[1].split("\n}")[0].count("query:") == 1
    # `o` and the button are one action; the three reports are named once.
    assert 'id="record-next" data-action="follow"' in head
    assert re.findall(r"(\w+): \"", ACTIONS_JS.split("MODE_LABELS = {")[1].split("}")[0]) == [
        "condensed", "diff", "raw"]


def test_a_capture_page_leads_with_the_picture(world):  # noqa: F811
    _scans, shots, _source, client = world
    from seek.web.source import capture_id

    with_shot = next(c for c in shots.all() if c.url == "https://192.0.2.30")
    page = client.get(f"/captures/{capture_id(with_shot)}").text
    body = page.split('class="cap-body"')[1]
    assert body.index('class="cap-shot"') < body.index('class="cap-facts"')
    assert 'class="full"' in body and "<h2>Response</h2>" in body
    actions = page.split('class="cap-actions"')[1].split("</nav>")[0]
    for control in ("Host 192.0.2.30", "Port 443/tcp", "Open the target"):
        assert control in actions, control
    assert '<details class="cap-list" open>' in page, "the headers are open, the rest fold"
    # The lists are in the grid, so a wide screen can put them beside the picture.
    assert body.index('class="cap-lists"') < body.index('class="cap-list"')
    assert "max-width" not in CSS.split(".cap {")[1].split("}")[0]


def test_a_capture_without_a_picture_says_so_and_offers_the_target(world):  # noqa: F811
    _scans, shots, _source, client = world
    from seek.web.source import capture_id

    failed = next((c for c in shots.all() if c.failed), None)
    if failed is None:
        pytest.skip("the fixture has no failed capture")
    box = client.get(f"/captures/{capture_id(failed)}").text.split('class="cap-none"')[1]
    assert "The capture failed" in box and "Open the target" in box.split("</div>")[0]


def test_an_empty_record_pane_says_how_to_fill_it(world):  # noqa: F811
    page = world[3].get("/v/hosts?q=zzzzzz").text
    assert "Select a row" in page.split('id="record"')[1]


# --- one set of controls ----------------------------------------------------------------


def test_the_gallery_s_grouping_is_the_viewer_s_chips(world):  # noqa: F811
    page = world[3].get("/?group=every").text
    choices = re.findall(r"<a [^>]*>", page.split('class="groupings"')[1].split("</nav>")[0])
    assert choices and all('class="chip"' in a for a in choices)
    current = [a for a in choices if "aria-current" in a]
    assert current == [a for a in choices if 'data-group="every"' in a]


def test_every_dialog_is_the_one_frame():
    calls = re.findall(r"\bdialog\(", ACTIONS_JS)
    # One definition; every other call passes a button row with exactly one primary.
    assert len(calls) - 1 == ACTIONS_JS.count('class="primary"') >= 5
    frame = ACTIONS_JS.split("function dialog(")[1].split("\n}")[0]
    assert "<h2" in frame and 'class="buttons"' in frame and "Esc leaves" in frame
    assert '<form method="dialog"' not in ACTIONS_JS.replace(frame, ""), "callers pass content"
    syntax = (WEB / "templates/_syntax.html").read_text()
    assert syntax.count('class="primary"') == 1 and "Esc leaves" in syntax


def test_the_capture_is_offered_among_the_scan_presets():
    """One dialog for everything that can be run against these hosts. It starts
    the capture the export dialog starts - one request, one scope rule. Without
    gowitness it stays choosable: its review can still be copied."""
    dialog = ACTIONS_JS.split("async function newScan(")[1].split("\nasync function ")[0]
    assert '<option value="${CAPTURE}" ${initial === CAPTURE ? "selected" : ""}>' in dialog
    assert "${esc(captureOff)}" in dialog, "unavailable is shown with its reason, not hidden"
    assert '"/api/v1/captures/review"' in dialog
    assert "await capture(notifyChoice(form))" in dialog, "with this run's notification"
    assert ACTIONS_JS.count('"/api/v1/captures/runs"') == 1
    assert 'newScan(CAPTURE)' in ACTIONS_JS, "the export dialog's capture opens the review"


def test_every_review_dialog_copies_with_the_terminals_keys():
    for name in ("newScan(", "scanGaps("):
        dialog = ACTIONS_JS.split(f"async function {name}")[1].split("\nasync function ")[0]
        assert "${COPY_BUTTONS}" in dialog and "copyControls(d," in dialog, name
    assert 'e.key === "y" || e.key === "Y"' in ACTIONS_JS


def test_a_refreshed_list_leaves_the_cursor_and_the_record_alone():
    """Marking refreshes the list. The row is found again by what it is, its
    record is not fetched again, and the selection survives in the URL."""
    handler = VIEWER_JS.split('addEventListener("list:replaced"')[1].split("\n});")[0]
    assert "tr.dataset.step === state.step" in handler
    assert "select(at, { scroll: false, load: false })" in handler
    app_js = (WEB / "static/app.js").read_text()
    assert 'url.searchParams.set("sel", selected)' in app_js


def test_static_files_are_revalidated(world):  # noqa: F811
    # An imported module has no version in its URL; a stale one breaks the page.
    response = world[3].get("/static/js/keys.js")
    assert response.status_code == 200 and response.headers["cache-control"] == "no-cache"


def test_the_builder_dialog_is_accessible_and_stateless():
    dialog = ACTIONS_JS.split("function openBuilder(")[1].split("\n}\n")[0]
    assert 'aria-current="step"' in dialog, "the stepper says where the user is"
    assert 'role="radiogroup"' in dialog and 'type="radio"' in dialog
    assert "aria-describedby" in dialog, "each choice's + and − lines describe it"
    assert 'aria-invalid' in dialog, "a refused value is marked on its field"
    assert '"/api/v1/builder/measure"' in dialog and "confirmed: true" in dialog
    assert "Measure now?" in dialog, "the measurement is confirmed before it is sent"
    assert "Discard the answers?" in dialog
    assert "state, measured" in dialog, "the state travels with every request"
