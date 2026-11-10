// What the keys do beyond moving: marks, export, scans, captures, the log.
// Every change is a request to the session the terminal shares, so a mark or a
// run made here shows there too.
const root = document.querySelector(".viewer");
const statusLine = document.getElementById("status");

export function say(text) {
  statusLine.textContent = text;
  clearTimeout(say.timer);
  say.timer = setTimeout(() => { statusLine.textContent = liveStatus.text; }, 6000);
}
const liveStatus = { text: "" };
export function setLive(text) { liveStatus.text = text; if (!say.timer) statusLine.textContent = text; }

function view() {
  const url = new URL(window.location.href);
  return { tab: root?.dataset.tab || "", path: root?.dataset.path || "", q: url.searchParams.get("q") || "" };
}

async function send(method, url, body) {
  const res = await fetch(url, {
    method, headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text();
  if (!res.ok) throw new Error(data.detail || data || res.statusText);
  return data;
}

export function refreshList() {
  const form = document.querySelector("form[data-list]");
  if (form) form.dispatchEvent(new Event("input", { bubbles: true }));
}

// --- marks ----------------------------------------------------------------------------

async function mark() {
  const tr = document.querySelector("table.rows tr.selected");
  if (!tr) return;
  try {
    const out = await send("POST", "/api/v1/marks", { ...view(), step: tr.dataset.step });
    say(`${out.marked ? "marked" : "unmarked"} · ${out.count} marked`);
    refreshList();
  } catch (e) { say(e.message); }
}

async function clearMarks() {
  try { await send("DELETE", "/api/v1/marks"); say("marks cleared"); refreshList(); }
  catch (e) { say(e.message); }
}

// --- dialogs ---------------------------------------------------------------------------

// Every dialog is this frame: a title, the caller's content, one row of buttons
// with exactly one primary, and a line saying how to leave. Callers pass content.
let dialogs = 0;
function dialog(title, body, buttons, note = "Esc leaves") {
  const d = document.createElement("dialog");
  const id = `dialog-title-${++dialogs}`;
  d.setAttribute("aria-labelledby", id);
  d.innerHTML = `<form method="dialog"><h2 id="${id}">${esc(title)}</h2>${body}
    <p class="buttons">${buttons} <span class="dim small">${esc(note)}</span></p></form>`;
  document.body.appendChild(d);
  d.addEventListener("close", () => d.remove());
  d.showModal();
  return d;
}

function esc(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// --- copying a reviewed command ----------------------------------------------------------

// The text comes from the server's plan, the same string the terminal copies.
// When the clipboard is refused the text is shown, selected, to copy by hand.
async function copyText(text, what) {
  try { await navigator.clipboard.writeText(text); say(`copied the ${what}`); return; }
  catch { /* shown below */ }
  const d = dialog(`No clipboard here - select the ${what} and copy it yourself`,
    `<p><textarea readonly rows="8" class="copy-text">${esc(text)}</textarea></p>`,
    '<button value="close" class="primary">Close</button>');
  d.querySelector("textarea").select();
}

// `y` copies for another machine, `Y` as shown - the review's keys in the terminal.
// `plan()` is the latest review, or null while there is none.
function copyControls(d, plan) {
  const copy = (form) => {
    const p = plan();
    const text = p && (form === "remote" ? p.copy_remote : p.copy_local);
    if (!text) { say(form === "local" ? "not available here - copy for another machine with y" : "nothing to copy yet"); return; }
    copyText(text, form === "remote" ? "command for another machine" : "command");
  };
  d.querySelectorAll("button[data-copy]").forEach((b) => b.addEventListener("click", () => copy(b.dataset.copy)));
  d.addEventListener("keydown", (e) => {
    if (e.target.closest("textarea, input, select") || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.key === "y" || e.key === "Y") { e.preventDefault(); copy(e.key === "y" ? "remote" : "local"); }
  });
}

const COPY_BUTTONS = `<button type="button" data-copy="remote">Copy for another machine <kbd>y</kbd></button>
  <button type="button" data-copy="local">Copy as shown <kbd>Y</kbd></button>`;

// What a review says beyond the command: why it cannot start here, and how a
// run made elsewhere comes back.
function blockedLine(plan, back) {
  return (plan.blocked ? `<br><span class="c-red">${esc(plan.blocked)}</span> - copy it to run on a machine that can` : "") +
    `<br>run elsewhere: copy ${esc(back)} back into the scan directory`;
}

// Where to say that a run ended - shown with the configured default, changeable
// for this run. Filled once: a later review must not undo the reader's edit.
const NOTIFY_FIELDS = `<p><label>notify <input type="text" name="notify_url" placeholder="an ntfy URL, told when it ends - empty: no notification"></label>
  <label><input type="checkbox" name="notify_progress"> and at 25 / 50 / 75 %</label></p>`;

function fillNotify(form, plan) {
  if (form.dataset.notifyFilled) return;
  form.dataset.notifyFilled = "1";
  form.notify_url.value = plan.notify_url || "";
  form.notify_progress.checked = Boolean(plan.notify_progress);
}

const notifyChoice = (form) => ({ notify_url: form.notify_url.value, notify_progress: form.notify_progress.checked });

async function exportDialog() {
  const v = view();
  let options;
  try { options = await send("GET", `/api/v1/export/options?${new URLSearchParams(v)}`); }
  catch (e) { say(e.message); return; }
  if (!options.count) { say("nothing to export"); return; }
  const d = dialog(`Export ${options.source}`, `
      <p><label>what <select name="which">${options.recipes.map((r) => `<option value="${r.key}">${esc(r.label)}</option>`).join("")}</select></label></p>
      <fieldset class="fields" hidden><legend>fields</legend>${options.fields.map((f) => `<label><input type="checkbox" name="fields" value="${f}" ${["address", "port_label", "service"].includes(f) ? "checked" : ""}> ${f}</label>`).join(" ")}</fieldset>
      <p><label>as <select name="fmt">${options.formats.map((f) => `<option value="${f.key}">${esc(f.label)}</option>`).join("")}</select></label>
         <span class="dim small fixed" hidden>the port list is always one line</span></p>`,
    `<button value="download" class="primary">Download</button> <button value="copy">Copy</button>
         <button value="capture">Capture the URLs with gowitness…</button>
         <button value="scan">Scan these hosts…</button>
         <button value="cancel">Cancel</button>
         ${options.capture ? `<span class="why">capture: ${esc(options.capture)} - it can still be planned and copied</span>` : ""}
         ${options.scan ? `<span class="why">scan: ${esc(options.scan)} - it can still be planned and copied</span>` : ""}`);
  const form = d.querySelector("form");
  const sync = () => {
    form.querySelector(".fields").hidden = form.which.value !== "custom";
    const fixed = options.fixed_format.includes(form.which.value);
    form.fmt.disabled = fixed;
    form.querySelector(".fixed").hidden = !fixed;
  };
  form.which.addEventListener("change", sync);
  sync();
  d.addEventListener("close", async () => {
    const choice = d.returnValue;
    if (choice === "capture") { newScan(CAPTURE); return; }
    if (choice === "scan") { newScan(); return; }
    if (choice !== "download" && choice !== "copy") return;
    const q = new URLSearchParams({ ...v, which: form.which.value, fmt: form.fmt.value });
    form.querySelectorAll("input[name=fields]:checked").forEach((c) => q.append("fields", c.value));
    if (choice === "download") { q.set("download", "1"); window.location.href = `/api/v1/export?${q}`; return; }
    try {
      const text = await send("GET", `/api/v1/export?${q}`);
      await navigator.clipboard.writeText(text);
      say(`copied ${text.trim().split("\n").length} line(s)`);
    } catch (e) { say(e.message); }
  });
}

async function capture(choice = {}) {
  try {
    const run = await send("POST", "/api/v1/captures/runs", { ...view(), ...choice });
    say(`capturing: ${run.label}`);
    return true;
  } catch (e) { say(e.message); return false; }
}

// One review text for every scan dialog.
function scanReview(plan) {
  if (plan.error) return `<span class="c-red">${esc(plan.error)}</span>`;
  const base = plan.out_base.split("/").pop();
  return (plan.warning ? `<strong>${esc(plan.warning)}</strong><br>` : "") + `runs <code>${esc(plan.argv.join(" "))}</code><br>${plan.targets.length} target(s) · writes ${esc(plan.out_base)}.{xml,nmap,gnmap}` +
    (plan.via === "sudo" ? `<br><strong>needs root</strong> (${esc(plan.privilege)}) - through <code>sudo -n</code>: the browser cannot let sudo ask for a password, the terminal viewer can` : "") +
    (plan.via === "capabilities" ? `<br><strong>needs root</strong> (${esc(plan.privilege)}) - nmap's own capabilities, with <code>--privileged</code>, no sudo` : "") +
    blockedLine(plan, `${base}.{xml,nmap,gnmap}`);
}

// --- the command builder ----------------------------------------------------------------

// The terminal's builder over /api/v1/builder: the server keeps no state - the
// dialog sends it back each time - so both front ends give the same commands.
const BUILD = "__build__";
const MARKS = { done: "✓", current: "●", ahead: "○", skipped: "–" };

function openBuilder(targetList, done) {
  let state = "", measured = "[]", query = "", last = null;
  const d = dialog("Build a command", `
      <ol class="stepper" aria-label="Steps"></ol>
      <h3 class="question" id="builder-question"></h3>
      <p class="filter" hidden><label>filter options <input type="search" name="q" autocomplete="off"></label></p>
      <div class="choices" role="radiogroup" aria-labelledby="builder-question"></div>
      <p class="notes dim small" aria-live="polite"></p>
      <pre class="command"></pre>`,
    `<button type="button" data-b="back">Back <kbd>←</kbd></button>
     <button type="button" data-b="finish" class="primary">Finish <kbd>Ctrl+S</kbd></button>
     <button value="cancel">Leave</button>`,
    "↑↓ move · Enter choose · ← back · Esc leaves");
  const form = d.querySelector("form");
  const area = form.querySelector(".choices");
  const notes = form.querySelector(".notes");

  const go = async (action = "", value = "") => {
    const q = new URLSearchParams({ targets: targetList.join(","), state, measured, action, value, query });
    try { last = await send("GET", `/api/v1/builder?${q}`); }
    catch (e) { notes.textContent = e.message; return false; }
    state = last.state;
    render(last);
    return true;
  };

  const render = (out) => {
    form.querySelector(".stepper").innerHTML = out.steps.filter((s) => s.status !== "skipped").map((s) =>
      `<li ${s.status === "current" ? 'aria-current="step"' : ""}><button type="button" data-jump="${s.key}" ${s.status === "done" || s.status === "current" ? "" : "disabled"}>${MARKS[s.status]} ${s.number} ${esc(s.title)}</button></li>`).join("");
    form.querySelector(".question").textContent = out.question;
    form.querySelector(".filter").hidden = out.step !== "tune";
    const reliable = out.commands.find((c) => c.profile === "reliable");
    form.querySelector(".command").textContent = `nmap ${reliable.text}  ‹${targetList.length} target(s)›`;
    if (out.step === "tune") area.innerHTML = out.groups.map((g) => `<details ${g.rows.some((r) => r.on) ? "open" : ""}><summary>${esc(g.group)}${g.rows.filter((r) => r.on).length ? ` · ${g.rows.filter((r) => r.on).length} set` : ""}</summary>
        ${g.rows.map((r) => r.owner ? `<p class="row dim"><code>${esc(r.name)}</code> set by seek - ${esc(r.owner)}</p>`
          : r.flag ? `<p class="row"><label><input type="checkbox" data-toggle="${esc(r.name)}" ${r.on ? "checked" : ""}> <code>${esc(r.name)}</code> ${esc(r.about)}</label>${r.on ? ` <span class="dim">‹${esc(r.source)}›</span>` : ""}</p>`
          : `<p class="row"><label><code>${esc(r.name)}</code> <input type="text" data-set="${esc(r.name)}" value="${esc(r.value ?? "")}" placeholder="${esc(r.hint)}" aria-describedby="err-${esc(r.name)}"></label> ${esc(r.about)}${r.on ? ` <span class="dim">‹${esc(r.source)}›</span>` : ""}<span class="error" id="err-${esc(r.name)}"></span></p>`).join("")}</details>`).join("");
    else if (out.step === "choose") area.innerHTML = out.commands.map((c) => `<p><button type="button" data-use="${c.profile}">${c.profile === "fast" ? "Fast" : "Reliable (recommended)"}</button></p>
        <pre class="command">nmap ${esc(c.text)}</pre>${c.misses.map((m) => `<p class="dim small">− ${esc(m)}</p>`).join("")}${c.notes.map((n) => `<p class="dim small">${esc(n)}</p>`).join("")}`).join("");
    else area.innerHTML = out.choices.map((c) => `<label class="choice"><input type="radio" name="choice" value="${esc(c.key)}" ${c.selected ? "checked" : ""} aria-describedby="g-${esc(c.key)} c-${esc(c.key)}">
        <strong>${esc(c.label)}</strong> ${c.adds ? `<code>${esc(c.adds)}</code>` : ""} ${c.recommended ? "<em>recommended</em>" : ""}
        <span class="dim small" id="g-${esc(c.key)}">+ ${esc(c.gain)}</span><span class="dim small" id="c-${esc(c.key)}">− ${esc(c.cost)}</span></label>`).join("");
    (area.querySelector("input:checked") || area.querySelector("input, button"))?.focus();
  };

  const measure = () => {
    const c = dialog("Measure now?", `<p>This sends a few probes to up to 8 of the ${targetList.length} target(s) - TCP connections to a port known open, or one nmap ping scan - for at most 8 seconds.</p>`,
      '<button value="measure" class="primary">Measure now</button> <button value="cancel">Send nothing</button>');
    c.addEventListener("close", async () => {
      if (c.returnValue !== "measure") { notes.textContent = "nothing was sent"; return; }
      notes.textContent = "measuring …";
      try {
        const out = await send("POST", "/api/v1/builder/measure", { targets: targetList, confirmed: true });
        measured = JSON.stringify(out.measured);
        notes.textContent = `${out.what}: ${out.note}`;
      } catch (e) { notes.textContent = e.message; }
      go("choose", "measure");
    });
  };

  area.addEventListener("change", async (e) => {
    const t = e.target;
    if (t.name === "choice") { if (t.value === "measure") measure(); else go("choose", t.value); }
    else if (t.dataset.toggle) go("toggle", t.dataset.toggle);
    else if (t.dataset.set) {
      const err = form.querySelector(`#err-${CSS.escape(t.dataset.set)}`);
      const ok = await go("set", `${t.dataset.set}=${t.value}`);
      if (!ok && err) { err.textContent = `✗ ${notes.textContent}`; t.setAttribute("aria-invalid", "true"); }
    }
  });
  area.addEventListener("click", (e) => {
    const use = e.target.closest("[data-use]");
    if (!use) return;
    const command = last.commands.find((c) => c.profile === use.dataset.use);
    const goal = JSON.parse(state).answers.goal || "scan";
    d.close();
    done(command.text, `build ${goal} ${use.dataset.use}`);
  });
  form.querySelector(".stepper").addEventListener("click", (e) => {
    const b = e.target.closest("[data-jump]");
    if (b) go("jump", b.dataset.jump);
  });
  form.querySelector("[data-b=back]").addEventListener("click", () => go("back"));
  form.querySelector("[data-b=finish]").addEventListener("click", () => go("finish"));
  form.q.addEventListener("input", () => { query = form.q.value; clearTimeout(go.t); go.t = setTimeout(go, 200); });
  d.addEventListener("keydown", (e) => {
    if (e.ctrlKey && e.key === "s") { e.preventDefault(); go("finish"); return; }
    if (e.target.closest("input[type=text], input[type=search]")) return;
    if (e.key === "ArrowLeft" || e.key === "Backspace") { e.preventDefault(); go("back"); }
  });
  // Esc with answers given asks first, as the terminal does.
  d.addEventListener("cancel", (e) => {
    if (!state || !Object.keys(JSON.parse(state).answers || {}).length) return;
    e.preventDefault();
    const c = dialog("Discard the answers?", "", '<button value="discard" class="primary">Discard</button> <button value="cancel">Continue building</button>');
    c.addEventListener("close", () => { if (c.returnValue === "discard") d.close(); });
  });
  go();
}

// The screenshot capture sits among the scan presets: to the reader it is one
// more thing to run against these hosts. It is not an nmap preset - it has no
// command to edit and its targets are the HTTP(S) URLs of the marks or the
// list, exactly what the export dialog's capture sends.
const CAPTURE = "__gowitness__";

async function newScan(initial = "") {
  let presets;
  try { presets = await send("GET", "/api/v1/scans/presets"); } catch (e) { say(e.message); return; }
  let earlier = { recent: [], frequent: [] };
  try { earlier = await send("GET", "/api/v1/scans/recent"); } catch { /* none yet */ }
  const earlierOf = (value) => {
    const [list, index] = value.slice(1).split(":");
    return (earlier[list] || [])[Number(index)];
  };
  let scope = "";
  try { scope = (await send("GET", `/api/v1/export?${new URLSearchParams({ ...view(), which: "all-hosts" })}`)).trim(); }
  catch { /* nothing marked or listed: the scope is typed */ }
  // Why a capture cannot run, "" when it can; unknown reads as it can, and the
  // server says otherwise when asked to start.
  let captureOff = "";
  let source = "this list";
  try {
    const options = await send("GET", `/api/v1/export/options?${new URLSearchParams(view())}`);
    captureOff = options.capture;
    source = options.source;
  } catch { /* the capture's own request will say */ }
  const d = dialog("New scan", `
      <p><label>scan with <select name="preset">
        <option value="${BUILD}">Build a command… (guided, explains each option)</option>
        ${["recent", "frequent"].filter((k) => earlier[k].length).map((k) => `<optgroup label="${k === "recent" ? "Recent" : "Frequent"}">${earlier[k].map((e, i) => `<option value="@${k}:${i}">${esc(e.args)} · ${esc(e.where)}${e.count > 1 ? ` · used ${e.count}×` : ""}</option>`).join("")}</optgroup>`).join("")}
        <optgroup label="Presets">${presets.map((p) => `<option value="${esc(p.name)}" ${p.name === presets[0].name && initial !== CAPTURE ? "selected" : ""}>${esc(p.name)}${p.needs_root ? " · root" : ""}</option>`).join("")}
        <option value="${CAPTURE}" ${initial === CAPTURE ? "selected" : ""}>gowitness · screenshots of the HTTP(S) services${captureOff ? ` - ${esc(captureOff)}` : ""}</option></optgroup></select></label></p>
      <p class="nmap-only"><label>scope<br><textarea name="targets" rows="4" placeholder="one address, range or name per line">${esc(scope)}</textarea></label></p>
      <p class="nmap-only"><label>command<br><textarea name="command" rows="3"></textarea></label></p>
      ${NOTIFY_FIELDS}
      <div class="review dim small"></div>`,
    `<button value="start" class="primary">Start the scan</button> ${COPY_BUTTONS} <button value="cancel">Cancel</button>`,
    "Esc leaves - nothing runs until you start it");
  const form = d.querySelector("form");
  const start = form.querySelector("button[value=start]");
  let edited = false;
  let current = null;
  let built = null;            // {args, name} from the builder
  copyControls(d, () => current);
  // What the review drafts from: a preset by name, or arguments under a name.
  const draft = () => {
    const value = form.preset.value;
    if (value === BUILD) return built ? { preset: built.name, args: built.args } : null;
    if (value.startsWith("@")) return { preset: "earlier", args: earlierOf(value).args };
    return { preset: value };
  };
  const targets = () => form.targets.value.split(/[\s,]+/).filter(Boolean);
  const capturing = () => form.preset.value === CAPTURE;
  // What a capture would photograph and run - the plan the terminal reviews.
  const reviewCapture = async (box) => {
    current = null;
    try {
      const plan = await send("POST", "/api/v1/captures/review", view());
      current = plan;
      fillNotify(form, plan);
      box.innerHTML = `${plan.urls.length} URL(s) from ${esc(source)} · writes ${esc(plan.where)}` +
        `<br><code>${esc(plan.urls.slice(0, 5).join("  "))}${plan.urls.length > 5 ? " …" : ""}</code>` +
        blockedLine(plan, "its gowitness/ directory");
      start.disabled = Boolean(plan.blocked);
    } catch (e) {
      box.innerHTML = `<span class="c-red">${esc(e.message)}</span>`;
      start.disabled = true;
    }
  };
  const review = async () => {
    const box = form.querySelector(".review");
    form.querySelectorAll(".nmap-only").forEach((el) => { el.hidden = capturing(); });
    start.textContent = capturing() ? "Start the capture" : "Start the scan";
    if (capturing()) { reviewCapture(box); return; }
    try {
      const from = draft();
      if (!from) { box.textContent = "build a command first"; start.disabled = true; return; }
      const plan = await send("POST", "/api/v1/scans/review",
        { ...from, targets: targets(), command: edited ? form.command.value : null });
      if (!edited) form.command.value = plan.command;
      current = plan.error ? null : plan;
      fillNotify(form, plan);
      box.innerHTML = scanReview(plan);
      start.disabled = Boolean(plan.error || plan.blocked);
    } catch (e) { current = null; box.innerHTML = `<span class="c-red">${esc(e.message)}</span>`; }
  };
  form.preset.addEventListener("change", () => {
    edited = false;
    if (form.preset.value === BUILD) {
      openBuilder(targets(), (args, name) => { built = { args, name }; review(); });
      return;
    }
    review();
  });
  form.targets.addEventListener("change", () => { edited = false; review(); });
  form.command.addEventListener("input", () => { edited = true; clearTimeout(review.t); review.t = setTimeout(review, 300); });
  review();
  d.addEventListener("close", async () => {
    if (d.returnValue !== "start") return;
    if (capturing()) {
      if (await capture(notifyChoice(form)) && root?.dataset.tab !== "scans") window.location.href = "/v/scans";
      return;
    }
    try {
      const run = await send("POST", "/api/v1/scans",
        { ...draft(), targets: targets(), command: form.command.value, ...notifyChoice(form) });
      say(`started ${run.label}`);
      if (root?.dataset.tab !== "scans") window.location.href = "/v/scans";
    } catch (e) { say(e.message); }
  });
}

// --- the vulnerability database ----------------------------------------------------

const vulndbButton = document.getElementById("vulndb");

async function showVulndb() {
  if (!vulndbButton) return null;
  try {
    const state = await send("GET", "/api/v1/vulndb");
    vulndbButton.textContent = state.label;
    vulndbButton.title = state.updating ? state.progress : "the vulnerability database - A updates it";
    vulndbButton.classList.toggle("dim", state.stale);
    if (state.updating) setTimeout(showVulndb, 1000);
    return state;
  } catch { return null; }
}

// Nothing is ever downloaded without this dialog being confirmed: the page asks
// the server for the state, says what an update fetches, and only then posts.
async function updateVulndb() {
  const state = await showVulndb();
  if (!state) { say("the vulnerability database is not available here"); return; }
  if (state.updating) {
    const d = dialog("Updating the vulnerability database", `<p>${esc(state.progress)}</p>`,
      '<button value="keep" class="primary">Keep going</button> <button value="cancel">Cancel the update</button>',
      "Esc leaves - a cancelled update leaves the data as it was");
    d.addEventListener("close", async () => {
      if (d.returnValue === "cancel") { try { await send("POST", "/api/v1/vulndb/cancel"); say("cancelling"); } catch (e) { say(e.message); } }
    });
    return;
  }
  const age = state.missing ? "There is none yet - about 600 MB the first time." : `It is ${Math.round(state.age_days)} days old; only what changed is downloaded.`;
  const d = dialog("Update the vulnerability database?", `<p>${esc(age)}</p>
    <p class="dim small">Downloads NVD CVE feeds, OSV npm advisories and endoflife.date release data. Nothing about this engagement is sent.</p>`,
    '<button value="update" class="primary">Download and update</button> <button value="no">Not now</button>');
  d.addEventListener("close", async () => {
    if (d.returnValue !== "update") return;
    try { await send("POST", "/api/v1/vulndb/update"); say("updating the vulnerability database"); showVulndb(); }
    catch (e) { say(e.message); }
  });
}

if (vulndbButton) { vulndbButton.addEventListener("click", updateVulndb); showVulndb(); }

async function scanGaps() {
  let plan;
  try { plan = await send("POST", "/api/v1/scans/gaps", view()); } catch (e) { say(e.message); return; }
  const d = dialog("Scan unversioned ports", `
      <p class="dim small">${esc(plan.note)}</p>
      <p><label>command<br><textarea name="command" rows="3">${esc(plan.command)}</textarea></label></p>
      ${NOTIFY_FIELDS}
      <div class="review dim small"></div>`,
    `<button value="start" class="primary">Start the scan</button> ${COPY_BUTTONS} <button value="cancel">Cancel</button>`,
    "Esc leaves - nothing runs until you start it");
  const form = d.querySelector("form");
  let current = null;
  copyControls(d, () => current);
  fillNotify(form, plan);
  const body = () => ({ preset: plan.preset, targets: plan.targets, command: form.command.value });
  const review = async () => {
    const box = form.querySelector(".review");
    try {
      const out = await send("POST", "/api/v1/scans/review", body());
      current = out.error ? null : out;
      box.innerHTML = scanReview(out);
      form.querySelector("button[value=start]").disabled = Boolean(out.error || out.blocked);
    } catch (e) { current = null; box.innerHTML = `<span class="c-red">${esc(e.message)}</span>`; }
  };
  form.command.addEventListener("input", () => { clearTimeout(review.t); review.t = setTimeout(review, 300); });
  review();
  d.addEventListener("close", async () => {
    if (d.returnValue !== "start") return;
    try {
      const run = await send("POST", "/api/v1/scans", { ...body(), ...notifyChoice(form) });
      say(`started ${run.label}`);
      if (root?.dataset.tab !== "scans") window.location.href = "/v/scans";
    } catch (e) { say(e.message); }
  });
}

// --- the log -----------------------------------------------------------------------------

export const logState = { frozen: false, mode: "condensed" };
const MODES = ["condensed", "diff", "raw"];

// The three reports of a run, in the terminal's order and words.
export const MODE_LABELS = { condensed: "overview", diff: "diff", raw: "raw output" };

export function setMode(mode) {
  if (root?.dataset.tab !== "scans" || !MODES.includes(mode)) return;
  logState.mode = mode;
  document.dispatchEvent(new CustomEvent("record:reload"));
}

// One run is cancelled; with several, which one is asked - the others go on.
async function cancel() {
  const running = (await send("GET", "/api/v1/runs")).filter((r) => r.running);
  if (!running.length) { say("nothing is running"); return; }
  const end = async (run) => {
    try { await send("POST", `/api/v1/runs/${run.id}/cancel`); say(`cancelling ${run.label}`); }
    catch (e) { say(e.message); }
  };
  if (running.length === 1) { end(running[0]); return; }
  const d = dialog("Cancel which run?", "<p>The others keep running.</p>",
    running.map((r, i) => `<button value="${i}"${i ? "" : ' class="primary"'}>${esc(r.label)} - ${esc(r.scope)}</button>`).join(" ") +
    ' <button value="cancel">None</button>');
  d.addEventListener("close", () => {
    if (/^\d+$/.test(d.returnValue)) end(running[Number(d.returnValue)]);   // Esc: ""
  });
}

function freeze() {
  logState.frozen = !logState.frozen;
  say(logState.frozen ? "log frozen - the scan is still running" : "log following again");
}

function shots() {
  const tr = document.querySelector("table.rows tr.selected");
  const step = tr?.dataset.step || "";
  const [kind, rest] = [step.slice(0, 2), step.slice(2)];
  if (kind === "h:") window.location.href = `/?${new URLSearchParams({ address: rest })}`;
  else if (kind === "p:") { const [a, proto, port] = rest.split("/"); window.location.href = `/?${new URLSearchParams({ address: a, protocol: proto, port })}`; }
  else window.location.href = "/";
}

export function help(keys) {
  dialog("Keys", `<table class="pairs">${keys.map(([k, , text]) =>
    `<tr><th>${k.map((x) => `<kbd>${esc(x === " " ? "Space" : x)}</kbd>`).join(" ")}</th><td>${esc(text)}</td></tr>`).join("")}</table>`,
    '<button value="close" class="primary">Close</button>');
}

// --- stopping the interface ----------------------------------------------------------

// What Stop ends is the server's to say: in the viewer, this interface (the
// terminal carries on); for `seek nmap serve`, the process, as Ctrl+C does.
async function stopWeb() {
  let state;
  try { state = await send("GET", "/api/v1/web"); } catch (e) { say(e.message); return; }
  if (!state.stoppable) { say("this interface cannot be stopped from here"); return; }
  const serving = state.mode === "serve";
  const d = dialog("Stop the web interface?", serving
    ? "<p>This ends <code>seek nmap serve</code>, as Ctrl+C would - a scan or capture still running is cancelled.</p>"
    : "<p>The web interface closes. seek keeps running in the terminal, scans included; <kbd>w</kbd> there starts it again.</p>",
    '<button value="stop" class="primary">Stop</button> <button value="cancel">Keep it running</button>');
  d.addEventListener("close", async () => {
    if (d.returnValue !== "stop") return;
    try { await send("POST", "/api/v1/web/stop"); say("stopping…"); }
    catch (e) { say(e.message); }
  });
}

export const handlers = { mark, clearMarks, export: exportDialog, newScan, scanGaps, updateVulndb, cancel, freeze, stopWeb, shots };
