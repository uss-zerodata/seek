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

// `H`: the host the row belongs to - from a port, a screenshot or a bucket.
async function markHost() {
  const tr = document.querySelector("table.rows tr.selected");
  if (!tr) return;
  try {
    const out = await send("POST", "/api/v1/marks/hosts", { row: { ...view(), step: tr.dataset.step } });
    say(`${out.marked ? "marked" : "unmarked"} the host · ${out.count} marked`);
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
  if (kind === "h:") window.location.href = `/gallery?${new URLSearchParams({ address: rest })}`;
  else if (kind === "p:") { const [a, proto, port] = rest.split("/"); window.location.href = `/gallery?${new URLSearchParams({ address: a, protocol: proto, port })}`; }
  else window.location.href = "/gallery";
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

// --- tags --------------------------------------------------------------------------

// What `t` and `T` act on: the marks when there are any - the server takes an
// empty row list as "the marks" - else the selected row. The terminal's rule.
async function tagTargets() {
  let marks;
  try { marks = await send("GET", "/api/v1/marks"); } catch (e) { say(e.message); return null; }
  if (marks.count) return { rows: [], label: `${marks.count} marked` };
  const tr = document.querySelector("table.rows tr.selected");
  if (!tr) { say("nothing to tag - select a row or mark some"); return null; }
  const v = view();
  return { rows: [{ tab: v.tab, path: v.path, step: tr.dataset.step }], label: "the selected row" };
}

function reportChange(out) {
  if (out.errors.length) say(out.errors.join("; "));
  else if (out.saved.length) say(`${out.summary} · saved in ${out.saved.join(", ")}`);
  else say("nothing to change");
  refreshList();
}

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

async function tag() {
  const t = await tagTargets();
  if (!t) return;
  let known;
  try { known = await send("GET", "/api/v1/tags"); } catch (e) { say(e.message); return; }
  const d = dialog(`Tag ${t.label}`, `
      <p><label>tag <input name="tag" list="tag-names" autocomplete="off"></label>
      <datalist id="tag-names">${known.tags.map((x) => `<option value="${esc(x.name)}">`).join("")}</datalist></p>
      <p class="dim small">lowercase letters, digits, . _ - · Remove takes off a tag given by hand</p>`,
    `<button value="add" class="primary">Add</button> <button value="remove">Remove</button>
         <button value="edit">Edit the tag: description, issues, rules…</button>
         <button value="global">Copy to the global file</button>
         <button value="cancel">Cancel</button>`);
  const form = d.querySelector("form");
  form.tag.focus();
  d.addEventListener("close", async () => {
    const choice = d.returnValue;
    const name = form.tag.value.trim();
    if (!["add", "remove", "edit", "global"].includes(choice)) return;
    if (choice === "edit") { openTagEditor(name.toLowerCase()); return; }
    if (!name) { say("no tag name given"); return; }
    try {
      reportChange(choice === "global"
        ? await send("POST", `/api/v1/tags/${encodeURIComponent(name)}/global`)
        : await send("POST", "/api/v1/tags/entries", { tag: name, add: choice === "add", rows: t.rows }));
    } catch (e) { say(e.message); }
  });
}

async function reloadTags() {
  try {
    const out = await send("POST", "/api/v1/tags/reload");
    const errors = out.problems.filter((p) => p.level === "error").length;
    say(`tag rules reloaded: ${out.files.length} file(s), ${out.tags.length} tag(s)` +
        (errors ? `, ${errors} problem(s)` : ""));
    refreshList();
  } catch (e) { say(e.message); }
}

// `T`: the rule builder - one dialog, as the terminal's workbench. The dialog
// holds only the draft; every count, proposal and condition is the server's, and
// a newer change aborts the request of an older one, so the last change shows.
const CYCLE = { ignore: "require", require: "exclude", exclude: "ignore" };
const FACT_MODES = [["equals", "equals"], ["contains", "contains"], ["start", "starts with"],
                    ["end", "ends with"], ["regex", "regex"]];
const MODE_WORD = { equals: "=", contains: "contains", start: "starts with", end: "ends with", regex: "matches" };
const GRANTS = [["host", "The host", "every host the rule matches carries the tag"],
                ["service", "The matched services", "only the ports that met the rule's port conditions"],
                ["both", "Both", "the hosts and those ports"]];
const KIND_WORD = { service: "service", product: "product", version: "version", title: "page title",
                    cert_issuer: "certificate issuer", header: "header" };
const factKey = (f) => JSON.stringify([f.kind, f.protocol || null, f.ports || "", f.value || "",
                                       f.mode || "equals", !!f.case]);

function withState(draft, fact, state) {
  const key = factKey(fact);
  const known = draft.facts.some((x) => factKey(x.fact) === key);
  const facts = known ? draft.facts.map((x) => factKey(x.fact) === key ? { ...x, state } : x)
                      : [...draft.facts, { fact, state }];
  return { ...draft, facts };
}

function stateOf(draft, fact) {
  return draft.facts.find((x) => factKey(x.fact) === factKey(fact))?.state || "ignore";
}

function choose(title, choices) {
  return new Promise((resolve) => {
    const d = dialog(title, "", choices.map(([value, label], k) =>
      `<button value="${esc(value)}"${k ? "" : ' class="primary"'}>${esc(label)}</button>`).join(" "));
    d.addEventListener("close", () => resolve(choices.some(([v]) => v === d.returnValue) ? d.returnValue : null));
  });
}

// A fact as words: what is tested, how, and the value - the port is its group's.
function factText(f) {
  if (f.kind === "open") return "open";
  if (f.kind === "tag") return `carries the tag <code>${esc(f.value)}</code>`;
  if (f.kind === "address") return `address <code>${esc(f.value)}</code>`;
  if (f.kind === "fixed") return `as written: <code>${esc(f.value)}</code>`;
  const what = f.kind === "os" ? "OS" : KIND_WORD[f.kind] || f.kind;
  return `${esc(what)} <span class="op">${MODE_WORD[f.mode] || "="}</span> <code>${esc(f.value)}</code>` +
         (f.case ? ' <span class="tagword">case</span>' : "");
}

function tri(state) {
  const b = (value, text, title) => `<button type="button" data-set="${value}" title="${title}" aria-pressed="${state === value}">${text}</button>`;
  return `<span class="tri" role="group" aria-label="use this fact">${b("ignore", "–", "ignore (space cycles)")}${b("require", "Require", "require (+)")}${b("exclude", "Exclude", "exclude (-)")}</span>`;
}

function countCell(selected, of, others) {
  const pct = of ? Math.round((100 * selected) / of) : 0;
  return `<span class="cover" title="${selected} of ${of} selected hosts have it"><span class="meter"><i style="width:${pct}%"></i></span>${selected}/${of}</span>` +
         `<span class="others${others ? "" : " none"}" title="hosts you did not select that have it">${others} other${others === 1 ? "" : "s"}</span>`;
}

async function buildRule() {
  let marks;
  try { marks = await send("GET", "/api/v1/marks"); } catch (e) { say(e.message); return; }
  const v = view();
  const tr = document.querySelector("table.rows tr.selected");
  const row = tr ? { rows: [{ tab: v.tab, path: v.path, step: tr.dataset.step }] } : null;
  let body = marks.count ? { rows: [] } : row;
  if (!marks.count && v.q && document.querySelectorAll("table.rows tr[data-step]").length > 1) {
    const from = await choose("Build a rule from:", [["view", "the rows in view"], ["row", "this row"]]);
    if (!from) return;
    body = from === "view" ? { view: { tab: v.tab, path: v.path, q: v.q } } : row;
  }
  if (!body) { say("mark the hosts a rule should find (m, or H for a row's host), then press T"); return; }
  let out;
  try { out = await send("POST", "/api/v1/tags/builder", body); } catch (e) { say(e.message); return; }
  bench(out, null);
}

function bench(started, rule) {
  const st = { draft: started.draft, start: JSON.stringify(started.draft), a: started.assessment,
               ids: {}, combo: [], pending: null, ports: started.draft.limit };
  const title = rule ? `Rule builder · ${rule.tag} · ${rule.name}` : "Rule builder";
  const d = dialog(title, `
      <div class="tb-bar">
        <div class="tb-stats" aria-live="polite"></div>
        <div class="tb-opts">
          <label class="switch" title="facts on the same ports must hold on one port"><input type="checkbox" name="same"> same port <kbd>p</kbd></label>
          ${st.ports ? `<span class="seg" role="group" aria-label="facts of">
            <button type="button" data-scope="ports">${esc(st.ports.map((x) => x.split("/").reverse().join("/")).join(", "))} only</button><button type="button" data-scope="host">whole host</button></span> <kbd>h</kbd>` : ""}
        </div>
      </div>
      <p class="tb-notes"></p>
      <div class="tb-body">
        <section class="tb-pane"><h3>Facts <span class="hint">require what your hosts share · exclude what the others have</span></h3>
          <div class="tb-scroll facts-list"></div></section>
        <section class="tb-pane"><h3>Hosts</h3><div class="tb-scroll hosts-list"></div></section>
      </div>
      <p class="tb-keys"><kbd>j</kbd><kbd>k</kbd> move · <kbd>space</kbd> cycle · <kbd>+</kbd> require · <kbd>-</kbd> exclude ·
        <kbd>e</kbd> edit · <kbd>a</kbd> add · <kbd>d</kbd> drop · <kbd>x</kbd> exclude host · <kbd>s</kbd> continue</p>`,
    `<button value="save" class="primary">Continue to the tag…</button> <button value="cancel">Cancel</button>`);
  d.classList.add("wide", "tb");
  const form = d.querySelector("form");
  const factsEl = d.querySelector(".facts-list");
  const hostsEl = d.querySelector(".hosts-list");
  form.same.checked = st.draft.same_port;

  const change = (draft) => { st.draft = draft; render(); recount(); };
  async function recount() {
    st.pending?.abort();
    const ctl = st.pending = new AbortController();
    d.classList.add("busy");
    await new Promise((r) => setTimeout(r, 120));
    if (ctl.signal.aborted) return;
    try {
      const res = await fetch("/api/v1/tags/builder/assess", { method: "POST", signal: ctl.signal,
        headers: { "Content-Type": "application/json" }, body: JSON.stringify({ draft: st.draft }) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || res.statusText);
      if (ctl === st.pending) { st.a = data; d.classList.remove("busy"); render(); }
    } catch (e) { if (e.name !== "AbortError") { d.classList.remove("busy"); say(e.message); } }
  }

  function stats(a) {
    if (!a.rule.length) return `<div class="stat lead"><b>No rule yet</b><span>require or exclude a fact to start one</span></div>`;
    const all = a.selected_matched === a.of_selection;
    return `<div class="stat lead"><b>${a.matched}</b><span>host${a.matched === 1 ? "" : "s"} match</span></div>
      <div class="stat ${all ? "ok" : "bad"}"><b>${a.selected_matched}/${a.of_selection}</b><span>of your hosts</span></div>
      <div class="stat ${a.other_count ? "warn" : "ok"}"><b>${a.other_count}</b><span>other${a.other_count === 1 ? "" : "s"}</span></div>
      <div class="stat${a.assumed.length ? " warn" : ""}"><b>${a.assumed.length}</b><span>on an assumption</span></div>`;
  }
  function render() {
    const a = st.a, n = a.of_selection;
    const keep = d.querySelector("[data-id]:focus")?.dataset.id;
    st.ids = {};
    let html = "", group = null;
    a.rows.forEach((r, k) => {
      if (r.fact.group !== group) {
        group = r.fact.group;
        html += `<div class="group">${group === "host" ? "the host" : `<span class="port">${esc(group)}</span>`}</div>`;
      }
      st.ids[`f${k}`] = r.fact;
      const state = stateOf(st.draft, r.fact);
      const editable = !["tag", "address", "fixed"].includes(r.fact.kind);
      html += `<div class="fact" data-id="f${k}" data-state="${state}" tabindex="-1">${tri(state)}
        <span class="what">${factText(r.fact)}</span>${countCell(r.selected, n, r.others)}
        <button type="button" class="icon" data-edit="f${k}" title="edit (e)"${editable ? "" : " disabled"}>edit</button></div>`;
    });
    if (!a.rows.length) html += `<p class="empty">the selected hosts share no fact</p>`;
    st.combo = [];
    if (a.other_count && (a.exclusions.length || a.combination)) {
      html += `<div class="group suggest">exclude to drop the ${a.other_count} other${a.other_count === 1 ? "" : "s"}</div>`;
      if (a.combination && a.combination.facts.length > 1) {
        st.combo = a.combination.facts;
        html += `<div class="fact suggestion" data-id="combo" tabindex="-1">
          <button type="button" data-set="exclude" class="small">Exclude all</button>
          <span class="what">${a.combination.facts.map((f) => esc(f.label)).join(" <span class=\"op\">and</span> ")}</span>
          <span class="drops">leaves ${a.combination.remaining}</span></div>`;
      }
      a.exclusions.forEach((p, k) => {
        st.ids[`x${k}`] = p.fact;
        html += `<div class="fact suggestion" data-id="x${k}" tabindex="-1">
          <button type="button" data-set="exclude" class="small">Exclude</button>
          <span class="what">${esc(p.fact.label)}</span>
          <span class="drops">drops ${p.excludes}/${a.other_count}${p.assumed_on.length ? ` · assumed on ${p.assumed_on.length} of yours` : ""}</span></div>`;
      });
    }
    factsEl.innerHTML = html;
    const host = (m, id, mark, acts) => `<div class="host" data-id="${esc(id)}" tabindex="-1">
        <span class="hm ${mark[0]}" title="${mark[2]}">${mark[1]}</span><code>${esc(m.address)}</code>
        <span class="ports">${esc(m.ports)}</span><span class="title">${esc(m.title)}</span>
        <span class="acts">${acts}</span></div>`;
    let hosts = `<div class="group">your hosts · ${a.selection.length}</div>`;
    a.selection.forEach((m) => {
      const mark = !a.rule.length ? ["", "", ""] : m.matched ? (m.assumed ? ["warn", "~", "matched on an assumption"] : ["ok", "✓", "matched"]) : ["bad", "✗", "not matched"];
      hosts += host(m, `s:${m.address}`, mark, `<button type="button" class="small" data-host="drop" title="drop from the selection (d)">Drop</button>`);
    });
    if (a.other_count) {
      hosts += `<div class="group warn">also matching · ${a.other_count}${a.other_count > a.others.length ? `, first ${a.others.length}` : ""}</div>`;
      a.others.forEach((m) => {
        hosts += host(m, `o:${m.address}`, ["", "", ""],
          `<button type="button" class="small" data-host="add" title="add to the selection (a)">Add</button><button type="button" class="small" data-host="exclude" title="exclude this host (x)">Exclude</button>`);
      });
    }
    hostsEl.innerHTML = hosts;
    d.querySelector(".tb-stats").innerHTML = stats(a);
    d.querySelector(".tb-notes").textContent = [...a.notes, ...(a.confirm ? [a.confirm] : [])].join(" · ");
    d.querySelector(".tb-notes").hidden = !a.notes.length && !a.confirm;
    d.querySelectorAll("[data-scope]").forEach((b) => b.setAttribute("aria-pressed",
      String((b.dataset.scope === "ports") === !!st.draft.limit)));
    (d.querySelector(`[data-id="${CSS.escape(keep || "")}"]`) || null)?.focus();
  }

  const focused = () => d.querySelector("[data-id]:focus")?.dataset.id || null;
  function setState(id, state) {
    if (id === "combo") { let draft = st.draft; st.combo.forEach((f) => { draft = withState(draft, f, "exclude"); }); change(draft); return; }
    const fact = st.ids[id];
    if (fact) change(withState(st.draft, fact, state));
  }
  function cycle(id) {
    if (id === "combo") { setState(id, "exclude"); return; }
    const fact = st.ids[id];
    if (!fact) return;
    const state = stateOf(st.draft, fact);
    setState(id, id.startsWith("x") && state === "ignore" ? "exclude" : CYCLE[state]);
  }
  async function edit(id) {
    const fact = st.ids[id];
    if (!fact) return;
    if (["tag", "address", "fixed"].includes(fact.kind)) { say("this fact is kept as it is - require, exclude or ignore it"); return; }
    const edited = await editFact(st.draft, fact);
    if (!edited) return;
    const old = stateOf(st.draft, fact);
    const rest = st.draft.facts.filter((x) => ![factKey(fact), factKey(edited)].includes(factKey(x.fact)));
    change({ ...st.draft, facts: [{ fact: edited, state: old === "ignore" ? "require" : old }, ...rest] });
  }
  function hostAct(id, act) {
    const address = id.slice(2);
    if (act === "add" && id.startsWith("o:")) change({ ...st.draft, selection: [...st.draft.selection, address] });
    if (act === "drop" && id.startsWith("s:")) change({ ...st.draft, selection: st.draft.selection.filter((x) => x !== address) });
    if (act === "exclude" && id.startsWith("o:")) change(withState(st.draft, { kind: "address", value: address }, "exclude"));
  }
  const scope = (to) => {
    if (!st.ports) { say("the rule is built from whole hosts already"); return; }
    const limit = to === undefined ? (st.draft.limit ? null : st.ports) : (to === "ports" ? st.ports : null);
    change({ ...st.draft, limit });
  };
  function move(step) {
    const pane = document.activeElement?.closest(".tb-scroll") || factsEl;
    const items = [...pane.querySelectorAll("[data-id]")];
    const at = items.indexOf(document.activeElement);
    items[Math.max(0, Math.min(items.length - 1, at + step))]?.focus();
  }

  d.addEventListener("click", (event) => {
    const item = event.target.closest("[data-id]");
    const set = event.target.closest("[data-set]");
    if (set && item) { item.focus(); setState(item.dataset.id, set.dataset.set); return; }
    const ed = event.target.closest("[data-edit]");
    if (ed) { edit(ed.dataset.edit); return; }
    const act = event.target.closest("[data-host]");
    if (act && item) { hostAct(item.dataset.id, act.dataset.host); return; }
    const sc = event.target.closest("[data-scope]");
    if (sc) { scope(sc.dataset.scope); return; }
    if (item) item.focus();
  });
  d.addEventListener("keydown", (event) => {
    if (event.target.matches("input:not([type=checkbox]), select, textarea")) return;
    const id = focused();
    const act = {
      " ": () => id && cycle(id), "+": () => id && setState(id, "require"),
      "-": () => id && setState(id, "exclude"), e: () => id && edit(id),
      p: () => { form.same.checked = !form.same.checked; change({ ...st.draft, same_port: form.same.checked }); },
      a: () => id && hostAct(id, "add"), d: () => id && hostAct(id, "drop"), x: () => id && hostAct(id, "exclude"),
      h: () => scope(), s: () => save(),
      ArrowDown: () => move(1), j: () => move(1), ArrowUp: () => move(-1), k: () => move(-1),
      Tab: () => ((document.activeElement?.closest(".hosts-list") ? factsEl : hostsEl).querySelector("[data-id]"))?.focus(),
    }[event.key];
    if (act) { event.preventDefault(); act(); }
  });
  form.same.addEventListener("change", () => change({ ...st.draft, same_port: form.same.checked }));
  const leaving = (event) => {
    if (JSON.stringify(st.draft) !== st.start && !window.confirm("Leave the rule builder? The draft is not saved.")) event.preventDefault();
  };
  d.addEventListener("cancel", leaving);
  form.addEventListener("submit", (event) => {
    if (event.submitter?.value === "save") { event.preventDefault(); save(); } else leaving(event);
  });

  async function save() {
    if (!st.a.rule.length) { say("require or exclude a fact first"); return; }
    if (st.a.confirm && !window.confirm(`${st.a.confirm} - continue anyway?`)) return;
    const got = await saveDialog(rule, st.a.of_selection, st.draft.limit ? "service" : "host");
    if (!got) return;
    let out;
    try {
      out = await send("POST", "/api/v1/tags/builder/rule",
                       { draft: st.draft, rule_name: got.name, grant: got.grant });
    } catch (e) { say(e.message); return; }
    st.start = JSON.stringify(st.draft);
    d.close("saved");
    // The rule goes to the tag editor; nothing is written before it is saved there.
    if (rule) rule.done(out.raw);
    else openTagEditor(got.tag, out.raw);
  }

  render();
  factsEl.querySelector("[data-id]")?.focus();
}

// The tag editor: everything about one tag - name, description, issues, rules -
// as the terminal's. Nothing is written until "Save the tag"; a change that
// rewrites a person's rule file is confirmed first.
async function openTagEditor(name, newRule = null) {
  let edit;
  try { edit = await send("GET", `/api/v1/tags/edit?name=${encodeURIComponent(name || "")}`); }
  catch (e) { say(e.message); return; }
  if (!edit.original) edit.name = name || "";
  if (newRule) edit.rules.unshift({ raw: newRule, origin: null, deleted: false, name: newRule.name,
                                    where: "new", changed: false, editable: true, reason: "" });
  const start = JSON.stringify(edit);
  const d = dialog(edit.original ? `Tag ${edit.original}` : "New tag", `
      <div class="form">
        <label class="field"><span>Name</span><input name="tname" value="${esc(edit.name)}" autocomplete="off"
          placeholder="lowercase letters, digits, . _ -"><small>renaming reaches every project file that uses the tag</small></label>
        <label class="field"><span>Description</span><textarea name="tdesc" rows="2" placeholder="what kind of system this is">${esc(edit.description)}</textarea></label>
      </div>
      <section class="ed-sec"><header><h3>Known issues</h3><button type="button" data-act="add-issue">+ Add an issue</button></header>
        <div class="cards issues-list"></div></section>
      <section class="ed-sec"><header><h3>Rules</h3><span class="hint">build a new one with <kbd>T</kbd></span></header>
        <div class="cards rules-list"></div></section>
      <p class="manual hint"></p>
      <p class="error-box" hidden></p>`,
    `<button value="save" class="primary">Save the tag</button> <button value="cancel">Cancel</button>`);
  d.classList.add("editor");
  const form = d.querySelector("form");
  const typed = () => { edit.name = form.tname.value.trim(); edit.description = form.tdesc.value; };
  function render() {
    d.querySelector(".issues-list").innerHTML = edit.issues.map((i, k) => `
      <div class="card-row"><span class="sev sev-${esc(i.severity)}">${esc(i.severity)}</span>
        <div class="body"><b>${esc(i.title)}</b>
          ${i.description ? `<p>${esc(i.description)}</p>` : ""}
          ${i.references.length ? `<p class="refs">${i.references.map((r) => /^https?:/.test(r) ? `<a href="${esc(r)}" target="_blank" rel="noopener noreferrer">${esc(r)}</a>` : esc(r)).join(" · ")}</p>` : ""}</div>
        <span class="acts"><button type="button" class="small" data-act="edit-issue" data-k="${k}">Edit</button><button type="button" class="small" data-act="del-issue" data-k="${k}">Remove</button></span></div>`).join("")
      || `<p class="empty">no known issues - add the weaknesses this kind of system has</p>`;
    d.querySelector(".rules-list").innerHTML = edit.rules.map((r, k) => {
      const badge = r.origin === null ? ["new", "new"] : r.deleted ? ["del", "deleted"] : r.changed ? ["chg", "changed"] : null;
      return `<div class="card-row${r.deleted ? " gone" : ""}">${badge ? `<span class="badge ${badge[0]}">${badge[1]}</span>` : '<span class="badge">rule</span>'}
        <div class="body"><b>${esc(r.name || "(unnamed)")}</b><p class="hint">${esc(r.where)}</p>
          ${r.editable ? "" : `<p class="hint">${esc(r.reason)}</p>`}</div>
        <span class="acts"><button type="button" class="small" data-act="open-rule" data-k="${k}"${r.deleted || !r.editable ? " disabled" : ""}>Open in the builder</button><button type="button" class="small" data-act="del-rule" data-k="${k}">${r.deleted ? "Keep" : "Delete"}</button></span></div>`;
    }).join("") || `<p class="empty">no rules - this tag is only given by hand</p>`;
    d.querySelector(".manual").textContent = edit.manual_hosts || edit.manual_services
      ? `Given by hand to ${edit.manual_hosts} host(s) and ${edit.manual_services} service(s).` : "";
  }
  d.addEventListener("click", async (event) => {
    const b = event.target.closest("button[data-act]");
    if (!b) return;
    typed();
    const k = Number(b.dataset.k);
    if (b.dataset.act === "add-issue") { const i = await issueDialog(null); if (i && i !== "delete") edit.issues.push(i); }
    if (b.dataset.act === "edit-issue") {
      const i = await issueDialog(edit.issues[k]);
      if (i === "delete") edit.issues.splice(k, 1); else if (i) edit.issues[k] = i;
    }
    if (b.dataset.act === "del-issue") edit.issues.splice(k, 1);
    if (b.dataset.act === "del-rule") {
      if (edit.rules[k].origin === null) edit.rules.splice(k, 1); else edit.rules[k].deleted = !edit.rules[k].deleted;
    }
    if (b.dataset.act === "open-rule") {
      const r = edit.rules[k];
      let out;
      try {
        out = await send("POST", "/api/v1/tags/builder/open", { tag: edit.original || edit.name, raw: r.raw, origin: r.origin });
      } catch (e) { say(e.message); return; }
      bench(out, { tag: edit.original || edit.name, name: out.rule_name, grant: out.grant,
                   done: (raw) => { r.raw = raw; r.name = raw.name; r.changed = r.origin !== null; render(); } });
    }
    render();
  });
  const fail = (text) => { const box = d.querySelector(".error-box"); box.textContent = text; box.hidden = !text; };
  async function saveAll(confirmOverwrite) {
    typed();
    try {
      reportChange(await send("POST", "/api/v1/tags/edit", { ...edit, confirm_overwrite: confirmOverwrite }));
      d.close("saved");
    } catch (e) {
      if (/rewrites/.test(e.message) && !confirmOverwrite && window.confirm(`${e.message}. Save anyway?`)) { saveAll(true); return; }
      fail(e.message);
    }
  }
  const leaving = (event) => {
    typed();
    if (JSON.stringify(edit) !== start && !window.confirm("Leave the tag editor? Nothing is saved.")) event.preventDefault();
  };
  form.addEventListener("submit", (event) => {
    if (event.submitter?.value === "save") { event.preventDefault(); saveAll(false); return; }
    leaving(event);
  });
  d.addEventListener("cancel", leaving);
  render();
  (edit.original ? form.tdesc : form.tname).focus();
}

function radios(name, options, current) {
  return `<span class="seg" role="radiogroup">${options.map(([value, label]) =>
    `<label><input type="radio" name="${name}" value="${esc(value)}"${value === current ? " checked" : ""}><span>${esc(label)}</span></label>`).join("")}</span>`;
}

function issueDialog(issue) {
  return new Promise((resolve) => {
    const i = issue || { title: "", severity: "medium", description: "", references: [] };
    const d = dialog(issue ? "Issue" : "New issue", `
        <div class="form">
          <label class="field"><span>Title</span><input name="ititle" value="${esc(i.title)}" autocomplete="off" placeholder="e.g. Admin PIN of four digits"></label>
          <div class="field"><span>Severity</span>${radios("severity", SEVERITIES.map((s) => [s, s]), i.severity).replace(/class="seg"/, 'class="seg sevs"')}</div>
          <label class="field"><span>Description</span><textarea name="idesc" rows="3" placeholder="what is wrong, and how to check it">${esc(i.description || "")}</textarea></label>
          <label class="field"><span>References</span><input name="refs" value="${esc((i.references || []).join(", "))}" autocomplete="off"
            placeholder="https://…, CVE-2024-…"><small>URLs or ids, separated by commas</small></label>
        </div>`,
      `<button value="take" class="primary">${issue ? "Keep the changes" : "Add the issue"}</button>${issue ? ' <button value="delete">Remove</button>' : ""} <button value="cancel">Cancel</button>`);
    const form = d.querySelector("form");
    form.ititle.focus();
    form.addEventListener("submit", (event) => {
      if (event.submitter?.value === "take" && !form.ititle.value.trim()) { event.preventDefault(); form.ititle.focus(); }
    });
    d.addEventListener("close", () => {
      if (d.returnValue === "delete") { resolve("delete"); return; }
      if (d.returnValue !== "take" || !form.ititle.value.trim()) { resolve(null); return; }
      resolve({ title: form.ititle.value.trim(), severity: form.severity.value, description: form.idesc.value.trim(),
                references: form.refs.value.split(",").map((r) => r.trim()).filter(Boolean) });
    });
  });
}

function editFact(draft, fact) {
  return new Promise((resolve) => {
    const text = fact.kind !== "open";
    const ports = !["os", "tag", "address", "fixed"].includes(fact.kind);
    const what = fact.kind === "open" ? "Open port" : fact.kind === "os" ? "OS" : (KIND_WORD[fact.kind] || fact.kind);
    const d = dialog(`Edit: ${what[0].toUpperCase()}${what.slice(1)}`, `
        <div class="form">
          ${text ? `<label class="field"><span>Value</span><input name="value" value="${esc(fact.value)}" autocomplete="off"></label>
          <div class="field"><span>Match</span>${radios("mode", FACT_MODES, fact.mode || "equals")}
            <label class="check"><input type="checkbox" name="case"${fact.case ? " checked" : ""}> match case</label></div>` : ""}
          ${ports ? `<label class="field"><span>Ports</span><input name="ports" value="${esc(fact.ports || "")}" placeholder="any port" autocomplete="off">
            <small>one port, a list such as 80,8000-8999, or empty for any port${fact.protocol ? ` (${esc(fact.protocol)})` : ""}</small></label>` : ""}
          <div class="result" aria-live="polite"><span class="hint">counting…</span></div>
          <p class="warn-box" hidden></p><p class="error-box" hidden></p>
        </div>`,
      `<button value="take" class="primary">Use this fact</button> <button value="cancel">Cancel</button>`);
    const form = d.querySelector("form");
    let current = null, pending = null;
    const box = (cls, text) => { const b = d.querySelector(cls); b.textContent = text; b.hidden = !text; };
    const typed = () => ({ kind: fact.kind, protocol: fact.protocol, ports: ports ? form.ports.value : "",
                           value: text ? form.value.value : "", mode: text ? form.mode.value : "equals",
                           case: text ? form.case.checked : false });
    async function recount() {
      pending?.abort();
      const ctl = pending = new AbortController();
      await new Promise((r) => setTimeout(r, 120));
      if (ctl.signal.aborted) return;
      try {
        const res = await fetch("/api/v1/tags/builder/refine", { method: "POST", signal: ctl.signal,
          headers: { "Content-Type": "application/json" }, body: JSON.stringify({ draft, fact: typed() }) });
        const data = await res.json();
        if (ctl !== pending) return;
        if (!res.ok) {
          current = null; form.querySelector("button[value=take]").disabled = true;
          box(".error-box", data.detail || res.statusText); return;
        }
        current = data.fact;
        form.querySelector("button[value=take]").disabled = false;
        box(".error-box", "");
        const all = data.selected === data.of_selection;
        d.querySelector(".result").innerHTML = `<code class="label">${esc(data.fact.label)}</code>
          <span class="stat ${all ? "ok" : "bad"}"><b>${data.selected}/${data.of_selection}</b><span>of your hosts</span></span>
          <span class="stat ${data.others ? "warn" : "ok"}"><b>${data.others}</b><span>others</span></span>`;
        box(".warn-box", data.dropped.length
          ? `No longer holds for ${data.dropped.length} of your hosts: ${data.dropped.slice(0, 5).join(", ")}${data.dropped.length > 5 ? " …" : ""}` : "");
      } catch (e) { if (e.name !== "AbortError") say(e.message); }
    }
    form.addEventListener("input", recount);
    form.addEventListener("change", recount);
    form.addEventListener("submit", (event) => {
      if (event.submitter?.value !== "cancel" && !current) event.preventDefault();
    });
    d.addEventListener("close", () => resolve(d.returnValue === "take" ? current : null));
    (form.value || form.ports)?.focus();
    recount();
  });
}

function saveDialog(rule, count, grant = "host") {
  return new Promise(async (resolve) => {
    let known = { tags: [] };
    try { known = await send("GET", "/api/v1/tags"); } catch { /* names are a convenience */ }
    const d = dialog("Which tag does the rule give?", `
        <div class="form">
          <label class="field"><span>Tag</span><input name="tag" list="bench-tags" autocomplete="off" value="${esc(rule?.tag || "")}"${rule ? " disabled" : ""}
            placeholder="an existing tag or a new name">
            <small>${rule ? "the rule stays with its tag" : `${known.tags.length} existing tag(s) are suggested as you type; a new name makes a new tag`}</small></label>
          <datalist id="bench-tags">${known.tags.map((x) => `<option value="${esc(x.name)}">`).join("")}</datalist>
          <label class="field"><span>Rule name</span><input name="rname" value="${esc(rule?.name || `built from ${count} host(s)`)}" autocomplete="off"></label>
          <fieldset class="field opt-cards"><legend>It tags</legend>
            ${GRANTS.map(([v, label, why]) => `<label class="opt-card"><input type="radio" name="grant" value="${v}"${v === (rule?.grant || grant) ? " checked" : ""}>
              <span><b>${label}</b><small>${why}</small></span></label>`).join("")}</fieldset>
          <p class="hint">Next: the tag editor, for its description and known issues. Nothing is saved before that.</p>
        </div>`,
      `<button value="save" class="primary">Continue</button> <button value="cancel">Cancel</button>`);
    const form = d.querySelector("form");
    (rule ? form.rname : form.tag).focus();
    d.addEventListener("close", () => {
      if (d.returnValue !== "save") { resolve(null); return; }
      const tag = form.tag.value.trim(), name = form.rname.value.trim();
      if (!tag || !name) { say("give a tag and a rule name"); resolve(null); return; }
      resolve({ tag, name, grant: form.grant.value });
    });
  });
}

export const handlers = { mark, markHost, clearMarks, export: exportDialog, newScan, scanGaps, updateVulndb, cancel, freeze, stopWeb, shots,
  tag, buildRule, reloadTags };
