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

function dialog(html) {
  const d = document.createElement("dialog");
  d.innerHTML = html;
  document.body.appendChild(d);
  d.addEventListener("close", () => d.remove());
  d.showModal();
  return d;
}

function esc(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function exportDialog() {
  const v = view();
  let options;
  try { options = await send("GET", `/api/v1/export/options?${new URLSearchParams(v)}`); }
  catch (e) { say(e.message); return; }
  if (!options.count) { say("nothing to export"); return; }
  const d = dialog(`
    <form method="dialog" class="export">
      <h2>Export ${esc(options.source)}</h2>
      <p><label>what <select name="which">${options.recipes.map((r) => `<option value="${r.key}">${esc(r.label)}</option>`).join("")}</select></label></p>
      <fieldset class="fields" hidden><legend>fields</legend>${options.fields.map((f) => `<label><input type="checkbox" name="fields" value="${f}" ${["address", "port_label", "service"].includes(f) ? "checked" : ""}> ${f}</label>`).join(" ")}</fieldset>
      <p><label>as <select name="fmt">${options.formats.map((f) => `<option value="${f.key}">${esc(f.label)}</option>`).join("")}</select></label>
         <span class="dim small fixed" hidden>the port list is always one line</span></p>
      <p class="buttons"><button value="download" class="primary">Download</button> <button value="copy">Copy</button>
         <button value="capture" ${options.capture ? "disabled" : ""} title="${esc(options.capture)}">Capture the URLs with gowitness</button>
         <button value="scan" ${options.scan ? "disabled" : ""} title="${esc(options.scan)}">Scan these hosts…</button>
         ${options.capture ? `<span class="dim small">capture: ${esc(options.capture)}</span>` : ""}
         <button value="cancel">Cancel</button> <span class="dim small">Esc leaves</span></p>
    </form>`);
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
    if (choice === "capture") { capture(); return; }
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

async function capture() {
  try { const run = await send("POST", "/api/v1/captures/runs", view()); say(`capturing: ${run.label}`); }
  catch (e) { say(e.message); }
}

async function newScan() {
  let presets;
  try { presets = await send("GET", "/api/v1/scans/presets"); } catch (e) { say(e.message); return; }
  let scope = "";
  try { scope = (await send("GET", `/api/v1/export?${new URLSearchParams({ ...view(), which: "all-hosts" })}`)).trim(); }
  catch { /* nothing marked or listed: the scope is typed */ }
  const d = dialog(`
    <form method="dialog" class="scan">
      <h2>New scan</h2>
      <p><label>preset <select name="preset">${presets.map((p) => `<option value="${esc(p.name)}">${esc(p.name)}${p.needs_root ? " · root" : ""}</option>`).join("")}</select></label></p>
      <p><label>scope<br><textarea name="targets" rows="4" placeholder="one address, range or name per line">${esc(scope)}</textarea></label></p>
      <p><label>command<br><textarea name="command" rows="3"></textarea></label></p>
      <div class="review dim small"></div>
      <p class="buttons"><button value="start" class="primary">Start the scan</button> <button value="cancel">Cancel</button>
        <span class="dim small">Esc leaves - nothing runs until you start it</span></p>
    </form>`);
  const form = d.querySelector("form");
  let edited = false;
  const targets = () => form.targets.value.split(/[\s,]+/).filter(Boolean);
  const review = async () => {
    const box = form.querySelector(".review");
    try {
      const plan = await send("POST", "/api/v1/scans/review",
        { preset: form.preset.value, targets: targets(), command: edited ? form.command.value : null });
      if (!edited) form.command.value = plan.command;
      box.innerHTML = plan.error
        ? `<span class="c-red">${esc(plan.error)}</span>`
        : `runs <code>${esc(plan.argv.join(" "))}</code><br>${plan.targets.length} target(s) · writes ${esc(plan.out_base)}.{xml,nmap,gnmap}` +
          (plan.elevated ? `<br><strong>needs root</strong> (${esc(plan.privilege)}) - through <code>sudo -n</code>, never a prompt` : "");
      form.querySelector("button[value=start]").disabled = Boolean(plan.error);
    } catch (e) { box.innerHTML = `<span class="c-red">${esc(e.message)}</span>`; }
  };
  form.preset.addEventListener("change", () => { edited = false; review(); });
  form.targets.addEventListener("change", () => { edited = false; review(); });
  form.command.addEventListener("input", () => { edited = true; clearTimeout(review.t); review.t = setTimeout(review, 300); });
  review();
  d.addEventListener("close", async () => {
    if (d.returnValue !== "start") return;
    try {
      const run = await send("POST", "/api/v1/scans",
        { preset: form.preset.value, targets: targets(), command: form.command.value });
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
    vulndbButton.classList.toggle("dim", state.stale);
    if (state.updating) setTimeout(showVulndb, 2000);
    return state;
  } catch { return null; }
}

// Nothing is ever downloaded without this dialog being confirmed: the page asks
// the server for the state, says what an update fetches, and only then posts.
async function updateVulndb() {
  const state = await showVulndb();
  if (!state) { say("the vulnerability database is not available here"); return; }
  if (state.updating) {
    const d = dialog(`<form method="dialog"><h2>Updating the vulnerability database</h2>
      <p>${esc(state.progress)}</p>
      <p class="buttons"><button value="cancel">Cancel the update</button> <button value="keep" class="primary">Keep going</button>
      <span class="dim small">a cancelled update leaves the data as it was</span></p></form>`);
    d.addEventListener("close", async () => {
      if (d.returnValue === "cancel") { try { await send("POST", "/api/v1/vulndb/cancel"); say("cancelling"); } catch (e) { say(e.message); } }
    });
    return;
  }
  const age = state.missing ? "There is none yet - about 600 MB the first time." : `It is ${Math.round(state.age_days)} days old; only what changed is downloaded.`;
  const d = dialog(`<form method="dialog"><h2>Update the vulnerability database?</h2>
    <p>${esc(age)}</p>
    <p class="dim small">Downloads NVD CVE feeds, OSV npm advisories and endoflife.date release data. Nothing about this engagement is sent.</p>
    <p class="buttons"><button value="update" class="primary">Download and update</button> <button value="no">Not now</button>
    <span class="dim small">Esc leaves</span></p></form>`);
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
  const d = dialog(`
    <form method="dialog" class="scan">
      <h2>Scan unversioned ports</h2>
      <p class="dim small">${esc(plan.note)}</p>
      <p><label>command<br><textarea name="command" rows="3">${esc(plan.command)}</textarea></label></p>
      <div class="review dim small"></div>
      <p class="buttons"><button value="start" class="primary">Start the scan</button> <button value="cancel">Cancel</button>
        <span class="dim small">Esc leaves - nothing runs until you start it</span></p>
    </form>`);
  const form = d.querySelector("form");
  const body = () => ({ preset: plan.preset, targets: plan.targets, command: form.command.value });
  const review = async () => {
    const box = form.querySelector(".review");
    try {
      const out = await send("POST", "/api/v1/scans/review", body());
      box.innerHTML = out.error
        ? `<span class="c-red">${esc(out.error)}</span>`
        : `runs <code>${esc(out.argv.join(" "))}</code><br>${out.targets.length} target(s) · writes ${esc(out.out_base)}.{xml,nmap,gnmap}` +
          (out.elevated ? `<br><strong>needs root</strong> (${esc(out.privilege)}) - through <code>sudo -n</code>, never a prompt` : "");
      form.querySelector("button[value=start]").disabled = Boolean(out.error);
    } catch (e) { box.innerHTML = `<span class="c-red">${esc(e.message)}</span>`; }
  };
  form.command.addEventListener("input", () => { clearTimeout(review.t); review.t = setTimeout(review, 300); });
  review();
  d.addEventListener("close", async () => {
    if (d.returnValue !== "start") return;
    try {
      const run = await send("POST", "/api/v1/scans", body());
      say(`started ${run.label}`);
      if (root?.dataset.tab !== "scans") window.location.href = "/v/scans";
    } catch (e) { say(e.message); }
  });
}

// --- the log -----------------------------------------------------------------------------

export const logState = { frozen: false, mode: "condensed" };
const MODES = ["condensed", "diff", "raw"];

export function cycleMode() {
  if (root?.dataset.tab !== "scans") return;
  logState.mode = MODES[(MODES.indexOf(logState.mode) + 1) % MODES.length];
  say(`report: ${logState.mode}`);
  document.dispatchEvent(new CustomEvent("record:reload"));
}

async function cancel() {
  const running = await send("GET", "/api/v1/runs");
  const run = running.find((r) => r.running);
  if (!run) { say("nothing is running"); return; }
  try { await send("POST", `/api/v1/runs/${run.tool}/cancel`); say(`cancelling ${run.label}`); }
  catch (e) { say(e.message); }
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
  dialog(`<form method="dialog"><h2>Keys</h2><table class="pairs">${keys.map(([k, , text]) =>
    `<tr><th>${k.map((x) => `<kbd>${esc(x === " " ? "Space" : x)}</kbd>`).join(" ")}</th><td>${esc(text)}</td></tr>`).join("")}</table>
    <p><button value="close">Close</button> <span class="dim small">Esc leaves</span></p></form>`);
}

export const handlers = { mark, clearMarks, export: exportDialog, newScan, scanGaps, updateVulndb, cancel, freeze, shots };
