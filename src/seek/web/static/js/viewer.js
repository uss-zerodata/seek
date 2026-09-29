// The viewer in the browser: one list, one record beside it, the terminal's
// keys. The page is server-rendered; this only moves the selection, fetches
// records and nmap's text, and turns keys into the same actions the terminal
// has. State that belongs to this window lives in its URL.
import { KEYS, actionFor } from "./keys.js";
import * as actions from "./actions.js";
import { logState } from "./actions.js";
import "./events.js";

const root = document.querySelector(".viewer");
const panel = document.getElementById("record");
const TABS = [...document.querySelectorAll("#tabs a[data-tab]")].map((a) => a.dataset.tab)
  .filter((t) => t !== "gallery");

export const state = { index: -1, raw: null, cursor: -1, full: false, lastRecord: null };

function rows() { return [...document.querySelectorAll("table.rows tr.row")]; }
function params() { return new URL(window.location.href).searchParams; }

function setParam(key, value) {
  const url = new URL(window.location.href);
  if (value === "" || value === null) url.searchParams.delete(key);
  else url.searchParams.set(key, value);
  history.replaceState(null, "", url);
}

// --- selection and the record -------------------------------------------------------

export function select(i, { scroll = true, load = true } = {}) {
  const all = rows();
  if (!all.length) return;
  i = Math.max(0, Math.min(all.length - 1, i));
  all.forEach((tr, n) => tr.classList.toggle("selected", n === i));
  state.index = i;
  const tr = all[i];
  if (scroll) tr.scrollIntoView({ block: "nearest" });
  setParam("sel", tr.dataset.step);
  if (load) loadRecord(tr.dataset.step);
}

export function selectedRow() { return rows()[state.index] || null; }

let recordSeq = 0;
async function loadRecord(step) {
  const mine = ++recordSeq;
  const q = new URLSearchParams({ step, path: root.dataset.path || "", mode: logState.mode });
  const res = await fetch(`/api/v1/records/${root.dataset.tab}?${q}`);
  if (mine !== recordSeq) return;
  if (!res.ok) { panel.innerHTML = `<p class="dim">${(await res.json()).detail}</p>`; return; }
  const rec = await res.json();
  state.raw = null;
  state.lastRecord = rec;
  showRecord(rec.title, rec.html);
}

function showRecord(title, html, extra = "") {
  // A running log follows its newest line, unless the reader scrolled away -
  // the terminal's rule: position is the mode.
  const pinned = panel.scrollTop + panel.clientHeight >= panel.scrollHeight - 4;
  const sameRun = panel.dataset.title === title;
  panel.dataset.title = title;
  panel.innerHTML = `
    <div class="record-head"><h2>${escapeHtml(title)}</h2>${extra}</div>
    <div class="record-search"><input type="search" placeholder="search this record" aria-label="search this record">
      <span class="dim small hits"></span></div>
    <div class="record">${html}</div>`;
  state.cursor = -1;
  panel.querySelector(".record-search input").addEventListener("input", (e) => search(e.target.value));
  if (sameRun && pinned && root.dataset.tab === "scans") panel.scrollTop = panel.scrollHeight;
}

function lines() { return [...panel.querySelectorAll(".record .ln")]; }

function moveCursor(delta) {
  const all = lines();
  if (!all.length) { panel.scrollBy(0, delta * 20); return; }
  const next = Math.max(0, Math.min(all.length - 1, state.cursor + delta));
  if (next === state.cursor) { panel.scrollBy(0, delta * 20); return; }
  all.forEach((ln) => ln.classList.remove("cursor"));
  state.cursor = next;
  all[next].classList.add("cursor");
  all[next].scrollIntoView({ block: "nearest" });
}

// --- nmap's own text ---------------------------------------------------------------

async function openRaw(query) {
  const res = await fetch(`/api/v1/raw?${query}`);
  if (!res.ok) { actions.say((await res.json()).detail); return; }
  const raw = await res.json();
  state.raw = raw;
  const nav = raw.total > 1
    ? `<span class="dim small">scan ${raw.position} of ${raw.total} · <kbd>←</kbd>/<kbd>→</kbd> the others</span>` : "";
  showRecord(raw.title, raw.html, `${nav}<span class="dim small"><kbd>Esc</kbd> back to the record</span>`);
}

function stepRaw(delta) {
  const target = delta > 0 ? state.raw.next : state.raw.previous;
  if (target) openRaw(target);
}

function closeRaw() {
  state.raw = null;
  if (state.lastRecord) showRecord(state.lastRecord.title, state.lastRecord.html);
}

panel.addEventListener("click", (e) => {
  const link = e.target.closest("a.opens");
  if (!link) return;
  e.preventDefault();
  openRaw(link.dataset.raw);
});

// --- search within the record ------------------------------------------------------

let hits = [];
let hitAt = -1;
function search(term) {
  const box = panel.querySelector(".record");
  box.querySelectorAll("mark.hit").forEach((m) => m.replaceWith(...m.childNodes));
  box.normalize();
  hits = [];
  hitAt = -1;
  const out = panel.querySelector(".hits");
  if (!term) { out.textContent = ""; return; }
  const needle = term.toLowerCase();
  const walker = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    let text = node.nodeValue;
    let at = text.toLowerCase().indexOf(needle);
    let current = node;
    while (at !== -1) {
      const match = current.splitText(at);
      const after = match.splitText(needle.length);
      const mark = document.createElement("mark");
      mark.className = "hit";
      match.replaceWith(mark);
      mark.appendChild(match);
      hits.push(mark);
      current = after;
      text = current.nodeValue;
      at = text.toLowerCase().indexOf(needle);
    }
  }
  out.textContent = hits.length ? `${hits.length} match${hits.length === 1 ? "" : "es"} · Enter next` : "no matches";
  if (hits.length) nextHit(1);
}

function nextHit(delta) {
  if (!hits.length) return;
  hits[hitAt]?.classList.remove("current");
  hitAt = (hitAt + delta + hits.length) % hits.length;
  hits[hitAt].classList.add("current");
  hits[hitAt].scrollIntoView({ block: "center" });
  panel.querySelector(".hits").textContent = `${hitAt + 1}/${hits.length}`;
}

// --- navigation --------------------------------------------------------------------

function go(url) { window.location.href = url; }

function sortBy(column) {
  const link = document.querySelectorAll("table.rows th a.sort")[column];
  if (link) go(link.href);
}

function switchTab(delta) {
  const at = TABS.indexOf(root.dataset.tab);
  go(`/v/${TABS[(at + delta + TABS.length) % TABS.length]}`);
}

function back() {
  const filter = document.querySelector(".controls .filter");
  if (state.raw) { closeRaw(); return; }
  if (document.activeElement === filter) { filter.blur(); return; }
  if (filter && filter.value) {
    filter.value = "";
    filter.dispatchEvent(new Event("input", { bubbles: true }));
    return;
  }
  if (root.dataset.path) { history.back(); return; }
  if (root.dataset.tab !== TABS[0]) go(`/v/${TABS[0]}`);
}

function toggleParam(key) {
  const url = new URL(window.location.href);
  if (url.searchParams.get(key)) url.searchParams.delete(key);
  else url.searchParams.set(key, "1");
  url.searchParams.delete("offset");
  go(url);
}

const HANDLERS = {
  down: () => select(state.index + 1),
  up: () => select(state.index - 1),
  pageDown: () => select(state.index + 15),
  pageUp: () => select(state.index - 15),
  first: () => select(0),
  last: () => select(rows().length - 1),
  lineDown: () => (state.raw ? stepRaw(1) : moveCursor(1)),
  lineUp: () => (state.raw ? stepRaw(-1) : moveCursor(-1)),
  open: () => { const tr = selectedRow(); if (tr?.dataset.open) go(tr.dataset.open); },
  follow: () => {
    const line = lines()[state.cursor];
    const raw = line?.querySelector("a.opens");
    const to = line?.querySelector("a.to");
    if (raw) openRaw(raw.dataset.raw);
    else if (to) go(to.href);
    else actions.cycleMode();
  },
  back,
  filter: () => document.querySelector(".controls .filter")?.focus(),
  nextTab: () => switchTab(1),
  prevTab: () => switchTab(-1),
  stats: () => go(root.dataset.tab === "stats" ? "/v/hosts" : "/v/stats"),
  group: () => {
    const groups = ["group-service", "group-product", "group-port"];
    const at = groups.indexOf(root.dataset.tab);
    go(`/v/${groups[(at + 1) % groups.length]}`);
  },
  openPorts: () => (root.dataset.tab === "hosts" && !root.dataset.path ? toggleParam("ports") : go("/v/hosts?ports=1")),
  full: () => { state.full = !state.full; root.classList.toggle("full", state.full); },
  help: () => actions.help(KEYS),
  ...actions.handlers,
};

document.addEventListener("keydown", (event) => {
  if (!root) return;
  const typing = event.target.closest("input, textarea, select, dialog");
  if (typing) {
    if (event.key === "Escape" && event.target.matches(".controls .filter")) { event.preventDefault(); back(); }
    if (event.key === "Enter" && event.target.closest(".record-search")) { event.preventDefault(); nextHit(event.shiftKey ? -1 : 1); }
    return;
  }
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  const action = actionFor(event);
  if (!action) return;
  if (action === "sort") { event.preventDefault(); sortBy(Number(event.key) - 1); return; }
  if (action === "upHosts") {
    event.preventDefault();
    if (root.dataset.tab === "hosts" && !root.dataset.path) toggleParam("up");
    else if ((root.dataset.path || "").startsWith("h:")) toggleParam("open");
    else go("/v/hosts?up=1");
    return;
  }
  const handler = HANDLERS[action];
  if (handler) { event.preventDefault(); handler(); }
});

// Rows are clicked as well as keyed; the list is swapped in place by the filter.
document.addEventListener("click", (e) => {
  const tr = e.target.closest("table.rows tr.row");
  if (!tr || e.target.closest("a")) return;
  select(rows().indexOf(tr), { scroll: false });
});

document.addEventListener("record:reload", () => {
  const tr = selectedRow();
  if (tr && !state.raw) loadRecord(tr.dataset.step);
});

document.addEventListener("list:replaced", () => {
  const step = params().get("sel");
  const at = rows().findIndex((tr) => tr.dataset.step === step);
  select(at >= 0 ? at : 0, { scroll: false });
});

export function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

if (root) {
  // The page arrives with the selected row's record already in it: keep it
  // rather than fetch it again, and remember it for `Esc` out of nmap's text.
  const step = params().get("sel");
  const at = rows().findIndex((tr) => tr.dataset.step === step);
  const rendered = panel.querySelector(".record");
  if (rendered) {
    state.lastRecord = { title: panel.querySelector(".record-head h2")?.textContent || "",
                         html: rendered.innerHTML };
  }
  select(at >= 0 ? at : 0, { scroll: at >= 0, load: !rendered });
}
