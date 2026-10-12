// Live updates from the session: a new model, changed marks, runs and their
// lines. The list keeps the selected row when it is replaced; the page says so
// when the server has gone away rather than showing stale data silently.
import { refreshList, setLive, logState } from "./actions.js";

const root = document.querySelector(".viewer");
// The key bar's trailing end: what is loaded, or that the session has gone.
const session = document.getElementById("session");
let running = new Map();

function status() {
  const live = [...running.values()].filter((r) => r.running);
  setLive(live.length ? live.map((r) => `◉ ${r.label} ${Math.round(r.elapsed)}s`).join(" · ") : "");
}

let reloadTimer = null;
function reloadRecordSoon() {
  if (logState.frozen || reloadTimer) return;
  reloadTimer = setTimeout(() => { reloadTimer = null; document.dispatchEvent(new CustomEvent("record:reload")); }, 400);
}

function connect() {
  const source = new EventSource("/api/v1/events");
  source.addEventListener("open", () => {
    document.body.classList.remove("offline");
    if (session) session.textContent = session.dataset.loaded;
    status();
  });
  source.addEventListener("error", () => {
    document.body.classList.add("offline");
    const lost = "connection to seek lost - the viewer may have been closed";
    if (session) session.textContent = lost; else setLive(lost);
  });
  // A changed model can change the selected row's record; a mark cannot.
  source.addEventListener("model", () => { refreshList(); reloadRecordSoon(); });
  source.addEventListener("marks", () => refreshList());
  source.addEventListener("run", (e) => {
    const { run } = JSON.parse(e.data);
    running.set(run.id, run);
    status();
    if (root?.dataset.tab === "scans") refreshList();
  });
  source.addEventListener("line", (e) => {
    const { run } = JSON.parse(e.data);
    running.set(run.id, run);
    const selected = document.querySelector("table.rows tr.selected");
    if (selected?.dataset.step === `r:${run.id}`) reloadRecordSoon();
  });
}

// A list that was replaced says what is loaded now.
document.addEventListener("list:replaced", () => {
  const loaded = document.querySelector("#list [data-loaded]")?.dataset.loaded;
  if (!session || !loaded) return;
  session.dataset.loaded = loaded;
  if (!document.body.classList.contains("offline")) session.textContent = loaded;
});

connect();
