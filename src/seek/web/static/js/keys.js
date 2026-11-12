// The terminal viewer's keys, in the browser. One table: the key handler and
// the help overlay are both built from it, and a test checks it against the
// terminal's bindings, so a key cannot exist in one front end only by accident.
export const KEYS = [
  // [keys, action, help]
  [["j", "ArrowDown"], "down", "next row"],
  [["k", "ArrowUp"], "up", "previous row"],
  [["PageDown"], "pageDown", "a page down"],
  [["PageUp"], "pageUp", "a page up"],
  [["g", "Home"], "first", "first row"],
  [["G", "End"], "last", "last row"],
  [["l", "ArrowRight"], "lineDown", "record: next line (in nmap's text: next scan)"],
  [["h", "ArrowLeft"], "lineUp", "record: previous line (in nmap's text: previous scan)"],
  [["Enter"], "open", "open the selected row - keep pressing to keep digging"],
  [["o"], "follow", "open what the record's cursor is on; on any other line, the record's next view (nmap's own text, a run's reports)"],
  [["Escape", "q"], "back", "leave the filter, clear it, back one level"],
  [["/"], "filter", "filter the list (the viewer's grammar)"],
  [["1", "2", "3", "4", "5", "6", "7", "8", "9"], "sort", "sort by that column; again reverses"],
  [["v"], "nextTab", "next overview"],
  [["V"], "prevTab", "previous overview"],
  [["s"], "stats", "statistics"],
  [["b"], "group", "group by service, then product, then port, then tag"],
  [["u"], "upHosts", "up hosts only (on a host: open ports only)"],
  [["r"], "openPorts", "hosts with open ports only"],
  [["m"], "mark", "mark the row (a bucket marks everything in it)"],
  [["M"], "clearMarks", "clear every mark"],
  [["H"], "markHost", "mark the host the row belongs to - from a port or a screenshot too"],
  [["x"], "export", "export the marks, else the filtered rows"],
  [["n"], "newScan", "new scan"],
  [["U"], "scanGaps", "scan the ports that have no version yet"],
  [["A"], "updateVulndb", "update the vulnerability database (asks first)"],
  [["c"], "cancel", "cancel the running scan"],
  [["p"], "freeze", "freeze the log view (the scan keeps running)"],
  [["d"], "full", "the record full-width"],
  [["i"], "shots", "the row's screenshots"],
  [["Q"], "stopWeb", "stop the web interface (asks first)"],
  [["t"], "tag", "tag the marks, else the row: add or remove a tag, edit or copy one"],
  [["T"], "buildRule", "build a tag rule from the marked hosts"],
  [["R"], "reloadTags", "read the tag rule files again"],
  [["?"], "help", "this list"],
];

export function actionFor(event) {
  for (const [keys, action] of KEYS) {
    if (keys.includes(event.key)) return action;
  }
  return null;
}

// --- the key bar ---------------------------------------------------------------
// Which hints the bar shows, in the terminal's order, and on which views. Keys
// are looked up in KEYS, never written here, so a hint cannot name a key that
// does something else. `keep` survives a bar too narrow for everything - the
// terminal's rule: navigation, the way out and `?` are the last to go.
const onHosts = (v) => v.tab === "hosts" && !v.path;
const onHost = (v) => v.path.startsWith("h:") && !v.path.includes("|");
const onScans = (v) => v.tab === "scans";
export const HINTS = [
  [["down", "up"], "rows", { keep: true }],
  [["lineUp", "lineDown"], "record", { keep: true }],
  [["open"], "open"],
  [["back"], "back", { keep: true }],
  [["filter"], "filter"],
  [["sort"], "sort"],
  [["mark"], "mark"],
  [["export"], "export"],
  [["tag"], "tag"],
  [["upHosts"], "up only", { when: onHosts }],
  [["upHosts"], "open ports only", { when: onHost }],
  [["openPorts"], "open ports only", { when: onHosts }],
  [["newScan"], "scan"],
  [["cancel"], "cancel the run", { when: onScans }],
  [["freeze"], "freeze the log", { when: onScans }],
  [["help"], "all keys", { keep: true }],
];

const SHOWN = { Escape: "Esc" };
export function keyOf(action) {
  const entry = KEYS.find(([, name]) => name === action);
  if (!entry) return "";
  // A run of digits is one hint: 1-9.
  if (action === "sort") return `${entry[0][0]}-${entry[0].at(-1)}`;
  return SHOWN[entry[0][0]] || entry[0][0];
}

export function hintsFor(view) {
  return HINTS.filter(([, , opt]) => !opt?.when || opt.when(view))
    .map(([actions, text, opt]) => ({ keys: actions.map(keyOf), text, keep: Boolean(opt?.keep) }));
}
