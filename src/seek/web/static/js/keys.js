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
  [["o"], "follow", "open what the record's cursor is on: a host, a port, a capture, nmap's own text"],
  [["Escape", "q"], "back", "leave the filter, clear it, back one level"],
  [["/"], "filter", "filter the list (the viewer's grammar)"],
  [["1", "2", "3", "4", "5", "6", "7", "8", "9"], "sort", "sort by that column; again reverses"],
  [["v"], "nextTab", "next overview"],
  [["V"], "prevTab", "previous overview"],
  [["s"], "stats", "statistics"],
  [["b"], "group", "group by service, then product, then port"],
  [["u"], "upHosts", "up hosts only (on a host: open ports only)"],
  [["r"], "openPorts", "hosts with open ports only"],
  [["m"], "mark", "mark the row (a bucket marks everything in it)"],
  [["M"], "clearMarks", "clear every mark"],
  [["x"], "export", "export the marks, else the filtered rows"],
  [["n"], "newScan", "new scan"],
  [["c"], "cancel", "cancel the running scan"],
  [["p"], "freeze", "freeze the log view (the scan keeps running)"],
  [["d"], "full", "the record full-width"],
  [["i"], "shots", "the row's screenshots"],
  [["?"], "help", "this list"],
];

export function actionFor(event) {
  for (const [keys, action] of KEYS) {
    if (keys.includes(event.key)) return action;
  }
  return null;
}
