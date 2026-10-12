// The header search: everything the session knows, found as you type.
// Results come grouped from /search?fragment=1 - the same page as the full
// results, cut short - so what the dropdown says and what "Enter" opens agree.
// Also: the syntax help, opened from the `?` beside any search box, whose
// examples fill in the box they were opened from.
const box = document.getElementById("global-q");
const panel = document.getElementById("global-results");
let timer = null;
let sent = 0;
let at = -1;

// The results themselves, in reading order - not the "all →" links in the
// group headings, which would otherwise come first and catch `↓ Enter`.
function hits() { return [...panel.querySelectorAll("a.hit")]; }

// Open or shut, and the box says which.
function show(open) {
  panel.hidden = !open;
  box.setAttribute("aria-expanded", String(open));
  if (!open) box.removeAttribute("aria-activedescendant");
}

function highlight(i) {
  const all = hits();
  all.forEach((a, n) => { a.classList.remove("active"); a.id = `hit-${n}`; });
  at = all.length ? (i + all.length) % all.length : -1;
  if (at < 0) return;
  all[at].classList.add("active");
  all[at].scrollIntoView({ block: "nearest" });
  box.setAttribute("aria-activedescendant", all[at].id);
}

async function run() {
  const q = box.value.trim();
  if (!q) { show(false); panel.innerHTML = ""; return; }
  const mine = ++sent;
  try {
    const res = await fetch(`/search?${new URLSearchParams({ q, fragment: "1" })}`);
    if (!res.ok || mine !== sent) return;
    panel.innerHTML = await res.text();
    show(true);
    at = -1;
  } catch (_) { /* the viewer was closed */ }
}

box?.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 150); });
box?.addEventListener("focus", () => { if (box.value.trim()) run(); });
box?.addEventListener("keydown", (e) => {
  if (e.key === "ArrowDown") { e.preventDefault(); highlight(at + 1); }
  else if (e.key === "ArrowUp") { e.preventDefault(); highlight(at - 1); }
  else if (e.key === "Enter" && at >= 0) { e.preventDefault(); window.location.href = hits()[at].href; }
  // Enter with nothing chosen submits the form: the full results page.
  else if (e.key === "Escape") { e.preventDefault(); show(false); box.blur(); }
});
document.addEventListener("click", (e) => {
  if (!e.target.closest(".global-search")) show(false);
});

// Ctrl+K anywhere; `/` too, where the page has no list filter of its own.
document.addEventListener("keydown", (e) => {
  const typing = e.target.closest("input, textarea, select, dialog");
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault(); box.focus(); box.select(); return;
  }
  if (!typing && e.key === "/" && !document.querySelector(".controls .filter")) {
    e.preventDefault(); box.focus();
  }
});

// --- the syntax help ----------------------------------------------------------
const help = document.getElementById("syntax");
let target = null;
document.addEventListener("click", (e) => {
  const opener = e.target.closest(".syntax-help");
  if (opener) {
    e.preventDefault();
    target = document.getElementById(opener.dataset.for);
    help.showModal();
    return;
  }
  const example = e.target.closest("#syntax button.ex");
  if (example && target) {
    target.value = example.textContent;
    help.close();
    target.focus();
    target.dispatchEvent(new Event("input", { bubbles: true }));
  }
});
