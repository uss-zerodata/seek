// A list form - filter box, sort, direction - updates the list in place: the
// server filters and sorts with the viewer's rules and sends the list back,
// which is swapped in. The newest request wins: a slow answer to an older
// query never overwrites a newer one. Without script the form is a plain GET.
function wire(form, target, fieldsOf) {
  let timer = null;
  let sent = 0;
  const refresh = (delay) => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const url = new URL(form.action || window.location.href, window.location.href);
      // The selected row is this window's, not the form's: it stays in the URL.
      const selected = url.searchParams.get("sel");
      url.search = "";
      if (selected) url.searchParams.set("sel", selected);
      for (const [key, value] of fieldsOf()) if (value !== "") url.searchParams.set(key, value);
      history.replaceState(null, "", url);
      url.searchParams.set("fragment", "1");
      const mine = ++sent;
      try {
        const response = await fetch(url);
        if (response.ok && mine === sent) {
          // The list scrolls in a pane of its own, and the pane is part of
          // what is replaced: put it back where the reader had it.
          const top = target.querySelector(".list-scroll")?.scrollTop || 0;
          target.innerHTML = await response.text();
          const pane = target.querySelector(".list-scroll");
          if (pane) pane.scrollTop = top;
          document.dispatchEvent(new CustomEvent("list:replaced"));
        }
      } catch (_) { /* the viewer was closed; leave the list as it is */ }
    }, delay);
  };
  form.addEventListener("input", (e) => refresh(e.target.type === "search" ? 200 : 0));
  form.addEventListener("submit", (e) => { e.preventDefault(); refresh(0); });
}

document.querySelectorAll("form[data-list]").forEach((form) => {
  wire(form, document.getElementById(form.dataset.list), () => new FormData(form));
});

// The plain filter boxes of the host and service lists.
document.querySelectorAll("input[data-filter]").forEach((box) => {
  const holder = document.createElement("form");
  holder.action = window.location.pathname;
  box.replaceWith(holder);
  holder.appendChild(box);
  wire(holder, document.getElementById(box.dataset.filter), () => [["q", box.value]]);
});

// The gallery's grouping: `b` steps to the next one, as `b` steps through the
// terminal's groupings. Not while typing.
document.addEventListener("keydown", (event) => {
  if (event.key !== "b" || event.ctrlKey || event.metaKey || event.altKey) return;
  if (event.target.closest("input, textarea, select, dialog")) return;
  const links = [...document.querySelectorAll(".groupings a")];
  if (!links.length) return;
  const at = links.findIndex((a) => a.hasAttribute("aria-current"));
  event.preventDefault();
  window.location.href = links[(at + 1) % links.length].href;
});

// "mark host" on the screenshots: the session's marks, as `H` in the viewer - so
// hosts found by their pictures can be tagged, built into a rule or exported.
async function syncMarkButtons() {
  const buttons = document.querySelectorAll("button.mark-host");
  if (!buttons.length) return;
  let marks;
  try { marks = await (await fetch("/api/v1/marks")).json(); } catch (_) { return; }
  const hosts = new Set(marks.marks.filter((m) => m.port == null).map((m) => m.address));
  buttons.forEach((b) => {
    const on = hosts.has(b.dataset.address);
    b.setAttribute("aria-pressed", String(on));
    b.textContent = on ? "● marked" : "mark host";
  });
}
document.addEventListener("click", async (event) => {
  const button = event.target.closest("button.mark-host");
  if (!button) return;
  event.preventDefault();
  try {
    const res = await fetch("/api/v1/marks/hosts", { method: "POST", headers: { "Content-Type": "application/json" },
                                                       body: JSON.stringify({ address: button.dataset.address }) });
    if (!res.ok) return;
  } catch (_) { return; }
  syncMarkButtons();
});
document.addEventListener("list:replaced", syncMarkButtons);
syncMarkButtons();

