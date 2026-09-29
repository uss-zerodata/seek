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
      url.search = "";
      for (const [key, value] of fieldsOf()) if (value !== "") url.searchParams.set(key, value);
      history.replaceState(null, "", url);
      url.searchParams.set("fragment", "1");
      const mine = ++sent;
      try {
        const response = await fetch(url);
        if (response.ok && mine === sent) target.innerHTML = await response.text();
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
