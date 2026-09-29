// Filter as you type: the server filters with the viewer's grammar and sends
// the list back; this swaps it in. The newest request wins - a slow answer to
// an older query never overwrites a newer one.
document.querySelectorAll("input[data-filter]").forEach((box) => {
  const target = document.getElementById(box.dataset.filter);
  let timer = null;
  let sent = 0;
  box.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      const url = new URL(window.location.href);
      url.searchParams.set("q", box.value);
      url.searchParams.delete("offset");
      history.replaceState(null, "", url);
      url.searchParams.set("fragment", "1");
      const mine = ++sent;
      try {
        const response = await fetch(url);
        if (response.ok && mine === sent) target.innerHTML = await response.text();
      } catch (_) { /* the viewer was closed; leave the list as it is */ }
    }, 200);
  });
});
