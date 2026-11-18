// Ask before destructive actions. Forms opt in with data-confirm="message".
document.addEventListener("submit", function (ev) {
  var msg = ev.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) {
    ev.preventDefault();
    return;
  }
  var btn = ev.target.querySelector("button");
  if (btn) {
    // Hub installs can take a while; avoid double submits.
    setTimeout(function () { btn.disabled = true; }, 0);
  }
});
