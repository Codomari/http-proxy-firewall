(() => {
  "use strict";
  const countdown = document.getElementById("countdown");
  const status = document.getElementById("restart-status");
  const unavailable = new Set([540, 502, 503, 504]);
  let remaining = 3, checking = false;

  function render() {
    countdown.textContent = String(remaining);
    status.textContent = checking ? "Checking the server…" : `Retrying in ${remaining} ${remaining === 1 ? "second" : "seconds"}…`;
  }

  async function retry() {
    if (checking) return;
    checking = true;
    remaining = 0;
    render();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    try {
      // Probe without replaying a form submission or downloading a full page.
      // Keep this screen visible through connection failures during restart.
      const response = await fetch(window.location.href, {method: "HEAD", cache: "no-store", credentials: "same-origin", redirect: "manual", signal: controller.signal});
      if (response.type === "opaqueredirect" || response.status > 0 && !unavailable.has(response.status)) {
        window.location.replace(window.location.href);
        return;
      }
    } catch (_) {
      // The listener may be closed until the new process has started.
    } finally {
      clearTimeout(timeout);
      checking = false;
      remaining = 3;
      render();
    }
  }

  setInterval(() => {
    if (checking) return;
    remaining--;
    if (remaining <= 0) retry();
    else render();
  }, 1000);

  document.getElementById("retry-now").addEventListener("click", event => {
    event.preventDefault();
    retry();
  });
  render();
})();
