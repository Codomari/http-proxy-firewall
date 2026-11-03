(() => {
  "use strict";
  const countdown = document.getElementById("countdown");
  const status = document.getElementById("restart-status");
  let remaining = 3, checking = false, navigating = false;

  function render() {
    countdown.textContent = String(remaining);
    status.textContent = checking ? "Checking the server…" : `Retrying in ${remaining} ${remaining === 1 ? "second" : "seconds"}…`;
  }

  async function retry() {
    if (checking || navigating) return;
    checking = true;
    remaining = 0;
    render();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500);
    try {
      // Probe without replaying a form submission or downloading a full page.
      // Keep this screen visible through connection failures during restart.
      const response = await fetch(window.location.href, {method: "HEAD", cache: "no-store", credentials: "same-origin", redirect: "manual", signal: controller.signal});
      if (response.type === "opaqueredirect" || response.status >= 200 && response.status < 400) {
        window.location.replace(window.location.href);
        navigating = true;
        clearInterval(timer);
        return;
      }
    } catch (_) {
      // The listener may be closed until the new process has started.
    } finally {
      clearTimeout(timeout);
      if (navigating) status.textContent = "Server is ready. Opening page…";
      else {
        checking = false;
        remaining = 3;
        render();
      }
    }
  }

  const timer = setInterval(() => {
    if (checking || navigating) return;
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
