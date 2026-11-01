(() => {
  "use strict";
  const base = "/__pf/__admin";
  const byId = (id) => document.getElementById(id);
  const number = new Intl.NumberFormat(undefined, {maximumFractionDigits: 0});
  const rateNumber = new Intl.NumberFormat(undefined, {maximumFractionDigits: 1});
  const state = {search: "", version: 0, previous: new Map(), previousTotal: null, previousRedis: null, timer: null, inflight: false, pending: false};
  const text = (id, value) => { byId(id).textContent = value; };
  const percent = (value) => value == null ? "—" : `${rateNumber.format(value)}%`;
  const frequency = (count, previous, key, now) => previous && now > previous.time && count >= previous[key] ? (count - previous[key]) * 1000 / (now - previous.time) : null;
  const bytes = (value) => {
    const n = Number(value || 0);
    if (n < 1024) return `${number.format(n)} B`;
    const units = ["KiB", "MiB", "GiB", "TiB"];
    const power = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length);
    return `${(n / Math.pow(1024, power)).toFixed(1)} ${units[power - 1]}`;
  };
  const uptime = (value) => {
    const seconds = Math.max(0, Math.floor(Number(value || 0)));
    const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), minutes = Math.floor(seconds % 3600 / 60);
    if (days) return `${days}d ${hours}h`;
    if (hours) return `${hours}h ${minutes}m`;
    return `${minutes}m ${seconds % 60}s`;
  };
  function connection(label, kind) {
    const node = byId("connection");
    node.textContent = label;
    node.className = `status ${kind || ""}`;
  }
  function cell(row, value, title) {
    const node = document.createElement("td");
    node.textContent = value;
    if (title) node.title = title;
    row.appendChild(node);
    return node;
  }
  function render(data) {
    const total = data.totals, runtime = data.runtime, now = Date.parse(data.timestamp) || Date.now();
    text("requests", number.format(total.requests));
    text("inflight", number.format(total.inflight));
    text("rejected", number.format(total.rejected));
    text("errors", number.format(total.errors_5xx));
    const previous = state.previousTotal;
    const requestRate = previous && now > previous.time && total.requests >= previous.requests ? (total.requests - previous.requests) * 1000 / (now - previous.time) : null;
    text("rate", requestRate === null ? "Collecting rate sample…" : `${rateNumber.format(requestRate)} requests / sec`);
    state.previousTotal = {time: now, requests: total.requests};
    text("goroutines", number.format(runtime.goroutines));
    text("heap", bytes(runtime.heap_allocated_bytes));
    text("heap-inuse", `${bytes(runtime.heap_in_use_bytes)} in use`);
    text("system-memory", bytes(runtime.system_bytes));
    text("stack", `${bytes(runtime.stack_bytes)} stack`);
    text("uptime", uptime(runtime.uptime_seconds));
    text("gc", number.format(runtime.gc_count));
    text("gc-pause", `${(Number(runtime.gc_pause_total_ns || 0) / 1e6).toFixed(1)} ms total pause`);
    text("cpu", `${runtime.gomaxprocs} / ${runtime.cpu_count}`);
    text("process-cpu", percent(runtime.process_cpu_percent));
    text("process-cpu-detail", runtime.process_resident_bytes == null ? "Unavailable on this OS" : runtime.process_cpu_percent == null ? "Collecting a CPU sample…" : "100% = one full CPU core");
    text("process-ram", runtime.process_resident_bytes == null ? "—" : bytes(runtime.process_resident_bytes));
    text("process-ram-detail", runtime.process_resident_bytes == null ? "Unavailable on this OS" : runtime.server_memory_bytes ? `${percent(runtime.process_resident_bytes * 100 / runtime.server_memory_bytes)} of server RAM` : "Resident physical memory");
    text("server-cpu", percent(runtime.server_cpu_percent));
    text("server-cpu-detail", runtime.server_memory_bytes == null ? "Unavailable on this OS" : runtime.server_cpu_percent == null ? "Collecting a CPU sample…" : "Across all visible logical CPUs");
    text("server-ram", percent(runtime.server_memory_percent));
    text("server-ram-detail", runtime.server_memory_used_bytes == null || runtime.server_memory_bytes == null ? "Unavailable on this OS" : `${bytes(runtime.server_memory_used_bytes)} / ${bytes(runtime.server_memory_bytes)} used`);
    renderServices(data.services, now);
    text("capacity", `${number.format(total.tracked_hosts)} / ${number.format(total.capacity)} hosts tracked · ${number.format(total.untracked_requests)} requests outside host table`);
    const body = byId("hosts"), fragment = document.createDocumentFragment(), samples = new Map();
    for (const host of data.hosts) {
      const row = document.createElement("tr"), last = state.previous.get(host.hostname);
      const rps = last && now > last.time && host.requests >= last.requests ? (host.requests - last.requests) * 1000 / (now - last.time) : null;
      samples.set(host.hostname, {time: now, requests: host.requests});
      cell(row, host.hostname, host.hostname);
      cell(row, number.format(host.requests));
      cell(row, rps === null ? "—" : rateNumber.format(rps));
      cell(row, number.format(host.inflight));
      cell(row, number.format(host.rejected));
      cell(row, number.format(host.errors_5xx));
      const status = cell(row, ""), badge = document.createElement("span");
      badge.className = `ddos-badge${host.ddos ? " active" : ""}`;
      badge.textContent = host.ddos ? "Cookie checks active" : "Normal";
      if (host.ddos_until) badge.title = `Active until ${new Date(host.ddos_until).toLocaleString()}`;
      status.appendChild(badge);
      fragment.appendChild(row);
    }
    if (!data.hosts.length) {
      const row = document.createElement("tr"), empty = cell(row, state.search ? "No domains match your search." : "No host traffic recorded yet.");
      empty.colSpan = 7; empty.className = "empty"; fragment.appendChild(row);
    }
    body.replaceChildren(fragment);
    state.previous = samples;
    text("host-count", `Showing all ${number.format(data.hosts.length)} ${state.search ? "matching " : "tracked "}hosts`);
    text("updated", `Updated ${new Date(now).toLocaleTimeString()}`);
    byId("error").hidden = true;
    connection(document.hidden ? "Paused" : "Live", document.hidden ? "paused" : "");
  }
  function renderServices(services, now) {
    const redis = services.redis, database = services.maxmind;
    const labels = {disabled: "Disabled", not_started: "Not started", stopped: "Stopped", not_checked: "Enabled · not checked", unavailable: "Unavailable · local fallback", available: "In use"};
    text("redis-status", labels[redis.status] || "Unknown");
    byId("redis-status").className = `service-state${redis.status === "available" ? " healthy" : redis.status === "unavailable" ? " warning" : ""}`;
    const previous = state.previousRedis;
    const reads = redis.enabled ? frequency(redis.reads, previous, "reads", now) : 0;
    const writes = redis.enabled ? frequency(redis.writes, previous, "writes", now) : 0;
    text("redis-reads", reads === null ? "—" : rateNumber.format(reads));
    text("redis-writes", writes === null ? "—" : rateNumber.format(writes));
    text("redis-totals", `${number.format(redis.reads)} reads · ${number.format(redis.writes)} writes · ${number.format(redis.queue_depth)} queued writes`);
    const lastSuccess = redis.last_success ? ` · last success ${new Date(redis.last_success).toLocaleTimeString()}` : "";
    text("redis-detail", redis.enabled ? `${number.format(redis.read_errors)} read errors · ${number.format(redis.write_errors)} write errors${lastSuccess}` : "Local state only · Redis is disabled");
    state.previousRedis = {time: now, reads: redis.reads, writes: redis.writes};
    text("maxmind-status", database.updating ? "Updating" : database.loaded ? "Loaded" : database.file_exists ? "File not loaded" : "Missing");
    byId("maxmind-status").className = `service-state${database.loaded && !database.updating ? " healthy" : !database.loaded || database.updating ? " warning" : ""}`;
    text("maxmind-modified", database.last_modified ? new Date(database.last_modified).toLocaleString() : "No database file");
    text("maxmind-update", database.updating ? "Downloading and validating an update…" : database.auto_update_enabled ? "Automatic updates enabled" : "Automatic updates disabled");
  }
  function schedule() {
    clearTimeout(state.timer);
    if (!document.hidden) state.timer = setTimeout(poll, 2000);
  }
  async function poll() {
    if (document.hidden) return;
    if (state.inflight) { state.pending = true; return; }
    clearTimeout(state.timer);
    state.pending = false;
    state.inflight = true;
    const version = state.version;
    byId("refresh").disabled = true;
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const query = new URLSearchParams({search: state.search});
      const response = await fetch(`${base}/api/overview?${query}`, {credentials: "same-origin", cache: "no-store", signal: controller.signal});
      if (!response.ok) throw new Error(response.status === 401 ? "Authentication expired. Reload this page to sign in." : `Server returned HTTP ${response.status}.`);
      const data = await response.json();
      if (version === state.version) render(data);
    } catch (error) {
      if (version === state.version) {
        connection(document.hidden ? "Paused" : "Disconnected", document.hidden ? "paused" : "failed");
        text("error", error.name === "AbortError" ? "The monitoring request timed out. Retrying…" : `Unable to refresh: ${error.message}`);
        byId("error").hidden = false;
      }
    } finally {
      clearTimeout(timeout);
      state.inflight = false;
      byId("refresh").disabled = false;
      if (state.pending && !document.hidden) { state.pending = false; poll(); } else { schedule(); }
    }
  }
  let searchTimer;
  byId("search").addEventListener("input", (event) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.search = event.target.value; state.version++; state.previous.clear(); poll(); }, 250);
  });
  byId("refresh").addEventListener("click", poll);
  document.addEventListener("visibilitychange", () => {
    clearTimeout(state.timer);
    if (document.hidden) connection("Paused", "paused"); else { connection("Connecting", "connecting"); poll(); }
  });
  poll();
})();
