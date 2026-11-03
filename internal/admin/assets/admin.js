(() => {
  "use strict";
  const base = "/__pf/__admin";
  const byId = (id) => document.getElementById(id);
  const number = new Intl.NumberFormat(undefined, {maximumFractionDigits: 0});
  const rateNumber = new Intl.NumberFormat(undefined, {maximumFractionDigits: 1});
  const state = {search: "", sort: "rps", direction: "descending", hosts: [], version: 0, previous: new Map(), previousTotal: null, previousRedis: null, timer: null, inflight: false, pending: false};
  let activeTab = "monitoring";
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
    text("cve-rejected", number.format(total.cve_rejected));
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
    renderDisks(data.disks);
    text("capacity", `${number.format(total.tracked_hosts)} / ${number.format(total.capacity)} hosts tracked · ${number.format(total.untracked_requests)} requests outside host table`);
    const samples = new Map();
    state.hosts = data.hosts.map((host) => {
      const last = state.previous.get(host.hostname);
      const rps = last && now > last.time && host.requests >= last.requests ? (host.requests - last.requests) * 1000 / (now - last.time) : null;
      samples.set(host.hostname, {time: now, requests: host.requests});
      return {...host, rps};
    });
    state.previous = samples;
    renderHosts();
    text("host-count", `Showing all ${number.format(data.hosts.length)} ${state.search ? "matching " : "tracked "}hosts`);
    text("updated", `Updated ${new Date(now).toLocaleTimeString()}`);
    byId("error").hidden = true;
    connection(document.hidden ? "Paused" : "Live", document.hidden ? "paused" : "");
  }
  function renderHosts() {
    const body = byId("hosts"), fragment = document.createDocumentFragment();
    const direction = state.direction === "ascending" ? 1 : -1;
    const hosts = [...state.hosts].sort((a, b) => {
      const left = a[state.sort], right = b[state.sort];
      // Hosts without a rate sample stay last in either direction.
      if (left == null && right != null) return 1;
      if (right == null && left != null) return -1;
      const comparison = state.sort === "hostname" ? left.localeCompare(right) : Number(left) - Number(right);
      return comparison * direction || a.hostname.localeCompare(b.hostname);
    });
    for (const button of document.querySelectorAll("[data-host-sort]")) {
      button.parentElement.setAttribute("aria-sort", button.dataset.hostSort === state.sort ? state.direction : "none");
    }
    for (const host of hosts) {
      const row = document.createElement("tr");
      cell(row, host.hostname, host.hostname);
      cell(row, number.format(host.requests));
      cell(row, host.rps === null ? "—" : rateNumber.format(host.rps));
      cell(row, number.format(host.inflight));
      cell(row, number.format(host.rejected));
      cell(row, number.format(host.cve_rejected));
      cell(row, number.format(host.errors_5xx));
      const status = cell(row, ""), badge = document.createElement("span");
      badge.className = `ddos-badge${host.ddos ? " active" : ""}`;
      badge.textContent = host.ddos ? "Cookie checks active" : "Normal";
      if (host.ddos_until) badge.title = `Active until ${new Date(host.ddos_until).toLocaleString()}`;
      status.appendChild(badge);
      fragment.appendChild(row);
    }
    if (!hosts.length) {
      const row = document.createElement("tr"), empty = cell(row, state.search ? "No hosts match your search." : "No host traffic recorded yet.");
      empty.colSpan = 8; empty.className = "empty"; fragment.appendChild(row);
    }
    body.replaceChildren(fragment);
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
  function renderDisks(disks) {
    const body = byId("disks"), fragment = document.createDocumentFragment();
    const mounts = disks && Array.isArray(disks.mounts) ? disks.mounts : [];
    text("disk-status", disks && disks.available ? `${number.format(mounts.length)} mounts visible to this service · space sampled every 5 seconds · shared filesystems are listed per mount` : "Disk information is unavailable on this OS.");
    for (const disk of mounts) {
      const row = document.createElement("tr"), mount = cell(row, disk.mount, disk.mount);
      const source = document.createElement("span");
      source.className = "mount-source";
      source.textContent = disk.source;
      mount.appendChild(source);
      cell(row, `${disk.filesystem}${disk.read_only ? " · read only" : ""}`);
      for (const key of ["total_bytes", "used_bytes", "available_bytes"]) cell(row, disk[key] == null ? "—" : bytes(disk[key]));
      const usage = cell(row, percent(disk.used_percent));
      if (disk.used_percent >= 90) usage.className = "disk-warning";
      fragment.appendChild(row);
    }
    if (!mounts.length) {
      const row = document.createElement("tr"), empty = cell(row, "No mounted filesystem information available.");
      empty.colSpan = 6; empty.className = "empty"; fragment.appendChild(row);
    }
    body.replaceChildren(fragment);
  }
  const logs = {open: false, cursor: "", timer: null, controller: null, limited: false};
  function appendLogs(data, target = logs, prefix = "log") {
    const view = byId(`${prefix}-lines`);
    const follow = view.childElementCount === 0 || view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const fragment = document.createDocumentFragment();
    for (const line of data.lines.slice(-10000)) {
      const node = document.createElement("div");
      node.textContent = line || " ";
      fragment.appendChild(node);
    }
    view.appendChild(fragment);
    const before = view.scrollHeight;
    while (view.childElementCount > 10000) view.firstElementChild.remove();
    if (follow) view.scrollTop = view.scrollHeight;
    else view.scrollTop = Math.max(0, view.scrollTop - (before - view.scrollHeight));
    target.cursor = data.cursor;
    target.limited = target.limited || data.limited;
    text(`${prefix}-status`, `${prefix === "debug" && !target.enabled ? "Capture disabled" : "Live"} · ${number.format(view.childElementCount)} / 10,000 lines${data.reset && view.childElementCount > data.lines.length ? " · log restarted or rotated" : ""}${target.limited ? " · some log content was truncated" : ""}`);
  }
  async function pollLogs() {
    if (!logs.open || activeTab !== "logs" || document.hidden || logs.controller) return;
    clearTimeout(logs.timer);
    const controller = new AbortController();
    logs.controller = controller;
    const timeout = setTimeout(() => controller.abort(), 10000);
    let more = false;
    try {
      const query = new URLSearchParams();
      if (logs.cursor) query.set("cursor", logs.cursor);
      const response = await fetch(`${base}/api/logs?${query}`, {credentials: "same-origin", cache: "no-store", signal: controller.signal});
      if (!response.ok) throw new Error(response.status === 401 ? "Authentication expired. Reload to sign in." : response.status === 503 ? "Log file unavailable. Waiting for the service log…" : `HTTP ${response.status}`);
      const data = await response.json();
      if (logs.open && logs.controller === controller && !controller.signal.aborted) { appendLogs(data); more = data.more; }
    } catch (error) {
      if (logs.open && logs.controller === controller) text("log-status", error.name === "AbortError" ? "Log request timed out. Retrying…" : `Unable to read logs: ${error.message}`);
    } finally {
      clearTimeout(timeout);
      if (logs.controller === controller) {
        logs.controller = null;
        if (logs.open && activeTab === "logs" && !document.hidden) logs.timer = setTimeout(pollLogs, more ? 100 : 2000);
      }
    }
  }
  byId("show-logs").addEventListener("click", () => {
    logs.open = !logs.open;
    byId("show-logs").setAttribute("aria-expanded", String(logs.open));
    text("show-logs", logs.open ? "Hide logs" : "Show logs");
    byId("log-content").hidden = !logs.open;
    clearTimeout(logs.timer);
    if (logs.controller) { logs.controller.abort(); logs.controller = null; }
    if (logs.open) {
      logs.cursor = ""; logs.limited = false;
      byId("log-lines").replaceChildren();
      text("log-status", "Loading latest 100 lines…");
      pollLogs();
    } else text("log-status", "Latest 100 lines · keeps up to 10,000 lines while open");
  });
  const debug = {hostname: "", clientIP: "", file: "", enabled: false, cursor: "", limited: false, unparsed: false, timer: null, controller: null, busy: false};
  function appendDebug(data) {
    const body = byId("debug-rows"), view = byId("debug-scroll");
    const follow = body.childElementCount === 0 || view.scrollHeight - view.scrollTop - view.clientHeight < 40;
    const fragment = document.createDocumentFragment();
    for (const entry of data.entries.slice(-10000)) {
      const row = document.createElement("tr");
      if (entry.raw !== undefined) {
        const content = cell(row, "Unparsed log entry"), raw = document.createElement("pre");
        content.colSpan = 9;
        raw.textContent = entry.raw;
        content.appendChild(raw);
        debug.unparsed = true;
      } else {
        for (const value of [entry.timestamp, entry.client_ip, entry.hostname, entry.method, entry.url]) cell(row, value);
        cell(row, entry.duration_ms == null ? "—" : `${Number(entry.duration_ms).toFixed(2)} ms`);
        cell(row, entry.response ? entry.response.status : "—");
        const headers = cell(row, ""), details = document.createElement("details"), summary = document.createElement("summary"), values = document.createElement("pre");
        summary.textContent = `${number.format(entry.headers.length)} headers`;
        values.textContent = entry.headers.map(header => `${header.name}: ${header.value}`).join("\n");
        details.appendChild(summary); details.appendChild(values); headers.appendChild(details);
        const response = cell(row, "");
        if (entry.response) {
          const result = entry.response, details = document.createElement("details"), summary = document.createElement("summary"), values = document.createElement("pre");
          summary.textContent = `${number.format(result.headers.length)} headers · ${bytes(result.bytes)} body${result.body_truncated ? " · preview truncated" : ""}${result.error ? " · transfer failed" : ""}`;
          values.textContent = result.headers.map(header => `${header.name}: ${header.value}`).join("\n") + `\n\nBody${result.body_encoding === "base64" ? " (base64)" : ""}${result.body_truncated ? " (first 16 KiB)" : ""}:\n${result.body || "(empty)"}${result.error ? `\n\nTransfer error: ${result.error}` : ""}`;
          details.appendChild(summary); details.appendChild(values); response.appendChild(details);
        } else response.textContent = "—";
      }
      fragment.appendChild(row);
    }
    body.appendChild(fragment);
    const before = view.scrollHeight;
    while (body.childElementCount > 10000) body.firstElementChild.remove();
    if (follow) view.scrollTop = view.scrollHeight;
    else view.scrollTop = Math.max(0, view.scrollTop - (before - view.scrollHeight));
    debug.cursor = data.cursor;
    debug.limited = debug.limited || data.limited;
    byId("debug-empty").hidden = body.childElementCount > 0;
    text("debug-status", `${debug.enabled ? "Live" : "Capture disabled"} · ${number.format(body.childElementCount)} / 10,000 requests · pulls every 2 seconds${data.reset && body.childElementCount > data.entries.length ? " · log restarted or rotated" : ""}${debug.limited ? " · some log content was truncated" : ""}${debug.unparsed ? " · unparsed entries shown as text" : ""}`);
  }
  const generalRules = {busy: false, dirty: false, key: "", available: false, controller: null};
  function renderGeneralRules(data, saved = false) {
    generalRules.available = data.available;
    byId("general-rules-save").disabled = generalRules.busy || !data.available;
    const key = JSON.stringify(data);
    if ((!generalRules.dirty || saved) && key !== generalRules.key) {
      byId("whitelist-ips").value = data.whitelist_ips.join("\n");
      byId("whitelist-networks").value = data.whitelist_networks.join("\n");
      byId("allowed-countries").value = data.allowed_countries.join("\n");
      byId("ip-checkpoint").checked = data.ip_checkpoint;
      byId("country-checkpoint").checked = data.country_checkpoint;
      byId("ddos-threshold").value = String(data.ddos_threshold);
      generalRules.key = key;
    }
    text("general-rules-status", data.available ? "Global rules · loaded from YAML · saved changes apply immediately" : "General rules are unavailable.");
    byId("general-rules-overrides").hidden = !data.overrides.length;
    text("general-rules-overrides", data.overrides.length ? `Process environment overrides take precedence after a restart: ${data.overrides.join(", ")}.` : "");
  }
  async function pollGeneralRules() {
    if (generalRules.busy || generalRules.controller) return;
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    generalRules.controller = controller;
    try {
      const response = await fetch(`${base}/api/general-rules`, {credentials: "same-origin", cache: "no-store", signal: controller.signal});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      if (generalRules.controller === controller && !controller.signal.aborted) renderGeneralRules(data);
    } catch (error) {
      if (generalRules.controller === controller && !controller.signal.aborted) text("general-rules-status", `Unable to load YAML settings: ${error.message}`);
    } finally {
      clearTimeout(timeout);
      if (generalRules.controller === controller) generalRules.controller = null;
    }
  }
  byId("general-rules-form").addEventListener("input", () => {
    generalRules.dirty = true;
    text("general-rules-feedback", "Unsaved changes");
  });
  byId("general-rules-form").addEventListener("submit", async event => {
    event.preventDefault();
    if (generalRules.busy || !generalRules.available) return;
    if (generalRules.controller) { generalRules.controller.abort(); generalRules.controller = null; }
    generalRules.busy = true;
    byId("general-rules-save").disabled = true;
    byId("general-rules-error").hidden = true;
    const list = id => byId(id).value.split(/[,\r\n]+/).map(value => value.trim()).filter(Boolean);
    const settings = {whitelist_ips: list("whitelist-ips"), whitelist_networks: list("whitelist-networks"), allowed_countries: list("allowed-countries"), ip_checkpoint: byId("ip-checkpoint").checked, country_checkpoint: byId("country-checkpoint").checked, ddos_threshold: Number(byId("ddos-threshold").value)};
    const inputs = byId("general-rules-form").querySelectorAll("input, textarea");
    for (const input of inputs) input.disabled = true;
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(`${base}/api/general-rules`, {method: "POST", headers: {"X-PF-Admin": "1", "Content-Type": "application/json"}, credentials: "same-origin", cache: "no-store", body: JSON.stringify(settings), signal: controller.signal});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      generalRules.dirty = false;
      generalRules.key = "";
      renderGeneralRules(data, true);
      text("general-rules-feedback", "Saved to override YAML and applied");
    } catch (error) {
      text("general-rules-error", error.name === "AbortError" ? "Save timed out. Reload settings to check whether it completed." : error.message);
      byId("general-rules-error").hidden = false;
    } finally {
      clearTimeout(timeout);
      generalRules.busy = false;
      for (const input of inputs) input.disabled = false;
      byId("general-rules-save").disabled = !generalRules.available;
    }
  });
  const cloudflare = {busy: false, key: "", timer: null, controller: null};
  function renderCloudflare(data) {
    if (!data || cloudflare.busy) return;
    const key = JSON.stringify(data);
    if (key === cloudflare.key) return;
    cloudflare.key = key;
    byId("cloudflare-save").disabled = !data.available;
    text("cloudflare-status", data.available ? `${number.format(data.hosts.length)} domain rules · changes apply immediately` : "Domain rules are unavailable.");
    const fragment = document.createDocumentFragment();
    for (const host of data.hosts) {
      const row = document.createElement("tr");
      cell(row, host.hostname);
      cell(row, "Behind CloudFlare");
      const action = cell(row, ""), button = document.createElement("button");
      button.type = "button";
      button.setAttribute("aria-label", `Remove Behind CloudFlare rule for ${host.hostname}`);
      button.textContent = "Remove rule";
      button.addEventListener("click", () => saveCloudflare(host.hostname, true));
      action.appendChild(button);
      fragment.appendChild(row);
    }
    if (!data.hosts.length) {
      const row = document.createElement("tr"), empty = cell(row, "No domain rules. Add a domain and select its rule above.");
      empty.colSpan = 3; empty.className = "empty"; fragment.appendChild(row);
    }
    byId("cloudflare-hosts").replaceChildren(fragment);
  }
  function pauseRules() {
    clearTimeout(cloudflare.timer);
    if (cloudflare.controller) { cloudflare.controller.abort(); cloudflare.controller = null; }
    if (generalRules.controller) { generalRules.controller.abort(); generalRules.controller = null; }
  }
  async function pollRules() {
    if (activeTab !== "rules" || document.hidden || cloudflare.controller || cloudflare.busy) return;
    pollGeneralRules();
    clearTimeout(cloudflare.timer);
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    cloudflare.controller = controller;
    try {
      const response = await fetch(`${base}/api/cloudflare-hosts`, {credentials: "same-origin", cache: "no-store", signal: controller.signal});
      if (!response.ok) throw new Error(response.status === 401 ? "Authentication expired. Reload to sign in." : `HTTP ${response.status}`);
      const data = await response.json();
      if (cloudflare.controller === controller && !controller.signal.aborted) renderCloudflare(data);
    } catch (error) {
      if (cloudflare.controller === controller) text("cloudflare-status", `Unable to load domain rules: ${error.message}`);
    } finally {
      clearTimeout(timeout);
      if (cloudflare.controller === controller) {
        cloudflare.controller = null;
        if (activeTab === "rules" && !document.hidden) cloudflare.timer = setTimeout(pollRules, 2000);
      }
    }
  }
  async function saveCloudflare(hostname, remove = false) {
    if (cloudflare.busy) return;
    pauseRules();
    cloudflare.busy = true;
    byId("cloudflare-save").disabled = true;
    for (const button of byId("cloudflare-hosts").querySelectorAll("button")) button.disabled = true;
    byId("cloudflare-error").hidden = true;
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const query = new URLSearchParams({hostname});
      const response = await fetch(`${base}/api/cloudflare-hosts?${query}`, {method: remove ? "DELETE" : "POST", headers: {"X-PF-Admin": "1"}, credentials: "same-origin", cache: "no-store", signal: controller.signal});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      cloudflare.busy = false;
      cloudflare.key = "";
      renderCloudflare(data);
    } catch (error) {
      text("cloudflare-error", error.name === "AbortError" ? "Settings save timed out. Refresh to check the current state." : error.message);
      byId("cloudflare-error").hidden = false;
    } finally {
      clearTimeout(timeout);
      cloudflare.busy = false;
      byId("cloudflare-save").disabled = false;
      for (const button of byId("cloudflare-hosts").querySelectorAll("button")) button.disabled = false;
      cloudflare.key = "";
      pollRules();
    }
  }
  byId("cloudflare-form").addEventListener("submit", (event) => {
    event.preventDefault();
    if (byId("rule-type").value === "cloudflare") saveCloudflare(byId("cloudflare-hostname").value);
  });
  function renderDebug(status) {
    if (status.hostname !== debug.hostname || status.file !== debug.file) {
      debug.cursor = ""; debug.limited = false; debug.unparsed = false;
      byId("debug-rows").replaceChildren();
      byId("debug-empty").hidden = false;
    }
    debug.hostname = status.hostname;
    debug.clientIP = status.client_ip;
    debug.file = status.file;
    debug.enabled = status.enabled;
    text("debug-empty", status.hostname ? "No captured requests yet for this hostname and source rule. Waiting for matching traffic…" : "Enable a capture rule to see matching requests.");
    text("debug-capture-status", status.hostname ? `${status.enabled ? "Capturing" : "Disabled"} · ${status.hostname} · source: ${status.client_ip || "all IPs"} · ${status.file}${status.error ? ` · ${status.error}` : ""}` : "Debug is disabled. Enter a hostname to start capturing requests.");
    byId("debug-disable").disabled = debug.busy || !status.enabled;
    const selector = byId("debug-capture"), options = document.createDocumentFragment();
    for (const capture of status.captures || []) {
      const option = document.createElement("option");
      option.value = JSON.stringify([capture.hostname, capture.client_ip]);
      option.textContent = `${capture.hostname} · ${capture.client_ip || "all sources"} · ${capture.enabled ? "enabled" : "disabled"}`;
      options.appendChild(option);
    }
    selector.replaceChildren(options);
    selector.value = JSON.stringify([status.hostname, status.client_ip]);
  }
  function pauseDebug() {
    clearTimeout(debug.timer);
    if (debug.controller) { debug.controller.abort(); debug.controller = null; }
  }
  async function pollDebug() {
    if (activeTab !== "debug" || document.hidden || debug.controller || debug.busy) return;
    clearTimeout(debug.timer);
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    debug.controller = controller;
    let more = false;
    try {
      const query = new URLSearchParams({hostname: debug.hostname, client_ip: debug.clientIP, cursor: debug.cursor});
      const response = await fetch(`${base}/api/debug/logs?${query}`, {credentials: "same-origin", cache: "no-store", signal: controller.signal});
      if (response.status === 401) throw new Error("Authentication expired. Reload to sign in.");
      const data = await response.json();
      if (debug.controller === controller && !controller.signal.aborted) {
        if (data.status) renderDebug(data.status);
        if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
        appendDebug(data); more = data.more;
      }
    } catch (error) {
      if (debug.controller === controller) text("debug-status", `Unable to read debug logs: ${error.message}`);
    } finally {
      clearTimeout(timeout);
      if (debug.controller === controller) {
        debug.controller = null;
        if (activeTab === "debug" && !document.hidden) debug.timer = setTimeout(pollDebug, more ? 100 : 2000);
      }
    }
  }
  async function changeDebug(disable) {
    if (debug.busy) return;
    pauseDebug();
    debug.busy = true;
    byId("debug-enable").disabled = true;
    byId("debug-disable").disabled = true;
    byId("debug-error").hidden = true;
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 10000);
    try {
      const query = new URLSearchParams({hostname: disable ? debug.hostname : byId("debug-hostname").value, client_ip: disable ? debug.clientIP : byId("debug-client-ip").value});
      const response = await fetch(`${base}/api/debug?${query}`, {method: disable ? "DELETE" : "POST", headers: {"X-PF-Admin": "1"}, credentials: "same-origin", cache: "no-store", signal: controller.signal});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
      renderDebug(data);
    } catch (error) {
      text("debug-error", error.name === "AbortError" ? "Debug control timed out. Refreshing the server state…" : error.message);
      byId("debug-error").hidden = false;
    } finally {
      clearTimeout(timeout);
      debug.busy = false;
      byId("debug-enable").disabled = false;
      byId("debug-disable").disabled = !debug.enabled;
      pollDebug();
    }
  }
  byId("debug-form").addEventListener("submit", (event) => { event.preventDefault(); changeDebug(false); });
  byId("debug-disable").addEventListener("click", () => changeDebug(true));
  byId("debug-capture").addEventListener("change", () => {
    if (!byId("debug-capture").value) return;
    pauseDebug();
    [debug.hostname, debug.clientIP] = JSON.parse(byId("debug-capture").value);
    debug.file = ""; debug.cursor = ""; debug.limited = false; debug.unparsed = false;
    byId("debug-rows").replaceChildren();
    byId("debug-hostname").value = debug.hostname;
    byId("debug-client-ip").value = debug.clientIP;
    pollDebug();
  });
  const tabNames = ["monitoring", "logs", "rules", "debug", "hosts"];
  function selectTab(name, focus = false) {
    activeTab = name;
    document.title = `Codomari | Proxy-Firewall | ${name === "hosts" ? "Host Activity" : name[0].toUpperCase() + name.slice(1)}`;
    for (const candidate of tabNames) {
      const button = byId(`tab-${candidate}`), selected = candidate === name;
      button.setAttribute("aria-selected", String(selected));
      button.tabIndex = selected ? 0 : -1;
      byId(`view-${candidate}`).hidden = !selected;
    }
    clearTimeout(logs.timer);
    if (name !== "logs") {
      if (logs.controller) { logs.controller.abort(); logs.controller = null; }
    } else pollLogs();
    if (name === "debug") pollDebug(); else pauseDebug();
    if (name === "rules") pollRules(); else pauseRules();
    if (focus) byId(`tab-${name}`).focus();
  }
  for (const [index, name] of tabNames.entries()) {
    byId(`tab-${name}`).addEventListener("click", () => selectTab(name));
    byId(`tab-${name}`).addEventListener("keydown", (event) => {
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabNames.length - 1 : event.key === "ArrowRight" ? (index + 1) % tabNames.length : event.key === "ArrowLeft" ? (index + tabNames.length - 1) % tabNames.length : null;
      if (next !== null) { event.preventDefault(); selectTab(tabNames[next], true); }
    });
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
  for (const button of document.querySelectorAll("[data-host-sort]")) {
    button.addEventListener("click", () => {
      const sort = button.dataset.hostSort;
      state.direction = sort === state.sort ? (state.direction === "ascending" ? "descending" : "ascending") : sort === "hostname" ? "ascending" : "descending";
      state.sort = sort;
      renderHosts();
    });
  }
  byId("search").addEventListener("input", (event) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.search = event.target.value; state.version++; state.previous.clear(); poll(); }, 250);
  });
  byId("refresh").addEventListener("click", () => { poll(); pollLogs(); pollRules(); pollDebug(); });
  document.addEventListener("visibilitychange", () => {
    clearTimeout(state.timer);
    clearTimeout(logs.timer);
    pauseDebug();
    pauseRules();
    if (!document.hidden) pollRules();
    if (!document.hidden) pollDebug();
    if (!document.hidden) pollLogs();
    if (document.hidden) connection("Paused", "paused"); else { connection("Connecting", "connecting"); poll(); }
  });
  poll();
})();
