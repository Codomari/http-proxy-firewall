# Changelog

## 0.3.32 — 2026-11-06

Two logical user-facing features since 0.3.30, following the project's patch-count convention.

### Added

- Edit global request concurrency and normal upstream connection limits in Admin → Rules → General settings. Saves persist to the private YAML override and update the running admission gate and every upstream route without a restart; older clients preserve omitted fields, and failed validation or file saves leave runtime limits unchanged.
- Add opt-in temporary upstream bursting with `PF_UPSTREAM_ALLOW_OVERFLOW` and `PF_UPSTREAM_MAX_OVERFLOW_CONNECTIONS`. The latter is an absolute total ceiling, including normal capacity. Overflow connections open on demand and close when their response finishes; normal keepalive remains reusable. Streams and upgraded tunnels share the hard ceiling. Live reductions drain active work, clear idle connections and reject new requests until capacity is available. Defaults remain 256 normal connections with overflow disabled and a configurable 512-connection burst ceiling.

## 0.3.30 — 2026-11-06

Fifteen logical user-facing changes since 0.3.15, following the project's patch-count convention.

### Added

- Validate certificate hostnames before network checks: require two or more nonempty labels, a letter, and no IP addresses. Verify eligible hostnames before issuance and renewal with three HTTP HEAD attempts, each limited to one second, and a fresh per-host `X-DNS-SIGNATURE`. A one-second DNS fallback accepts only a public IP assigned to this server. Loopback/private addresses and hostnames marked Behind CloudFlare by live rules cannot authorize issuance.
- Persist failed hostname checks for 14 days in `.certbot.blacklist`, with atomic private-file updates and expiry across restarts. Requests for blacklisted hostnames return a 409 Conflict page asking the operator to point the domain to this server.
- Add the CERTBOT admin tab with certificate names, issuer, validity and source; expiring blacklist entries with removal controls; and asynchronous manual certificate requests that retain all admission checks.
- Support native HTTPS HTTP/2 negotiation through the existing firewall, admin and proxy pipeline, including response streaming, body limits and graceful connection shutdown.
- Translate restart and blocked-hostname pages into Azerbaijani, English, Turkish, Russian, Ukrainian, German, Italian, Spanish, Portuguese, Kazakh (Kazakhstan) and Japanese. Select the language using the verified client IP country, with English as the default. Restart messages include reassurance that the server will return shortly.
- Embed an unlimited tic-tac-toe game against the computer on a responsive 12×12 restart-page board, with five in a row to win. Visitors who start playing keep their game after recovery and receive a ready message plus a Return to website button; other visitors reconnect automatically.
- Return a translated 409 Conflict page for TLS requests without a hostname in SNI: "Secure request without hostname not allowed." Use the configured certificate or an in-memory fallback to complete TLS without invoking automatic certificate issuance; clients enforcing certificate trust may stop before receiving the HTTP page.
- Add an 11-language selector to both 409 pages and the restart page, updating text without a reload or game reset and remembering the preference per site.
- Save the board and pending turn in local storage to resume later, with a Start fresh button that clears saved progress and cancels a pending computer move.
- Preserve the selected admin tab in the URL hash for refreshes and direct links, with a safe default for unknown tab names.
- Add a TEST PAGES admin tab and authenticated, extensible status previews under `/<PF_ADMIN_URI>/test/pages/`, including restart, blocked-hostname and missing-TLS-hostname pages without changing server state.

### Changed

- Replace the restart screen's three-second countdown and Retry-After delay with an indeterminate request animation and immediate background recovery checking. Keep all page styles, scripts, translations and game assets embedded in the binary.
- Configure additional upstream connection retries with `PF_UPSTREAM_REQUEST_RETRY_TIMES`, defaulting to `3`; `0` disables retries. Admin General settings saves apply immediately to all upstream routes and persist to the private YAML override. Empty GET/HEAD requests can recover from connection closure, reset or a broken pipe after stale idle connections are cleared; submitted actions, timeouts, TLS failures and HTTP error responses are not replayed.
- Include the canonical hostname in certificate guard errors returned to TLS and ACME callers, preserving error classification and structured hostname logs.
- Route HTTP/2 warnings through the same sampled structured logger as HTTP/1, including labelled time, level, message, peer IP, error and known hostname/SNI instead of standard-library text logs.

## 0.3.15

Three user-facing changes since 0.3.12, following the project's patch-count convention.

### Fixed

- Retry empty GET/HEAD requests once on selected connection failures to recover from stale upstream connections without replaying form submissions or retrying timeouts, TLS failures or HTTP error responses.
- Increase the ordinary upstream response-header buffer to 32 KiB so larger cookie/header sets can be forwarded.

### Changed

- Include HTTP status, upstream address, request method and a fixed error reason in sampled upstream failure warnings while preserving verified client IPs, optional hostnames and private-data protection.

## 0.3.12

### Changed

- Reorganize the README around setup, YAML configuration, admin controls and deployment. Add diagrams for request handling, configuration precedence and saved settings, document environment variables and legacy migration, and clarify how immediate admin changes interact with process overrides after restart.

## 0.3.11

### Added

- Debug request-body capture with a 4 KiB limit before base64 encoding and frontend decoding in the existing body dialog. Oversized, incomplete and unread bodies have explicit omission reasons; streamed uploads are observed during firewall inspection without additional reads or buffering.

### Changed

- Capture response bodies only for `application/json`, including media-type parameters such as `charset=utf-8`. Other responses retain headers, status and byte counts with an omission reason, and older non-JSON body captures are hidden in the viewer.

## 0.3.9

### Changed

- Omit base64 response bodies from debug captures when the original response body exceeds 4 KiB, retaining byte counts, headers and an explicit omission reason for buffered and streamed responses.
- Open debug response bodies in a dialog with browser-side base64 decoding, formatted JSON/text, binary hex/ASCII, and bounded gzip/deflate decompression when supported. Render captured content as plain text and hide oversized binary bodies in older captures.

## 0.3.7

Seven features added since the preceding commit, using the requested 0.3 release baseline.

### Added

- YAML configuration with public `proxy-firewall.default.yaml`, ignored private `proxy-firewall.override.yaml`, environment export, typed override merging, and persistent concurrent host/source debug captures with configured log files. Admin changes save atomically to the override file. Verified migration preserves the effective legacy settings before removing `.env` and `proxy-firewall.conf`.
- Presence-only **Behind CloudFlare** domain rules: add or remove a hostname without an on/off checkbox; YAML hostname parameters use `value: true`.
- Optional `hostname` in HTTP connection failure warnings, using TLS SNI for handshake/certificate failures and a known HTTP Host for later connection failures. Connection metadata is released on closure or protocol handoff.
- Build-time embedding of `VERSION`, versioned `Server: codomari/proxy-firewall/<version>` headers, and Codomari admin branding with version display and tab-specific browser titles.
- Optional canonical `hostname` in upstream request failure warnings while retaining verified client IPs, error types and log sampling.
- Optional canonical `hostname` in firewall request-rejection warnings, including body-policy failures, without changing rejection reasons or suppression accounting.
- Public-host restart/recovery screen that stays visible while background HEAD probes retry; 4xx/5xx responses keep retrying and a successful 2xx/3xx response resumes navigation once.

### Changed

- Replace legacy dotenv/configuration samples and installation paths with YAML defaults and private overrides; Docker build contexts exclude private overrides.
- Replace old benchmark result sets and performance claims with 67 fresh cases measured on the 0.3.4 baseline: 36,091,583 firewall requests and zero failures. The final upstream/rejection log hostname changes were tested without rerunning benchmarks, as requested.

## 0.2.5

Five features added since 0.2.0; the patch number increases by the feature count.

### Added

- Debug request duration, final response status/headers, body byte counts, bounded text/base64 previews, streaming completion and transfer errors, with older capture compatibility.
- Embedded HTTP 540 Server restarting screen during proxy-firewall shutdown, with a repeating three-second countdown and recovery probes that keep the page visible through connection failures. Upstream errors retain their existing responses.
- Global IP/network/country whitelist settings at the top of Rules, read from and saved atomically to .env while preserving unrelated configuration; changes apply immediately.
- Separate checkboxes controlling the cookie checkpoint for whitelisted IPs/networks and countries during DDoS penalties. Both default to enabled; CVE/body and bot-query checks always apply, and an enabled checkpoint takes priority when both lists match.
- Editable DDoS request-rate threshold in General settings, saved to `DOS_DETECTOR_HOSTNAME_REQUEST_THRESHOLD` in .env and applied immediately without resetting existing penalties.

### Changed

- Increment the patch number by the number of features added since the preceding commit, retaining the major/minor numbers: 0.2.0 + 3 features = 0.2.3, then + 5 = 0.2.8.
- Allow atomic .env updates in the systemd sandbox while keeping the executable, credentials and other deployment configuration read-only.

## 0.2.0

### Added

- Live Debug request table with timestamp, source IP, hostname, method, raw URL and expandable headers, continuous cursor-based polling, retry after read errors and capture-specific history.
- Debug tab with exact/wildcard hostname and optional source IPv4/IPv6 capture, immediate disable, protected live viewing, and private sanitized log files containing ISO timestamps, verified client IPs, methods, raw URLs and request headers, including firewall and admission rejections.
- Separate Rules tab for adding per-domain or wildcard rules, with Cloudflare as the first supported rule type and independent rule polling.
- Plain domain rules also cover their `www.` subdomain by default; an explicit `www.` hostname rule takes precedence.
- Persistent per-host Behind Cloudflare switches that apply to all requests, with exact/wildcard precedence, Cloudflare edge verification, spoof protection and consistent client IPs for firewall, debug filtering and upstream forwarding.
- Expandable Service logs viewer in the Logs tab: initially loads the latest 100 complete log lines, follows appended lines every two seconds, and retains up to 10,000 lines in the browser.
- Authenticated, bounded log reads with replacement and truncation detection, plain text rendering, and scroll position preservation.
- Disk space and mounts table with filesystem, source, read-only status, total, used, available space, and usage percentage on Linux and macOS.
- Collapsible dashboard sections for traffic, CPU/RAM, services, disks, Runtime and Host activity, alongside the Show/Hide logs control.
- Separate Monitoring, Logs, Rules, Debug and Host Activity tabs with keyboard navigation; polling for logs, rules and debug pauses outside its corresponding tab.

### Changed

- Move Runtime into the Monitoring tab, before the separate Logs view.

## 0.1.5

### Changed

- Include the underlying error in HTTP connection failure warnings, alongside the client IP, while preserving log sampling.
- Enable secure parser error formatting to omit sensitive request content from connection diagnostics.

## 0.1.4

### Added

- Aggregate CVE block counter in the admin traffic overview and a sortable CVE blocks column for each hostname.
- Process-local `cve_rejected` counters in the overview and host APIs, independent of rejection log sampling and bounded host capacity.

## 0.1.3

### Changed

- Sort admin Host Activity by request rate, highest first, by default.
- Click any Host Activity column heading to toggle ascending or descending order, retained across live refreshes. DDoS checkpoint sorting groups active or normal hosts first.
- Rename the Domain column to Host and align search labels with host terminology.

## 0.1.2

### Added

- Multiple admin accounts through `PF_ADMIN_CREDS_FILE`, with one `user:password` entry per line and blank lines allowed between accounts.
- Authentication and upstream credential stripping for every configured account, including when the admin interface is disabled.
- GitHub bug report, feature request, usage question and pull request templates with reproduction, validation and private security-reporting guidance.

## 0.1.1

### Changed

- Set the HTTP `Server` header to `pf` for proxied responses, admin routes, errors and protocol upgrades.

## 0.1

### HTTP proxy and routing

- Native HTTP/1.1 proxy with pooled HTTP and HTTPS upstream connections.
- Host-based upstream routes with a configurable fallback origin.
- Preservation of request methods, Host, escaped paths, query strings and inspected bodies.
- HTTP and HTTPS keep-alive, streamed responses, server-sent events and protocol upgrade tunnels.
- Removal of hop-by-hop headers and generation of verified forwarding headers.
- Configurable redirect for IPv4 Host requests.
- Consistent `Server: pf-v2` responses, including errors, admin assets and upgrades.
- Bounded upstream pools, timeout handling and explicit overload responses.

### TLS and certificates

- Automatic ACME certificates with configurable email, domain allowlist and local cache.
- Static certificate/key support that bypasses automatic issuance.
- TLS 1.2 minimum by default, with an explicit TLS 1.0/1.1 compatibility option.
- Shared monitoring and administration across HTTP and HTTPS listeners.

### Firewall and client identity

- Request inspection before static-file, client IP, country and bot bypass decisions.
- Strict protection for CVE-2026-109618 malformed forms and CVE-2026-109619 upload-progress fields.
- URL-encoded and multipart validation, including framing, boundaries, headers, field counts and nesting.
- Configurable blocked upload-progress field names.
- Method/body policy, complete chunked-body inspection and rejection of unsupported content encodings.
- Default 32 MiB body limit, 1,000 input fields/parts, 20 file controls and nesting depth 16.
- Multipart limits of 16 headers and 16 KiB of headers per part.
- IP and CIDR allowlists, country allowlists and validated Googlebot network matching.
- Sensitive-query blocking for recognized bot user agents.
- Trusted proxy chain resolution, optional trusted Cloudflare headers and spoof-resistant client identity.

### Traffic control and sessions

- Per-host traffic sampling, configurable request thresholds and timed DDoS penalties.
- Cookie challenges with domain, nonce and user-agent validation.
- Configurable session lifetime, with a 24-hour default.
- HttpOnly and SameSite=Lax cookies, with Secure cookies over HTTPS.
- Bounded TTL/LRU caches and concurrent request accounting.
- Global request-body buffering budget, connection limits and active-request admission control.
- Configurable inbound, upstream and idle timeouts.

### Redis and intelligence

- Optional Redis persistence for session, country and bot-range data.
- Bounded asynchronous write queues, worker counts and retained-byte budgets.
- Short operation deadlines, backoff and local-state fallback when Redis is unavailable.
- Local MaxMind country lookup and validated, atomic database replacement.
- Bounded database download/extraction, temporary-file cleanup and preservation of a working database on refresh failure.
- Background Googlebot network refresh with bounded responses, validation and retry backoff.
- Explicit startup and shutdown ownership for workers, listeners, caches and upstream connections.

### Embedded admin dashboard

- Authenticated interface at `/__pf/__admin`, with embedded HTML, CSS, JavaScript and favicon.
- Configurable admin URL through `PF_ADMIN_URI`, including automatic asset/API URL rewriting and authenticated subtree handling.
- Startup credential loading through `PF_ADMIN_CREDS_FILE`, using a single `user:password` line.
- Bounded credential parsing, support for colons in passwords and an explicit admin-disable setting.
- Protected overview, host and runtime APIs, plus security headers and removal of admin credentials from backend requests.
- Automatic refresh every two seconds, manual refresh and polling paused in hidden tabs.
- Searchable activity table containing all tracked hosts without pagination.
- Per-host request totals and rates, in-flight requests, 4xx/5xx counts and DDoS state.
- Aggregate counters, bounded host capacity and accounting for requests outside the host table.
- Linux process CPU and resident RAM, plus OS-visible server CPU and RAM usage.
- Process uptime, goroutines, Go heap/stack memory, GC counters and CPU parallelism.
- Redis enabled/availability status, actual read/write rates and totals, error counts and queue depth.
- MaxMind loaded/update status and last-modified time read from the installed database file.
- Admin and metrics requests excluded from proxy traffic totals.

### Logging and observability

- Structured warning and error logs with verified client IPs where request context is available.
- Socket peer IPs on HTTP connection failures, including failures before header parsing.
- Sampled rejection logs by fixed reason, suppressed-message counts and configurable sampling intervals.
- Escaped malformed-form excerpts capped at 30 serialized characters, with truncation indicators.
- Sampled upstream failure warnings and configurable informational logging.
- Prometheus request/status/latency metrics and Go/process collectors.
- Optional loopback-only profiling endpoints.

### Installation and development

- Go 1.27 application using Fiber, fasthttp and Uber Fx lifecycle composition.
- Graceful request draining, listener failure reporting and startup rollback.
- Configuration through deployment files, environment variables and command-line flags, with validation at startup.
- `make` targets for build, tests, race checks, vet, formatting, installation and installer verification.
- Preservation of existing deployment configuration, credentials, certificates, caches, data and logs during installation.
- Creation of missing runtime directories and example-based configuration files under `/etc/proxy-firewall`.
- Atomic executable replacement and installation of the systemd service unit.
- Installation-time `GOMAXPROCS=max(1, floor(online CPU threads × 2/5))` calculation.
- Append-only service stdout/stderr logging to `/etc/proxy-firewall/log/proxy-firewall.log`.
- Private source-sync helper with dry-run support and exclusions for credentials and runtime data.
- Git and Docker exclusions for private configuration, credentials and generated artifacts.
- Git exclusions for AI/LLM assistant instructions and local settings.
- Docker images, isolated local/benchmark Compose setups and a load-generation harness.
- Regression coverage for request validation, forwarding, streaming, upgrades, lifecycle, telemetry, authentication and installer preservation.
- Version metadata, MIT licensing and maintainer contact guidance.
