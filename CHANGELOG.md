# Changelog

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
