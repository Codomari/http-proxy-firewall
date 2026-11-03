# http-proxy-firewall

Version **0.3.7** · [Changelog](CHANGELOG.md) · [MIT license](LICENSE)

A Layer 7 firewall using **Uber Fx 1.24** for dependency injection and lifecycle management, **Fiber 3.6** for HTTP handling, and a pooled native fasthttp upstream client. Requires **Go 1.27 or newer**.

The previous application is retained in the sibling `http-proxy-firewall.bak` directory. Deployment configuration, certificates and local data remain outside source control.

## Build and run

```sh
go mod download
make build
test -e proxy-firewall.override.yaml || printf 'env: []\nrules: []\ndebug: []\n' > proxy-firewall.override.yaml
test -e .creds || cp .creds.example .creds
chmod 600 .creds proxy-firewall.override.yaml
```

Edit `proxy-firewall.override.yaml` for your domains, upstream and network policy; `proxy-firewall.default.yaml` supplies public defaults. For local HTTP development:

```sh
./bin/proxy-firewall \
  --listen=127.0.0.1:8080 \
  --proxy-to=127.0.0.1:8008 \
  --tls=false \
  --pprof-addr= \
  --ipv4-redirect=
```

Run an upstream on port 8008 before sending requests. No Redis, MaxMind download or ACME account is required for this local mode. Googlebot ranges refresh in the background by default; set `PF_GOOGLE_RANGES_URL=` in the environment to disable that source for offline runs.

Configuration precedence is command-line flags, existing process environment, `proxy-firewall.override.yaml`, `proxy-firewall.default.yaml`, then built-in defaults. Startup exports the effective YAML `env` entries to the process environment, including custom keys; existing process values retain precedence. Invalid values fail startup. Existing flags `--listen`, `--proxy-to`, `--metrics`, `--silent`, `--enable-redis` and `--pprof-addr` are accepted. `--help` lists additional options. Upstream addresses accept `host:port` or an HTTP(S) origin.

## Structure and responsibilities

```text
cmd/proxy-firewall/       CLI entry point
internal/app/            Fx composition and lifecycle hooks
internal/config/         Typed configuration, defaults and validation
internal/server/         HTTP/TLS listeners, admission and graceful shutdown
internal/proxy/          Connection pool, forwarding, streamed responses and upgrades
internal/firewall/       Body inspection and ordered request decisions
internal/firewall/cves/  Independent, strict CVE form checks
internal/session/        Cookie challenge and validation
internal/cache/          Bounded, synchronized TTL/LRU storage
internal/storage/        One optional Redis client and bounded persistence workers
internal/intelligence/   Local country database and Googlebot IP ranges
internal/observability/  Prometheus request metrics
internal/monitoring/     Bounded per-host counters and runtime snapshots
internal/admin/          Authenticated API and embedded dashboard assets
```

The design applies the practices described in Robert C. Martin's [Clean Code](https://www.informit.com/store/clean-code-a-handbook-of-agile-software-craftsmanship-9780136083252): descriptive names, focused functions, cohesive packages, explicit ownership, and separation of construction from request handling. Interfaces describe actual external dependencies, and tests cover observable behavior. Fx is confined to the composition root; business components can be constructed directly in tests. There are no application `init()` functions, global service instances or background jobs started by imports.

[Fx lifecycle hooks](https://uber-go.github.io/fx/lifecycle.html) start Redis workers and intelligence before opening listeners. Shutdown first announces the firewall restart for up to three seconds: new HTTP/HTTPS requests receive HTTP **540 Server Restarting**, `Retry-After: 3`, and a self-contained **Server restarting** screen. Its HTML, CSS and JavaScript are embedded in the binary. The screen counts down 3 → 2 → 1, probes the current URL with HEAD, and keeps the restart screen visible through connection failures and all 4xx/5xx responses. A 2xx/3xx response resumes navigation with one GET. This applies to public hostnames as well as admin requests on both listeners. Forms are never automatically resubmitted. The notice window is shortened to one tenth of a tighter shutdown deadline to reserve time for draining. Already running requests finish normally. Shutdown then closes listeners, drains requests, closes proxy connections, stops intelligence and stops Redis workers. The page also appears during a normal graceful stop; abrupt termination and requests arriving after listeners close cannot receive the page. The retry loop on an already displayed screen continues through that gap. Backend restarts/errors retain their existing status and response. Startup bind failures roll back acquired resources; listener failures request application shutdown.

## Request behavior

1. ACME HTTP challenges, the admin subtree and the optional metrics endpoint are handled locally.
2. Admission control bounds active request handlers.
3. Every proxied request passes body/method/header validation before static-file, IP, Googlebot, country or cookie bypasses.
4. Recognized bot user agents are denied when they request the existing sensitive query keys.
5. Static assets and allowed clients bypass the cookie challenge.
6. Other clients reach the per-host traffic detector. The existing ten-second sampling window and configured average requests/second threshold determine when the cookie challenge applies.
7. Accepted requests are forwarded with their original Host, escaped path, query and inspected body. Forwarding headers are generated from the verified client address.

Bodies are allowed only for `POST`, `PUT` and `PATCH`; other methods must have empty bodies. Chunked bodies are fully inspected before upstream forwarding. Unsupported content encodings return 415. Malformed forms return 400, resource-limit violations 413, and blocked upload-progress fields 403. Body bytes and the measured content length are preserved; multipart content type is normalized to the inspected boundary.

The strict CVE parsing algorithms and their regression cases are retained under separate packages. Default limits remain 32 MiB per body, 1,000 fields/parts, 20 file controls, nesting depth 16, and 16 headers / 16 KiB of headers per part. Sampled rejection logs include the verified client IP and suppressed-message count; malformed-form excerpts are escaped and capped at 30 serialized characters, including quotes and escapes. `PF_REJECTION_LOG_INTERVAL` defaults to one second per fixed rejection reason, keeping hostile traffic from producing unlimited log output. Set it to `0s` for every rejection. Prometheus status counters still count every request.

The cookie remains `_X-SID_`, with the existing SHA-512/domain/nonce/user-agent scheme, Redis `COOKIES:<sid>` keys and JSON fields. Expiry remains fixed at 24 hours by default. Cookies now use HttpOnly and SameSite=Lax; HTTPS cookies use Secure. In-memory entries are bounded and checked for expiry when accessed.

These frontend checks are defense in depth. They do not replace patched PHP workers or application resource limits.

## Embedded admin dashboard

`PF_ADMIN_URI=__pf/__admin` selects the admin URL. For example, `PF_ADMIN_URI=ops/control` serves the page at `/ops/control`; assets and API polling automatically use that prefix. The configured subtree stays authenticated, and changing the URI removes the default admin route. Root paths, traversal segments and unsafe URL characters are rejected.

Set `PF_ADMIN_CREDS_FILE=.creds` to enable `/__pf/__admin` on the HTTP/HTTPS listener. The file supports multiple accounts, with one `user:password` entry per line, and is read once at startup. Blank lines are ignored, LF and CRLF line endings are supported, and the first colon separates the username so passwords retain spaces and additional colons. All accounts have the same admin access. Files are limited to 4 KiB; missing, empty or malformed files, duplicate usernames, and entries exceeding the authentication header limit fail startup without logging credentials. Relative paths resolve from the working directory (`/etc/proxy-firewall` under systemd). With no credentials file configured the route returns 404. `.creds.example` contains `admin:serveradmin`; replace the example credentials before deployment and use HTTPS for Basic authentication. `PF_ADMIN_ENABLED=false` explicitly disables the interface. Restart after changing credentials. Matching credentials for every configured account are removed before forwarding backend requests, even when the interface is disabled.

Use different credentials for the admin page and backend services. Authorization values matching the configured admin pair are removed from nonadmin requests before proxying, including when the page is explicitly disabled, so browser-cached admin credentials cannot reach a backend. Unrelated backend authorization values are preserved.

The HTML, CSS and JavaScript are compiled into the Go binary with `go:embed`. They require no runtime asset files, external fonts, CDN or frontend build tool. Every dashboard asset and API route requires authentication. The page polls `/__pf/__admin/api/overview` every two seconds, pausing when the tab is hidden. Separate protected `/__pf/__admin/api/hosts` and `/__pf/__admin/api/runtime` endpoints are also available.

Disk space and mounts are included in the overview on Linux and macOS, sampled every five seconds. The table shows mounts visible to the service, including virtual and bind mounts, with source, filesystem, read-only status, total, used and available bytes. Usage percentage excludes reserved space from the available capacity, as `df` does. Mounts sharing a filesystem are listed separately; their capacities should not be added together. Filesystems without capacity measurements show a dash.

The **Monitoring** tab contains traffic, CPU/RAM, services, disk space and Runtime; **Logs** contains the Service logs viewer; **Rules** manages per-domain rules; **Debug** captures requests for a selected hostname; **Host Activity** contains the searchable, sortable host table. Each section is collapsible, with native keyboard controls and all sections except logs initially expanded. Use the arrow keys, Home or End to switch tabs when a tab button is focused. Runtime appears at the bottom of Monitoring. Press **Show logs** in Logs to load the latest 100 complete lines from `log/proxy-firewall.log` in the service working directory (`/etc/proxy-firewall/log/proxy-firewall.log` under the supplied systemd unit). The protected `/api/logs` endpoint follows appended lines every two seconds while the panel, Logs tab and browser tab are visible. The browser retains the most recent 10,000 lines and follows new lines only when scrolled to the bottom. Hiding and reopening the panel starts again from the latest 100 lines. File replacement and truncation reset the file cursor while preserving visible history. Missing logs show an unavailable message and retry; deployments writing only to stdout/stderr need to redirect output to this file to use the viewer. Reads are capped at 1 MiB per request, individual displayed lines at 4 KiB, and unfinished lines wait for a newline. Very large initial tails may contain fewer than 100 lines; any truncation is indicated in the panel. Log content is rendered as plain text.

In **Debug**, enter `example.com` or `*.example.com`, optionally enter a single IPv4/IPv6 address in **Source IP**, and press **Enable debug**. Leave Source IP blank to capture all sources; otherwise both hostname and verified source IP must match. Exact matching preserves `www` as a separate hostname; wildcards match subdomains at any depth, excluding the bare domain. Matching ignores hostname case, a final dot and the request's port. IPv4-mapped IPv6 source addresses normalize to IPv4. Multiple captures can run concurrently across HTTP/HTTPS listeners. Each host/source combination is independent. Starting another adds or updates that capture; use the capture selector to view its history. Matching requests are selected and their original metadata copied before admission and firewall inspection, including requests that become firewall rejections or admission 503s. Entries are appended when the response completes. Admin routes and ACME challenges are handled separately; malformed requests rejected by the HTTP parser cannot be captured here.

Captures append to `log/<sanitized-hostname>-<hash>.log` in the service working directory; source-filtered filenames also include `-from-<sanitized-ip>`. Basenames contain only lowercase letters, numbers and dashes before `.log`; a short stable hash distinguishes hostname/source combinations that otherwise flatten to the same name. Changing the source filter uses separate history. Wildcard matches share one file, with the actual destination hostname in each line. The Debug tab shows the active capture file and a table with Time (UTC), Client IP, Hostname, Method, URL, Duration, Status, expandable Request headers and expandable Response sent. Responses include headers, body byte count and a preview capped at 16 KiB. Binary previews use base64; compressed bodies retain their content encoding. Text, including HTML and scripts, is rendered as plain text. Duplicate request and response headers are preserved. Duration starts at the debug middleware and includes firewall/body inspection, upstream handling and streamed body transfer until the stream closes. Buffered local responses measure time until the response is prepared; 101 upgrades measure handshake preparation only, without tunnel traffic. Stream errors are shown with the captured response; byte counts describe body bytes read for transfer, without headers or wire framing, and do not confirm client receipt. Streaming previews do not buffer or delay the forwarded response. HEAD, 204 and 304 responses have no captured body.

The table continuously pulls logs for the active hostname/source rule every two seconds while the tab is visible, including idle polls, and retries failed reads. It initially loads the latest 100 complete entries and retains up to 10,000 rows. Cursor-based reads append only new requests; switching capture rules clears the previous table. Scroll to the bottom to follow incoming requests automatically. Older request-only entries remain readable, with unavailable duration/response fields shown as dashes; unparseable log lines remain visible as text rows. Debug reads are bounded to 1 MiB per poll, preserving full headers within that bound, with rotation/truncation detection. Files are created with mode `0600`. Request bodies are not read by the debug logger. Entries retain the original request prefix and append JSON response metadata (control characters are escaped to keep entries on one line):

```text
[2026-11-03T12:34:56.123Z] FROM: 203.0.113.42, TO: www.example.com, GET /path?q=1 [Host: "www.example.com", User-Agent: "example-client", X-Example: "value"] | {"duration_ms":12.345,"response":{"status":200,"headers":[{"name":"Content-Type","value":"text/plain"}],"bytes":2,"body":"OK","body_encoding":"utf-8","body_truncated":false}}
```

The client IP uses the firewall's trusted proxy and per-host Cloudflare settings. Captured headers and response bodies can contain credentials, cookies and private data. **Disable debug** stops selecting new requests for the selected capture and preserves its file and visible history; other captures continue. Already selected requests finish logging to their original file, even if capture is disabled or another rule is enabled while they are in flight. Closing the tab only pauses viewing; captures continue until disabled, and enabled captures resume after a restart. Debug controls persist enabled state and log-file paths to the override YAML. Logs are append-only and can be rotated externally. Write failures appear in the Debug status without changing request handling. The authenticated `/api/debug` endpoint exposes status via GET, enables via POST with `hostname` and optional `client_ip` query parameters, and disables via DELETE; mutations require `X-PF-Admin: 1` for CSRF protection. `/api/debug/logs` reads the current capture and returns structured `entries` for the table alongside the original `lines` and file cursor. New entries include `duration_ms` and `response` metadata.

The **Rules** tab manages per-domain rules. Select **Behind CloudFlare**, enter an exact domain or wildcard, and press **Save rule**. Presence enables the rule; **Remove rule** removes that explicit rule and restores inherited/default behavior. There is no on/off checkbox. Rules refresh every two seconds while the Rules tab is visible and use the authenticated `/api/cloudflare-hosts` endpoint (POST adds, DELETE removes). Changes apply immediately and persist in the override YAML. Plain domain rules also cover their `www.` alias; the most specific matching wildcard applies where no exact/inherited domain rule exists. Existing `PF_TRUST_CLOUDFLARE_HEADER` still supplies the fallback when no rule matches.

An enabled hostname trusts `CF-Connecting-IP` only when the socket peer belongs to the bundled [Cloudflare IPv4](https://www.cloudflare.com/ips-v4/) / [IPv6](https://www.cloudflare.com/ips-v6/) ranges (verified November 3, 2026), or to operator-configured `PF_TRUSTED_PROXIES`. The bundled ranges require a code update if Cloudflare changes them. Trusted intermediaries must sanitize client-supplied identity headers. Direct untrusted requests cannot spoof their IP by setting Cloudflare or forwarding headers. Duplicate, malformed and zoned Cloudflare IP values are rejected. Cloudflare Pseudo IPv4 overwrite mode uses a valid `CF-Connecting-IPv6` value for the actual IPv6 client. This follows [Cloudflare's header definitions](https://developers.cloudflare.com/fundamentals/reference/http-headers/). Off rules disable Cloudflare-specific trust for the matching hostname; separately configured trusted-proxy forwarding still applies. The resolved IP is shared by debug filtering/logging, firewall checks and the upstream `X-Forwarded-For` value for each request.

Monitoring reports per-host request counts, request rate, active requests, 4xx rejections, CVE rule blocks, 5xx errors, payload bytes and DDoS penalty state, plus process uptime, goroutines, Go heap/stack memory and GC counters. CVE block counters are also included in the overview totals; they count requests rejected by the CVE rules regardless of log sampling, overlap with 4xx rejections, and reset on restart. The host table and host API return every tracked host without pagination; domain search filters that complete list. Streams and upgraded connections remain in flight until closure. Admin and metrics requests are excluded from proxy traffic totals. The DDoS marker reflects the firewall detector's actual threshold/penalty state; an authenticated or whitelisted request may still be forwarded while a marker is active.

`PF_ADMIN_MAX_HOSTS` defaults to 10,000. Host storage is bounded: after capacity is reached, new hostnames contribute to aggregate totals and an untracked-request counter. Counters are process-local and reset on restart.

On Linux, the dashboard measures process CPU, resident process RAM (RSS), server CPU and server RAM from `/proc`. Process CPU uses 100% for one fully utilized core and can exceed 100%; server CPU spans all visible logical CPUs. Server RAM usage is total minus available memory. These describe OS-visible resources, including host resources exposed inside containers, not container quota percentages. CPU usage appears after two samples; samples are cached for at least one second across dashboard clients. Unsupported or inaccessible OS measurements display as unavailable. Go runtime memory remains separately labeled.

The Redis panel shows whether Redis is enabled, whether a storage operation has succeeded, circuit-breaker fallback, queued writes, and read/write rates and totals. Rates are calculated between dashboard samples from actual backend operation attempts; local cache hits and skipped operations during backoff are excluded. An empty Redis result is a successful read. Viewing the dashboard never issues Redis commands. The MaxMind panel shows whether the database is loaded, whether an update is running, whether automatic updates are configured, and the installed file's actual modification time.

Payload counters exclude HTTP/TLS framing. Inbound bytes count what body inspection consumes; unread rejected payloads and later client-to-upstream tunnel traffic are excluded. Outbound bytes count nonstreaming body length or payload consumed from response streams; stream reads can exceed delivered bytes after a downstream write failure. Upgraded tunnels count bytes successfully copied to the client. Bodies created by the framework's final error handler are excluded.

## Resource and performance changes

- HTTP/1.1 connections remain reusable over HTTP and HTTPS.
- Native request forwarding avoids an additional body-sized proxy copy; response bodies stream from upstream.
- `PF_MAX_BUFFERED_BYTES` bounds reserved retained inspection-buffer capacity across requests; overload returns 503 before reading an upload. Known-length bodies reserve their length plus one overflow-probe byte; unknown/chunked bodies conservatively reserve the per-body maximum plus one. Empty bodies retain no reservation. Reservations cover the full middleware chain. This is a payload budget, not a process RSS limit: TLS, headers, allocations awaiting garbage collection and framework buffers use additional memory.
- `PF_MAX_CONCURRENT_REQUESTS` and `PF_MAX_CONNECTIONS` bound inbound work; `PF_UPSTREAM_MAX_CONNECTIONS` bounds each configured origin's shared upstream pool. Upstream requests are not automatically retried.
- Memory caches have explicit capacity and TTL. Redis values use expiring keys; writes use a bounded queue and fixed worker count with an additional retained-byte budget.
- Redis operations have short deadlines and unavailable-state backoff. Optional Redis failures fall back to local state.
- Googlebot updates replace immutable snapshots. Failed downloads use timeouts and retry backoff while retaining the last good ranges.
- MaxMind starts from the existing local database, downloads into temporary files, validates before replacement, and safely closes retired readers after lookups release them.
- Query arguments are parsed once for bot checks. Background work has explicit start/stop ownership.

These are implementation changes, not a measured throughput guarantee. Use the same traffic mix, payload sizes, concurrency, backend and machine when comparing v1 and v2.

The reproducible Docker harness is documented in [bench/README.md](bench/README.md). Measured results and their limits are recorded in [BENCHMARKS.md](BENCHMARKS.md).

## Migration settings

| Setting | v2 behavior |
| --- | --- |
| `IP_FILTER_*`, `DOS_DETECTOR_*`, `CVE_MITIGATOR_*` | Existing environment names retained. Country names remain English names, such as `Azerbaijan,Turkey`. |
| Client IP forwarding | Direct peer by default. Per-host Behind CloudFlare rules trust Cloudflare edges for matching hostnames. Configure `PF_TRUSTED_PROXIES` for other proxies; `PF_TRUST_CLOUDFLARE_HEADER` remains the global fallback. |
| TLS | Enabled by default on port 443. TLS 1.2 minimum; `--tls-legacy` explicitly enables compatibility with TLS 1.0/1.1. Configure `PF_TLS_HOSTS` to restrict certificate issuance. |
| Static certificates | Set both `PF_TLS_CERT_FILE` and `PF_TLS_KEY_FILE` (or `--tls-cert` and `--tls-key`) to use your own certificate and skip ACME. |
| Multiple internal hosts | `PF_UPSTREAM_ROUTES=example.test=http://internal-a:8080,api.example.test=https://internal-b:8443` selects a dedicated connection pool by incoming hostname. Unmatched hosts use `PF_PROXY_TO`. |
| IPv4 Host redirect | Existing `https://hostinq.biz` redirect retained; `--ipv4-redirect=` disables it. |
| HTTP protocol | Native Fiber listeners serve HTTP/1.1. Use a frontend proxy for HTTP/2 or HTTP/3 termination. |
| Redis | Disabled by default. Configure `REDIS_ADDRESS`, `REDIS_PASSWORD`, `REDIS_DB` and `PF_ENABLE_REDIS`. Cookie storage format is compatible; country cache entries use expiring individual keys. |
| Profiling | `127.0.0.1:8068` by default; empty disables it. Non-loopback profiling addresses are rejected. |
| Metrics | Optional `--metrics` exposes `/__system__/__metrics__`; labels use bounded method/status values. |
| Local data | `files/geo.mmdb` and `.cache/` stay local and ignored. No v1 files are imported automatically. |

Legacy `.env` and `proxy-firewall.conf` files are no longer read at startup. To migrate an existing deployment, run `./bin/proxy-firewall --migrate-config /etc/proxy-firewall` before starting it. Migration copies legacy values into the private override YAML, preserves the old effective precedence, retains shadowed `.env` values as private comments, verifies the written file, then removes the legacy files. The installer performs the same migration. No private override is copied into source control or the Docker build context.

## Verification

```sh
make test
make race
make vet
make test-install
```

Tests use local servers and fakes for external services. They cover strict CVE parsing, body forwarding, bypass ordering, host/query fidelity, concurrent state access, bounded caches, expiry, updater failures and lifecycle behavior. Live ACME issuance and external MaxMind/Google/Redis services require deployment-specific validation.

## Optional systemd deployment

On the deployment server:

```sh
make build
sudo make install
```

`make install` builds and replaces `/etc/proxy-firewall/bin/proxy-firewall`, refreshes the public default YAML, creates missing `bin`, `log`, `files`, `.cache` and `.certs` directories, and installs `/etc/systemd/system/proxy-firewall.service`. The private override and credentials are preserved. Legacy configuration is verified and migrated before removal. A missing override starts with empty `env`, `rules` and `debug` lists; missing credentials are copied from `.creds.example` with mode `0600`. Local private deployment settings are never copied over an existing server override.

Installation counts the server's online logical CPUs (including hardware threads) and sets `GOMAXPROCS` to `max(1, floor(count * 2 / 5))` in the generated systemd command. For example, 16 threads gives `GOMAXPROCS=6`. This takes precedence over any `GOMAXPROCS` in existing configuration files, without modifying them. Reinstalling recalculates the value.

Both stdout and stderr append to `/etc/proxy-firewall/log/proxy-firewall.log`. Installation creates that file only when missing and preserves existing log content. `PF_SILENT=true` logs warnings and errors; `false` also includes informational messages. Rejection sampling is controlled by `PF_REJECTION_LOG_INTERVAL`. Direct CLI runs write to the terminal unless redirected.

Upstream failure warnings include the firewall's verified `client_ip`, honoring the configured trusted proxy policy. HTTP connection warnings include the socket peer IP; failures before HTTP headers are parsed cannot identify a client behind a proxy. Listener-wide failures without a connection use `client_ip=unknown`.

HTTP responses identify the firewall as `Server: codomari/proxy-firewall/<version>`, including proxied responses, admin assets, errors and protocol upgrades. Upstream `Server` values are replaced.

Installation does not start, restart or enable the service. When ready:

```sh
sudo systemctl daemon-reload
sudo systemctl enable proxy-firewall
sudo systemctl restart proxy-firewall
tail -f /etc/proxy-firewall/log/proxy-firewall.log
```

The service has a 35-second stop deadline and permits atomic override YAML saves in its working directory. The binary directory, credentials file, public default YAML and license remain read-only inside the systemd sandbox; log, data, cache and certificate directories remain writable. Install the updated unit and run `systemctl daemon-reload` before restarting an existing deployment to enable settings saves. To stage an installation without writing to `/etc`, use `make install DESTDIR=/absolute/staging/path`. `make test-install` checks fresh installation, repeat installation, configuration preservation and CPU sizing in temporary directories.

Fiber settings and ownership rules follow the [official Fiber API documentation](https://docs.gofiber.io/api/fiber/). Request-scoped Fiber values are copied before retention in caches or worker queues.

## YAML configuration

Both files use this structure. Override `env` entries replace defaults by `key`; rule parameters replace defaults by hostname key; debug entries merge by `host` and `source`. Debug fields omitted in the override inherit the default entry. Multiple entries may have `enabled: true`.

```yaml
env:
  - key: PF_PROXY_TO
    value: "http://127.0.0.1:8008"
rules:
  - type: Behind CloudFlare
    params:
      - key: "*.example.com"
        value: true
debug:
  - host: "*.example.com"
    source: "203.0.113.8"
    enabled: true
    log_file: "log/example.log"
```

`rules[].params[].value` is a presence marker, so the admin UI needs no boolean argument. Use `false` in an override to remove a rule inherited from defaults; the admin Remove action writes that marker. Empty lists inherit other default entries. Debug `source` may be blank for all IPs, and an omitted/empty `log_file` uses the generated private log filename. Both configuration files are limited to 1 MiB; invalid/duplicate fields fail validation without logging their values. The private override is ignored by Git and Docker. `VERSION` is embedded by the Go compiler; response headers and admin branding need no version file at runtime.

## General firewall settings

At the top of **Rules**, **General settings** displays whitelisted IPs, CIDR networks, country names and the DDoS request-rate threshold from the merged YAML. Entries can be separated by commas or newlines. **Save general settings** updates only the six corresponding `env` entries in `proxy-firewall.override.yaml` and applies the settings immediately. Unrelated YAML values and comments, including credentials, are preserved. Saves use an atomic file replacement; failures leave active rules unchanged. The API never returns unrelated environment values. Existing process overrides are shown because they still take precedence after restart.

The two cookie-checkpoint checkboxes default to enabled: whitelisted IPs/networks and countries still pass through the cookie checkpoint when the hostname is under a DDoS penalty. Disable a checkbox to restore checkpoint bypass for that whitelist. If a client matches both lists, an enabled checkpoint takes priority. Static-file exemptions continue to apply. CVE/body validation and sensitive-query bot rules always run before these decisions, regardless of the switches. Loopback networks remain whitelisted automatically and follow the IP checkpoint switch. Country lookup uses the existing country names from the GeoIP database. The DDoS threshold is a positive integer from 1 to 1,000,000,000 requests/second per hostname, measured over the existing sampling window (10 seconds by default). Threshold changes apply immediately to detection; active penalties retain their expiry.

The authenticated `/api/general-rules` endpoint supports GET/HEAD and POST with a JSON object containing `whitelist_ips`, `whitelist_networks`, `allowed_countries`, `ip_checkpoint`, `country_checkpoint` and `ddos_threshold`. POST requires `X-PF-Admin: 1`, same-origin access, both boolean switches and the numeric threshold. Bodies are limited to 64 KiB and each whitelist to 512 entries. A failed file save leaves the active firewall rules unchanged. Editing fields in the browser pauses replacement of those fields by background refreshes.

## Versioning

Increase the patch field by the number of user-facing features added since the preceding commit, keeping the major and minor fields unchanged. For example, `0.2.0` plus three features becomes `0.2.3`; after committing that version, five more features produce `0.2.8`. Count each logical feature once, using the committed `VERSION` as the baseline so repeated updates before a commit do not count it twice. Update `VERSION`, the README version and the changelog together. For the 0.3 release, seven feature groups since the preceding commit produce `0.3.7`.

## Maintainer

Maintained by **Anar K. Jafarov** (`num8er`), [anar.k.jafarov@gmail.com](mailto:anar.k.jafarov@gmail.com). Contact the maintainer for project questions and contribution coordination.

## Contributing and security reports

Keep changes focused, update the relevant documentation and examples, and run `make check` before submitting. Include a reproducible test for behavioral fixes. Keep `proxy-firewall.override.yaml`, `.creds`, legacy deployment configuration, keys and runtime data out of commits and public reports.

Report suspected vulnerabilities privately to [anar.k.jafarov@gmail.com](mailto:anar.k.jafarov@gmail.com). Include the affected version, impact, reproduction steps and sanitized configuration/log excerpts. Coordinate disclosure with the maintainer before publishing sensitive details.

## License

Copyright © 2026 Anar K. Jafarov (`num8er`). Distributed under the [MIT license](LICENSE). Third-party dependencies retain their respective licenses and notices.
