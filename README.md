# http-proxy-firewall

Version **0.1.2** · [Changelog](CHANGELOG.md) · [MIT license](LICENSE)

A Layer 7 firewall using **Uber Fx 1.24** for dependency injection and lifecycle management, **Fiber 3.6** for HTTP handling, and a pooled native fasthttp upstream client. Requires **Go 1.27 or newer**.

The previous application is retained in the sibling `http-proxy-firewall.bak` directory. Deployment configuration, certificates and local data remain outside source control.

## Build and run

```sh
go mod download
make build
test -e .env || cp .env.example .env
test -e .creds || cp .creds.example .creds
chmod 600 .creds
```

Edit `.env` for your domains, upstream and network policy. For local HTTP development:

```sh
./bin/proxy-firewall \
  --listen=127.0.0.1:8080 \
  --proxy-to=127.0.0.1:8008 \
  --tls=false \
  --pprof-addr= \
  --ipv4-redirect=
```

Run an upstream on port 8008 before sending requests. No Redis, MaxMind download or ACME account is required for this local mode. Googlebot ranges refresh in the background by default; set `PF_GOOGLE_RANGES_URL=` in the environment to disable that source for offline runs.

Configuration precedence is command-line flags, process environment, optional `proxy-firewall.conf`, optional `.env`, then defaults. Invalid values fail startup. Existing flags `--listen`, `--proxy-to`, `--metrics`, `--silent`, `--enable-redis` and `--pprof-addr` are accepted. `--help` lists additional options. Upstream addresses accept `host:port` or an HTTP(S) origin.

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

[Fx lifecycle hooks](https://uber-go.github.io/fx/lifecycle.html) start Redis workers and intelligence before opening listeners. Shutdown reverses that order: stop accepting traffic, drain requests, close proxy connections, stop intelligence, then stop Redis workers. Startup bind failures roll back acquired resources; listener failures request application shutdown.

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
| Client IP forwarding | Direct peer by default. Configure `PF_TRUSTED_PROXIES` with your proxy CIDRs. Enable `PF_TRUST_CLOUDFLARE_HEADER` only when those peers supply the header. |
| TLS | Enabled by default on port 443. TLS 1.2 minimum; `--tls-legacy` explicitly enables compatibility with TLS 1.0/1.1. Configure `PF_TLS_HOSTS` to restrict certificate issuance. |
| Static certificates | Set both `PF_TLS_CERT_FILE` and `PF_TLS_KEY_FILE` (or `--tls-cert` and `--tls-key`) to use your own certificate and skip ACME. |
| Multiple internal hosts | `PF_UPSTREAM_ROUTES=example.test=http://internal-a:8080,api.example.test=https://internal-b:8443` selects a dedicated connection pool by incoming hostname. Unmatched hosts use `PF_PROXY_TO`. |
| IPv4 Host redirect | Existing `https://hostinq.biz` redirect retained; `--ipv4-redirect=` disables it. |
| HTTP protocol | Native Fiber listeners serve HTTP/1.1. Use a frontend proxy for HTTP/2 or HTTP/3 termination. |
| Redis | Disabled by default. Configure `REDIS_ADDRESS`, `REDIS_PASSWORD`, `REDIS_DB` and `PF_ENABLE_REDIS`. Cookie storage format is compatible; country cache entries use expiring individual keys. |
| Profiling | `127.0.0.1:8068` by default; empty disables it. Non-loopback profiling addresses are rejected. |
| Metrics | Optional `--metrics` exposes `/__system__/__metrics__`; labels use bounded method/status values. |
| Local data | `files/geo.mmdb` and `.cache/` stay local and ignored. No v1 files are imported automatically. |

`proxy-firewall.example.conf` supplies the existing deployment format: `PF_LISTEN_AT=--listen=...`, `PF_PROXY_TO=--proxy-to=...`, `PF_ENABLE_METRICS=--metrics=...`, `PF_ENABLE_SILENT_MODE=--silent=...` and `PF_ENABLE_REDIS=--enable-redis=...`. These values are translated to typed settings without shell evaluation. Existing `.env` and `proxy-firewall.conf` files are read without modification. Under systemd, the application reads both files from `/etc/proxy-firewall`; values in `proxy-firewall.conf` take precedence over `.env`.

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

`make install` builds and replaces `/etc/proxy-firewall/bin/proxy-firewall`, creates missing `bin`, `log`, `files`, `.cache` and `.certs` directories, and installs `/etc/systemd/system/proxy-firewall.service`. Existing directory contents and permissions are preserved. A missing `.env` is copied from `.env.example`; a missing `.creds` is copied from `.creds.example` with mode `0600`; a missing `proxy-firewall.conf` is copied from `proxy-firewall.example.conf`. Existing credential and configuration files are preserved. Local deployment files are never copied over existing server configuration. Review newly created examples before starting the service.

Installation counts the server's online logical CPUs (including hardware threads) and sets `GOMAXPROCS` to `max(1, floor(count * 2 / 5))` in the generated systemd command. For example, 16 threads gives `GOMAXPROCS=6`. This takes precedence over any `GOMAXPROCS` in existing configuration files, without modifying them. Reinstalling recalculates the value.

Both stdout and stderr append to `/etc/proxy-firewall/log/proxy-firewall.log`. Installation creates that file only when missing and preserves existing log content. `PF_SILENT=true` logs warnings and errors; `false` also includes informational messages. Rejection sampling is controlled by `PF_REJECTION_LOG_INTERVAL`. Direct CLI runs write to the terminal unless redirected.

Upstream failure warnings include the firewall's verified `client_ip`, honoring the configured trusted proxy policy. HTTP connection warnings include the socket peer IP; failures before HTTP headers are parsed cannot identify a client behind a proxy. Listener-wide failures without a connection use `client_ip=unknown`.

HTTP responses identify the firewall as `Server: pf`, including proxied responses, admin assets, errors and protocol upgrades. Upstream `Server` values are replaced.

Installation does not start, restart or enable the service. When ready:

```sh
sudo systemctl daemon-reload
sudo systemctl enable proxy-firewall
sudo systemctl restart proxy-firewall
tail -f /etc/proxy-firewall/log/proxy-firewall.log
```

The service has a 35-second stop deadline and write access to the log, data, cache and certificate directories. To stage an installation without writing to `/etc`, use `make install DESTDIR=/absolute/staging/path`. `make test-install` checks fresh installation, repeat installation, configuration preservation and CPU sizing in temporary directories.

Fiber settings and ownership rules follow the [official Fiber API documentation](https://docs.gofiber.io/api/fiber/). Request-scoped Fiber values are copied before retention in caches or worker queues.

## Maintainer

Maintained by **Anar K. Jafarov** (`num8er`), [anar.k.jafarov@gmail.com](mailto:anar.k.jafarov@gmail.com). Contact the maintainer for project questions and contribution coordination.

## Contributing and security reports

Keep changes focused, update the relevant documentation and examples, and run `make check` before submitting. Include a reproducible test for behavioral fixes. Keep real `.env`, `.creds`, deployment configuration, keys and runtime data out of commits and public reports.

Report suspected vulnerabilities privately to [anar.k.jafarov@gmail.com](mailto:anar.k.jafarov@gmail.com). Include the affected version, impact, reproduction steps and sanitized configuration/log excerpts. Coordinate disclosure with the maintainer before publishing sensitive details.

## License

Copyright © 2026 Anar K. Jafarov (`num8er`). Distributed under the [MIT license](LICENSE). Third-party dependencies retain their respective licenses and notices.
