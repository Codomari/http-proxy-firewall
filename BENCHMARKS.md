# Docker performance verification

Measured on **2026-11-01**, with the final embedded admin interface enabled and
its authenticated overview API polled every two seconds.

The main matrix processed **16,372,392 firewall requests with zero failed
requests**, including **1,054,259 correctly rejected requests**. The separate
direct-backend calibration processed 833,031 requests. Each accepted measured
request had to return the backend's marker and complete its response body;
cookie challenge pages could not count as forwarded successes.

The highest observed main-matrix HTTP GET rate was **94,140 requests/sec** at
64 clients, with **1.67 ms p99**. A **60-second HTTPS run at 1,024 clients**
completed **3,785,984 requests**, averaging **63,089 requests/sec**, with
**23.86 ms p99**, zero errors, and no OOM kill. These are measurements for the
configuration below, rather than a capacity guarantee for other workloads.

## Machine and configuration

| Item | Measured configuration |
| --- | --- |
| Host | Apple M4 Max, 16 physical CPUs, 128 GiB RAM |
| Docker VM | Linux/ARM64, 8 vCPUs, 31.3 GiB RAM |
| Engine | Docker 29.8.1; kernel 7.0.14-linuxkit |
| Compiler | Go 1.27.3 linux/arm64 in Docker; host checks used Go 1.27.1 |
| Firewall budget | 2-CPU quota, `GOMAXPROCS=2`, 1 GiB RAM, 512 PIDs |
| Backend budget | 1 CPU, 512 MiB RAM |
| Load-client budget | 4 CPUs, 2 GiB RAM |
| Limits | 8,192 inbound connections, 2,048 handlers/upstream connections, 65,536 open-file limit |
| Body budget | 32 MiB/request, 256 MiB aggregate retained inspection capacity |
| Topology | Dedicated internal Docker network; no published ports |
| Protocol | HTTP/1.1 keep-alive; HTTPS verifies the generated ECDSA certificate |
| Payloads | 1,024-byte origin response; form values total 1,024 bytes before framing |
| Workloads | GET, URL-encoded form, legitimate 20-field multipart, rejection/mixed traffic, slow origin |
| Classifiers | Body/CVE and bot/query checks, IP checks, hostname detector, SID validation; no static/IP bypass for the target |
| External services | Country allowlist empty, no GeoIP database, empty Google ranges, Redis disabled |
| Monitoring | Prometheus and bounded admin tracking enabled; authenticated admin polling every 2 seconds |

The DDoS threshold was 1 averaged request/sec over the existing ten-second
window, with a 30-minute penalty. Warmup first observed a real SID challenge
and then primed a separate cookie jar for every worker. Measured accepted
requests used those cookies and still passed request inspection.

Firewall image: `sha256:59229a730e5581d96820f2f35a980498fbdd3112aca7fc7be0b0aaaea813b6be`.
Load/backend image: `sha256:624e65dc2342f78f1e7ef8b916bdd84b0ccd51b432453fc9a2fe428da660aa51`.
Exact limits, image IDs, state and source hashes are saved in
[environment.json](bench/results/final/environment.json).

## Main matrix

Ordinary cases ran for 10 seconds after two seconds of warmup. The soak ran for
60 seconds. All rows below had **zero failed requests**.

| Protocol/workload | Concurrent clients | Requests/sec | p99 ms |
| --- | ---: | ---: | ---: |
| HTTP GET | 64 | 94,140 | 1.67 |
| HTTP GET | 256 | 93,207 | 5.37 |
| HTTP GET | 1,024 | 75,650 | 19.14 |
| HTTPS GET | 64 | 79,071 | 2.49 |
| HTTPS GET | 256 | 79,501 | 6.36 |
| HTTPS GET | 1,024 | 66,266 | 22.02 |
| HTTP URL-encoded form | 256 | 75,882 | 6.68 |
| HTTPS URL-encoded form | 256 | 67,426 | 7.73 |
| HTTP multipart, 20 fields | 256 | 23,293 | 20.97 |
| HTTPS multipart, 20 fields | 256 | 21,808 | 21.76 |
| HTTPS origin delayed 50 ms | 1,024 | 19,105 | 63.96 |
| HTTPS GET, 60-second soak | 1,024 | 63,089 | 23.86 |

The direct backend at 1,024 clients measured 83,200 requests/sec, p99 17.56 ms.
It is a calibration at that concurrency, not an upper bound for lower-concurrency
proxy cases. Backend/client CPU and the shared Docker network can limit results.

All four hostile cases produced their exact expected outcomes without an origin
marker: malformed multipart **400**, upload-progress field **403**, GET body
**400**, and encoded body **415**. HTTP rejection rates ranged from 58,530 to
65,423 requests/sec; HTTPS ranged from 10,004 to 10,317. Rejections close their
connection, so HTTPS rejection measurements include repeated TLS handshakes.
The 15% malicious mix reached 82,487 requests/sec over HTTP and 36,132 over
HTTPS, with zero incorrect outcomes. The full 31-case table, counts and
percentiles are in [summary.md](bench/results/final/summary.md).

## Sustained resources and dashboard verification

The firewall's cgroup high-water mark over the complete main matrix was
**230,060,032 bytes (219.4 MiB)**, against a 1 GiB limit. Its container remained
running with `OOMKilled=false`; peak process/thread count was 16. This includes
kernel-accounted container memory and is not a process-RSS measurement.

During the 60-second soak, 120 firewall samples covered a 59.5-second span, with
no gap above 0.51 seconds. Docker-reported memory usage ranged **175.3–186.3 MiB**
and CPU averaged **192.6%** (roughly 1.93 CPUs). Twenty-eight admin samples
covered 56.6 seconds of the same window, with no gap above 2.11 seconds.
All reported **1,038 goroutines** and unchanged **158,464,296 runtime system
bytes**. Live heap allocation varied with GC. These observations support the
one-minute result; they do not establish long-term memory stability.

Once firewall traffic began, admin samples reported the active DDoS penalty, one tracked hostname,
zero untracked hosts, zero 5xx errors, and `GOMAXPROCS=2`. In-flight counters
returned to zero between cases. Admin polls were excluded from traffic totals.
Raw [Docker samples](bench/results/final/docker-stats.jsonl) and
[admin responses](bench/results/final/admin-samples.jsonl) are retained.

Chrome checks separately verified the embedded dashboard from an **empty working
directory**: live rendering, domain search, inert HTML-shaped input, desktop and
390-pixel mobile layouts, and no external requests or browser errors. See
[verification.json](bench/results/admin-ui/verification.json),
[desktop screenshot](bench/results/admin-ui/desktop.png) and
[mobile screenshot](bench/results/admin-ui/mobile.png).

## Profile-guided optimization and repeatability

The initial v2 profile exposed an unconditional immediate-header flush on
ordinary fixed-length responses. On plaintext TCP, that separated header and
body writes and entered an `io.Copy` path allocating 32 KiB per response.
The final version batches ordinary fixed-length headers with body bytes in the
existing bounded writer buffer. Unknown-length streams and SSE retain prompt
header delivery; response bodies continue streaming.

Coordinated ten-second allocation profiles during separate 20-second HTTP
256-client runs showed:

| Profile | Sampled allocated space | Dominant finding |
| --- | ---: | --- |
| Initial v2 | 17,964.66 MB | `io.copyBuffer`: 17,351.62 MB, 96.59% |
| Final v2 | 1,079.25 MB | The previous `io.copyBuffer` allocation is absent from the reported hot nodes |

These are sampled allocations over time, not retained heap or RSS. The profiled
runs had different achieved throughput (54,779 vs 90,128 requests/sec), and the
final run also included per-host monitoring. Do not interpret the totals as a
controlled per-request allocation comparison. A wire regression test additionally
verifies one frontend write for an ordinary 1 KiB fixed response, while SSE and
chunked-stream tests preserve delivery behavior. The profiles and text reports
are under [bench/results](bench/results/).

Two additional 10-second runs repeated HTTP GET and URL-encoded forms at
256 clients. Combining those runs with the main matrix gives:

| HTTP workload, 256 clients | Initial v2 RPS, one run | Final RPS range, three runs | Final median RPS | Final per-run p99 range |
| --- | ---: | ---: | ---: | ---: |
| GET | 59,238 | 92,367–93,207 | 93,109 | 5.37–5.83 ms |
| URL-encoded form | 50,752 | 75,882–83,423 | 82,340 | 6.49–6.68 ms |

Final median rates were 57% and 62% above those initial v2 points. This compares
the complete tuning/monitoring bundle, not an isolated single change, and
**does not compare v1 with v2**. HTTPS throughput was broadly similar to the
initial run; the identified copy-buffer problem was specific to plaintext TCP.
All ten additional repeat/calibration/rejection cases also had zero failed
requests: [repeat summary](bench/results/repeats/summary.md).

## Reproduce

```sh
docker compose -f bench/compose.yaml build backend firewall
BENCH_RESULTS_DIR="$PWD/bench/results/rerun" NO_BUILD=1 REPEATS=1 \
  DURATION=10s WARMUP=2s WORKLOADS='get form multipart' \
  SOAK=1 SOAK_DURATION=60s python3 bench/measure.py
python3 bench/summarize.py bench/results/rerun
```

`python3 bench/profile.py` captures the coordinated HTTP CPU/allocation profiles
against running benchmark containers. It writes `http-after-*` artifacts and
should run separately from throughput measurements. The harness leaves its
containers available for inspection; remove only this test project with:

```sh
docker compose -f bench/compose.yaml down -v
```

The load generator is closed-loop. Percentiles include all measured requests
and use bounded histogram buckets with less than 1.6% rounding error. Throughput
includes in-flight drain time. This is neither a fixed offered-arrival-rate test
nor a coordinated-omission-corrected capacity test. GeoIP/Google datasets, live
Redis, external TLS/ACME issuance, WAN clients, large uploads, arbitrary CVEs,
and HTTP/2 or HTTP/3 were not load-tested here. The native proxy serves HTTP/1.1.

`go test -race ./...`, `go vet ./...`, host build, Docker build, and browser QA
passed. Wire tests also cover overload admission with the admin still available,
stream/tunnel lifetimes, and failed 101 delivery/deadline/pipeline cleanup.

The final profile identifies smaller remaining allocation candidates in hostname
IP parsing and SID base64 construction. Those are future optimization options;
they are not additional changes in this version and would need compatibility
tests before implementation.
