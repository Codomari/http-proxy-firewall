# Local Docker benchmark

This harness measures proxy forwarding and the configured firewall chain on an isolated Docker network.
The firewall has 2 CPUs and 1 GiB RAM; the upstream has 1 CPU; the load client has
4 CPUs and 2 GiB RAM. No ports are published and the network has `internal: true`.
The Go load tool also rejects public IPs and arbitrary internet hostnames.

```sh
./bench/run.sh
```

The default matrix uses HTTP and HTTPS, GET and URL-encoded forms, concurrency
64/256/1024, 15-second measurements, 2-second warmup, and three repetitions. It
also calibrates the direct backend, checks all four rejection workloads, runs a
15% malicious mixed workload, and checks a 50 ms upstream. The matrix takes
approximately 12 minutes. Optional `SOAK=1` adds a 60-second HTTPS run;
`OVERLOAD=1` adds a 4096-worker run that may correctly report admission failures.

For a shorter first pass:

```sh
REPEATS=1 DURATION=10s ./bench/run.sh
```

To record timestamped CPU/RAM/PID samples, Docker limits, image IDs, source hashes,
and cgroup peak memory alongside that matrix:

```sh
NO_BUILD=1 REPEATS=1 DURATION=10s SOAK=1 python3 bench/measure.py
```

Build the images first, or omit `NO_BUILD=1`. Docker stats terminal control
sequences are removed before parsing JSON. The wrapper fails if it records no
resource samples. A standalone resource sampler is available with
`python3 bench/measure.py --collect-only --seconds 60`.

Summarize completed results with `python3 bench/summarize.py bench/results/final`.
It separates direct-backend traffic, preserves failure counts, and reports sample
coverage. `python3 bench/profile.py` captures CPU/allocation profiles during a
separate coordinated HTTP run against already-running benchmark containers.

`DURATION`, `WARMUP`, `REPEATS`, `CONCURRENCIES`, `SCHEMES`, `WORKLOADS`,
`REJECT_DURATION`, `BENCH_RESULTS_DIR`, `NO_BUILD`, `SLOW`, `SOAK`, and `OVERLOAD`
are configurable. Results are retained in `bench/results` by default. Each case
writes JSON even when measured requests fail; `exits.tsv` records exit status.
Warmup failure produces an error instead of a misleading measurement artifact.

The runner leaves containers available for inspection. Remove the isolated
containers and disposable certificate volume with:

```sh
docker compose -f bench/compose.yaml down -v
```

## What is measured

The upstream returns an exact 1024-byte body with
`X-Benchmark-Origin: benchmark-upstream-v1`. GET uses `/bench`, which has no static
extension. The country allowlist is empty, so country lookup is skipped; no local
GeoIP database is supplied. Explicit-IP bypasses are disabled for Docker clients.
Google ranges, live intelligence refresh, and Redis are disabled. These runs do
not measure classification with populated GeoIP/Google datasets, country caching,
Redis operations, or refresh jobs. This classifier configuration stays unchanged
between the initial and tuned primary measurements.
The final measurement enables the embedded admin interface with disposable example
credentials from `.creds.example`. The measurement wrapper polls its overview API every two seconds and
records responses in `admin-samples.jsonl`, exercising monitoring during load.
The DOS threshold is
1 and penalty lasts 30 minutes. The client first observes an actual `_X-SID_`
challenge, primes a separate cookie jar for every worker, and verifies each
measured valid response carries the origin marker. A challenge page cannot count
as a successful proxied response. Direct backend calibration explicitly disables
the challenge requirement.

One transport is shared across workers, with HTTP/1.1 keep-alive and HTTP/2
disabled. TLS verifies the generated test certificate with `--ca`; `--insecure`
exists only as an explicit benchmark option. The ECDSA key is generated at run
time in a disposable volume and never appears in source. The cert-init command
reuses a valid matching certificate/key pair across runs, so an existing firewall
cannot retain a different certificate from the client's trust file. If that pair
expires or becomes malformed, remove/recreate the containers and volume with the
`down -v` command above. The cert-init command
explicitly makes this test key readable inside that volume so the firewall can
retain its nonroot user; this is not a production key permission recommendation.

The load model is closed-loop: each worker waits for its response before issuing
another request. Percentiles describe measured requests, include failed requests,
and are rounded to histogram bucket bounds with less than 1.6% relative error.
This model does not correct coordinated omission or establish a fixed offered
request rate. No new requests start after the duration; in-flight requests drain,
and throughput divides by actual elapsed time including that drain.

JSON includes request totals, fully read responses, unique failed-request count,
HTTP status counts, error-category counts, per-workload counts, origin/challenge
counts, throughput, p50/p95/p99/mean/max latency, actual response body bytes, and
attempted request payload bytes. Multiple validation errors can apply to one
failed request. Byte counts exclude HTTP headers and TLS/network framing.

Rejection workloads expect malformed multipart `400`, a valid multipart upload
progress field `403`, GET with body `400`, and encoded body `415`. Rejected
requests must not carry the upstream marker. Mixed mode sends a deterministic
15% combination of those workloads alongside valid GET; actual counts appear in
the artifact.

Measure load-client and backend CPU as well as firewall CPU/RSS to identify the
limiting component. A client/core or backend limit is not proof of proxy capacity.
Collect Docker stats throughout repeats and soak; compare RSS at stable load
after warmup rather than claiming stability from a single sample. The root
benchmark report should record Docker resources, architecture, build versions,
test configuration, raw artifacts, failure counts, and repeat variability.

## Individual commands

```sh
docker compose -f bench/compose.yaml run --rm --no-deps loadclient load \
  --url https://firewall:8443/bench --ca /certs/server.crt \
  --workload form --concurrency 256 --duration 15s --warmup 2s \
  --json /results/individual.json
```

The benchmark executable has `upstream`, `load`, `cert`, and `check` subcommands.
`upstream` also provides `/echo`, `/ready`, and `/bench?delay=50ms`.
`--form-bytes` changes the form's payload size before encoding overhead.
The optional `--workload multipart` sends 20 legitimate regular form fields whose
values total `--form-bytes` bytes (1024 by default), with complete MIME framing.
It requires status 200 and the origin marker, exercising the strict multipart
inspection path. It is available for focused runs without extending the default
GET/URL-encoded matrix; for example set `WORKLOADS=multipart CONCURRENCIES='64 256'`.

If image-registry access prevents the normal build, compile the stdlib-only load
tool with the host Go toolchain, setting the Docker VM architecture explicitly:

```sh
mkdir -p bench/bin
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bench/bin/benchmark ./bench
docker build -t http-proxy-firewall-benchmark:local -f bench/Dockerfile.prebuilt .
```

Build the firewall image separately using the repository Dockerfile, then use
`NO_BUILD=1 ./bench/run.sh`. Use `amd64` instead of `arm64` when that matches Docker.
