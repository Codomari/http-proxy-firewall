# Codomari Proxy-Firewall benchmarks

## Latest run: changes released in 0.3.45

The complete Docker benchmark ran on **2026-11-08** against the working tree containing the 200 MiB limit, GC controls, conditional restart and grouped Rules controls. The measured binaries still reported **0.3.39** because the release version was bumped after measurement; this is recorded in the source hashes and run metadata.

**68 cases completed. All 67 standard cases passed with zero failures**, including **53,864,376 firewall requests**. The deliberate 4,096-client overload run recorded **429,867 HTTP 200** and **1,020,520 HTTP 503** responses. Firewall resources were limited to **2 CPUs and 1 GiB RAM**. The 60-second soak sustained **65,175 requests/sec** with **26.2 ms p99 latency**; peak cgroup memory across the complete run, including overload, was **635.3 MiB**, with no OOM kill.

- [Full report and repeated throughput matrix](bench/results/20261108T230101Z-v0.3.39-working-tree/report.md)
- [Every case, resource samples and soak coverage](bench/results/20261108T230101Z-v0.3.39-working-tree/summary.md)
- [Validated totals](bench/results/20261108T230101Z-v0.3.39-working-tree/validation.json)
- [Docker verification, including the 413 page](bench/results/20261108T230101Z-v0.3.39-working-tree/verification.json)

## Historical baseline: 0.3.4

Fresh measurements recorded on **2026-11-03** using the **0.3.4 baseline**. The final **0.3.7** release adds hostname metadata to upstream-failure and request-rejection warnings and refines background restart recovery. Those final changes were tested without rerunning the benchmark matrix, as requested. Previous result sets were deleted.

The run completed **67 cases**, including **36,091,583 firewall requests**, with **zero failed requests**. Of those firewall requests, **976,812** were correctly rejected hostile requests. The separate backend calibration completed **908,733** requests. Accepted responses had to carry the origin marker and be fully read; cookie challenge pages were excluded from forwarded successes.

## Environment and method

| Item | Recorded setting |
| --- | --- |
| Host | Apple M4 Max, 16 physical CPUs, 128 GiB RAM |
| Docker VM | 8 vCPUs, 31.3 GiB RAM, aarch64 |
| Docker/kernel | 29.8.1; 7.0.14-linuxkit |
| Compiler | Go 1.27.3 linux/arm64 in Docker; Go 1.27.1 darwin/arm64 for native validation |
| Resource quotas | Firewall: 2 CPUs / 1 GiB / 512 PIDs; backend: 1 CPU / 512 MiB; client: 4 CPUs / 2 GiB |
| Limits | 8,192 connections, 2,048 handlers/upstream connections, 32 MiB body / 256 MiB aggregate inspection budget |
| Topology | Internal Docker network; no published ports; HTTP/1.1 keep-alive |
| TLS | Verified generated ECDSA certificate, reused during this matrix |
| Payloads | 1,024-byte origin response; form and 20-field multipart values total 1,024 bytes |
| Detector | Threshold 1 request/sec averaged over 10 seconds, 30-minute penalty; each worker primes a valid SID cookie |
| Classifiers | Full body/CVE and bot-query checks, hostname detector, cookie validation; no target static/IP bypass |
| External services | Redis disabled; empty country/Google allowlists; no GeoIP database or live refresh |
| Monitoring | Admin and Prometheus enabled; authenticated admin overview polled every two seconds |

Ordinary combinations ran three times for ten seconds after two seconds of warmup, at 64, 256 and 1,024 clients over HTTP and HTTPS. Rejection cases ran for three seconds; mixed and slow-origin cases ran for ten seconds. The HTTPS soak ran for sixty seconds. Warmup traffic is separate from measured counts.

## Repeated measurements

RPS values are per-run results: median and min–max over three runs. p99 is the range of per-run p99 values, without pooling histograms. All rows had zero failures.

| Protocol | Workload | Clients | Median RPS | RPS range | p99 range (ms) |
| --- | --- | ---: | ---: | ---: | ---: |
| HTTP | get | 64 | 96,484 | 96,423–97,482 | 1.62–1.65 |
| HTTP | get | 256 | 95,329 | 91,937–96,171 | 5.31–5.57 |
| HTTP | get | 1,024 | 73,477 | 72,477–74,351 | 19.92–20.45 |
| HTTP | form | 64 | 73,694 | 73,465–73,769 | 2.65–2.82 |
| HTTP | form | 256 | 74,311 | 74,030–75,138 | 7.01–7.14 |
| HTTP | form | 1,024 | 66,171 | 65,963–66,617 | 22.28–22.54 |
| HTTP | multipart | 64 | 20,569 | 19,501–20,785 | 6.95–7.41 |
| HTTP | multipart | 256 | 20,848 | 20,771–20,911 | 22.28–22.54 |
| HTTP | multipart | 1,024 | 21,916 | 21,458–22,293 | 57.67–59.24 |
| HTTPS | get | 64 | 76,072 | 75,936–76,172 | 2.56–2.62 |
| HTTPS | get | 256 | 75,473 | 75,074–75,558 | 7.08–7.27 |
| HTTPS | get | 1,024 | 64,755 | 63,160–65,543 | 23.59–24.64 |
| HTTPS | form | 64 | 67,199 | 66,988–67,616 | 3.08–3.15 |
| HTTPS | form | 256 | 65,727 | 65,548–65,841 | 9.04–9.18 |
| HTTPS | form | 1,024 | 58,199 | 58,068–58,333 | 26.48–26.74 |
| HTTPS | multipart | 64 | 17,950 | 17,595–18,020 | 8.06–8.39 |
| HTTPS | multipart | 256 | 18,702 | 18,558–19,056 | 23.86–24.38 |
| HTTPS | multipart | 1,024 | 19,637 | 19,229–19,926 | 64.49–67.11 |

## Rejection, mixed, slow-origin and soak checks

All malformed multipart requests returned 400, upload-progress requests 403, GET bodies 400 and encoded bodies 415, without an origin marker. Expected 4xx responses are successful security checks, not failed requests. HTTPS rejection measurements include repeated handshakes because rejected requests close their connections.

| Case | RPS | p99 (ms) | Measured requests | Failed |
| --- | ---: | ---: | ---: | ---: |
| backend-get-c1024 | 90,749 | 15.86 | 908,733 | 0 |
| http-mixed15-c256 | 78,121 | 7.54 | 781,351 | 0 |
| http-reject-encoded-c64 | 58,394 | 2.33 | 175,237 | 0 |
| http-reject-get-body-c64 | 59,380 | 2.26 | 178,209 | 0 |
| http-reject-malformed-multipart-c64 | 58,950 | 2.36 | 176,890 | 0 |
| http-reject-progress-c64 | 54,383 | 2.69 | 163,201 | 0 |
| https-mixed15-c256 | 33,998 | 17.30 | 340,155 | 0 |
| https-reject-encoded-c64 | 9,708 | 13.37 | 29,183 | 0 |
| https-reject-get-body-c64 | 9,646 | 13.37 | 28,983 | 0 |
| https-reject-malformed-multipart-c64 | 9,561 | 13.63 | 28,723 | 0 |
| https-reject-progress-c64 | 9,351 | 13.37 | 28,086 | 0 |
| https-slow50ms-c1024 | 19,183 | 62.91 | 192,615 | 0 |
| https-soak-c1024 | 63,151 | 25.69 | 3,789,800 | 0 |

The direct-backend calibration used 1,024 clients. It does not establish an upper bound for lower-concurrency proxy runs; the backend, client and shared VM/network can limit throughput.

## Resource observations and verification

The firewall cgroup memory high-water mark was **277.1 MiB** against a 1 GiB limit, with `OOMKilled=false` and a cgroup peak of **16 tasks**. Docker reported a sampled peak of 271.9 MiB. These measures include different accounting and are not process RSS.

During the sixty-second soak, **120 firewall samples** covered 59.5 seconds, with a maximum gap including edges of 0.501 seconds. Sampled memory ranged **176.6–217.4 MiB**; average CPU was **196.1%** (100% is one core). Twenty-nine admin samples covered 58.65 seconds with a maximum gap of 2.101 seconds. These observations describe this one-minute window, not long-term stability.

Native tests and a DOM harness verified YAML merging/export, atomic persistence, simultaneous debug captures, presence-only rule actions, all five tab titles and TLS SNI diagnostics. The running benchmark image returned `Server: codomari/proxy-firewall/0.3.4` and the expected Codomari/versioned admin page without a runtime `VERSION` file. Private override YAML was absent from the image. See [verification.json](bench/results/v0.3.4/verification.json).

The throughput matrix used debug capture disabled. It does not quantify debug-file I/O, YAML save latency, external Redis/GeoIP classification, or failure-log throughput. Closed-loop latency includes client/backend scheduling; it does not correct coordinated omission. Histogram values are rounded to buckets with less than 1.6% relative error.

## Reproduction and evidence

```sh
NO_BUILD=1 REPEATS=3 DURATION=10s WARMUP=2s WORKLOADS="get form multipart" SOAK=1 \
  BENCH_RESULTS_DIR="$PWD/bench/results/new-run" python3 bench/measure.py
python3 bench/summarize.py bench/results/new-run
```

Build images first with `docker compose -f bench/compose.yaml build backend firewall`. See [bench/README.md](bench/README.md) for workload semantics and isolation. The recorded dataset is the 0.3.4 baseline; choose a new output directory when measuring a later build.

- [Complete case table and sample coverage](bench/results/v0.3.4/summary.md)
- [Environment, image IDs and recorded source hashes](bench/results/v0.3.4/environment.json)
- [Docker resource samples](bench/results/v0.3.4/docker-stats.jsonl)
- [Admin samples](bench/results/v0.3.4/admin-samples.jsonl)
- [Case exit statuses](bench/results/v0.3.4/exits.tsv)

Firewall image: `sha256:907fe667aca945ea0f60c2eb16c5529380a5fe023149a58e4c0fd6062fea4767`. Backend/client image: `sha256:f069344aa755b708c66eebc33c715c108851fc1f96afb2fe13472b116f35f614`.
