# Full Docker benchmark — 2026-11-08

Current working tree based on version **0.3.39**, including the 200 MiB body limit, GC configuration, conditional restart and grouped admin Rules controls. This is an uncommitted working-tree measurement, not a released-version baseline. The recorded source hashes identify the measured files.

**68 cases completed. All 67 standard cases passed with zero failed requests.** Standard firewall cases processed **53,864,376 requests**, including **52,698,798 origin responses** and **1,165,578 correct security rejections**. Backend calibration is separate. The deliberate overload case recorded **1,020,520 failed requests**, all HTTP 503; those failures remain failures in the raw results and are reported separately.

## Environment and method

| Setting | Value |
| --- | --- |
| Docker | 29.8.1; aarch64; 8 vCPUs; 31.3 GiB VM RAM |
| Kernel / compiler | 7.0.14-linuxkit; Go 1.27.3 linux/arm64 |
| Container quotas | Firewall 2 CPUs / 1 GiB / 512 PIDs; backend 1 CPU / 512 MiB; load client 4 CPUs / 2 GiB |
| Firewall limits | 8,192 inbound connections; 2,048 handlers and upstream connections; overflow disabled |
| Body / GC | 200 MiB per request; 256 MiB inspection-buffer budget; GOGC=100; GOMEMLIMIT=off |
| Topology | Isolated internal Docker network, no published ports; verified TLS; HTTP/1.1 keep-alive |
| Matrix | HTTP/HTTPS × GET/form/20-field multipart × 64/256/1,024 clients × 3 repeats |
| Timing | 15 s per regular measurement, 2 s warmup; rejection cases 3 s; soak 60 s |
| Payloads | 1,024-byte origin response; form/multipart values total 1,024 bytes before framing |
| Monitoring | Admin and Prometheus enabled; benchmark admin sampler every 2 s; Docker samples about every 0.5 s |
| External services | Redis and live intelligence disabled; no GeoIP database; no external network traffic |

Workers must observe the cookie challenge and obtain valid cookies before measured valid traffic. Successful responses must be fully read and carry the origin marker. The load model is closed-loop; latency includes client/backend scheduling and does not correct coordinated omission. Backend/client/shared-VM capacity can constrain throughput.

The admin sampler is independent of the browser UI, whose automatic refresh interval is five seconds. Debug capture was disabled. GC settings were applied at startup; this run does not compare GC tuning values.

## Repeated throughput and latency

RPS is the median of three runs; ranges show individual runs. p99 values are not pooled across runs. Every row had zero failures.

| Protocol | Workload | Clients | Median RPS | RPS range | p99 range (ms) |
| --- | --- | ---: | ---: | ---: | ---: |
| HTTP | get | 64 | 98,222 | 97,369–98,875 | 1.64–1.67 |
| HTTP | get | 256 | 97,239 | 96,727–97,567 | 5.44–5.51 |
| HTTP | get | 1,024 | 78,512 | 77,255–79,767 | 19.40–20.45 |
| HTTP | form | 64 | 79,318 | 78,776–79,590 | 2.59–2.72 |
| HTTP | form | 256 | 78,925 | 78,799–79,229 | 6.88–7.14 |
| HTTP | form | 1,024 | 67,824 | 67,509–68,074 | 23.33–23.86 |
| HTTP | multipart | 64 | 21,843 | 21,490–22,176 | 6.49–6.68 |
| HTTP | multipart | 256 | 22,211 | 22,194–22,215 | 22.28–22.54 |
| HTTP | multipart | 1,024 | 22,726 | 22,650–22,916 | 62.91–69.21 |
| HTTPS | get | 64 | 80,417 | 79,989–80,422 | 2.52–2.59 |
| HTTPS | get | 256 | 79,290 | 79,202–79,932 | 7.08–7.27 |
| HTTPS | get | 1,024 | 67,265 | 66,794–68,109 | 23.86–25.17 |
| HTTPS | form | 64 | 69,913 | 68,772–70,900 | 3.08–3.11 |
| HTTPS | form | 256 | 65,200 | 65,194–66,322 | 9.31–9.70 |
| HTTPS | form | 1,024 | 56,557 | 56,300–56,769 | 28.31–30.41 |
| HTTPS | multipart | 64 | 17,993 | 17,968–19,103 | 8.19–9.04 |
| HTTPS | multipart | 256 | 19,195 | 19,092–19,407 | 24.90–25.69 |
| HTTPS | multipart | 1,024 | 20,134 | 19,953–20,316 | 66.06–66.58 |

## Security and stress cases

| Case | RPS | p99 (ms) | Requests | Failed |
| --- | ---: | ---: | ---: | ---: |
| backend-get-c1024 | 96,608 | 15.20 | 1,450,116 | 0 |
| http-mixed15-c256 | 83,337 | 7.34 | 1,250,292 | 0 |
| http-reject-encoded-c64 | 65,986 | 2.10 | 197,991 | 0 |
| http-reject-get-body-c64 | 66,524 | 2.05 | 199,654 | 0 |
| http-reject-malformed-multipart-c64 | 65,949 | 2.20 | 197,896 | 0 |
| http-reject-progress-c64 | 59,820 | 2.62 | 179,522 | 0 |
| https-mixed15-c256 | 36,301 | 16.65 | 544,745 | 0 |
| https-overload-c4096 | 96,208 | 111.15 | 1,450,387 | 1,020,520 |
| https-reject-encoded-c64 | 10,169 | 12.71 | 30,562 | 0 |
| https-reject-get-body-c64 | 10,068 | 13.24 | 30,243 | 0 |
| https-reject-malformed-multipart-c64 | 10,163 | 12.85 | 30,534 | 0 |
| https-reject-progress-c64 | 9,919 | 13.11 | 29,821 | 0 |
| https-slow50ms-c1024 | 19,143 | 63.96 | 288,029 | 0 |
| https-soak-c1024 | 65,175 | 26.21 | 3,911,290 | 0 |

All malformed-multipart and GET-body checks returned 400; upload-progress checks returned 403; encoded-body checks returned 415. Rejected requests did not carry the origin marker. Both mixed workloads correctly handled their deterministic 15% malicious request mix.

The 4,096-client overload case used a 50 ms upstream delay against 2,048-handler/upstream limits. It completed **1,450,387 responses**: **429,867 HTTP 200** and **1,020,520 HTTP 503**. Successful admitted throughput was **28,514 requests/sec**. Total RPS includes the 503 responses and must not be read as successful forwarding capacity. The container remained running and was not OOM-killed.

## Resources and soak

- Firewall cgroup peak: **635.3 MiB** of 1 GiB, including overload; `OOMKilled=false`; cgroup peak **16 tasks**.
- Docker sampled firewall peak: **626.6 MiB**, from **2,217 samples**. This is Docker memory accounting, not process RSS.
- The 60-second soak completed **3,911,290 requests** at **65,175 requests/sec**, with **26.21 ms p99** and zero failures.
- Soak resource coverage: **120 firewall samples**, spanning 59.5 s, with a maximum gap including edges of approximately 0.501 s. Sampled memory ranged **278.3–294.7 MiB**, with average CPU **195.1%** (100% is one core). This one-minute window does not establish long-term memory stability.

## Additional Docker verification

The container used the 200 MiB body limit and 256 MiB buffer budget, with no private override YAML in its image/runtime. A separate request declaring 200 MiB plus one byte, with only an 8 KiB prefix transmitted, returned the designed **413 HTML page**, displayed **200 MiB**, and included all **11 language options**. This is a rejection check, not a large-upload throughput measurement. A preliminary request ended before the parser received its prefix and correctly returned 400; both wire responses are retained.

All **160 recorded source hashes** matched the working tree after measurement. This matrix does not quantify full-size 200 MiB uploads, HTTP/2, debug-file I/O, restart downtime, YAML-save latency, or populated external classification services.

## Evidence

- [Full case table and resource coverage](summary.md)
- [Validated totals](validation.json)
- [Run settings and working-tree identity](run-settings.json)
- [Environment, image IDs and source hashes](environment.json)
- [Docker verification](verification.json)
- [413 wire response](413-verification.http)
- [Case exit statuses](exits.tsv)
- [Docker samples](docker-stats.jsonl) and [admin samples](admin-samples.jsonl)
- Runner and firewall diagnostic logs are retained locally as `runner.log` and `firewall.log`; generated logs are excluded from source releases.

Reproduction:

```sh
docker compose -f bench/compose.yaml build backend firewall
COMPOSE_PROJECT_NAME=proxy-firewall-benchmark-fresh \
BENCH_RESULTS_DIR="$PWD/bench/results/fresh-run" \
NO_BUILD=1 REPEATS=3 DURATION=15s WARMUP=2s SOAK=1 OVERLOAD=1 \
python3 bench/measure.py
python3 bench/summarize.py bench/results/fresh-run
```
