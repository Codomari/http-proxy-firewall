Results: bench/results/v0.3.4

Measured cases

| case | target_group | RPS | p99_ms | requests | failed_requests | observed_4xx |
| --- | --- | --- | --- | --- | --- | --- |
| backend-get-c1024 | backend-direct | 90749.124 | 15.860 | 908733 | 0 | 0 |
| http-form-c1024-r1 | firewall | 65963.288 | 22.282 | 660278 | 0 | 0 |
| http-form-c1024-r2 | firewall | 66170.928 | 22.544 | 662383 | 0 | 0 |
| http-form-c1024-r3 | firewall | 66617.480 | 22.282 | 666895 | 0 | 0 |
| http-form-c256-r1 | firewall | 74029.556 | 7.078 | 740470 | 0 | 0 |
| http-form-c256-r2 | firewall | 74311.132 | 7.143 | 743298 | 0 | 0 |
| http-form-c256-r3 | firewall | 75137.629 | 7.012 | 751531 | 0 | 0 |
| http-form-c64-r1 | firewall | 73464.566 | 2.818 | 734705 | 0 | 0 |
| http-form-c64-r2 | firewall | 73768.779 | 2.720 | 737726 | 0 | 0 |
| http-form-c64-r3 | firewall | 73694.402 | 2.654 | 736979 | 0 | 0 |
| http-get-c1024-r1 | firewall | 74351.188 | 19.923 | 744225 | 0 | 0 |
| http-get-c1024-r2 | firewall | 73476.983 | 20.185 | 735485 | 0 | 0 |
| http-get-c1024-r3 | firewall | 72477.264 | 20.447 | 725481 | 0 | 0 |
| http-get-c256-r1 | firewall | 96170.603 | 5.308 | 961894 | 0 | 0 |
| http-get-c256-r2 | firewall | 95328.561 | 5.374 | 953581 | 0 | 0 |
| http-get-c256-r3 | firewall | 91937.474 | 5.571 | 919529 | 0 | 0 |
| http-get-c64-r1 | firewall | 96423.300 | 1.655 | 964276 | 0 | 0 |
| http-get-c64-r2 | firewall | 97481.558 | 1.622 | 974849 | 0 | 0 |
| http-get-c64-r3 | firewall | 96483.520 | 1.638 | 964865 | 0 | 0 |
| http-mixed15-c256 | firewall | 78120.920 | 7.537 | 781351 | 0 | 117211 |
| http-multipart-c1024-r1 | firewall | 22292.780 | 57.672 | 223484 | 0 | 0 |
| http-multipart-c1024-r2 | firewall | 21916.278 | 58.196 | 219763 | 0 | 0 |
| http-multipart-c1024-r3 | firewall | 21458.175 | 59.245 | 215180 | 0 | 0 |
| http-multipart-c256-r1 | firewall | 20770.942 | 22.544 | 207832 | 0 | 0 |
| http-multipart-c256-r2 | firewall | 20910.892 | 22.282 | 209264 | 0 | 0 |
| http-multipart-c256-r3 | firewall | 20848.270 | 22.282 | 208623 | 0 | 0 |
| http-multipart-c64-r1 | firewall | 19501.269 | 7.406 | 195073 | 0 | 0 |
| http-multipart-c64-r2 | firewall | 20569.049 | 7.012 | 205746 | 0 | 0 |
| http-multipart-c64-r3 | firewall | 20785.156 | 6.947 | 207896 | 0 | 0 |
| http-reject-encoded-c64 | firewall | 58394.231 | 2.327 | 175237 | 0 | 175237 |
| http-reject-get-body-c64 | firewall | 59379.544 | 2.261 | 178209 | 0 | 178209 |
| http-reject-malformed-multipart-c64 | firewall | 58949.528 | 2.359 | 176890 | 0 | 176890 |
| http-reject-progress-c64 | firewall | 54382.758 | 2.687 | 163201 | 0 | 163201 |
| https-form-c1024-r1 | firewall | 58199.271 | 26.477 | 582718 | 0 | 0 |
| https-form-c1024-r2 | firewall | 58332.840 | 26.477 | 584057 | 0 | 0 |
| https-form-c1024-r3 | firewall | 58068.235 | 26.739 | 581362 | 0 | 0 |
| https-form-c256-r1 | firewall | 65840.758 | 9.044 | 658620 | 0 | 0 |
| https-form-c256-r2 | firewall | 65548.192 | 9.175 | 655665 | 0 | 0 |
| https-form-c256-r3 | firewall | 65726.508 | 9.044 | 657433 | 0 | 0 |
| https-form-c64-r1 | firewall | 66987.969 | 3.146 | 669918 | 0 | 0 |
| https-form-c64-r2 | firewall | 67199.293 | 3.113 | 672029 | 0 | 0 |
| https-form-c64-r3 | firewall | 67616.426 | 3.080 | 676215 | 0 | 0 |
| https-get-c1024-r1 | firewall | 65543.245 | 23.593 | 656138 | 0 | 0 |
| https-get-c1024-r2 | firewall | 64755.194 | 23.855 | 648280 | 0 | 0 |
| https-get-c1024-r3 | firewall | 63159.952 | 24.642 | 632333 | 0 | 0 |
| https-get-c256-r1 | firewall | 75557.826 | 7.078 | 755770 | 0 | 0 |
| https-get-c256-r2 | firewall | 75074.378 | 7.274 | 750956 | 0 | 0 |
| https-get-c256-r3 | firewall | 75473.478 | 7.143 | 755106 | 0 | 0 |
| https-get-c64-r1 | firewall | 76072.194 | 2.621 | 760764 | 0 | 0 |
| https-get-c64-r2 | firewall | 76172.175 | 2.556 | 761774 | 0 | 0 |
| https-get-c64-r3 | firewall | 75935.508 | 2.556 | 759405 | 0 | 0 |
| https-mixed15-c256 | firewall | 33998.392 | 17.302 | 340155 | 0 | 51089 |
| https-multipart-c1024-r1 | firewall | 19926.275 | 64.487 | 199870 | 0 | 0 |
| https-multipart-c1024-r2 | firewall | 19229.169 | 67.109 | 192907 | 0 | 0 |
| https-multipart-c1024-r3 | firewall | 19636.639 | 65.536 | 197098 | 0 | 0 |
| https-multipart-c256-r1 | firewall | 18557.887 | 24.379 | 185689 | 0 | 0 |
| https-multipart-c256-r2 | firewall | 18701.554 | 24.379 | 187216 | 0 | 0 |
| https-multipart-c256-r3 | firewall | 19055.950 | 23.855 | 190724 | 0 | 0 |
| https-multipart-c64-r1 | firewall | 18020.207 | 8.258 | 180278 | 0 | 0 |
| https-multipart-c64-r2 | firewall | 17594.711 | 8.389 | 175981 | 0 | 0 |
| https-multipart-c64-r3 | firewall | 17949.977 | 8.061 | 179533 | 0 | 0 |
| https-reject-encoded-c64 | firewall | 9708.056 | 13.369 | 29183 | 0 | 29183 |
| https-reject-get-body-c64 | firewall | 9646.145 | 13.369 | 28983 | 0 | 28983 |
| https-reject-malformed-multipart-c64 | firewall | 9561.186 | 13.631 | 28723 | 0 | 28723 |
| https-reject-progress-c64 | firewall | 9351.373 | 13.369 | 28086 | 0 | 28086 |
| https-slow50ms-c1024 | firewall | 19182.949 | 62.915 | 192615 | 0 | 0 |
| https-soak-c1024 | firewall | 63151.342 | 25.690 | 3789800 | 0 | 0 |

Aggregate measured counts (backend-direct is separate from firewall)

| target_group | cases | requests | known_failed_requests | cases_missing_failure_count | observed_4xx | configured_rejection_attempts | origin_responses | warmup_requests_separate | success_false_cases |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| backend-direct | 1 | 908733 | 0 | 0 | 0 | 0 | 908733 | 181920 | 0 |
| firewall | 66 | 36091583 | 0 | 0 | 976812 | 976812 | 35114771 | 8731691 | 0 |
Failures are the load tool's unique failed_requests, unchanged; error-category counts are not summed. Observed 4xx are separate outcomes and can be expected for rejection/mixed workloads. Nonzero failures are never reclassified as passing. No pooled RPS or latency is inferred.

Resource sample counts and ranges

| source | rows | timestamped_rows | first_utc | last_utc | ignored_invalid_lines |
| --- | --- | --- | --- | --- | --- |
| docker-stats | 4715 | 4715 | 2026-11-03T13:37:38.630Z | 2026-11-03T13:51:00.128Z | 0 |
| admin-samples | 385 | 385 | 2026-11-03T13:37:37.791Z | 2026-11-03T13:50:59.371Z | 0 |

Per-container observed sample peaks

| container | samples | peak_cpu_pct | peak_mem_usage_MiB | largest_mem_limit_MiB | peak_pids | first_utc | last_utc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| proxy-firewall-benchmark-backend-1 | 1604 | 99.150 | 61.570 | 512.000 | 12.000 | 2026-11-03T13:37:38.630Z | 2026-11-03T13:51:00.128Z |
| proxy-firewall-benchmark-firewall-1 | 1604 | 204.140 | 271.900 | 1024.000 | 14.000 | 2026-11-03T13:37:38.630Z | 2026-11-03T13:51:00.128Z |
| proxy-firewall-benchmark-loadclient-run-014ad80da094 | 24 | 263.300 | 50.780 | 2048.000 | 11.000 | 2026-11-03T13:43:34.629Z | 2026-11-03T13:43:46.129Z |
| proxy-firewall-benchmark-loadclient-run-0234e49961d4 | 24 | 211.660 | 162.100 | 2048.000 | 11.000 | 2026-11-03T13:41:18.129Z | 2026-11-03T13:41:29.629Z |
| proxy-firewall-benchmark-loadclient-run-026bf0274679 | 24 | 207.110 | 53.390 | 2048.000 | 11.000 | 2026-11-03T13:46:39.128Z | 2026-11-03T13:46:50.629Z |
| proxy-firewall-benchmark-loadclient-run-02fc25d36513 | 23 | 201.590 | 22.040 | 2048.000 | 11.000 | 2026-11-03T13:47:29.129Z | 2026-11-03T13:47:40.128Z |
| proxy-firewall-benchmark-loadclient-run-08122332cd2d | 23 | 206.130 | 22.360 | 2048.000 | 11.000 | 2026-11-03T13:39:40.630Z | 2026-11-03T13:39:51.630Z |
| proxy-firewall-benchmark-loadclient-run-082634d63c8f | 22 | 209.680 | 23.320 | 2048.000 | 11.000 | 2026-11-03T13:43:47.629Z | 2026-11-03T13:43:58.130Z |
| proxy-firewall-benchmark-loadclient-run-17a8f42a364b | 25 | 202.050 | 159.500 | 2048.000 | 12.000 | 2026-11-03T13:45:12.629Z | 2026-11-03T13:45:24.629Z |
| proxy-firewall-benchmark-loadclient-run-185e11287949 | 22 | 219.410 | 22.020 | 2048.000 | 11.000 | 2026-11-03T13:38:02.630Z | 2026-11-03T13:38:13.129Z |
| proxy-firewall-benchmark-loadclient-run-18d664c2b4f2 | 24 | 200.990 | 160.400 | 2048.000 | 10.000 | 2026-11-03T13:47:16.128Z | 2026-11-03T13:47:27.629Z |
| proxy-firewall-benchmark-loadclient-run-1cc3b4e839de | 23 | 196.460 | 159.800 | 2048.000 | 11.000 | 2026-11-03T13:49:07.628Z | 2026-11-03T13:49:18.629Z |
| proxy-firewall-benchmark-loadclient-run-2610e838059a | 22 | 202.190 | 141.400 | 2048.000 | 10.000 | 2026-11-03T13:43:09.629Z | 2026-11-03T13:43:20.129Z |
| proxy-firewall-benchmark-loadclient-run-2a57c3d07c63 | 22 | 216.920 | 23.340 | 2048.000 | 11.000 | 2026-11-03T13:38:14.630Z | 2026-11-03T13:38:25.130Z |
| proxy-firewall-benchmark-loadclient-run-339803a2cda4 | 23 | 208.240 | 21.380 | 2048.000 | 11.000 | 2026-11-03T13:40:04.629Z | 2026-11-03T13:40:15.629Z |
| proxy-firewall-benchmark-loadclient-run-365e1d7432e5 | 22 | 206.690 | 59.040 | 2048.000 | 10.000 | 2026-11-03T13:44:36.628Z | 2026-11-03T13:44:47.128Z |
| proxy-firewall-benchmark-loadclient-run-3fa5df1ef33d | 23 | 204.420 | 152.200 | 2048.000 | 11.000 | 2026-11-03T13:40:54.130Z | 2026-11-03T13:41:05.129Z |
| proxy-firewall-benchmark-loadclient-run-402e27de122d | 23 | 198.670 | 174.600 | 2048.000 | 11.000 | 2026-11-03T13:46:52.129Z | 2026-11-03T13:47:03.129Z |
| proxy-firewall-benchmark-loadclient-run-409267aba236 | 25 | 206.470 | 52.480 | 2048.000 | 11.000 | 2026-11-03T13:48:05.129Z | 2026-11-03T13:48:17.128Z |
| proxy-firewall-benchmark-loadclient-run-4287a820ee37 | 22 | 216.800 | 50.430 | 2048.000 | 11.000 | 2026-11-03T13:40:42.130Z | 2026-11-03T13:40:52.630Z |
| proxy-firewall-benchmark-loadclient-run-441b7dc4eba2 | 24 | 211.480 | 53.340 | 2048.000 | 11.000 | 2026-11-03T13:44:23.629Z | 2026-11-03T13:44:35.129Z |
| proxy-firewall-benchmark-loadclient-run-49335f3bf128 | 23 | 221.540 | 24.650 | 2048.000 | 11.000 | 2026-11-03T13:44:11.628Z | 2026-11-03T13:44:22.629Z |
| proxy-firewall-benchmark-loadclient-run-4fb96edcda36 | 24 | 79.420 | 161.400 | 2048.000 | 10.000 | 2026-11-03T13:49:45.629Z | 2026-11-03T13:49:57.128Z |
| proxy-firewall-benchmark-loadclient-run-545020791928 | 23 | 199.070 | 162.400 | 2048.000 | 10.000 | 2026-11-03T13:48:55.628Z | 2026-11-03T13:49:06.629Z |
| proxy-firewall-benchmark-loadclient-run-554e69e9552e | 24 | 202.790 | 147.900 | 2048.000 | 11.000 | 2026-11-03T13:42:44.129Z | 2026-11-03T13:42:55.629Z |
| proxy-firewall-benchmark-loadclient-run-559213b32a87 | 23 | 210.280 | 59.120 | 2048.000 | 11.000 | 2026-11-03T13:44:48.629Z | 2026-11-03T13:44:59.628Z |
| proxy-firewall-benchmark-loadclient-run-55d433eae84b | 24 | 200.490 | 166.400 | 2048.000 | 10.000 | 2026-11-03T13:45:00.629Z | 2026-11-03T13:45:12.128Z |
| proxy-firewall-benchmark-loadclient-run-591bcb61ae9b | 24 | 215.970 | 53.330 | 2048.000 | 11.000 | 2026-11-03T13:40:16.630Z | 2026-11-03T13:40:28.129Z |
| proxy-firewall-benchmark-loadclient-run-5b5b35a9cfd3 | 22 | 212.370 | 48.320 | 2048.000 | 10.000 | 2026-11-03T13:42:20.129Z | 2026-11-03T13:42:30.630Z |
| proxy-firewall-benchmark-loadclient-run-61f8f67f10ba | 22 | 208.600 | 24.650 | 2048.000 | 11.000 | 2026-11-03T13:46:03.129Z | 2026-11-03T13:46:13.629Z |
| proxy-firewall-benchmark-loadclient-run-63ceff35ea8c | 5 | 362.440 | 21.450 | 2048.000 | 11.000 | 2026-11-03T13:43:21.629Z | 2026-11-03T13:43:23.629Z |
| proxy-firewall-benchmark-loadclient-run-65efce32bdb8 | 24 | 213.000 | 21.570 | 2048.000 | 10.000 | 2026-11-03T13:47:53.129Z | 2026-11-03T13:48:04.629Z |
| proxy-firewall-benchmark-loadclient-run-6845798933cd | 23 | 231.710 | 52.840 | 2048.000 | 11.000 | 2026-11-03T13:38:26.630Z | 2026-11-03T13:38:37.630Z |
| proxy-firewall-benchmark-loadclient-run-68ea8d1ed60d | 23 | 276.020 | 58.690 | 2048.000 | 11.000 | 2026-11-03T13:49:33.628Z | 2026-11-03T13:49:44.629Z |
| proxy-firewall-benchmark-loadclient-run-6bb174930bdd | 4 | 307.860 | 24.430 | 2048.000 | 10.000 | 2026-11-03T13:49:30.629Z | 2026-11-03T13:49:32.129Z |
| proxy-firewall-benchmark-loadclient-run-6c740c6574d6 | 22 | 198.450 | 21.440 | 2048.000 | 10.000 | 2026-11-03T13:41:31.129Z | 2026-11-03T13:41:41.629Z |
| proxy-firewall-benchmark-loadclient-run-745992bff4fc | 24 | 228.080 | 54.680 | 2048.000 | 11.000 | 2026-11-03T13:38:50.629Z | 2026-11-03T13:39:02.129Z |
| proxy-firewall-benchmark-loadclient-run-76e03931673f | 23 | 208.780 | 60.400 | 2048.000 | 11.000 | 2026-11-03T13:48:30.629Z | 2026-11-03T13:48:41.629Z |
| proxy-firewall-benchmark-loadclient-run-796519e20250 | 6 | 308.580 | 25.830 | 2048.000 | 10.000 | 2026-11-03T13:49:19.629Z | 2026-11-03T13:49:22.129Z |
| proxy-firewall-benchmark-loadclient-run-79e945dc22ae | 23 | 202.210 | 22.030 | 2048.000 | 10.000 | 2026-11-03T13:41:55.129Z | 2026-11-03T13:42:06.129Z |
| proxy-firewall-benchmark-loadclient-run-7d4087d9daa6 | 5 | 368.020 | 22.520 | 2048.000 | 11.000 | 2026-11-03T13:43:31.629Z | 2026-11-03T13:43:33.629Z |
| proxy-firewall-benchmark-loadclient-run-80c3b237026d | 22 | 208.650 | 55.260 | 2048.000 | 11.000 | 2026-11-03T13:48:18.629Z | 2026-11-03T13:48:29.129Z |
| proxy-firewall-benchmark-loadclient-run-833b1bc6fa47 | 23 | 211.310 | 47.730 | 2048.000 | 11.000 | 2026-11-03T13:42:32.129Z | 2026-11-03T13:42:43.129Z |
| proxy-firewall-benchmark-loadclient-run-844cdb215fe2 | 23 | 206.560 | 23.800 | 2048.000 | 11.000 | 2026-11-03T13:47:41.129Z | 2026-11-03T13:47:52.129Z |
| proxy-firewall-benchmark-loadclient-run-8838e8d2a5dc | 23 | 206.770 | 24.240 | 2048.000 | 11.000 | 2026-11-03T13:43:59.629Z | 2026-11-03T13:44:10.629Z |
| proxy-firewall-benchmark-loadclient-run-89edd9f715f7 | 24 | 213.660 | 57.500 | 2048.000 | 10.000 | 2026-11-03T13:42:07.130Z | 2026-11-03T13:42:18.629Z |
| proxy-firewall-benchmark-loadclient-run-8b272d436bad | 23 | 212.860 | 61.330 | 2048.000 | 11.000 | 2026-11-03T13:46:15.129Z | 2026-11-03T13:46:26.129Z |
| proxy-firewall-benchmark-loadclient-run-8b44d10fe811 | 24 | 198.380 | 176.100 | 2048.000 | 11.000 | 2026-11-03T13:47:04.129Z | 2026-11-03T13:47:15.629Z |
| proxy-firewall-benchmark-loadclient-run-8fd13f59913c | 24 | 222.700 | 22.180 | 2048.000 | 11.000 | 2026-11-03T13:37:49.629Z | 2026-11-03T13:38:01.130Z |
| proxy-firewall-benchmark-loadclient-run-904d1dda08df | 123 | 201.570 | 169.700 | 2048.000 | 11.000 | 2026-11-03T13:49:58.628Z | 2026-11-03T13:50:59.628Z |
| proxy-firewall-benchmark-loadclient-run-a6d8b73c748a | 23 | 214.430 | 154.700 | 2048.000 | 11.000 | 2026-11-03T13:39:03.630Z | 2026-11-03T13:39:14.629Z |
| proxy-firewall-benchmark-loadclient-run-aa2d67e620af | 24 | 200.390 | 139.800 | 2048.000 | 10.000 | 2026-11-03T13:42:56.129Z | 2026-11-03T13:43:07.629Z |
| proxy-firewall-benchmark-loadclient-run-b2f3c0851dc0 | 23 | 206.680 | 145.100 | 2048.000 | 11.000 | 2026-11-03T13:41:06.129Z | 2026-11-03T13:41:17.130Z |
| proxy-firewall-benchmark-loadclient-run-b7b4679e1eaa | 24 | 208.650 | 147.100 | 2048.000 | 11.000 | 2026-11-03T13:39:27.630Z | 2026-11-03T13:39:39.129Z |
| proxy-firewall-benchmark-loadclient-run-c11bfb352d89 | 23 | 206.450 | 48.520 | 2048.000 | 10.000 | 2026-11-03T13:46:27.129Z | 2026-11-03T13:46:38.129Z |
| proxy-firewall-benchmark-loadclient-run-c235ad2ee846 | 6 | 315.770 | 23.930 | 2048.000 | 10.000 | 2026-11-03T13:49:26.628Z | 2026-11-03T13:49:29.128Z |
| proxy-firewall-benchmark-loadclient-run-cacf81401500 | 23 | 202.140 | 22.430 | 2048.000 | 11.000 | 2026-11-03T13:39:52.630Z | 2026-11-03T13:40:03.629Z |
| proxy-firewall-benchmark-loadclient-run-d5aceda3f7a3 | 23 | 197.260 | 160.600 | 2048.000 | 10.000 | 2026-11-03T13:45:25.630Z | 2026-11-03T13:45:36.629Z |
| proxy-firewall-benchmark-loadclient-run-dc17b170b471 | 24 | 197.500 | 163.500 | 2048.000 | 10.000 | 2026-11-03T13:48:42.629Z | 2026-11-03T13:48:54.129Z |
| proxy-firewall-benchmark-loadclient-run-dc3efd84c67b | 24 | 206.790 | 25.150 | 2048.000 | 11.000 | 2026-11-03T13:45:37.629Z | 2026-11-03T13:45:49.129Z |
| proxy-firewall-benchmark-loadclient-run-dcd6ef6da805 | 23 | 211.400 | 150.800 | 2048.000 | 11.000 | 2026-11-03T13:39:15.630Z | 2026-11-03T13:39:26.630Z |
| proxy-firewall-benchmark-loadclient-run-e504c9ca6aae | 23 | 207.150 | 26.310 | 2048.000 | 10.000 | 2026-11-03T13:45:50.129Z | 2026-11-03T13:46:01.130Z |
| proxy-firewall-benchmark-loadclient-run-e6c41e6845fc | 23 | 207.720 | 19.790 | 2048.000 | 11.000 | 2026-11-03T13:41:43.130Z | 2026-11-03T13:41:54.129Z |
| proxy-firewall-benchmark-loadclient-run-e8669fe06576 | 5 | 307.330 | 23.700 | 2048.000 | 10.000 | 2026-11-03T13:49:23.628Z | 2026-11-03T13:49:25.629Z |
| proxy-firewall-benchmark-loadclient-run-e90081c877aa | 21 | 207.430 | 149.100 | 2048.000 | 11.000 | 2026-11-03T13:37:38.630Z | 2026-11-03T13:37:48.630Z |
| proxy-firewall-benchmark-loadclient-run-e9b9eb5f94fb | 5 | 354.130 | 22.290 | 2048.000 | 11.000 | 2026-11-03T13:43:24.628Z | 2026-11-03T13:43:26.630Z |
| proxy-firewall-benchmark-loadclient-run-f0ff0c97a91b | 23 | 212.630 | 53.580 | 2048.000 | 11.000 | 2026-11-03T13:40:29.129Z | 2026-11-03T13:40:40.130Z |
| proxy-firewall-benchmark-loadclient-run-f8a6bbea5253 | 4 | 369.330 | 22.020 | 2048.000 | 11.000 | 2026-11-03T13:43:28.629Z | 2026-11-03T13:43:30.129Z |
| proxy-firewall-benchmark-loadclient-run-fb6b42277ac0 | 23 | 230.690 | 52.970 | 2048.000 | 11.000 | 2026-11-03T13:38:38.629Z | 2026-11-03T13:38:49.629Z |
CPU percentages are Docker's raw values (multiple cores may exceed 100%). Memory is Docker's displayed MemUsage, not process RSS. Sample maxima do not establish an unsampled peak or memory stability.

Admin cumulative/gauge ranges

| metric | samples | min | max |
| --- | --- | --- | --- |
| totals.requests | 385 | 0 | 44782829 |
| totals.inflight | 385 | 0 | 1024 |
| totals.rejected | 385 | 0 | 976812 |
| totals.errors_5xx | 385 | 0 | 0 |
| totals.tracked_hosts | 385 | 0 | 1 |
| totals.untracked_requests | 385 | 0 | 0 |
| totals.capacity | 385 | 10000 | 10000 |
| runtime.uptime_seconds | 385 | 1.166 | 802.746 |
| runtime.goroutines | 385 | 11 | 1038 |
| runtime.heap_allocated_bytes | 385 | 1877792 | 120165000 |
| runtime.heap_in_use_bytes | 385 | 2924544 | 135913472 |
| runtime.stack_bytes | 385 | 458752 | 14123008 |
| runtime.system_bytes | 385 | 12802312 | 180115752 |
| runtime.gc_count | 385 | 0 | 28634 |
| runtime.gc_pause_total_ns | 385 | 0 | 1607823369 |
Admin totals include warmup and other proxy traffic; they are not asserted equal to measured case counts. runtime.system_bytes is Go runtime memory, not RSS.

Soak window https-soak-c1024: 2026-11-03T13:49:59.982Z to 2026-11-03T13:50:59.993Z (60.011s, measured elapsed including drain).

Soak sample coverage

| case | target_group | source | samples_in_window | sample_span_s | sample_span_pct | leading_gap_s | trailing_gap_s | max_gap_with_edges_s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| https-soak-c1024 | firewall | docker:proxy-firewall-benchmark-backend-1 | 120 | 59.500 | 99.148 | 0.147 | 0.365 | 0.501 |
| https-soak-c1024 | firewall | docker:proxy-firewall-benchmark-firewall-1 | 120 | 59.500 | 99.148 | 0.147 | 0.365 | 0.501 |
| https-soak-c1024 | firewall | docker:proxy-firewall-benchmark-loadclient-run-904d1dda08df | 120 | 59.500 | 99.148 | 0.147 | 0.365 | 0.501 |
| https-soak-c1024 | firewall | admin | 29 | 58.650 | 97.732 | 0.739 | 0.622 | 2.101 |
Coverage is the first-to-last sample span within each case window, not continuous observation. Gaps include window boundaries; zero samples cannot support soak resource claims.
