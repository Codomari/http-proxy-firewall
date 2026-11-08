Results: bench/results/20261108T230101Z-v0.3.39-working-tree

Measured cases

| case | target_group | RPS | p99_ms | requests | failed_requests | observed_4xx |
| --- | --- | --- | --- | --- | --- | --- |
| backend-get-c1024 | backend-direct | 96608.183 | 15.204 | 1450116 | 0 | 0 |
| http-form-c1024-r1 | firewall | 68073.514 | 23.331 | 1021859 | 0 | 0 |
| http-form-c1024-r2 | firewall | 67823.538 | 23.331 | 1018082 | 0 | 0 |
| http-form-c1024-r3 | firewall | 67508.558 | 23.855 | 1013370 | 0 | 0 |
| http-form-c256-r1 | firewall | 79228.771 | 6.881 | 1188627 | 0 | 0 |
| http-form-c256-r2 | firewall | 78925.089 | 7.012 | 1184047 | 0 | 0 |
| http-form-c256-r3 | firewall | 78798.781 | 7.143 | 1182163 | 0 | 0 |
| http-form-c64-r1 | firewall | 78775.605 | 2.720 | 1181654 | 0 | 0 |
| http-form-c64-r2 | firewall | 79589.592 | 2.589 | 1193871 | 0 | 0 |
| http-form-c64-r3 | firewall | 79318.184 | 2.621 | 1189807 | 0 | 0 |
| http-get-c1024-r1 | firewall | 79767.258 | 19.399 | 1197235 | 0 | 0 |
| http-get-c1024-r2 | firewall | 78512.166 | 19.399 | 1178369 | 0 | 0 |
| http-get-c1024-r3 | firewall | 77255.055 | 20.447 | 1159524 | 0 | 0 |
| http-get-c256-r1 | firewall | 97567.062 | 5.439 | 1463685 | 0 | 0 |
| http-get-c256-r2 | firewall | 97239.179 | 5.439 | 1458745 | 0 | 0 |
| http-get-c256-r3 | firewall | 96727.280 | 5.505 | 1451056 | 0 | 0 |
| http-get-c64-r1 | firewall | 98874.698 | 1.638 | 1483173 | 0 | 0 |
| http-get-c64-r2 | firewall | 98221.963 | 1.655 | 1473377 | 0 | 0 |
| http-get-c64-r3 | firewall | 97369.185 | 1.671 | 1460587 | 0 | 0 |
| http-mixed15-c256 | firewall | 83336.548 | 7.340 | 1250292 | 0 | 187572 |
| http-multipart-c1024-r1 | firewall | 22916.143 | 69.206 | 344337 | 0 | 0 |
| http-multipart-c1024-r2 | firewall | 22650.360 | 69.206 | 340323 | 0 | 0 |
| http-multipart-c1024-r3 | firewall | 22725.772 | 62.915 | 341554 | 0 | 0 |
| http-multipart-c256-r1 | firewall | 22210.893 | 22.544 | 333283 | 0 | 0 |
| http-multipart-c256-r2 | firewall | 22193.589 | 22.282 | 333056 | 0 | 0 |
| http-multipart-c256-r3 | firewall | 22214.903 | 22.282 | 333332 | 0 | 0 |
| http-multipart-c64-r1 | firewall | 21490.409 | 6.488 | 322412 | 0 | 0 |
| http-multipart-c64-r2 | firewall | 21842.664 | 6.685 | 327663 | 0 | 0 |
| http-multipart-c64-r3 | firewall | 22176.464 | 6.554 | 332668 | 0 | 0 |
| http-reject-encoded-c64 | firewall | 65985.600 | 2.097 | 197991 | 0 | 197991 |
| http-reject-get-body-c64 | firewall | 66524.050 | 2.048 | 199654 | 0 | 199654 |
| http-reject-malformed-multipart-c64 | firewall | 65948.758 | 2.195 | 197896 | 0 | 197896 |
| http-reject-progress-c64 | firewall | 59820.250 | 2.621 | 179522 | 0 | 179522 |
| https-form-c1024-r1 | firewall | 56768.804 | 28.312 | 852212 | 0 | 0 |
| https-form-c1024-r2 | firewall | 56299.805 | 29.098 | 845208 | 0 | 0 |
| https-form-c1024-r3 | firewall | 56556.671 | 30.409 | 849493 | 0 | 0 |
| https-form-c256-r1 | firewall | 66322.279 | 9.306 | 995017 | 0 | 0 |
| https-form-c256-r2 | firewall | 65200.203 | 9.568 | 978192 | 0 | 0 |
| https-form-c256-r3 | firewall | 65194.120 | 9.699 | 978094 | 0 | 0 |
| https-form-c64-r1 | firewall | 69913.225 | 3.113 | 1048742 | 0 | 0 |
| https-form-c64-r2 | firewall | 70900.013 | 3.080 | 1063547 | 0 | 0 |
| https-form-c64-r3 | firewall | 68772.009 | 3.113 | 1031645 | 0 | 0 |
| https-get-c1024-r1 | firewall | 68108.679 | 23.855 | 1022370 | 0 | 0 |
| https-get-c1024-r2 | firewall | 67265.437 | 24.642 | 1009677 | 0 | 0 |
| https-get-c1024-r3 | firewall | 66793.560 | 25.166 | 1002625 | 0 | 0 |
| https-get-c256-r1 | firewall | 79931.708 | 7.078 | 1199171 | 0 | 0 |
| https-get-c256-r2 | firewall | 79202.279 | 7.274 | 1188230 | 0 | 0 |
| https-get-c256-r3 | firewall | 79290.155 | 7.078 | 1189546 | 0 | 0 |
| https-get-c64-r1 | firewall | 80417.290 | 2.556 | 1206309 | 0 | 0 |
| https-get-c64-r2 | firewall | 79988.562 | 2.589 | 1199872 | 0 | 0 |
| https-get-c64-r3 | firewall | 80421.508 | 2.523 | 1206371 | 0 | 0 |
| https-mixed15-c256 | firewall | 36301.047 | 16.646 | 544745 | 0 | 81783 |
| https-multipart-c1024-r1 | firewall | 20316.391 | 66.585 | 305358 | 0 | 0 |
| https-multipart-c1024-r2 | firewall | 19952.883 | 66.060 | 299750 | 0 | 0 |
| https-multipart-c1024-r3 | firewall | 20133.983 | 66.585 | 302645 | 0 | 0 |
| https-multipart-c256-r1 | firewall | 19406.622 | 24.904 | 291270 | 0 | 0 |
| https-multipart-c256-r2 | firewall | 19194.970 | 25.428 | 288043 | 0 | 0 |
| https-multipart-c256-r3 | firewall | 19092.102 | 25.690 | 286523 | 0 | 0 |
| https-multipart-c64-r1 | firewall | 17968.095 | 9.044 | 269563 | 0 | 0 |
| https-multipart-c64-r2 | firewall | 17992.821 | 8.913 | 269903 | 0 | 0 |
| https-multipart-c64-r3 | firewall | 19102.824 | 8.192 | 286562 | 0 | 0 |
| https-overload-c4096 | firewall | 96208.368 | 111.149 | 1450387 | 1020520 | 0 |
| https-reject-encoded-c64 | firewall | 10169.122 | 12.714 | 30562 | 0 | 30562 |
| https-reject-get-body-c64 | firewall | 10068.054 | 13.238 | 30243 | 0 | 30243 |
| https-reject-malformed-multipart-c64 | firewall | 10162.967 | 12.845 | 30534 | 0 | 30534 |
| https-reject-progress-c64 | firewall | 9918.952 | 13.107 | 29821 | 0 | 29821 |
| https-slow50ms-c1024 | firewall | 19143.072 | 63.963 | 288029 | 0 | 0 |
| https-soak-c1024 | firewall | 65175.399 | 26.214 | 3911290 | 0 | 0 |

Aggregate measured counts (backend-direct is separate from firewall)

| target_group | cases | requests | known_failed_requests | cases_missing_failure_count | observed_4xx | configured_rejection_attempts | origin_responses | warmup_requests_separate | success_false_cases |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| backend-direct | 1 | 1450116 | 0 | 0 | 0 | 0 | 1450116 | 198024 | 0 |
| firewall | 67 | 55314763 | 1020520 | 0 | 1165578 | 1165578 | 53128665 | 9051642 | 1 |
Failures are the load tool's unique failed_requests, unchanged; error-category counts are not summed. Observed 4xx are separate outcomes and can be expected for rejection/mixed workloads. Nonzero failures are never reclassified as passing. No pooled RPS or latency is inferred.

Resource sample counts and ranges

| source | rows | timestamped_rows | first_utc | last_utc | ignored_invalid_lines |
| --- | --- | --- | --- | --- | --- |
| docker-stats | 6565 | 6565 | 2026-11-08T23:01:32.572Z | 2026-11-08T23:20:00.570Z | 0 |
| admin-samples | 533 | 533 | 2026-11-08T23:01:32.331Z | 2026-11-08T23:20:00.326Z | 0 |

Per-container observed sample peaks

| container | samples | peak_cpu_pct | peak_mem_usage_MiB | largest_mem_limit_MiB | peak_pids | first_utc | last_utc |
| --- | --- | --- | --- | --- | --- | --- | --- |
| proxy-firewall-benchmark-20261108t230101z-backend-1 | 2217 | 100.150 | 124.300 | 512.000 | 13.000 | 2026-11-08T23:01:32.572Z | 2026-11-08T23:20:00.570Z |
| proxy-firewall-benchmark-20261108t230101z-firewall-1 | 2217 | 204.640 | 626.600 | 1024.000 | 15.000 | 2026-11-08T23:01:32.572Z | 2026-11-08T23:20:00.570Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-02906564406f | 34 | 201.930 | 149.800 | 2048.000 | 10.000 | 2026-11-08T23:09:00.573Z | 2026-11-08T23:09:17.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-04e48062b288 | 33 | 206.750 | 141.700 | 2048.000 | 10.000 | 2026-11-08T23:08:43.573Z | 2026-11-08T23:08:59.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-04e751eb0678 | 31 | 215.850 | 155.100 | 2048.000 | 11.000 | 2026-11-08T23:01:32.572Z | 2026-11-08T23:01:47.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-0980ebc7445e | 34 | 227.900 | 55.730 | 2048.000 | 11.000 | 2026-11-08T23:02:57.571Z | 2026-11-08T23:03:14.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-0bac189d91be | 34 | 207.910 | 147.100 | 2048.000 | 11.000 | 2026-11-08T23:04:06.571Z | 2026-11-08T23:04:23.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-139629b4a49b | 32 | 206.730 | 53.480 | 2048.000 | 11.000 | 2026-11-08T23:13:51.572Z | 2026-11-08T23:14:07.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-197bbad3a984 | 33 | 202.600 | 21.960 | 2048.000 | 10.000 | 2026-11-08T23:07:17.074Z | 2026-11-08T23:07:33.074Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-1c1b0abaff51 | 35 | 206.930 | 166.200 | 2048.000 | 11.000 | 2026-11-08T23:12:24.071Z | 2026-11-08T23:12:41.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-1cac8b3fa41b | 33 | 209.880 | 25.820 | 2048.000 | 11.000 | 2026-11-08T23:10:06.071Z | 2026-11-08T23:10:22.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-223745546de2 | 34 | 187.960 | 177.700 | 2048.000 | 11.000 | 2026-11-08T23:14:25.571Z | 2026-11-08T23:14:42.070Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-2251b0bcd5f6 | 6 | 349.970 | 22.680 | 2048.000 | 11.000 | 2026-11-08T23:09:38.573Z | 2026-11-08T23:09:41.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-26da5f987de1 | 33 | 206.540 | 25.260 | 2048.000 | 10.000 | 2026-11-08T23:12:59.572Z | 2026-11-08T23:13:15.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-27af60505131 | 34 | 195.990 | 160.600 | 2048.000 | 11.000 | 2026-11-08T23:15:00.571Z | 2026-11-08T23:15:17.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-2f0267a214eb | 33 | 205.350 | 141.600 | 2048.000 | 11.000 | 2026-11-08T23:06:25.072Z | 2026-11-08T23:06:41.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-3975fb99a33a | 34 | 205.440 | 23.210 | 2048.000 | 10.000 | 2026-11-08T23:15:35.071Z | 2026-11-08T23:15:51.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-4b7a39bb0e5f | 33 | 216.800 | 54.920 | 2048.000 | 11.000 | 2026-11-08T23:05:16.072Z | 2026-11-08T23:05:32.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-4cd54576be42 | 35 | 207.420 | 165.700 | 2048.000 | 11.000 | 2026-11-08T23:17:36.071Z | 2026-11-08T23:17:53.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-5ec66286ee7b | 32 | 219.570 | 22.210 | 2048.000 | 11.000 | 2026-11-08T23:02:06.571Z | 2026-11-08T23:02:22.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-6451caf9bb64 | 34 | 213.310 | 50.060 | 2048.000 | 11.000 | 2026-11-08T23:08:08.574Z | 2026-11-08T23:08:25.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-64e824f6bfdd | 5 | 363.140 | 24.660 | 2048.000 | 11.000 | 2026-11-08T23:09:45.573Z | 2026-11-08T23:09:47.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-6abc1ece04e5 | 34 | 216.890 | 52.920 | 2048.000 | 11.000 | 2026-11-08T23:05:33.072Z | 2026-11-08T23:05:49.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-6c00c91a432f | 33 | 231.010 | 22.650 | 2048.000 | 11.000 | 2026-11-08T23:02:23.572Z | 2026-11-08T23:02:39.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-7613bf6ed575 | 6 | 304.380 | 25.960 | 2048.000 | 10.000 | 2026-11-08T23:17:57.070Z | 2026-11-08T23:17:59.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-7db51f35b267 | 33 | 205.030 | 22.130 | 2048.000 | 10.000 | 2026-11-08T23:07:34.574Z | 2026-11-08T23:07:50.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-80b6d3b94d3a | 33 | 203.780 | 22.780 | 2048.000 | 11.000 | 2026-11-08T23:13:16.572Z | 2026-11-08T23:13:32.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-82e8c0004cfb | 5 | 298.590 | 25.230 | 2048.000 | 10.000 | 2026-11-08T23:18:01.070Z | 2026-11-08T23:18:03.070Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-85dfc52b6092 | 33 | 221.680 | 51.430 | 2048.000 | 10.000 | 2026-11-08T23:07:51.574Z | 2026-11-08T23:08:07.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-8b12c9e5a638 | 32 | 204.260 | 22.430 | 2048.000 | 11.000 | 2026-11-08T23:10:41.073Z | 2026-11-08T23:10:56.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-902cf2ebdc47 | 6 | 366.730 | 23.680 | 2048.000 | 11.000 | 2026-11-08T23:09:41.573Z | 2026-11-08T23:09:44.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-90e532f03d53 | 34 | 216.640 | 50.800 | 2048.000 | 11.000 | 2026-11-08T23:05:50.072Z | 2026-11-08T23:06:06.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-93abe40d5f7d | 33 | 204.420 | 52.500 | 2048.000 | 10.000 | 2026-11-08T23:16:27.071Z | 2026-11-08T23:16:43.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a12c5845fe83 | 33 | 181.410 | 172.200 | 2048.000 | 10.000 | 2026-11-08T23:17:02.070Z | 2026-11-08T23:17:18.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a2f56ccba856 | 33 | 213.340 | 152.100 | 2048.000 | 11.000 | 2026-11-08T23:03:32.572Z | 2026-11-08T23:03:48.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a3e805624b2d | 33 | 200.110 | 23.350 | 2048.000 | 11.000 | 2026-11-08T23:12:42.073Z | 2026-11-08T23:12:58.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a5433ba40f86 | 33 | 213.920 | 143.400 | 2048.000 | 11.000 | 2026-11-08T23:03:49.572Z | 2026-11-08T23:04:05.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a75bff8832b6 | 33 | 77.650 | 155.400 | 2048.000 | 10.000 | 2026-11-08T23:18:25.571Z | 2026-11-08T23:18:41.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a80bbf6160bc | 34 | 200.860 | 23.960 | 2048.000 | 11.000 | 2026-11-08T23:15:17.570Z | 2026-11-08T23:15:34.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-a993d8db906e | 33 | 210.010 | 55.770 | 2048.000 | 11.000 | 2026-11-08T23:10:58.072Z | 2026-11-08T23:11:14.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-ab709fd55830 | 5 | 306.760 | 25.370 | 2048.000 | 10.000 | 2026-11-08T23:17:54.071Z | 2026-11-08T23:17:56.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-ac4744839847 | 32 | 203.400 | 21.950 | 2048.000 | 11.000 | 2026-11-08T23:04:59.072Z | 2026-11-08T23:05:14.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-acad9dd519da | 34 | 208.290 | 55.360 | 2048.000 | 11.000 | 2026-11-08T23:11:15.073Z | 2026-11-08T23:11:31.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-ad908c8baa9d | 34 | 206.560 | 52.230 | 2048.000 | 11.000 | 2026-11-08T23:11:32.072Z | 2026-11-08T23:11:48.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-ae4988aba85e | 33 | 199.350 | 49.510 | 2048.000 | 12.000 | 2026-11-08T23:14:08.571Z | 2026-11-08T23:14:24.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-b088020edc78 | 32 | 281.060 | 633.000 | 2048.000 | 11.000 | 2026-11-08T23:19:44.570Z | 2026-11-08T23:20:00.070Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-b08e43fc3f9c | 34 | 230.070 | 51.570 | 2048.000 | 11.000 | 2026-11-08T23:03:14.572Z | 2026-11-08T23:03:31.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-b2e81d7a109f | 33 | 198.420 | 164.000 | 2048.000 | 11.000 | 2026-11-08T23:11:50.071Z | 2026-11-08T23:12:06.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-b7e58ff08597 | 32 | 204.590 | 25.810 | 2048.000 | 11.000 | 2026-11-08T23:15:53.071Z | 2026-11-08T23:16:08.570Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-b827116479ea | 34 | 270.130 | 53.900 | 2048.000 | 11.000 | 2026-11-08T23:09:48.573Z | 2026-11-08T23:10:05.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-b9c588c57e33 | 33 | 197.830 | 161.700 | 2048.000 | 10.000 | 2026-11-08T23:14:43.571Z | 2026-11-08T23:14:59.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-be67ea9072ec | 34 | 197.690 | 168.700 | 2048.000 | 11.000 | 2026-11-08T23:12:07.073Z | 2026-11-08T23:12:23.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-c80ddc0955a3 | 33 | 195.260 | 20.210 | 2048.000 | 11.000 | 2026-11-08T23:07:00.074Z | 2026-11-08T23:07:16.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-cc10b14d8728 | 34 | 193.790 | 160.000 | 2048.000 | 10.000 | 2026-11-08T23:17:19.071Z | 2026-11-08T23:17:35.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-d05c58efd8da | 34 | 209.450 | 51.420 | 2048.000 | 10.000 | 2026-11-08T23:13:33.571Z | 2026-11-08T23:13:50.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-d3807ff8904d | 6 | 299.860 | 24.620 | 2048.000 | 10.000 | 2026-11-08T23:18:04.071Z | 2026-11-08T23:18:06.570Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-d49a1e083147 | 34 | 226.350 | 23.840 | 2048.000 | 11.000 | 2026-11-08T23:01:48.572Z | 2026-11-08T23:02:05.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-d4ebc1013917 | 34 | 206.930 | 48.870 | 2048.000 | 11.000 | 2026-11-08T23:16:44.070Z | 2026-11-08T23:17:00.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-da0e9b8fda3f | 34 | 266.470 | 56.760 | 2048.000 | 11.000 | 2026-11-08T23:18:07.071Z | 2026-11-08T23:18:23.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e06519d42e5e | 33 | 202.130 | 144.900 | 2048.000 | 10.000 | 2026-11-08T23:06:08.073Z | 2026-11-08T23:06:24.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e16e114cd42a | 33 | 234.980 | 53.080 | 2048.000 | 11.000 | 2026-11-08T23:02:40.572Z | 2026-11-08T23:02:56.572Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e2ab653ec055 | 34 | 200.660 | 141.600 | 2048.000 | 11.000 | 2026-11-08T23:09:17.573Z | 2026-11-08T23:09:34.073Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e3cffa7f6e00 | 5 | 360.610 | 22.150 | 2048.000 | 11.000 | 2026-11-08T23:09:35.573Z | 2026-11-08T23:09:37.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e4c4b2d6bbc6 | 34 | 206.640 | 141.600 | 2048.000 | 11.000 | 2026-11-08T23:06:42.073Z | 2026-11-08T23:06:58.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e704740e4409 | 33 | 208.550 | 52.570 | 2048.000 | 11.000 | 2026-11-08T23:16:10.071Z | 2026-11-08T23:16:26.071Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-e8920a25b690 | 124 | 196.390 | 179.300 | 2048.000 | 11.000 | 2026-11-08T23:18:42.571Z | 2026-11-08T23:19:44.070Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-ec6270505816 | 34 | 205.290 | 23.130 | 2048.000 | 11.000 | 2026-11-08T23:04:23.571Z | 2026-11-08T23:04:40.072Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-fbf1725b01eb | 32 | 205.040 | 23.240 | 2048.000 | 11.000 | 2026-11-08T23:04:42.072Z | 2026-11-08T23:04:57.571Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-fc0c9fe902a3 | 32 | 206.640 | 23.210 | 2048.000 | 12.000 | 2026-11-08T23:10:24.073Z | 2026-11-08T23:10:39.573Z |
| proxy-firewall-benchmark-20261108t230101z-loadclient-run-fcc3a07ba5dc | 32 | 215.230 | 49.070 | 2048.000 | 11.000 | 2026-11-08T23:08:26.573Z | 2026-11-08T23:08:42.074Z |
CPU percentages are Docker's raw values (multiple cores may exceed 100%). Memory is Docker's displayed MemUsage, not process RSS. Sample maxima do not establish an unsampled peak or memory stability.

Admin cumulative/gauge ranges

| metric | samples | min | max |
| --- | --- | --- | --- |
| totals.requests | 533 | 0 | 64366405 |
| totals.inflight | 533 | 0 | 2048 |
| totals.rejected | 533 | 0 | 1165578 |
| totals.errors_5xx | 533 | 0 | 1026943 |
| totals.tracked_hosts | 533 | 0 | 1 |
| totals.untracked_requests | 533 | 0 | 0 |
| totals.capacity | 533 | 10000 | 10000 |
| runtime.uptime_seconds | 533 | 1.763 | 1109.761 |
| runtime.goroutines | 533 | 11 | 4110 |
| runtime.heap_allocated_bytes | 533 | 2467368 | 389280328 |
| runtime.heap_in_use_bytes | 533 | 3997696 | 413679616 |
| runtime.stack_bytes | 533 | 458752 | 49905664 |
| runtime.system_bytes | 533 | 13474056 | 512287096 |
| runtime.gc_count | 533 | 4 | 33133 |
| runtime.gc_pause_total_ns | 533 | 199750 | 3186581556 |
Admin totals include warmup and other proxy traffic; they are not asserted equal to measured case counts. runtime.system_bytes is Go runtime memory, not RSS.

Soak window https-soak-c1024: 2026-11-08T23:18:44.049Z to 2026-11-08T23:19:44.061Z (60.012s, measured elapsed including drain).

Soak sample coverage

| case | target_group | source | samples_in_window | sample_span_s | sample_span_pct | leading_gap_s | trailing_gap_s | max_gap_with_edges_s |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| https-soak-c1024 | firewall | docker:proxy-firewall-benchmark-20261108t230101z-backend-1 | 120 | 59.500 | 99.147 | 0.022 | 0.490 | 0.501 |
| https-soak-c1024 | firewall | docker:proxy-firewall-benchmark-20261108t230101z-firewall-1 | 120 | 59.500 | 99.147 | 0.021 | 0.490 | 0.501 |
| https-soak-c1024 | firewall | docker:proxy-firewall-benchmark-20261108t230101z-loadclient-run-e8920a25b690 | 120 | 59.500 | 99.147 | 0.022 | 0.490 | 0.501 |
| https-soak-c1024 | firewall | admin | 29 | 58.586 | 97.624 | 0.770 | 0.656 | 2.108 |
Coverage is the first-to-last sample span within each case window, not continuous observation. Gaps include window boundaries; zero samples cannot support soak resource claims.
