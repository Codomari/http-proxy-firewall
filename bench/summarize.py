#!/usr/bin/env python3
"""Summarize measured case JSON and sampled resources without reclassifying failures."""

import argparse
from collections import defaultdict
import datetime as dt
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


DEFAULT_RESULTS = Path(__file__).resolve().parent / "results" / "final"
UTC = dt.timezone.utc
REJECTION_WORKLOADS = {"malformed-multipart", "progress", "get-body", "encoded"}


def number(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return value
    return None


def timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(UTC)
    except ValueError:
        return None


def iso(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z") if value else "n/a"


def memory_bytes(value):
    """Parse Docker's displayed used/limit values, preserving decimal/binary units."""
    match = re.fullmatch(r"\s*([\d.]+)\s*([kmgtpe]i?b|b)\s*", str(value), re.I)
    if not match:
        return None
    try:
        amount = float(match[1])
    except ValueError:
        return None
    if not math.isfinite(amount):
        return None
    unit = match[2].lower()
    exponent = "bkmgtpe".index(unit[0]) if unit != "b" else 0
    return amount * (1024 if "i" in unit else 1000) ** exponent


def percentage(value):
    try:
        parsed = float(str(value).removesuffix("%"))
        return parsed if math.isfinite(parsed) else None
    except ValueError:
        return None


def read_jsonl(path):
    rows, ignored = [], 0
    if path.exists():
        with path.open() as source:
            for line in source:
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError("not an object")
                    rows.append(value)
                except (ValueError, json.JSONDecodeError):
                    ignored += 1
    return rows, ignored


def load_cases(directory):
    cases = []
    for path in sorted(directory.glob("*.json")):
        if path.name.endswith(".stdout.json"):
            continue
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError) as error:
            print(f"warning: skipped {path.name}: {error}", file=sys.stderr)
            continue
        if not isinstance(data, dict) or "requests" not in data or not isinstance(data.get("target"), str):
            continue
        if not isinstance(data["requests"], int) or isinstance(data["requests"], bool) or data["requests"] < 0:
            print(f"warning: skipped {path.name}: invalid requests", file=sys.stderr)
            continue
        try:
            hostname = urlsplit(data["target"]).hostname
        except ValueError:
            hostname = None
        role = {"backend": "backend-direct", "firewall": "firewall"}.get(hostname, "other-target")
        cases.append((path.stem, role, data))
    return cases


def count_4xx(data):
    return sum(value for status, value in data.get("status_counts", {}).items()
               if str(status).isdigit() and 400 <= int(status) < 500 and number(value) is not None)


def expected_rejection_attempts(data):
    return sum(value for workload, value in data.get("workload_counts", {}).items()
               if workload in REJECTION_WORKLOADS and number(value) is not None)


def cell(value):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value).replace("\t", " ").replace("\n", "\\n")


def table(title, headers, rows, output_format):
    print(f"\n{title}\n")
    if output_format == "tsv":
        print("\t".join(headers))
        for row in rows:
            print("\t".join(map(cell, row)))
    else:
        print("| " + " | ".join(headers) + " |")
        print("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            print("| " + " | ".join(cell(value).replace("|", "\\|") for value in row) + " |")


def sample_time(row, admin=False):
    keys = ("sample_timestamp_utc", "timestamp") if admin else ("timestamp_utc",)
    return next((parsed for key in keys if (parsed := timestamp(row.get(key))) is not None), None)


def range_row(name, rows, admin, ignored):
    times = sorted(value for row in rows if (value := sample_time(row, admin)) is not None)
    return [name, len(rows), len(times), iso(times[0]) if times else "n/a", iso(times[-1]) if times else "n/a", ignored]


def docker_groups(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[str(row.get("Name") or row.get("Container") or row.get("ID") or "unknown")].append(row)
    return groups


def docker_peaks(rows):
    result = []
    for name, samples in sorted(docker_groups(rows).items()):
        cpu, used, limits, pids = [], [], [], []
        for row in samples:
            if (value := percentage(row.get("CPUPerc"))) is not None:
                cpu.append(value)
            parts = str(row.get("MemUsage", "")).split("/", 1)
            if (value := memory_bytes(parts[0])) is not None:
                used.append(value / (1 << 20))
            if len(parts) == 2 and (value := memory_bytes(parts[1])) is not None:
                limits.append(value / (1 << 20))
            if (value := percentage(row.get("PIDs"))) is not None:
                pids.append(value)
        times = sorted(value for row in samples if (value := sample_time(row)) is not None)
        result.append([name, len(samples), max(cpu, default=None), max(used, default=None), max(limits, default=None), max(pids, default=None), iso(times[0]) if times else "n/a", iso(times[-1]) if times else "n/a"])
    return result


def coverage_rows(name, role, case, docker, admin):
    start = timestamp(case.get("timestamp_utc"))
    elapsed = number(case.get("elapsed_seconds"))
    if start is None or elapsed is None or elapsed <= 0:
        return [[name, role, "invalid case window", 0, None, None, None, None, None]]
    end = start + dt.timedelta(seconds=elapsed)
    groups = []
    for container, samples in sorted(docker_groups(docker).items()):
        times = [value for row in samples if (value := sample_time(row)) is not None]
        # Ephemeral load clients from other cases need no soak coverage.
        if times and min(times) <= end and max(times) >= start:
            groups.append((f"docker:{container}", samples, False))
    if not groups:
        groups.append(("docker:no samples", [], False))
    groups.append(("admin", admin, True))
    result = []
    for source, samples, is_admin in groups:
        times = sorted(value for row in samples if (value := sample_time(row, is_admin)) is not None and start <= value <= end)
        if not times:
            result.append([name, role, source, 0, 0.0, 0.0, None, None, elapsed])
            continue
        span = (times[-1] - times[0]).total_seconds()
        gaps = [(right-left).total_seconds() for left, right in zip([start] + times, times + [end])]
        result.append([name, role, source, len(times), span, 100*span/elapsed, (times[0]-start).total_seconds(), (end-times[-1]).total_seconds(), max(gaps)])
    print(f"\nSoak window {name}: {iso(start)} to {iso(end)} ({elapsed:.3f}s, measured elapsed including drain).")
    return result


def nested_number(row, dotted):
    value = row
    for key in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return number(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", nargs="?", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--format", choices=("markdown", "tsv"), default="markdown")
    args = parser.parse_args()
    if not args.directory.is_dir():
        parser.error(f"result directory does not exist: {args.directory}")
    cases = load_cases(args.directory)
    if not cases:
        parser.error("no case JSON objects with requests and target fields were found")
    print(f"Results: {args.directory}")
    table("Measured cases", ["case", "target_group", "RPS", "p99_ms", "requests", "failed_requests", "observed_4xx"],
          [[name, role, number(data.get("requests_per_second")), number(data.get("latency_all_requests", {}).get("p99_ms")), data["requests"], number(data.get("failed_requests")), count_4xx(data)] for name, role, data in cases], args.format)
    aggregates = []
    for role in sorted({role for _, role, _ in cases}):
        data = [case for _, group, case in cases if group == role]
        aggregates.append([role, len(data), sum(case["requests"] for case in data), sum(number(case.get("failed_requests")) or 0 for case in data), sum(number(case.get("failed_requests")) is None for case in data), sum(count_4xx(case) for case in data), sum(expected_rejection_attempts(case) for case in data), sum(number(case.get("origin_responses")) or 0 for case in data), sum(number(case.get("warmup", {}).get("requests")) or 0 for case in data), sum(case.get("success") is False for case in data)])
    table("Aggregate measured counts (backend-direct is separate from firewall)", ["target_group", "cases", "requests", "known_failed_requests", "cases_missing_failure_count", "observed_4xx", "configured_rejection_attempts", "origin_responses", "warmup_requests_separate", "success_false_cases"], aggregates, args.format)
    print("Failures are the load tool's unique failed_requests, unchanged; error-category counts are not summed. Observed 4xx are separate outcomes and can be expected for rejection/mixed workloads. Nonzero failures are never reclassified as passing. No pooled RPS or latency is inferred.")
    docker, docker_ignored = read_jsonl(args.directory / "docker-stats.jsonl")
    admin, admin_ignored = read_jsonl(args.directory / "admin-samples.jsonl")
    table("Resource sample counts and ranges", ["source", "rows", "timestamped_rows", "first_utc", "last_utc", "ignored_invalid_lines"], [range_row("docker-stats", docker, False, docker_ignored), range_row("admin-samples", admin, True, admin_ignored)], args.format)
    table("Per-container observed sample peaks", ["container", "samples", "peak_cpu_pct", "peak_mem_usage_MiB", "largest_mem_limit_MiB", "peak_pids", "first_utc", "last_utc"], docker_peaks(docker), args.format)
    print("CPU percentages are Docker's raw values (multiple cores may exceed 100%). Memory is Docker's displayed MemUsage, not process RSS. Sample maxima do not establish an unsampled peak or memory stability.")
    metrics = ["totals.requests", "totals.inflight", "totals.rejected", "totals.errors_5xx", "totals.tracked_hosts", "totals.untracked_requests", "totals.capacity", "runtime.uptime_seconds", "runtime.goroutines", "runtime.heap_allocated_bytes", "runtime.heap_in_use_bytes", "runtime.stack_bytes", "runtime.system_bytes", "runtime.gc_count", "runtime.gc_pause_total_ns"]
    admin_ranges = []
    for metric in metrics:
        values = [value for row in admin if (value := nested_number(row, metric)) is not None]
        if values:
            admin_ranges.append([metric, len(values), min(values), max(values)])
    table("Admin cumulative/gauge ranges", ["metric", "samples", "min", "max"], admin_ranges, args.format)
    print("Admin totals include warmup and other proxy traffic; they are not asserted equal to measured case counts. runtime.system_bytes is Go runtime memory, not RSS.")
    coverage = []
    for name, role, case in cases:
        if "soak" in name.lower():
            coverage.extend(coverage_rows(name, role, case, docker, admin))
    table("Soak sample coverage", ["case", "target_group", "source", "samples_in_window", "sample_span_s", "sample_span_pct", "leading_gap_s", "trailing_gap_s", "max_gap_with_edges_s"], coverage, args.format)
    print("Coverage is the first-to-last sample span within each case window, not continuous observation. Gaps include window boundaries; zero samples cannot support soak resource claims.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
