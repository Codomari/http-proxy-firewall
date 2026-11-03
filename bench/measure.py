#!/usr/bin/env python3
"""Run the local matrix while recording container resource samples and metadata."""
import datetime
import base64
import hashlib
import json
import os
import argparse
from pathlib import Path
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
RESULTS = Path(os.environ.get("BENCH_RESULTS_DIR", ROOT / "bench/results/v0.3.4"))
COMPOSE = ["docker", "compose", "-f", str(ROOT / "bench/compose.yaml")]


def capture(command):
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
    return result.stdout.strip() if result.returncode == 0 else None


def collect_resources(stop):
    while not stop.is_set():
        running = capture(COMPOSE + ["ps", "--status", "running", "-q", "firewall"])
        if running:
            break
        stop.wait(0.5)
    if stop.is_set():
        return
    process = subprocess.Popen(["docker", "stats", "--no-trunc", "--format", "{{json .}}"], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    def finish():
        stop.wait()
        process.terminate()
    terminator = threading.Thread(target=finish, daemon=True)
    terminator.start()
    try:
        with (RESULTS / "docker-stats.jsonl").open("w") as output:
            for line in process.stdout:
                try:
                    first, last = line.find("{"), line.rfind("}")
                    if first < 0 or last < first:
                        continue
                    sample = json.loads(line[first:last + 1])
                except json.JSONDecodeError:
                    continue
                if not sample.get("Name", "").startswith("proxy-firewall-benchmark-"):
                    continue
                sample["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                output.write(json.dumps(sample) + "\n")
                output.flush()
    finally:
        process.terminate()
        process.wait(timeout=10)


def collect_admin(stop):
    """Poll the same authenticated endpoint used by the dashboard under load."""
    with (RESULTS / "admin-samples.jsonl").open("w") as output:
        while not stop.is_set():
            raw = capture(COMPOSE + ["exec", "-T", "firewall", "wget", "-q", "-O", "-",
                "--header", "Authorization: Basic " + base64.b64encode((ROOT / ".creds.example").read_text().strip().encode()).decode(),
                "http://127.0.0.1:8080/__pf/__admin/api/overview"])
            if raw:
                try:
                    sample = json.loads(raw)
                    sample["sample_timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    output.write(json.dumps(sample) + "\n")
                    output.flush()
                except (json.JSONDecodeError, TypeError):
                    pass
            stop.wait(2)


def metadata():
    raw = capture(["docker", "info", "--format", "{{json .}}"])
    info = json.loads(raw) if raw else {}
    result = {key: info.get(key) for key in ("NCPU", "MemTotal", "Architecture", "OSType", "OperatingSystem", "ServerVersion", "KernelVersion")}
    result["timestamp_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result["version"] = (ROOT / "VERSION").read_text().strip()
    result["host_go_version"] = capture(["go", "version"])
    sources = set(ROOT.rglob("*.go")) | set((ROOT / "internal/admin/assets").glob("*"))
    sources.update(ROOT / name for name in ("go.mod", "go.sum", "Dockerfile", "bench/Dockerfile", "bench/compose.yaml", "bench/run.sh", "bench/measure.py", "VERSION", "version.go", "proxy-firewall.default.yaml"))
    result["source_sha256"] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(sources) if p.is_file()}
    result["containers"] = {}
    for name in ("firewall", "backend"):
        identifier = capture(COMPOSE + ["ps", "-q", name])
        raw = capture(["docker", "inspect", identifier]) if identifier else None
        if not raw:
            continue
        container = json.loads(raw)[0]
        host = container["HostConfig"]
        details = {"image": container["Image"], "state": container["State"], "cpu_limit": host.get("NanoCpus", 0) / 1e9, "memory_limit_bytes": host.get("Memory"), "pids_limit": host.get("PidsLimit"), "ulimits": host.get("Ulimits")}
        for filename in ("memory.peak", "memory.current", "cpu.stat", "pids.peak"):
            details[filename] = capture(["docker", "exec", identifier, "cat", "/sys/fs/cgroup/" + filename])
        result["containers"][name] = details
    (RESULTS / "environment.json").write_text(json.dumps(result, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect-only", action="store_true")
    parser.add_argument("--seconds", type=float, default=60)
    args = parser.parse_args()
    RESULTS.mkdir(parents=True, exist_ok=True)
    if args.collect_only:
        stop = threading.Event()
        timer = threading.Timer(args.seconds, stop.set)
        timer.start()
        try:
            collect_resources(stop)
            metadata()
        finally:
            stop.set()
            timer.cancel()
        return 0
    env = os.environ.copy()
    env["BENCH_RESULTS_DIR"] = str(RESULTS)
    stop = threading.Event()
    collector = threading.Thread(target=collect_resources, args=(stop,), daemon=True)
    admin_collector = threading.Thread(target=collect_admin, args=(stop,), daemon=True)
    collector.start()
    admin_collector.start()
    try:
        with (RESULTS / "runner.log").open("w") as output:
            process = subprocess.Popen([str(ROOT / "bench/run.sh")], cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in process.stdout:
                output.write(line)
                output.flush()
                if line.startswith(("Running ", "Artifacts:", "benchmark:")):
                    print(line, end="", flush=True)
            status = process.wait()
        metadata()
    finally:
        stop.set()
        collector.join(timeout=15)
        admin_collector.join(timeout=15)
    samples = RESULTS / "docker-stats.jsonl"
    if not samples.exists() or samples.stat().st_size == 0:
        raise SystemExit("resource sampling produced no data; inspect Docker stats before trusting resource claims")
    samples = RESULTS / "admin-samples.jsonl"
    if not samples.exists() or samples.stat().st_size == 0:
        raise SystemExit("admin sampling produced no data; inspect the enabled admin API")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
