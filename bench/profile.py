#!/usr/bin/env python3
"""Capture coordinated CPU/allocation profiles during an isolated HTTP run."""
import concurrent.futures
import os
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "bench/results"
COMPOSE = ["docker", "compose", "-f", str(ROOT / "bench/compose.yaml")]


def main():
    RESULTS.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["BENCH_RESULTS_DIR"] = str(RESULTS)
    with (RESULTS / "profile-after-run.log").open("w") as output:
        load = subprocess.Popen(COMPOSE + ["run", "--rm", "--no-deps", "loadclient", "load",
            "--url", "http://firewall:8080/bench", "--concurrency", "256", "--duration", "20s",
            "--warmup", "2s", "--json", "/results/http-profile-after.json"],
            cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        time.sleep(5)
        identifier = subprocess.check_output(COMPOSE + ["ps", "-q", "firewall"], cwd=ROOT, text=True).strip()

        def profile(kind, endpoint):
            temporary = "/tmp/pf-after-" + kind + ".pprof"
            subprocess.run(["docker", "exec", identifier, "wget", "-q", "-O", temporary,
                "http://127.0.0.1:8068/debug/pprof/" + endpoint + "?seconds=10"], check=True)
            target = RESULTS / ("http-after-" + kind + ".pprof")
            subprocess.run(["docker", "cp", identifier + ":" + temporary, str(target)], check=True)
            flags = ["-top", "-alloc_space"] if kind == "allocs" else ["-top"]
            with target.with_suffix(".txt").open("w") as report:
                subprocess.run(["go", "tool", "pprof"] + flags + [str(target)], stdout=report, check=True)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = [pool.submit(profile, "cpu", "profile"), pool.submit(profile, "allocs", "allocs")]
                for result in results:
                    result.result()
            if load.wait(timeout=40):
                raise SystemExit("profile load failed; inspect profile-after-run.log")
        finally:
            if load.poll() is None:
                load.terminate()
                load.wait(timeout=10)


if __name__ == "__main__":
    main()
