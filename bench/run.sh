#!/bin/sh
# Run only inside the local, isolated Docker benchmark network.
set -eu
BENCH_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export BENCH_RESULTS_DIR=${BENCH_RESULTS_DIR:-"$BENCH_DIR/results/v0.3.4"}
mkdir -p "$BENCH_RESULTS_DIR"
DURATION=${DURATION:-15s}
WARMUP=${WARMUP:-2s}
REPEATS=${REPEATS:-3}
CONCURRENCIES=${CONCURRENCIES:-"64 256 1024"}
SCHEMES=${SCHEMES:-"http https"}
WORKLOADS=${WORKLOADS:-"get form multipart"}
COMPOSE_FILE="$BENCH_DIR/compose.yaml"

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }
if [ "${NO_BUILD:-0}" != 1 ]; then compose build backend firewall; fi
compose up -d backend firewall
printf 'case\texit_status\n' > "$BENCH_RESULTS_DIR/exits.tsv"
BENCH_FAILED=0

run_case() {
  case_name=$1
  shift
  printf 'Running %s\n' "$case_name"
  rc=0
  compose run --rm --no-deps loadclient load "$@" --json "/results/$case_name.json" > "$BENCH_RESULTS_DIR/$case_name.stdout.json" || rc=$?
  printf '%s\t%s\n' "$case_name" "$rc" >> "$BENCH_RESULTS_DIR/exits.tsv"
  if [ "$rc" -ne 0 ]; then
    case "$case_name" in
      *overload*) : ;;
      *) BENCH_FAILED=1 ;;
    esac
  fi
}

# Calibrate the complete load generator + direct origin first.
run_case backend-get-c1024 --url http://backend:8081/bench --concurrency 1024 --duration "$DURATION" --warmup "$WARMUP" --require-challenge=false

for scheme in $SCHEMES; do
  port=8080
  if [ "$scheme" = https ]; then port=8443; fi
  target="$scheme://firewall:$port/bench"
  for workload in $WORKLOADS; do
    for concurrent in $CONCURRENCIES; do
      repeat=1
      while [ "$repeat" -le "$REPEATS" ]; do
        run_case "$scheme-$workload-c$concurrent-r$repeat" --url "$target" --ca /certs/server.crt --workload "$workload" --concurrency "$concurrent" --duration "$DURATION" --warmup "$WARMUP"
        repeat=$((repeat+1))
      done
    done
  done
  for workload in malformed-multipart progress get-body encoded; do
    run_case "$scheme-reject-$workload-c64" --url "$target" --ca /certs/server.crt --workload "$workload" --concurrency 64 --duration "${REJECT_DURATION:-3s}" --warmup 0s
  done
  run_case "$scheme-mixed15-c256" --url "$target" --ca /certs/server.crt --workload mixed --malicious-percent 15 --concurrency 256 --duration "$DURATION" --warmup "$WARMUP"
done

if [ "${SLOW:-1}" = 1 ]; then
  run_case https-slow50ms-c1024 --url https://firewall:8443/bench --path '/bench?delay=50ms' --ca /certs/server.crt --concurrency 1024 --duration "$DURATION" --warmup "$WARMUP"
fi
if [ "${SOAK:-0}" = 1 ]; then
  run_case https-soak-c1024 --url https://firewall:8443/bench --ca /certs/server.crt --concurrency 1024 --duration "${SOAK_DURATION:-60s}" --warmup "$WARMUP"
fi
if [ "${OVERLOAD:-0}" = 1 ]; then
  # Expected to record admission/connection errors; inspect the JSON and stats.
  run_case https-overload-c4096 --url https://firewall:8443/bench --path '/bench?delay=50ms' --ca /certs/server.crt --concurrency 4096 --duration "$DURATION" --warmup 0s --timeout 2s
fi
printf 'Artifacts: %s\n' "$BENCH_RESULTS_DIR"
if [ "$BENCH_FAILED" -ne 0 ]; then
  printf 'One or more required cases failed; inspect exits.tsv and JSON artifacts.\n' >&2
  exit 1
fi
