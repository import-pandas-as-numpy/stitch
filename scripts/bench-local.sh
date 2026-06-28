#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${STITCH_BENCH_PROFILE:-release}"
REPETITIONS="${STITCH_BENCH_REPETITIONS:-1000}"
OUT_DIR="${STITCH_BENCH_OUT_DIR:-$ROOT/target/benchmarks}"
TIME_BIN="${STITCH_BENCH_TIME:-/usr/bin/time}"

case "$PROFILE" in
  dev)
    TARGET_DIR="$ROOT/target/debug"
    CARGO_PROFILE_ARGS=()
    ;;
  *)
    TARGET_DIR="$ROOT/target/$PROFILE"
    CARGO_PROFILE_ARGS=(--profile "$PROFILE")
    ;;
esac

BIN="$TARGET_DIR/stitch"
PATH_LIST="$OUT_DIR/repeated-fixtures.txt"
REPORT="$OUT_DIR/report.md"

mkdir -p "$OUT_DIR"

if [[ ! -x "$TIME_BIN" ]]; then
  echo "time binary not found or not executable: $TIME_BIN" >&2
  exit 1
fi

cd "$ROOT"

cargo build "${CARGO_PROFILE_ARGS[@]}"

: > "$PATH_LIST"
for _ in $(seq 1 "$REPETITIONS"); do
  printf '%s\n' \
    tests/fixtures/evtx/security-auth.evtx \
    tests/fixtures/evtx/sysmon-activity.evtx \
    tests/fixtures/evtx/wmi-activity.evtx \
    tests/fixtures/evtx/task-scheduler-operational.evtx \
    tests/fixtures/evtx/defender-operational.evtx \
    tests/fixtures/evtx/system-services.evtx \
    tests/fixtures/evtx/powershell-activity.evtx \
    >> "$PATH_LIST"
done

{
  echo "# Stitch Local Benchmark Report"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  echo "Profile: \`$PROFILE\`"
  echo
  echo "Binary: \`$BIN\`"
  echo
  echo "Path list: \`$PATH_LIST\`"
  echo
  echo "Fixture repetitions: \`$REPETITIONS\`"
  echo
  echo "Scenarios use the local built binary directly, not \`stitch\` from \`PATH\`."
  echo
  echo "| Scenario | Jobs | real | user | sys |"
  echo "| --- | ---: | ---: | ---: | ---: |"
} > "$REPORT"

run_case() {
  local label="$1"
  local jobs="$2"
  shift 2

  local slug
  slug="$(printf '%s-j%s' "$label" "$jobs" | tr '[:upper:] /' '[:lower:]--')"
  local time_file="$OUT_DIR/$slug.time"
  local stdout_file="$OUT_DIR/$slug.stdout"
  local stderr_file="$OUT_DIR/$slug.stderr"

  if ! "$TIME_BIN" -p -o "$time_file" "$@" > "$stdout_file" 2> "$stderr_file"; then
    echo "benchmark failed: $label jobs=$jobs" >&2
    echo "stderr:" >&2
    cat "$stderr_file" >&2
    exit 1
  fi

  local real user sys
  real="$(awk '$1 == "real" { print $2 }' "$time_file")"
  user="$(awk '$1 == "user" { print $2 }' "$time_file")"
  sys="$(awk '$1 == "sys" { print $2 }' "$time_file")"

  printf '| %s | %s | %s | %s | %s |\n' "$label" "$jobs" "$real" "$user" "$sys" >> "$REPORT"
}

for jobs in 1 4; do
  run_case "dump csv projected" "$jobs" \
    "$BIN" -j "$jobs" --paths-from "$PATH_LIST" \
    dump --format csv \
    --fields timestamp \
    --fields event.id \
    --fields computer \
    --output "$OUT_DIR/dump-j$jobs.csv"

  run_case "search metadata filter quiet" "$jobs" \
    "$BIN" -j "$jobs" --paths-from "$PATH_LIST" --quiet \
    search --query 'event.id >= 0' --format jsonl

  run_case "hunt non-correlation quiet" "$jobs" \
    "$BIN" -j "$jobs" --paths-from "$PATH_LIST" --quiet \
    hunt --rules tests/fixtures/sigma --format jsonl
done

run_case "hunt correlation quiet" 1 \
  "$BIN" -j 1 -i tests/fixtures/correlation-evtx/sysmon-correlation.evtx --quiet \
  hunt --rules tests/fixtures/sigma-correlation --format jsonl

echo "benchmark report written to $REPORT"
