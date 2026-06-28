# Performance Notes

This page documents Stitch's concurrency behavior and the repeatable benchmark
harness used to compare local changes. Timings here are workload-specific and
should not be treated as universal performance claims.

## Rayon File-Level Parallelism

Rayon is used for file-level parallelism in modes where each input file can be
processed independently and then merged back in discovery order.

Concurrency is the default execution strategy when there is more than one input
file and the mode can be parallelized safely. `--jobs 0`, the CLI default, uses
Rayon's system-sized worker pool. Use `--jobs 1` to force sequential file
processing.

Current parallelized paths:

1. `search` when `--limit` is not set.
2. `dump` for JSONL, JSON, and projected CSV.
3. `hunt` only when correlation is disabled or no correlation rules are loaded.

Sequential paths by design:

1. Single-file input, because current parallelism is file-level.
2. Explicit `--jobs 1`.
3. `search --limit`, because early termination affects scan counts and output.
4. Correlation-enabled `hunt`, because correlation state is event-order and
   watermark sensitive.

Concurrency regression tests use repeated generated fixture paths through
`--paths-from`. They compare `--jobs 1` and `--jobs 4` output under a 10-second
child-process timeout, killing the child process if the timeout is exceeded.

### Fixture Timing Harness

Use the checked-in harness for repeatable fixture timing:

```bash
scripts/bench-local.sh
```

The harness builds the configured local profile, calls the resulting
`target/<profile>/stitch` binary directly, generates a repeated fixture path list
under `target/benchmarks`, and writes `target/benchmarks/report.md`.

Environment controls:

```bash
STITCH_BENCH_PROFILE=release      # default
STITCH_BENCH_REPETITIONS=1000     # default repeated fixture count
STITCH_BENCH_OUT_DIR=target/benchmarks
STITCH_BENCH_TIME=/usr/bin/time
```

For a quick smoke run:

```bash
STITCH_BENCH_PROFILE=dev STITCH_BENCH_REPETITIONS=1 scripts/bench-local.sh
```

When publishing new timing results, include:

1. Date.
2. Command.
3. Dataset.
4. Job count.
5. Wall-clock result.
6. Notes about cache warmth and output destination.

#### 2026-06-28 Repeated Generated Fixtures

Dataset:

1. `/tmp/stitch-rayon-paths.txt`
2. 1,000 repetitions of seven generated EVTX fixture paths.
3. 7,000 file work items total.
4. Commands were run after the binary was already built, using `cargo run --quiet`.
5. These timings include process startup and fixture parser overhead.

Path-list creation:

```bash
for i in {1..1000}; do
  printf '%s\n' \
    tests/fixtures/evtx/security-auth.evtx \
    tests/fixtures/evtx/sysmon-activity.evtx \
    tests/fixtures/evtx/wmi-activity.evtx \
    tests/fixtures/evtx/task-scheduler-operational.evtx \
    tests/fixtures/evtx/defender-operational.evtx \
    tests/fixtures/evtx/system-services.evtx \
    tests/fixtures/evtx/powershell-activity.evtx
done > /tmp/stitch-rayon-paths.txt
```

Dump projected CSV to file:

```bash
command time -p cargo run --quiet -- -j 1 --paths-from /tmp/stitch-rayon-paths.txt dump --format csv --fields timestamp --fields event.id --fields computer --output /tmp/stitch-dump-j1.csv
```

Result: `real 9.02`

```bash
command time -p cargo run --quiet -- -j 4 --paths-from /tmp/stitch-rayon-paths.txt dump --format csv --fields timestamp --fields event.id --fields computer --output /tmp/stitch-dump-j4.csv
```

Result: `real 2.55`

Search all events with quiet output:

```bash
command time -p cargo run --quiet -- -j 1 --paths-from /tmp/stitch-rayon-paths.txt --quiet search --query 'event.id >= 0' --format jsonl
```

Result: `real 8.91`

```bash
command time -p cargo run --quiet -- -j 4 --paths-from /tmp/stitch-rayon-paths.txt --quiet search --query 'event.id >= 0' --format jsonl
```

Result: `real 2.21`

Non-correlation hunt with quiet output:

```bash
command time -p cargo run --quiet -- -j 1 --paths-from /tmp/stitch-rayon-paths.txt --quiet hunt --rules tests/fixtures/sigma --format jsonl
```

Result: `real 8.48`

```bash
command time -p cargo run --quiet -- -j 4 --paths-from /tmp/stitch-rayon-paths.txt --quiet hunt --rules tests/fixtures/sigma --format jsonl
```

Result: `real 2.22`

Summary: on this repeated-fixture workload, `--jobs 4` was roughly 3.5x to 4.0x
faster than `--jobs 1`. This is expected to overstate benefits for tiny input
sets and understate or differ from benefits on large real-world EVTX
collections.

#### 2026-06-28 Quiet Search/Hunt Fast Path

Command:

```bash
STITCH_BENCH_REPETITIONS=1000 scripts/bench-local.sh
```

Change:

1. `search --quiet` without `--stats` or `--limit` scans EVTX records through
   the parser's JSON-byte rendering path instead of materializing
   `serde_json::Value` events and evaluating predicates whose results are not
   observable.
2. Non-correlation `hunt --quiet` without `--stats` uses the same record-scan
   path after rule loading, preserving EVTX open/parse error behavior while
   avoiding match rendering and rule evaluation.

Before:

| Scenario | Jobs | real |
| --- | ---: | ---: |
| dump csv projected | 1 | 0.39 |
| search metadata filter quiet | 1 | 0.38 |
| hunt non-correlation quiet | 1 | 0.39 |
| dump csv projected | 4 | 0.10 |
| search metadata filter quiet | 4 | 0.10 |
| hunt non-correlation quiet | 4 | 0.11 |

After:

| Scenario | Jobs | real |
| --- | ---: | ---: |
| dump csv projected | 1 | 0.38 |
| search metadata filter quiet | 1 | 0.23 |
| hunt non-correlation quiet | 1 | 0.36 |
| dump csv projected | 4 | 0.10 |
| search metadata filter quiet | 4 | 0.06 |
| hunt non-correlation quiet | 4 | 0.06 |

The dump row stayed effectively flat, while quiet search and quiet
non-correlation hunt improved materially on the benchmarked workload.
