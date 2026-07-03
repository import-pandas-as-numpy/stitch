# Performance Notes

This page documents Stitch's concurrency behavior and the repeatable benchmark
harness used to compare local changes. Public docs describe how to measure
performance, not project-internal benchmark results.

## Rayon File-Level Parallelism

Rayon is used for file-level parallelism in modes where each input file can be
processed independently and then merged back in discovery order.

Concurrency is the default execution strategy when there is more than one input
file and the mode can be parallelized safely. `--jobs 0`, the CLI default, uses
Rayon's system-sized worker pool. Use `--jobs 1` to force sequential file
processing.

Current parallelized paths:

1. `search` when `--limit` is not set, including `| summarize` aggregation.
2. `dump` for JSONL, JSON, and projected CSV.
3. `hunt` only when correlation is disabled or no correlation rules are loaded.

Sequential paths by design:

1. Single-file input, because current parallelism is file-level.
2. Explicit `--jobs 1`.
3. `search --limit`, because early termination affects scan counts, output, and
   aggregation input.
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

When recording timing results during development, include:

1. Date.
2. Command.
3. Dataset.
4. Job count.
5. Wall-clock result.
6. Notes about cache warmth and output destination.
7. Peak resident memory when the change may affect buffering or streaming.
8. Whether stdout was redirected, written to a file, or left attached to a
   terminal.

Prefer `cargo run --profile <profile> -- ...` or an explicit
`target/<profile>/stitch` path. Do not benchmark an older installed `stitch`
from `PATH`.

For large-file checks, use a generated or representative EVTX file that is large
enough to exercise output buffering and parser throughput. Compare baseline and
branch commands with the same binary profile, dataset, output destination, and
cache conditions. Record benchmark notes in the pull request or local benchmark
report rather than publishing dated results in this public page.

## Aggregation Memory Behavior

`search | summarize` keeps one in-memory state row per distinct group key. It
does not retain raw event payloads. `count()` stores only a counter per group.
`make_set()` stores distinct stringified field values up to its optional
`maxSize`; use a small explicit `maxSize` for high-cardinality fields such as
process command lines, file paths, or remote IPs in broad searches.

Parallel aggregation builds per-input partial group state and merges those
states after file processing. This keeps worker ownership simple and avoids
unbounded event queues, but peak memory is roughly the sum of live partial group
states plus the final merged state.
