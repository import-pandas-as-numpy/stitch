# Dependency Review

This document records why dependencies are used by `stitch` and what role they play.

## Runtime Dependencies

### `clap`

Purpose: command-line parsing and generated help text.

Justification:

1. Widely adopted Rust CLI parser.
2. Actively maintained.
3. Strong derive support keeps CLI definitions readable and testable.
4. Avoids hand-rolled argument parsing and inconsistent help behavior.

Usage notes:

1. Keep CLI structs in `src/cli.rs`.
2. Prefer explicit argument names and help text.
3. Preserve script-friendly behavior.

### `globset`

Purpose: efficient include/exclude path glob matching during input discovery.

Justification:

1. Widely used by Rust tooling.
2. Compiles multiple globs into a reusable matcher.
3. Keeps path filtering explicit and testable.
4. Avoids ad hoc wildcard handling.

Usage notes:

1. Only compile globs once per run.
2. Treat invalid globs as configuration errors.

### `evtx`

Purpose: parse Windows EVTX files into structured records.

Justification:

1. Purpose-built Rust EVTX parser.
2. Supports JSON value output, which lets early search and dump work share a common event model.
3. Avoids writing a binary EVTX parser in the initial milestones.
4. Can be wrapped behind local input APIs so the project can optimize or replace the parser later.

Usage notes:

1. Keep all direct parser usage under `src/input`.
2. Convert parser records into `Event` immediately so the rest of the application depends on local types.
3. Preserve parse errors and support strict/non-strict behavior.

### `serde_json`

Purpose: store raw EVTX event records and emit machine-readable search output.

Justification:

1. Standard Rust JSON implementation with high adoption.
2. Required by the `evtx` JSON-value workflow.
3. Keeps field lookup and JSONL output straightforward during early milestones.

Usage notes:

1. Use normalized metadata for fast/common fields.
2. Use raw JSON values as a fallback for less common fields.
3. Avoid cloning raw event payloads in hot paths unless necessary.

### `serde`

Purpose: derive typed deserialization for rule and configuration models.

Justification:

1. Standard Rust serialization/deserialization framework.
2. Required by `noyalib` for typed YAML loading.
3. Keeps Sigma rule models explicit instead of loosely shaped maps.

Usage notes:

1. Prefer typed structs for known Sigma metadata and mappings.
2. Use dynamic values only where the specification is intentionally open-ended.

### `noyalib`

Purpose: parse YAML Sigma rules into typed Rust models.

Justification:

1. Pure Rust YAML parser with Serde integration.
2. Advertises zero unsafe code, aligning with the project unsafe policy.
3. MIT OR Apache-2.0 licensed.
4. Replaces deprecated `serde_yaml`/`serde_yml` options for YAML parsing.

Usage notes:

1. Keep YAML parsing isolated under `src/sigma` and future mapping loaders.
2. Treat YAML parse failures as rule load errors with the source path attached.
3. Keep application code free of `unsafe`; dependency use should be re-reviewed as the crate matures.

### `regex`

Purpose: compile and evaluate `stql` regex predicates.

Justification:

1. Standard Rust regex engine with high adoption and active maintenance.
2. Provides safe regular expressions without backtracking-based denial-of-service behavior.
3. Lets `stql` compile regex predicates once during query parsing instead of per event.

Usage notes:

1. Keep regex compilation in query parsing/planning, not event evaluation.
2. Surface invalid regex patterns as query parse errors.
3. Prefer literal or metadata filters before regex matching where future planning supports it.

### `time`

Purpose: parse and compare query timestamps.

Justification:

1. Focused date/time crate with active maintenance.
2. Supports RFC3339 parsing without pulling in broader time-zone behavior.
3. Keeps timestamp comparisons typed instead of relying on string ordering.

Usage notes:

1. Parse query timestamp literals during evaluation until a query planning layer is added.
2. Prefer RFC3339 strings in user-facing documentation and examples.
3. Keep display formatting separate from comparison semantics.

### `thiserror`

Purpose: typed application errors with readable messages.

Justification:

1. Widely adopted for Rust error definitions.
2. Small and focused.
3. Keeps error variants explicit.
4. Produces clear messages without custom boilerplate.

Usage notes:

1. Use typed errors for expected failure modes.
2. Preserve source errors where useful.

### `rayon`

Purpose: file-level parallel processing for EVTX workloads.

Justification:

1. Widely adopted Rust data-parallelism library.
2. Uses work-stealing thread pools with a small, focused API.
3. Lets `stitch` parallelize independent per-file parsing and evaluation without hand-rolled worker lifecycle code.
4. Supports local thread pools, which keeps `--jobs` behavior explicit and avoids hidden global worker configuration.

Usage notes:

1. Parallelize across files first; do not split individual EVTX files until the parser backend is reviewed for safe chunk-level processing.
2. Preserve deterministic output by collecting per-file results and merging them in discovery order.
3. Keep Sigma correlation hunts sequential until cross-file ordering, watermarks, and bounded state are designed for concurrent ingestion.
4. Tests that exercise Rayon paths must run the CLI under a timeout and kill the child process on timeout to avoid deadlocked test hangs.

## Development Dependencies

### `tempfile`

Purpose: isolated filesystem fixtures in tests.

Justification:

1. Widely adopted for Rust tests.
2. Avoids hard-coded paths and cleanup leaks.
3. Supports practical path discovery tests.

Usage notes:

1. Keep fixtures small.
2. Use temporary directories for path discovery and CLI behavior tests.
