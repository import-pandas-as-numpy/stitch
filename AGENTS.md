# Stitch Agent and Contributor Guide

This file defines the working standards for `stitch`. It applies to all code, documentation, tests, benchmarks, automation, and GitHub work in this repository.

## Project Priorities

`stitch` is a CLI-first Rust application for high-speed Windows Event Log analysis. The project should be judged by:

1. Correctness of EVTX parsing, query behavior, Sigma behavior, and output formats.
2. Speed on realistic event log collections.
3. Predictable memory use in constrained environments.
4. Clear, aesthetic CLI behavior.
5. Practical tests with readable failures.
6. Documentation that makes behavior obvious.

## Code Paradigms

Functions should be obvious, self-documenting, and easy to test.

Prefer:

1. Small functions with direct names.
2. Inputs and outputs that are easy to construct in tests.
3. Explicit data types over loosely shaped maps when the domain is known.
4. Early returns over deep nesting.
5. Clear error variants with enough context to diagnose the failure.
6. Straight-line code when it is easier to audit than clever abstractions.

Avoid:

1. Extreme nesting.
2. Hidden global state.
3. Large functions that mix parsing, evaluation, output, and side effects.
4. Implicit panics in normal error paths.
5. Premature abstractions that do not remove real duplication.
6. Stringly typed control flow when enums or structured types are available.

## Unsafe Code

`unsafe` is explicitly prohibited.

The crate should deny unsafe code at the crate level:

```rust
#![forbid(unsafe_code)]
```

Do not add dependencies or feature flags that require application-level unsafe code. If a transitive dependency uses unsafe internally, that dependency must be justified during dependency review.

## Linting and Formatting

All formatting, linting, and general checking must run in the strictest practical mode.

Required baseline:

```text
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-targets --all-features
```

Warnings are errors. Address warnings directly rather than suppressing them.

Suppression rules:

1. Prefer code changes over `#[allow(...)]`.
2. Any `#[allow(...)]` must be narrow, local, and justified with a comment.
3. Do not add broad crate-level lint allows without a documented project decision.

## Testing Principles

Tests should be practical and emit readable errors with a clear cause.

Required test style:

1. Test public behavior and important internal logic.
2. Keep fixtures small unless the test is explicitly a performance or memory test.
3. Use assertion messages when the default failure would be ambiguous.
4. Prefer table-driven tests for query parsing, Sigma modifiers, and field mapping.
5. Include malformed input tests for parsers and rule loaders.
6. Avoid brittle tests that depend on terminal color or exact spacing unless testing golden CLI output.

Test errors should answer:

1. What behavior failed?
2. What input caused it?
3. What was expected?
4. What actually happened?

## Concurrency Principles

Concurrency must be designed and tested for memory-constrained environments. Do not assume the developer machine is representative of deployment environments, even if the current development machine has 64 GB of memory.

Concurrency requirements:

1. Use bounded channels or explicit backpressure for pipelines.
2. Avoid unbounded queues of parsed events, rule matches, or output records.
3. Keep ownership and shutdown paths simple.
4. Make worker lifetimes explicit.
5. Ensure cancellation and error propagation cannot leave workers blocked forever.
6. Test low-buffer and low-worker configurations.
7. Prefer deterministic tests for deadlock-prone code.

Concurrency testing should include:

1. `--jobs 1`.
2. More jobs than input files.
3. Very small channel bounds.
4. Early output termination, such as `search --limit`.
5. Parser errors while workers are active.
6. Correlation windows with bounded state.

## Performance Principles

Speed is a primary project metric. Performance must be easy to test, benchmark, and trace.

Performance work should:

1. Include benchmarks for relevant modes.
2. Track throughput, peak memory, and error counts.
3. Avoid repeated parsing, repeated regex compilation, and avoidable allocation.
4. Push cheap filters early: timestamp, channel, event ID, provider, and file filters.
5. Keep output streaming where possible.
6. Use buffered writes for machine output.
7. Measure before and after optimization changes.

Benchmark caution:

1. Confirm the benchmark is using the intended binary.
2. Prefer `cargo run --profile <profile> -- ...` or an explicit `target/<profile>/stitch` path.
3. Do not accidentally benchmark an old installed `stitch` from `PATH`.
4. Record the command, dataset, profile, and machine constraints in benchmark notes.

## Memory Principles

Memory behavior is a first-class performance concern.

The implementation should:

1. Stream EVTX records instead of loading whole collections.
2. Keep correlation state bounded.
3. Prefer projections when only a subset of fields is needed.
4. Avoid cloning raw event payloads unless necessary.
5. Document memory tradeoffs for features such as exact correlation and CSV schema discovery.
6. Include memory-focused tests or benchmarks for large collections and small limits.

## Dependency Policy

Dependencies must be vetted, justified, and secure.

Prefer dependencies that have:

1. High adoption.
2. Consistent maintenance.
3. Clear licenses compatible with the project.
4. No known reputation of compromise.
5. Long-term support or a stable ecosystem position.
6. Minimal unnecessary transitive dependency load.

Before adding a dependency, document why it is needed and why standard library or existing dependencies are insufficient. For security-sensitive or parsing-related dependencies, be especially conservative.

Dependency review should consider:

1. Maintenance activity.
2. Open security advisories.
3. Unsafe usage.
4. License.
5. Feature flags.
6. Binary size and compile-time impact.
7. Whether the dependency is required in the hot path.

## Documentation

Documentation is a primary project focus. Project documentation lives under `/docs`.

Documentation must make behavior explicit, especially:

1. CLI usage.
2. Query language syntax and semantics.
3. Sigma rule support.
4. Sigma correlation behavior.
5. Chainsaw-compatible mapping behavior.
6. Output schemas.
7. Performance and memory tradeoffs.
8. Known unsupported behavior.

Query language semantics and Sigma behavior must not be unobvious. If a behavior would surprise an analyst, document it.

## CLI Experience

`stitch` is CLI-first. The terminal experience is part of the product.

CLI output should:

1. Be readable by default.
2. Use color to enhance meaning when stdout is a terminal.
3. Avoid excessive color.
4. Disable color automatically for non-terminal output.
5. Support explicit color controls when implemented.
6. Pretty-print human output where practical.
7. Provide stable machine formats such as JSONL and CSV.
8. Include clear error messages with actionable context.

Help text should be concise but useful. Commands should behave predictably in scripts.

## Git and Commit Discipline

Commits should be frequent, atomic, documented, and concise.

Commit messages should:

1. Call out the milestone or feature area.
2. Describe the change directly.
3. Avoid bundling unrelated edits.
4. Mention important test or benchmark coverage when relevant.

Examples:

```text
milestone-0: add clap command skeleton
search: parse equality predicates
hunt: load chainsaw-compatible mappings
docs: define stql comparison semantics
```

Do not rewrite or discard user changes unless explicitly asked.

## GitHub Workflow

When manipulating GitHub, write pull request bodies and other long GitHub text to a file first. GitHub CLI often breaks on escape characters and shell quoting.

Preferred flow:

1. Draft PR body in a file under a suitable temporary or docs location.
2. Review the file.
3. Pass the file to GitHub CLI with file-based flags where possible.

Do not place complex Markdown directly in shell arguments.

## Documentation Hygiene

Public documentation should describe supported behavior, operational guidance,
and contributor-relevant decisions. Do not add private planning notes,
session-transfer notes, or milestone journals to the public tree.

## Agent Operating Notes

Before substantial work:

1. Inspect the current tree and git status.
2. Read relevant documentation under `/docs`.
3. Confirm the current milestone.

Before finishing work:

1. Run the relevant formatting, linting, tests, or benchmarks.
2. State clearly if any check was not run.
3. Update public documentation when behavior or project status changes.
4. Verify that commands used the intended local binary.
