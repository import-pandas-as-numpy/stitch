# Stitch

`stitch` is a CLI-first Rust tool for fast offline Windows Event Log (`.evtx`)
analysis. It can search EVTX collections with an ad hoc query language, hunt
with Sigma rules, run supported Sigma correlation rules, and dump EVTX records
to stable machine formats.

The project is early, but the current implementation is usable against local
EVTX fixtures and directories.

## What It Does

- Searches EVTX files and recursive EVTX directories.
- Runs Sigma rules directly against EVTX records.
- Supports a practical Sigma subset, including selected correlation rule types.
- Emits readable human output and stable JSONL/JSON/CSV machine output.
- Uses Rayon for file-level parallelism where ordering and behavior are safe.
- Preserves normalized event metadata plus raw event content for re-analysis.

## Install

Build from source:

```bash
cargo build --release
```

Run the local binary:

```bash
target/release/stitch --help
```

During development, use:

```bash
cargo run -- --help
```

## Commands

### Search

Run an ad hoc STQL query:

```bash
stitch search -i tests/fixtures/evtx/security-auth.evtx \
  --query 'event.id == 4625' \
  --format jsonl
```

Pretty output is the default. When no `| keep` pipeline or `--fields`
projection is supplied, pretty search output includes the full raw event record
as a YAML-like nested block.

Projected search:

```bash
stitch search -i tests/fixtures/evtx/security-auth.evtx \
  --query 'event.id == 4625 | keep timestamp, event.id, computer, Event.EventData.TargetUserName'
```

### Hunt

Run Sigma rules:

```bash
stitch hunt -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma \
  --format jsonl
```

Pretty hunt output is tabular by default and includes timestamp, rule match,
event ID/record ID, level, host, and a concise payload. Use `--full` to include
expanded source columns and less-truncated payload content:

```bash
stitch hunt -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma/sysmon_powershell_network.yml \
  --full
```

Correlation rules run through `hunt` when correlation is enabled and supported:

```bash
stitch hunt -i tests/fixtures/correlation-evtx/sysmon-correlation.evtx \
  --rules tests/fixtures/sigma-correlation \
  --correlation-event-field Event.EventData.ProcessGuid \
  --correlation-event-field Event.EventData.Image
```

Correlation-enabled hunt is intentionally sequential because event-time
watermarks and bounded state are order-sensitive.

### Dump

Dump EVTX records as JSONL:

```bash
stitch dump -i tests/fixtures/evtx/security-auth.evtx
```

Write projected CSV:

```bash
stitch dump -i tests/fixtures/evtx/security-auth.evtx \
  --format csv \
  --fields timestamp \
  --fields event.id \
  --fields computer \
  --output /tmp/security.csv
```

`dump --format xml` is listed by the CLI enum but is intentionally unsupported
right now. JSONL, JSON, and projected CSV are the supported dump formats.

## Inputs

All primary commands support:

- `-i, --input <PATH>` for EVTX files or directories.
- `--paths-from <FILE>` for newline-delimited path lists.
- Recursive directory discovery by default.
- `--include <GLOB>` and `--exclude <GLOB>` path filtering.

Source identity is retained in outputs through fields such as
`source.file_path`, `source.collection_root`, `channel`, `computer`, and
`record_id`.

## Parallelism

`--jobs 0` is the default and uses Rayon's system-sized thread pool when the
mode can parallelize safely. Use `--jobs 1` to force sequential processing.

Parallelized paths:

- `search` when `--limit` is not set.
- `dump` for JSONL, JSON, and projected CSV.
- Non-correlation `hunt`.

Sequential paths:

- Single-file input.
- Explicit `--jobs 1`.
- `search --limit`.
- Correlation-enabled `hunt`.

## Documentation

- [Project specification](docs/project-spec.md)
- [STQL query language](docs/stql.md)
- [Sigma support](docs/sigma.md)
- [Output guide](docs/output.md)
- [Dump behavior](docs/dump.md)
- [Performance notes](docs/performance.md)
- [CI/CD](docs/ci.md)
- [Dependency review](docs/dependencies.md)

## Development

Baseline checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-targets --all-features
```

Benchmark smoke and local fixture timing:

```bash
scripts/bench-local.sh
```

Workflow audit:

```bash
zizmor --persona pedantic .github/workflows
```

## Status

`stitch` is under active development. Current focus areas are correctness,
performance on realistic EVTX collections, predictable memory use, readable CLI
output, and practical Sigma behavior.
