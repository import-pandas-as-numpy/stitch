# Stitch

[![CI](https://github.com/import-pandas-as-numpy/stitch/actions/workflows/ci.yml/badge.svg)](https://github.com/import-pandas-as-numpy/stitch/actions/workflows/ci.yml)
[![Security](https://github.com/import-pandas-as-numpy/stitch/actions/workflows/security.yml/badge.svg)](https://github.com/import-pandas-as-numpy/stitch/actions/workflows/security.yml)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Fast offline Windows Event Log analysis from the command line.

**Docs:** [stitch.sudorem.dev](https://stitch.sudorem.dev/)

`stitch` searches EVTX collections, hunts with Sigma rules, runs supported
Sigma correlation rules, and dumps records into machine-friendly formats. It is
built for incident-response style workflows where speed, readable output, and
source identity matter.

```text
EVTX files/directories  ->  search | hunt | dump  ->  pretty tables, JSONL, JSON, CSV
```

## Highlights

| Capability | Current Support |
| --- | --- |
| EVTX input | Single files, recursive directories, and `--paths-from` lists |
| Search | STQL predicates over normalized metadata and raw event paths |
| Hunt | Direct Sigma rule loading with Windows EVTX field aliases |
| Correlation | Supported Sigma correlation windows with bounded state |
| Output | Pretty analyst output plus JSONL, JSON, and projected CSV |
| Speed | Rayon file-level parallelism where execution is order-safe |
| CI/security | Pinned GitHub Actions, Zizmor audits, Socket, grouped Dependabot updates |

## Quickstart

Build:

```bash
cargo build --release
```

Search EVTX files under the current directory:

```bash
target/release/stitch search \
  --query 'event.id == 4625' \
  --format jsonl
```

Hunt with Sigma rules:

```bash
target/release/stitch hunt \
  -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma \
  --format jsonl
```

Dump projected CSV:

```bash
target/release/stitch dump \
  -i tests/fixtures/evtx/security-auth.evtx \
  --format csv \
  --fields timestamp \
  --fields event.id \
  --fields computer \
  --output /tmp/security.csv
```

## Commands

### `search`

Run ad hoc STQL queries against EVTX input.

```bash
stitch search -i tests/fixtures/evtx/security-auth.evtx \
  --query 'event.id == 4625 | keep timestamp, event.id, computer, Event.EventData.TargetUserName'
```

Pretty output is the default. Without `| keep` or `--fields`, pretty search
prints the full raw event record as a YAML-like nested block. Use `--format
jsonl` for scripting.

### `hunt`

Run Sigma detections directly against EVTX records.

```bash
stitch hunt -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma/sysmon_powershell_network.yml
```

Default hunt output is tabular and compact: timestamp, detection, event
ID/record ID, level, host, and a concise payload. Add `--full` for source
columns and less-truncated payload content.

Correlation rules run through `hunt` when enabled and supported:

```bash
stitch hunt -i tests/fixtures/correlation-evtx/sysmon-correlation.evtx \
  --rules tests/fixtures/sigma-correlation \
  --correlation-event-field Event.EventData.ProcessGuid \
  --correlation-event-field Event.EventData.Image
```

Correlation-enabled hunt is intentionally sequential because event-time
watermarks and bounded state are order-sensitive.

### `dump`

Serialize EVTX records for downstream tooling.

```bash
stitch dump -i tests/fixtures/evtx/security-auth.evtx
```

Supported dump formats are JSONL, JSON, and projected CSV. CSV requires
explicit fields to avoid expensive schema discovery:

```bash
stitch dump -i tests/fixtures/evtx/security-auth.evtx \
  --format csv \
  --fields timestamp \
  --fields event.id \
  --fields computer
```

`dump --format xml` is visible in the CLI enum but intentionally unsupported
right now.

## Input Model

When no input path is specified, `stitch` recursively searches the current
working directory as if `-i .` had been passed.

All primary commands support:

- `-i, --input <PATH>` for EVTX files or directories.
- `--paths-from <FILE>` for newline-delimited path lists.
- Recursive directory discovery by default.
- `--include <GLOB>` and `--exclude <GLOB>` filtering.

Source identity is retained in output:

- `source.file_path`
- `source.collection_root`
- `channel`
- `computer`
- `record_id`

## Parallel Execution

`--jobs 0` is the default and uses Rayon's system-sized worker pool where the
mode can parallelize safely. Use `--jobs 1` for sequential execution.

Parallelized:

- `search` when `--limit` is not set.
- `dump` for JSONL, JSON, and projected CSV.
- Non-correlation `hunt`.

Sequential by design:

- Single-file input.
- Explicit `--jobs 1`.
- `search --limit`.
- Correlation-enabled `hunt`.

## Documentation

The documentation website is published at
[stitch.sudorem.dev](https://stitch.sudorem.dev/). Source lives in [site](site).
Build the static site with `npm run docs:build`; Vercel publishes the generated
`site/dist` directory.

| Topic | Link |
| --- | --- |
| STQL query language | [docs/stql.md](docs/stql.md) |
| Sigma support | [docs/sigma.md](docs/sigma.md) |
| Output examples | [docs/output.md](docs/output.md) |
| Dump behavior | [docs/dump.md](docs/dump.md) |
| Performance notes | [docs/performance.md](docs/performance.md) |
| CI/CD | [docs/ci.md](docs/ci.md) |
| Dependency review | [docs/dependencies.md](docs/dependencies.md) |

## Development

Strict local checks:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-targets --all-features
```

Benchmark harness:

```bash
scripts/bench-local.sh
```

Workflow audit:

```bash
zizmor --persona pedantic .github/workflows
```

## Status

`stitch` is under active development. The priority stack is correctness,
performance on realistic EVTX collections, predictable memory use, readable CLI
output, and practical Sigma behavior.

`stitch` is licensed under the [MIT License](LICENSE).
