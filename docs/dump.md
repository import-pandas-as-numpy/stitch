# Dump Support

`stitch dump` serializes EVTX records without applying search queries or Sigma
rules.

## Supported Formats

Supported:

1. `jsonl`
2. `json`
3. `csv`

Unsupported for now:

1. `xml`

XML is intentionally out of scope for the MVP. Unsupported formats fail with an
explicit error instead of silently changing the requested output shape.

## JSONL Shape

Default JSONL output emits one compact JSON object per parsed EVTX record. Each
object includes normalized metadata, source identity, and the raw parsed event:

```json
{"timestamp":"2026-01-01T00:00:00Z","record_id":1,"channel":"Security","provider":"Microsoft-Windows-Security-Auditing","event_id":4624,"computer":"LAB-WKS-001","source":{"file_path":"Security.evtx","collection_root":"."},"raw":{}}
```

Use repeated `--fields FIELD` options to project selected fields. Projected
output keeps normalized metadata and source identity but omits the raw event:

```bash
stitch dump -i Security.evtx --fields timestamp --fields event.id --fields computer
```

Use `--raw` to emit only the parsed raw EVTX JSON shape:

```bash
stitch dump -i Security.evtx --raw
```

## JSON Shape

`--format json` emits a JSON array of the same record objects used by JSONL.
JSON array output is pretty-formatted by default. Use `--compact` for a
single-line array or `--pretty` to request formatted output explicitly:

```bash
stitch dump -i Security.evtx --format json --pretty
```

If both `--compact` and `--pretty` are supplied, pretty output wins.

Projection and raw output use the same `--fields` and `--raw` flags as JSONL.

## CSV Shape

`--format csv` requires one or more `--fields` values. CSV output contains a
header row using the requested field names, followed by one row per parsed EVTX
record. Missing fields are emitted as empty values.

```bash
stitch dump -i Security.evtx --format csv --fields timestamp --fields event.id --fields computer
```

CSV without `--fields` fails intentionally. Automatic schema discovery would
require buffering or a discovery pass, so it is deferred to preserve dump's
speed-first streaming behavior. CSV also rejects `--raw`; use explicit
`--fields` to choose CSV columns.

## Output Files

By default, dump output is written to stdout. Use `--output <FILE>` to write the
JSONL stream, JSON array, or CSV stream to a file:

```bash
stitch dump -i Security.evtx --output security.jsonl
```

When `--stats` is also supplied with `--output`, stats are printed to stdout and
dump records are written to the output file.

`--output` is treated as a file path. Parent directories must already exist.

## Memory Behavior

Sequential dump writes records as they are parsed. This keeps the output path
streaming for `--jobs 1` and for single-input workloads.

Parallel dump buffers each input's serialized records before merging results in
discovery order. This preserves deterministic output, but memory use scales with
the largest in-flight input result set. Use `--jobs 1` when deterministic output
and lower peak memory are more important than file-level parallelism.

## Parse Errors

By default, recoverable parse errors are skipped and counted. Use `--stats` to
show parse-error counts. Use `--errors <FILE>` to write skipped parse errors as
JSONL.

Use `--fail-fast` or global `--strict` to stop on the first parse error.
