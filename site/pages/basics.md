# Basics

This page summarizes the behavior that applies across the primary Stitch
commands.

## Commands

| Command | Purpose |
| --- | --- |
| `search` | Run STQL queries against EVTX input. |
| `hunt` | Run Sigma rules and supported Sigma correlation rules. |
| `dump` | Serialize EVTX records into JSONL, JSON, or projected CSV. |

## Input discovery

Inputs can be single EVTX files, directories, or newline-delimited path lists.
Directories are searched recursively by default.

```bash
stitch search -i cases/acme --query 'event.id == 4625'
stitch hunt --paths-from case-files.txt --rules rules/windows
```

When no input path is specified, Stitch scans the current working directory.

## Output formats

Pretty output is optimized for terminal reading. JSONL and JSON are stable for
scripting. CSV is available for projected fields where the schema is known up
front.

Use `--full` with hunt output when the compact table hides payload details that
matter for an investigation.

## Parallel execution

Concurrency is the default. `--jobs 0` uses Rayon's system-sized worker pool
where the command can parallelize safely.

Use `--jobs 1` for sequential execution.

Some modes stay sequential by design:

- Single-file input.
- `search --limit`.
- Correlation-enabled `hunt`.

Correlation depends on event-time watermarks and bounded state, so it must
preserve order-sensitive behavior.

## Errors

Stitch should report malformed inputs, unsupported options, and output path
failures with actionable diagnostics. Use `--fail-fast` when partial results are
not acceptable.
