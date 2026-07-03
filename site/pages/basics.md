# Basics

This page summarizes the behavior that applies across Stitch commands and
documents the CLI arguments exposed by the current binary.

## Command Model

| Command | Purpose |
| --- | --- |
| `search` | Run STQL filters against EVTX input. |
| `hunt` | Run Sigma rules and supported Sigma correlation rules. |
| `dump` | Serialize EVTX records into JSONL, JSON, or projected CSV. |

Common options are global. They may appear before or after the subcommand:

```bash
stitch -i Security.evtx --stats search --query 'event.id == 4625'
stitch search --query 'event.id == 4625' -i Security.evtx --stats
```

## Input Discovery

Inputs can be EVTX files, directories, or newline-delimited path lists. When no
input path is supplied, Stitch behaves as if `-i .` was passed and scans the
current directory.

| Option | Behavior |
| --- | --- |
| `-i, --input <PATH>` | Adds an input root. May be repeated. Roots may be EVTX files or directories. |
| `--paths-from <FILE>` | Reads additional roots from a UTF-8 text file. Blank lines and `#` comments are ignored. |
| `--no-recursive` | Stops directory discovery at the immediate directory. |
| `--include <GLOB>` | Includes matching EVTX paths. May be repeated. If omitted, all EVTX files are candidates. |
| `--exclude <GLOB>` | Excludes matching EVTX paths after include filtering. May be repeated. |

Only files with an `.evtx` extension are processed. Extension matching is
case-insensitive. Discovered inputs are sorted by path before processing so
output order is stable.

Each result keeps source identity:

```text
source.file_path
source.collection_root
channel
computer
record_id
```

## Global Execution Options

| Option | Behavior |
| --- | --- |
| `-j, --jobs <N>` | Worker count. `0` uses Rayon's default logical CPU count where the command can parallelize safely. `1` forces sequential processing. |
| `--quiet` | Suppresses non-result diagnostics and stats. Search still emits matching results; hunt can use a faster no-output path when quiet and stats are both off. |
| `--strict` | Treats recoverable parse, query, or rule-load issues as command errors. |
| `--stats` | Appends processing counters to stdout unless `--quiet` is set. |
| `--no-progress` | Reserved. The current binary does not emit a progress meter. |
| `--from <TIMESTAMP>` | Reserved. Timestamp bounds are parsed by the CLI but are not applied yet. Use STQL timestamp predicates today. |
| `--to <TIMESTAMP>` | Reserved. Timestamp bounds are parsed by the CLI but are not applied yet. Use STQL timestamp predicates today. |

Use STQL for timestamp filtering:

```bash
stitch search -i case \
  --query 'timestamp >= "2026-03-21T00:00:00Z" and timestamp < "2026-03-22T00:00:00Z"'
```

## Parallel Execution

Concurrency is file-level. Stitch parallelizes only when there is more than one
discovered input and the command mode can be merged safely.

Parallelized paths:

- `search` when `--limit` is not set.
- `dump` for JSONL, JSON, and projected CSV.
- `hunt` when correlation is disabled or no correlation rules are loaded.

Sequential paths:

- Single-file input.
- Explicit `--jobs 1`.
- `search --limit`, because early termination affects scan counts and output.
- Correlation-enabled `hunt`, because event-time watermarks and bounded state
  are order-sensitive.

Parallel `search`, `dump`, and non-correlation `hunt` preserve discovery order
by buffering each input's output before merging. Use `--jobs 1` for lower peak
memory on large single streams or when debugging ordering-sensitive behavior.

## `search`

`search` requires exactly one query source:

| Option | Behavior |
| --- | --- |
| `-q, --query <QUERY>` | Inline STQL query. Conflicts with `--query-file`. |
| `--query-file <FILE>` | Reads the STQL query from a file. Conflicts with `--query`. |
| `--fields <FIELD>` | Projects selected fields in output. May be repeated. Overrides the STQL keep pipeline. |
| `--format <FORMAT>` | `pretty`, `json`, or `jsonl`. Default: `pretty`. |
| `--limit <N>` | Stops after `N` matches. Forces sequential processing. |
| `--errors <FILE>` | Writes skipped parse errors as JSONL. |
| `--explain` | Prints the parsed query and planned metadata prefilters, then exits without scanning input. |
| `--before-context <N>` | Reserved. Parsed but not applied yet. |
| `--after-context <N>` | Reserved. Parsed but not applied yet. |

Pretty search output includes source metadata. Without `| keep` or `--fields`,
pretty output includes the full raw EVTX record. JSON and JSONL include either
`raw` or projected `fields`.

## `hunt`

`hunt` requires at least one Sigma rule file or directory:

| Option | Behavior |
| --- | --- |
| `--rules <PATH>` | Sigma rule file or directory. Required. May be repeated. |
| `--mapping <FILE>` | Chainsaw-compatible field mapping file. |
| `--rule-status <STATUS>` | Includes rules with the listed Sigma status. May be repeated. |
| `--level <LEVEL>` | Includes rules with the listed Sigma level. May be repeated. |
| `--min-level <LEVEL>` | Includes rules at or above a minimum level. Accepts `informational`, `info`, `low`, `medium`, `high`, or `critical`. |
| `--tag <TAG>` | Includes rules with the listed tag. May be repeated. |
| `--exclude-rule <GLOB>` | Excludes rules by path or title glob. May be repeated. |
| `--enable-correlation` | Enables supported Sigma correlation documents. |
| `--disable-correlation` | Disables Sigma correlation documents. |
| `--correlation-scope <SCOPE>` | Correlation grouping scope: `file`, `host`, or `global`. Default: `host`. |
| `--correlation-lateness <DURATION>` | Allowed out-of-order event-time lateness. Default: `2m`. |
| `--correlation-max-state <N>` | Maximum active correlation state groups. Default: `100000`. |
| `--correlation-event-field <FIELD>` | Stores selected contributing-event field values in correlation output. May be repeated. |
| `--correlation-event-limit <N>` | Pretty-output contributing-event display limit. Default: `3`; `0` hides details. |
| `--format <FORMAT>` | `pretty`, `compact`, `json`, `jsonl`, `csv`, or `timeline`. Current non-JSON alternatives render through pretty output. |
| `--full` | Expands pretty tables with source columns and less-truncated payload content. |
| `--summary` | Writes a rule/input/match summary to stderr after results. |
| `--output <FILE>` | Reserved. Parsed but not applied yet; hunt results currently write to stdout. |

When `--strict` is not set, invalid Sigma files are skipped and counted. When
`--strict` is set, invalid rule files fail the command.

Correlation output is sequential by design. See [Sigma](/sigma/) for supported
rule shapes and correlation behavior.

## `dump`

`dump` serializes parsed EVTX records without applying STQL or Sigma rules:

| Option | Behavior |
| --- | --- |
| `--format <FORMAT>` | `jsonl`, `json`, `csv`, or `xml`. Default: `jsonl`. `xml` is currently rejected at runtime. |
| `--output <PATH>` | Writes dump records to a file. Without it, records are written to stdout. |
| `--fields <FIELD>` | Projects selected fields. May be repeated. Required for CSV. |
| `--raw` | Emits only the parsed raw EVTX JSON shape. Not valid with CSV. |
| `--compact` | Uses compact JSON array output for `--format json`. |
| `--pretty` | Uses pretty JSON array output for `--format json`. |
| `--fail-fast` | Stops on the first parse error. Equivalent to strict parse handling for dump. |
| `--errors <PATH>` | Writes skipped parse errors as JSONL. |

CSV requires explicit `--fields` values. Stitch does not infer CSV schemas,
because schema discovery would require buffering or an additional pass.

## Output Destinations

Default result output goes to stdout. Diagnostics go to stderr. Parse-error logs
created by `--errors` are JSONL files.

When `dump --output <FILE>` is used, records are written to the file. If
`--stats` is also supplied, stats are still written to stdout.

## Parse Errors

Recoverable record parse errors are skipped by default and counted in stats.
Use `--errors <FILE>` to capture skipped record errors as JSONL. Use `--strict`
or dump's `--fail-fast` when partial results are not acceptable.
