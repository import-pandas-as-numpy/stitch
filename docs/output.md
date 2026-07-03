# Output Guide

Stitch has human-readable output for analyst workflows and stable machine
formats for scripts.

## Destinations

By default, command results are written to stdout and diagnostics are written to
stderr.

`dump --output <FILE>` writes dump records to a file. `hunt --output` is
currently reserved and does not redirect results. `search` does not expose an
output-file option.

When `--stats` is used with `dump --output`, records go to the output file and
stats go to stdout.

## Search Output

Supported formats:

| Format | Behavior |
| --- | --- |
| `pretty` | Human-readable source line plus projected fields or full raw record. Default. |
| `json` | Pretty JSON object per match, separated by blank lines. |
| `jsonl` | One compact JSON object per matching event. |

Pretty search output uses a visible delimiter between matches. When stdout is a
terminal, pretty output also uses subtle ANSI color to distinguish metadata,
field names, and field values. Use global `--no-color` to suppress ANSI color.

Search output always includes normalized metadata and source identity:

```text
timestamp
record_id
channel
provider
event_id
computer
source.file_path
source.collection_root
```

When no projection is supplied, output includes the full raw EVTX record under
`raw`. Projections can come from either STQL `| keep` or repeated CLI
`--fields`; CLI `--fields` takes precedence.

Projected JSON and JSONL put selected values under `fields`. Missing projected
fields are emitted as JSON `null`.

## Hunt Output

Supported format values:

| Format | Behavior |
| --- | --- |
| `pretty` | Compact table with timestamp, detection, event ID/record ID, level, host, and payload. Default. |
| `json` | Pretty JSON object per match. |
| `jsonl` | One compact JSON object per match. |
| `compact` | Currently renders through pretty output. |
| `csv` | Currently renders through pretty output. |
| `timeline` | Currently renders through pretty output. |

Use `--full` with pretty output to include source columns such as channel and
file path and to show less-truncated payload content.

`--summary` writes the rule/input/match summary to stderr after results. When
invalid rules are skipped in non-strict mode, a warning summary is written to
stderr even without `--summary`.

## Correlation Output

Correlation output is emitted by `hunt` when supported correlation rules are
loaded and correlation is enabled.

Pretty correlation output uses a table with timestamp, correlation rule, match
count, level, group, and payload. `--full` adds the window column and disables
payload truncation.

`--correlation-event-field FIELD` stores selected contributing-event values in
correlation output. Repeat it to include multiple fields. Pretty output displays
at most `--correlation-event-limit` contributing events per match; the default
is `3`, and `0` hides those details. JSON and JSONL include selected fields for
every contributing event.

## Dump Output

Supported formats:

| Format | Behavior |
| --- | --- |
| `jsonl` | One compact JSON object per parsed EVTX record. Default. |
| `json` | JSON array of parsed records. |
| `csv` | Header row plus projected field rows. Requires `--fields`. |
| `xml` | Exposed by the CLI enum but rejected at runtime. |

Default dump records include normalized metadata, source identity, and the raw
parsed EVTX event:

```json
{"timestamp":"2026-01-01T00:00:00Z","record_id":1,"channel":"Security","provider":"Microsoft-Windows-Security-Auditing","event_id":4624,"computer":"LAB-WKS-001","source":{"file_path":"Security.evtx","collection_root":"."},"raw":{}}
```

With `--fields`, dump keeps normalized metadata and source identity and writes
selected values under `fields`. With `--raw`, dump emits only the parsed raw EVTX
JSON shape.

CSV requires one or more `--fields` values. Missing fields are emitted as empty
cells. Field names are used as CSV headers and quoted when needed.

## Stats

`--stats` appends counters unless `--quiet` is set.

Search stats:

```text
stats: scanned=<N> matched=<N> parse_errors=<N>
```

Dump stats:

```text
stats: dumped=<N> parse_errors=<N> inputs=<N>
```

Non-correlation hunt stats:

```text
stats: scanned=<N> matched=<N> rules=<N> skipped_rules=<N> inputs=<N>
```

Correlation hunt stats also include correlation counters:

```text
stats: scanned=<N> matched=<N> correlation_matched=<N> rules=<N> correlation_rules=<N> correlation_state=<N> correlation_evicted=<N> skipped_rules=<N> inputs=<N>
```

## Memory Behavior

Sequential stdout paths stream search and dump records as they are parsed.

Parallel output preserves discovery order by buffering each input's rendered
records before merging. This keeps output deterministic, but peak memory can
scale with the largest in-flight input result set. Use `--jobs 1` for lower
memory on large output-heavy runs.
