# Stitch Project Specification

Status: Draft  
Last updated: 2026-06-27

## 1. Purpose

`stitch` is a cross-platform Rust CLI for parsing, hunting, searching, and converting Windows Event Log (`.evtx`) data at high speed.

The tool should feel approachable like Chainsaw, handle modern Sigma rule repositories including Sigma correlation rules, and remain fast enough to use against large offline log collections during incident response.

Primary modes:

1. `hunt`: run a Sigma rule repository against EVTX input.
2. `search`: run an ad hoc query against EVTX input and return pretty event matches.
3. `dump`: serialize EVTX input into another format as quickly as possible.

Non-goals for the initial implementation:

1. Live Windows Event Log subscription.
2. A GUI.
3. Remote collection over WinRM, SMB, or EDR APIs.
4. Full SIEM replacement semantics.

## 2. Research Notes

### 2.1 Chainsaw

Chainsaw is the closest behavioral model for `stitch`: it is a Rust-based command-line tool for hunting through Windows forensic artifacts, especially EVTX, with `hunt`, `search`, and `dump` style workflows. It supports Sigma rules, output customization, mapping files, and a separate search language called Tau.

Design inspiration to keep:

1. Simple top-level commands.
2. Fast recursive collection processing.
3. Sigma-oriented hunting.
4. Friendly terminal output by default.
5. Structured output for automation.

Design choices to avoid:

1. Tau syntax as the default query language. It is powerful, but its shape is unfamiliar to many users coming from KQL, Splunk, SQL, jq, or Sigma.
2. Treating correlation as an optional slow second pass. `stitch` should plan for streaming correlation from the start.

Reference: <https://github.com/WithSecureLabs/chainsaw>

### 2.2 Hayabusa

Hayabusa is a mature Windows event log threat hunting and timeline generator that focuses heavily on speed, rule quality, alert presentation, and timeline output. It also has a strong operational model around rule repositories, level/status metadata, computer names, and compact analyst-facing output.

Design inspiration to keep:

1. Timeline-friendly output.
2. Rule metadata visibility.
3. Severity/level filtering.
4. High-throughput EVTX processing.
5. Analyst-centered summaries.

Reference: <https://github.com/Yamato-Security/hayabusa>

### 2.3 EVTXECmd

EVTXECmd is a widely used EVTX parser from Eric Zimmerman. It is known for robust parsing, batch operation, maps, and practical conversion output for forensic workflows.

Design inspiration to keep:

1. Reliable bulk conversion.
2. Speed-first export paths.
3. Useful format options for downstream tools.
4. Preserve enough raw event detail for later re-analysis.

Reference: <https://github.com/EricZimmerman/evtx>

### 2.4 Sigma

Sigma rules are YAML detections that describe log patterns independent of a single backend. The current Sigma ecosystem includes regular detection rules and correlation rules. Correlation rules define temporal relationships over rule matches, including event-count style thresholds, value counts, temporal ordering, grouping, and time windows.

`stitch` should parse Sigma directly instead of shelling out to a backend converter. This lets the engine preserve efficient local execution plans and support offline EVTX collections without requiring a SIEM target.

References:

1. Rules specification: <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-rules-specification.md>
2. Correlation specification: <https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md>

### 2.5 Rust EVTX Parser

The Rust `evtx` crate provides EVTX parsing with Serde support and is the most likely initial parser backend. It should be wrapped behind a local parser trait so `stitch` can add faster specialized paths, recovery behavior, or alternate parsers later without coupling the whole application to one crate.

Reference: <https://docs.rs/evtx/latest/evtx/>

## 3. Design Principles

1. Speed is a feature. Avoid avoidable allocation, repeated parsing, repeated regex compilation, and late filtering.
2. Correctness beats cleverness for parser and rule semantics.
3. The CLI should be useful without a config file.
4. Human output should be readable; machine output should be stable.
5. Internal APIs should use normalized event records, but outputs should preserve source-specific fields.
6. Correlation should be integrated into the hunt pipeline rather than bolted on after single-event matching.
7. Every expensive feature should have a bounded-memory design.

## 4. Core Concepts

### 4.1 Event Input

Initial input support:

1. One EVTX file.
2. An arbitrary directory tree containing nested EVTX files.
3. A newline-delimited list of paths via `--paths-from`.

Input behavior:

1. All primary modes must support both a single EVTX file and nested directory collections.
2. Directory processing must preserve each event's source file path.
3. Multiple machines may appear in one file, one directory, or one merged collection.
4. Machine and channel identity must be derived from event metadata first, especially EVTX `System` metadata such as `Computer` and `Channel`, not from directory names.
5. Directory and file names may be used as fallback context, but they must not override event-provided machine or channel values.
6. Results must make machine and channel boundaries clear in human and machine output.

Future input support:

1. JSON/JSONL event records emitted by `stitch dump`.
2. XML event logs.
3. Windows live channel reads.
4. Compressed collections such as `.zip`, `.tar`, `.gz`, and `.zst`.

### 4.2 Normalized Event Model

Each parsed event should be represented as:

```rust
struct Event {
    source: EventSource,
    metadata: EventMetadata,
    fields: EventFields,
    raw: RawEvent,
}
```

Required normalized metadata:

1. `timestamp`: event timestamp if present.
2. `record_id`: EVTX record ID if present.
3. `channel`: log channel, for example `Security`.
4. `provider`: provider name.
5. `event_id`: numeric event ID.
6. `computer`: computer name.
7. `file_path`: source file path.
8. `file_offset` or equivalent parser location when available.

### 4.3 Source Identity

`stitch` must clearly distinguish events by source file, machine, and event log channel.

Source identity fields:

1. `source.file_path`: the EVTX file the event came from.
2. `source.collection_root`: the input root that discovered the file, when applicable.
3. `source.channel`: the event log channel, for example `Security`, `System`, or `Microsoft-Windows-Sysmon/Operational`.
4. `source.computer`: the machine name reported by the event.
5. `source.record_id`: the record ID within the source EVTX file.

Identity rules:

1. Channel and computer values from the event are authoritative when present.
2. A single EVTX file may contain events from more than one computer; do not assume one file equals one machine.
3. A directory may contain logs from many machines; do not assume one directory equals one machine.
4. Human output should show at least computer, channel, source file, and record ID for matches.
5. Machine-readable output must include source identity fields so downstream tools can group by machine, channel, and file.
6. Correlation scope `host` must group by event-provided computer identity, with channel retained as match context.

Field access should support both normalized aliases and raw paths:

1. `event.id`
2. `winlog.event_id`
3. `Event.System.EventID`
4. `event_data.TargetUserName`
5. `message`

### 4.4 Field Mapping

Sigma rules depend on field names that vary by backend. `stitch` needs a mapping layer.

Initial mapping sources:

1. Built-in EVTX mapping for common Sigma Windows fields.
2. Chainsaw-compatible mapping files.
3. User-supplied YAML mapping files in the same compatibility shape.
4. Rule-level field references.

Mapping behavior:

1. Prefer normalized fast paths for common fields like Event ID, channel, provider, computer, timestamp, and user names.
2. Fall back to raw JSON/XML field lookup.
3. Warn once per run for unmapped fields unless `--quiet` is set.
4. Treat Chainsaw mapping compatibility as the primary mapping contract so existing Chainsaw users can reuse their rule and mapping workflows with minimal migration.

## 5. CLI Specification

Top-level:

```text
stitch <COMMAND> [OPTIONS]
```

Common options:

```text
-i, --input <PATH>...          File or directory input
--paths-from <FILE>            Read input paths from a file
--no-recursive                 Do not recurse through input directories
-j, --jobs <N>                 Worker count, defaults to logical CPUs
--no-progress                  Disable progress bars
--quiet                        Suppress non-result messages
--strict                       Treat recoverable parse/rule issues as errors
--timezone <TZ>                Display timezone, default local
--from <TIMESTAMP>             Inclusive lower timestamp bound
--to <TIMESTAMP>               Exclusive upper timestamp bound
--include <GLOB>               Include path glob
--exclude <GLOB>               Exclude path glob
--stats                        Print processing stats
```

Common options are global. They may appear before or after the subcommand, for
example `stitch -i Security.evtx search -q 'event.id == 4625'` and
`stitch search -q 'event.id == 4625' -i Security.evtx` are both valid.

When `--stats` is enabled, recoverable parse failures should be counted. In
non-strict mode, stats may include a small bounded sample of skipped record
errors so damaged inputs are visible without flooding normal output.

### 5.1 Hunt

```text
stitch hunt --rules <PATH> -i <PATH> [OPTIONS]
```

Options:

```text
--rules <PATH>...              Sigma rule file or directory
--mapping <FILE>               Field mapping file
--rule-status <STATUS>...      Include statuses, for example stable/test
--level <LEVEL>...             Include levels, for example high/critical
--tag <TAG>...                 Include rules with tag
--exclude-rule <GLOB>          Exclude rule path/name glob
--enable-correlation           Enable correlation rules, default true when present
--disable-correlation          Disable correlation rules
--correlation-scope <SCOPE>    file, host, or global; default host
--correlation-lateness <DUR>   Event-time tolerance, default 2m
--correlation-max-state <N>    Max correlation state entries per rule
--format <FORMAT>              pretty, compact, json, jsonl, csv, timeline
--output <FILE>                Write results to file
--min-level <LEVEL>            Minimum Sigma level
--summary                      Print rule/file summary after results
```

Default output should be a compact readable table grouped by hit:

```text
2026-06-27T12:10:44Z  HIGH  Security  4625  Failed Logon From Public IP
  host: WIN-01  user: alice  src_ip: 203.0.113.10
  file: Security.evtx  record: 88421
```

Hunt execution model:

1. Load and validate all Sigma rules.
2. Split rules into single-event rules and correlation rules.
3. Build a rule execution plan:
   1. metadata prefilters by channel, provider, event ID, level, status, tags.
   2. string keyword prefilters where safe.
   3. compiled regex predicates.
   4. field predicates.
4. Parse events in parallel across files.
5. Apply cheap metadata and timestamp filters before full field materialization when possible.
6. Emit single-event matches immediately.
7. Feed rule matches into the correlation engine.
8. Emit correlation matches when windows close or thresholds are reached.

### 5.2 Search

```text
stitch search -q '<QUERY>' -i <PATH> [OPTIONS]
```

Options:

```text
-q, --query <QUERY>            Query string
--query-file <FILE>            Read query from file
--fields <FIELD>...            Fields to display
--format <FORMAT>              pretty, json, jsonl, csv
--limit <N>                    Stop after N matches
--errors <FILE>                Write skipped parse errors as JSONL
--before-context <N>           Include N events before each match per file
--after-context <N>            Include N events after each match per file
--explain                      Print query plan
```

In non-strict mode, `--errors` writes one JSON object per skipped parse error:

```json
{"file_path":"Security.evtx","error":"..."}
```

Recommended query language: Stitch Query Language (`stql`).

Rationale:

1. KQL-like field predicates are familiar to security analysts.
2. SQL-like boolean operators are easy to read.
3. The language can compile into the same predicate plan used by Sigma.
4. It avoids Tau's more specialized syntax.

Example queries:

```text
event.id in (4624, 4625) and channel == "Security"
provider == "Microsoft-Windows-Sysmon" and event.id == 1 and process.command_line contains_ci "powershell"
exists(event_data.TargetUserName) and event_data.TargetUserName =~ /admin.*/i
timestamp >= "2026-06-27T00:00:00Z" and message contains "LSASS"
cidr_contains(Event.EventData.SourceIp, "10.0.0.0/8")
```

Core grammar:

```text
query       := expr
expr        := or_expr
or_expr     := and_expr ("or" and_expr)*
and_expr    := not_expr ("and" not_expr)*
not_expr    := "not" not_expr | primary
primary     := comparison | function | "(" expr ")"
comparison  := field operator value
operator    := "==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "contains" |
               "contains_ci" | "starts_with" | "ends_with" | "=~" | "!~"
function    := ident "(" args? ")"
field       := ident ("." ident)*
value       := string | number | bool | timestamp | regex | list
```

Required functions:

1. `exists(field)`
2. `is_null(field)`
3. `lower(value)`
4. `upper(value)`
5. `len(value)`
6. `cidr_contains(field, cidr)`
7. `ip_in_cidr(field, cidr)`

Potential later additions:

1. Pipe operations: `| fields timestamp, event.id, user | sort timestamp desc | limit 50`
2. Aggregation for search mode.
3. Saved query files with metadata.

Alternative query language options considered:

1. CEL: good embedding story and familiar expression model, but less analyst-friendly for event logs.
2. SQL subset: familiar, but awkward for deeply nested event fields.
3. jq subset: excellent JSON traversal, weaker for common security predicates and pretty event returns.
4. KQL clone: familiar to Microsoft Sentinel users, but implementing a partial clone risks surprising incompatibilities.

Recommendation: implement `stql` as a small KQL-inspired infix language with explicit documented semantics.

### 5.3 Dump

```text
stitch dump -i <PATH> --format <FORMAT> [OPTIONS]
```

Options:

```text
--format <FORMAT>              jsonl, json, csv, xml
--output <PATH>                Output file or directory
--fields <FIELD>...            Field projection
--flatten                      Flatten nested fields for CSV
--raw                          Preserve raw parsed event shape
--compact                      Compact JSON output
--pretty                       Pretty JSON output
--fail-fast                    Stop on first parse error
--errors <PATH>                Write parse errors as JSONL
```

Dump defaults:

1. Default format: `jsonl`.
2. Default output: stdout for one input, output directory for many inputs if `--output` is a directory.
3. Default shape: normalized metadata plus raw event fields.

Speed-first behavior:

1. Avoid rule/query planning.
2. Avoid pretty formatting unless requested.
3. Stream output records.
4. Use buffered writes.
5. For CSV, compute headers from projection when supplied; otherwise perform a bounded schema discovery pass or require `--fields`.

## 6. Sigma Support

### 6.1 Rule Loading

The rule loader should support:

1. Recursive directory loading.
2. `.yml` and `.yaml`.
3. Multi-document YAML.
4. Stable warning/error reporting with file path and YAML document index.
5. `--strict` mode.

### 6.2 Single-Event Detection Semantics

Required Sigma support:

1. `title`, `id`, `status`, `description`, `references`, `author`, `date`, `modified`, `tags`, `logsource`, `detection`, `falsepositives`, `level`.
2. Detection selections.
3. `condition` expressions with `and`, `or`, `not`, `1 of`, `all of`.
4. Lists of maps and maps of lists.
5. Field modifiers:
   1. `contains`
   2. `startswith`
   3. `endswith`
   4. `re`
   5. `cidr`
   6. `base64`
   7. `base64offset`
   8. `wide`
   9. `windash`
   10. `all`
6. Null checks.
7. Numeric and string comparison where defined.

### 6.3 Logsource Mapping

`logsource` should compile into prefilters:

1. `product: windows` maps to EVTX-capable Windows sources.
2. `service: security` maps to `Security`.
3. `service: sysmon` maps to Sysmon channels.
4. `category` maps through a built-in table.

If the mapping is ambiguous, keep the rule active and emit a warning. Do not silently drop rules.

### 6.4 Correlation Rules

Correlation support is a first-class requirement.

Correlation rule inputs are single-event rule matches, not raw events. The engine should therefore:

1. Assign stable internal IDs to all rules.
2. Build dependency edges from correlation rules to referenced event rules.
3. Ensure dependency rules are evaluated even if their own alerts are suppressed.
4. Feed compact `RuleMatch` records to the correlation engine.

`RuleMatch` should include:

1. rule ID.
2. timestamp.
3. source event key.
4. relevant field values.
5. group-by key values.
6. selected output fields.

Required correlation capabilities:

1. event count over a timeframe.
2. value count over a timeframe.
3. temporal ordering.
4. grouped correlations.
5. aliases and references to source rules.

Correlation execution model:

```text
EVTX event -> single-event rule planner -> RuleMatch stream -> correlation windows -> alert output
```

To avoid significant performance penalties:

1. Only rules referenced by correlation rules feed correlation state.
2. Only fields required by correlation rules are extracted into `RuleMatch`.
3. Use hash maps keyed by `(correlation_rule_id, group_key)`.
4. Use deque-backed event-time windows for each group.
5. Evict state as watermarks advance.
6. Bound memory with `--correlation-max-state`.
7. Track late events using `--correlation-lateness`.
8. Do not globally sort all events by default.

Correctness tradeoff:

1. Default mode should be streaming and fast.
2. `--correlation-exact` can be added later to perform an external sort or larger merge window for fully deterministic cross-file event-time ordering.

## 7. Concurrency and Performance Architecture

### 7.1 Pipeline

Recommended pipeline:

```text
path discovery
  -> file work queue
  -> parser workers
  -> predicate/rule workers
  -> ordered or unordered result writer
```

`dump` can collapse predicate/rule workers into parser workers.

### 7.2 Parallelism

Initial strategy:

1. Parallelize across files.
2. Within very large files, rely on parser streaming first; evaluate chunk-level parallelism later if the parser backend safely supports it.
3. Use bounded channels to avoid unbounded memory growth.
4. Keep output writing single-owner for deterministic formatting.

### 7.3 Fast Paths

Fast paths to implement early:

1. Timestamp bounds.
2. Channel filter.
3. Event ID filter.
4. Provider filter.
5. Computer filter.
6. Keyword prefilter for literal string rules.
7. Field projection for dump and search output.

### 7.4 Benchmark Targets

Benchmarks should be checked into the repo with synthetic and public test fixtures where licensing allows.

Metrics:

1. events per second.
2. MB per second.
3. peak RSS.
4. parse errors.
5. rule matches per second.
6. correlation state size.

Initial benchmark scenarios:

1. `dump` one large Security EVTX to JSONL.
2. `hunt` with 100 Sigma rules.
3. `hunt` with the full Sigma Windows repository.
4. `hunt` with correlation rules enabled.
5. `search` Event ID filter only.
6. `search` regex against command line fields.

## 8. Output Design

### 8.1 Human Output

Human output should:

1. Fit common terminals.
2. Use color only when stdout is a terminal.
3. Include timestamp, level, rule title, channel, event ID, computer, and key fields.
4. Show source file and record ID.
5. Truncate long values by default with `--no-truncate` available.

### 8.2 Machine Output

Machine output must be stable and documented.

Hunt JSONL result shape:

```json
{
  "type": "sigma_match",
  "timestamp": "2026-06-27T16:00:00Z",
  "rule": {
    "id": "rule-id",
    "title": "Rule title",
    "level": "high",
    "tags": ["attack.t1059"]
  },
  "event": {
    "file": "Security.evtx",
    "record_id": 123,
    "channel": "Security",
    "event_id": 4624,
    "computer": "WIN-01"
  },
  "fields": {}
}
```

Correlation JSONL result shape:

```json
{
  "type": "sigma_correlation_match",
  "timestamp": "2026-06-27T16:05:00Z",
  "rule": {},
  "group": {},
  "window": {
    "start": "2026-06-27T16:00:00Z",
    "end": "2026-06-27T16:05:00Z"
  },
  "matches": []
}
```

## 9. Error Handling

Errors should be classified:

1. input discovery errors.
2. EVTX parse errors.
3. malformed event records.
4. Sigma parse errors.
5. unsupported Sigma semantics.
6. query parse errors.
7. output serialization errors.

Default policy:

1. Continue past per-file parse errors.
2. Continue past unsupported rules unless `--strict`.
3. Exit non-zero if no input could be processed, no rules could be loaded for `hunt`, or query parsing fails.

## 10. Crate Layout

Suggested initial modules:

```text
src/
  main.rs
  cli.rs
  input/
    mod.rs
    discover.rs
    evtx.rs
  event/
    mod.rs
    fields.rs
    normalize.rs
  query/
    mod.rs
    ast.rs
    parser.rs
    planner.rs
    eval.rs
  sigma/
    mod.rs
    model.rs
    loader.rs
    condition.rs
    modifiers.rs
    planner.rs
    mapping.rs
    correlation.rs
  output/
    mod.rs
    pretty.rs
    json.rs
    csv.rs
  runtime/
    mod.rs
    pipeline.rs
    stats.rs
```

Likely dependencies:

1. `clap` for CLI.
2. `evtx` for EVTX parsing.
3. `serde`, `serde_json`, `noyalib` for data model and YAML/JSON serialization.
4. `chrono` or `time` for timestamps.
5. `rayon` or `crossbeam` for parallel processing.
6. `regex` and `aho-corasick` for predicates.
7. `globset` for path/rule filters.
8. `comfy-table` or `termcolor` for terminal output.
9. `miette` or `ariadne` for query/rule diagnostics.

## 11. Implementation Milestones

### Milestone 0: CLI Skeleton

1. Add `clap` command structure.
2. Add path discovery.
3. Add stats and error reporting scaffolding.

Acceptance:

1. `stitch --help`, `stitch hunt --help`, `stitch search --help`, and `stitch dump --help` are stable.

### Milestone 1: Search MVP

1. Parse EVTX files enough to support event filtering.
2. Add normalized metadata and field lookup.
3. Implement `stql` parser and evaluator.
4. Add pretty event output.
5. Add `--fields`, `--limit`, and `--explain`.
6. Add parse error reporting.

Acceptance:

1. `stitch search -i Security.evtx -q 'event.id == 4625'` returns matching failed logon events.

### Milestone 2: Hunt MVP Without Correlation

1. Load Sigma rules.
2. Implement core detection conditions and common modifiers.
3. Add built-in Windows EVTX mapping.
4. Add Chainsaw-compatible mapping file support.
5. Add pretty and JSONL hunt output.
6. Detect correlation rules and report them as skipped with a clear message.

Acceptance:

1. `stitch hunt --rules rules/windows -i logs/` runs non-correlation Sigma rules against a rule directory and emits matches.
2. Existing Chainsaw-compatible mapping files can be supplied with `--mapping`.

### Milestone 3: Hunt With Correlation

1. Parse Sigma correlation rules.
2. Build rule dependency graph.
3. Implement event-count, value-count, and temporal ordered correlations.
4. Add grouped correlation state.
5. Add bounded window state and watermarks.

Acceptance:

1. Correlation rules produce alerts from offline EVTX collections without requiring a separate post-processing command.
2. Correlation can be disabled with `--disable-correlation`.

### Milestone 4: Dump MVP

1. Stream EVTX records to JSONL.
2. Add JSON, CSV, and XML output options.
3. Add field projection.
4. Add `--raw`, `--flatten`, `--compact`, and `--pretty`.
5. Add speed-first buffered output paths.

Acceptance:

1. `stitch dump -i Security.evtx --format jsonl` emits valid JSONL.
2. `stitch dump -i Security.evtx --format csv --fields timestamp,event.id,computer` emits projected CSV.

### Post-MVP Hardening

1. Build deeper rule/query plans.
2. Add more metadata prefilters.
3. Add literal keyword prefilters.
4. Add benchmark harness.
5. Add summary output.
6. Add better diagnostics.
7. Add documentation examples.
8. Add packaging and release workflow.

## 12. Test Strategy

Unit tests:

1. Query parser.
2. Query evaluator.
3. Sigma condition parser.
4. Sigma modifiers.
5. Field mapping.
6. Correlation window logic.

Integration tests:

1. Dump known EVTX fixture.
2. Search known EVTX fixture.
3. Hunt known EVTX fixture with small ruleset.
4. Correlation rule fixture.
5. Malformed EVTX handling.
6. Malformed Sigma handling.

Golden output tests:

1. Pretty search output.
2. Pretty hunt output.
3. JSONL schemas.
4. CSV projection behavior.

Fuzz/property tests:

1. Query parser should not panic.
2. Field lookup should not panic on unusual JSON structures.
3. Rule loader should not panic on malformed YAML.

## 13. Open Questions

1. Should `stitch` prioritize full Sigma semantic compatibility first, or Chainsaw-like speed/usability first with explicit unsupported-rule warnings?
2. Should correlation default to `host` scope or `global` scope? `host` is safer for common Windows detection semantics, but `global` may be expected for merged collections.
3. Should `search` support aggregation in the first public version, or stay focused on fast event filtering and pretty event returns?
4. What exact output shape should downstream users rely on: ECS-like fields, Sigma-like fields, or a `stitch`-native schema?
5. Should CSV dump without `--fields` perform schema discovery, or should it require explicit fields to preserve speed-first behavior?
6. What platforms are release targets for v0.1: Linux only, or Linux/macOS/Windows from the start?
7. Should `stitch hunt` include built-in rule update helpers, or leave repository management to Git?

## 14. Recommended Decisions

1. Use the Rust `evtx` crate initially, behind a local parser abstraction.
2. Build the project in this order: CLI skeleton, search, hunt without correlation, hunt with correlation, then dump.
3. Implement `stql` as the search language: KQL-inspired, small, documented, and compiled into the same predicate planner as Sigma.
4. Store event fields in a normalized-plus-raw structure so output remains faithful while filters stay fast.
5. Treat Sigma correlation as a streaming window engine fed by single-event rule matches.
6. Make JSONL the default machine format.
7. Keep correlation enabled by default when correlation rules are present, but expose `--disable-correlation`.
8. Emit warnings for unsupported Sigma features by default and hard-fail under `--strict`.
9. Make Chainsaw-compatible mapping files the primary mapping contract.
