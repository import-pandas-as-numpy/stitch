# Stitch Handoff

Last updated: 2026-06-28

## Current State

Current milestone: Post-MVP Hardening.

Milestone 0 is functionally complete:

1. `clap` CLI exists with `hunt`, `search`, and `dump`.
2. Shared global options exist for input paths, path-list files, recursive discovery control, worker count, timestamp bounds, include/exclude globs, strict mode, quiet mode, and stats.
3. EVTX path discovery supports single files and recursive directory trees by default.
4. Include/exclude glob filtering is implemented.
5. `dump` is implemented for JSONL, JSON, and projected CSV output.

Search MVP is functionally complete for current purposes:

1. EVTX files stream through the `evtx` crate.
2. Events normalize source identity and common metadata:
   1. timestamp
   2. record ID
   3. channel
   4. provider
   5. event ID
   6. computer
   7. source file
   8. collection root
3. `stitch search` parses a query once, streams events, evaluates matches, honors `--limit`, and emits pretty or JSON output.
4. Pretty `search` output now prints the full raw event record as a YAML-like nested block when no `| keep` or `--fields` projection is supplied.
5. Pretty projected `search` output keeps the metadata/source header and only prints selected fields.
6. Source identity is preserved and displayed so one EVTX file can contain multiple machine names safely.
7. Non-strict parse failures are counted and a bounded sample is shown in `--stats` output.
8. Detailed non-strict parse failures can be written as JSONL with `search --errors <FILE>`.
9. Common CLI options are global and may appear before or after subcommands.
10. Generated EVTX fixture integration tests now cover search against normalized metadata, raw EventData paths, projections, CIDR helpers, regex matching, limits, stats, and recursive discovery.

Milestone 2 and Milestone 3 are functionally complete for the current supported subset:

1. Sigma YAML loading uses `noyalib`, not deprecated `serde_yaml` or `serde_yml`.
2. `hunt` loads `.yml` and `.yaml` rules from files or directories.
3. Multi-document Sigma files can contain base rules and correlation documents.
4. `hunt` evaluates the first supported Sigma subset: field equality/list matching with boolean conditions over named selections.
5. Supported Sigma modifiers currently include `contains`, `startswith`, `endswith`, `all`, `cased`, `re`, and `cidr`.
6. Supported Sigma condition patterns include `1 of selection_*`, `all of selection_*`, and `1/all of them`.
7. Hunt output supports pretty, JSON, and JSONL match rendering for supported rules.
8. Pretty non-correlation hunt output uses Chainsaw-inspired Unicode tables containing timestamp, detections, event ID/record ID, level, host, and wrapped/truncated payload columns by default; `--full` expands the table with source columns such as channel and file and disables payload truncation while preserving renderer-controlled wrapping.
9. Bare Windows Sigma fields now map to EVTX `Event.EventData` by default, while common metadata aliases such as `EventID`, `Channel`, `ProviderName`, and `Computer` resolve through normalized fields.
10. Sigma string equality and string modifiers are case-insensitive by default unless `cased` is present.
11. `hunt` now applies `--rule-status`, `--level`, `--tag`, `--min-level`, and `--exclude-rule`.
12. Sigma detection support now includes condition lists as OR, lists of maps as OR alternatives, keyword search identifiers, `|all` keyword lists, `null` field values, and `*`/`?` string wildcards.
13. Non-correlation Sigma modifiers now cover `all`, `cased`, `contains`, `startswith`, `endswith`, `exists`, `neq`, `lt`, `lte`, `gt`, `gte`, `re` with `i/m/s`, `cidr`, `windash`, Base64/UTF-16 encodings, `fieldref`, and time extractors. `expand` is rejected because placeholder configuration is not implemented.
14. Initial Sigma `event_count`, `value_count`, `temporal`, and `temporal_ordered` correlation support is implemented with grouped streaming windows, `condition` thresholds where applicable, `timespan`, rule references by `name`/`id`/`title`, `--correlation-scope`, and JSONL/pretty output.
15. Parser-focused Sigma syntax fixtures now cover valid base rules, valid correlation rules, malformed base rules, malformed correlation rules, and broken YAML.
16. Correlation output can include selected contributing-event fields with `--correlation-event-field`; pretty output uses a Unicode correlation table with timestamp, detections, matches, level, group, and wrapped/truncated payload columns by default, with `--full` adding the window column and disabling payload truncation.
17. `--correlation-lateness` is now enforced as an event-time watermark. Bounded out-of-order matches can complete, events older than the watermark are ignored, and stale state is pruned without expanding rule `timespan` windows.
18. Host-scoped correlation is covered against mixed-host streams, and global scope is covered for intentional cross-host correlation.

Milestone 4 is functionally complete:

1. `stitch dump` supports `--format jsonl`, which is also the default.
2. `dump --format json` emits a JSON array of the same record objects, with `--compact` and `--pretty` controls.
3. Default JSONL/JSON dump records include normalized metadata, source identity, and the raw parsed EVTX event.
4. `dump --fields FIELD ...` emits normalized metadata, source identity, and only selected field values.
5. `dump --raw` emits only the parsed raw EVTX JSON shape.
6. `dump --output <FILE>` writes JSONL/JSON/CSV to a file, while `--stats` reports counts on stdout.
7. `dump --fail-fast` and global `--strict` stop on the first parse error; `dump --errors <FILE>` writes non-strict parse errors as JSONL.
8. `dump --format csv` emits projected CSV and requires explicit `--fields`.
9. CSV without `--fields` is intentionally rejected to avoid schema discovery or buffering in the speed-first dump path.
10. CSV rejects `--raw`; use explicit `--fields` to choose CSV columns.
11. Dump format `xml` is intentionally out of scope for the MVP and remains an explicit unsupported-format error.

Post-MVP Rayon work has started:

1. File-level Rayon processing is the default when more than one input file is available and the mode can be parallelized safely.
2. `--jobs 0`, the CLI default, uses Rayon's system-sized worker pool; `--jobs 1` forces sequential file processing.
3. File-level Rayon processing is wired for `search` when `--limit` is not set.
4. File-level Rayon processing is wired for `dump` across JSONL, JSON, and projected CSV.
5. File-level Rayon processing is wired for non-correlation `hunt`.
6. Correlation-enabled `hunt` intentionally remains sequential because correlation state is event-order and watermark sensitive.
7. Concurrency integration tests compare `--jobs 1` and `--jobs 4` under 10-second child-process timeouts.
8. Local repeated-fixture timings are recorded in `docs/performance.md`; `--jobs 4` was roughly 3.5x to 4.0x faster than `--jobs 1` on dump/search/non-correlation hunt fixture workloads.
9. Search now builds safe metadata prefilters for `and`-required normalized predicates on timestamp, event ID, channel, provider, and computer before running the full STQL predicate.
10. Sigma rules now build safe metadata prefilters for required positive detection predicates on timestamp, event ID, channel, provider, and computer.
11. Hunt now reuses a per-event Sigma context so keyword-heavy rules share one cached raw-event string per event instead of serializing the same event for each keyword predicate.
12. Sigma `logsource.service` now compiles common Windows services to safe channel prefilters; unknown services stay unfiltered.
13. `scripts/bench-local.sh` provides a repeatable local benchmark harness that builds and runs the intended local binary, generates repeated fixture paths, and writes `target/benchmarks/report.md`.
14. CLI integration coverage now checks readable create errors for dump output files and search parse-error files.
15. `docs/output.md` documents search, hunt, correlation, dump, `--full`, and parallelism examples.
16. GitHub Actions CI/security workflows are added with least-privilege permissions, pinned official actions, no persisted checkout credentials, Cargo registry/git caching, benchmark smoke coverage, and `zizmor` workflow auditing.

## Current `stql` Support

Boolean logic:

```text
and
or
not
(...)
```

Predicates:

```text
==
!=
<
<=
>
>=
contains
contains_ci
in (...)
=~
!~
exists(field)
/regex/i
cidr_contains(field, "CIDR")
ip_in_cidr(field, "CIDR")
```

Projection:

```text
event.id == 4624 | keep timestamp, event.id, computer, Event.EventData.TargetUserName
```

Notes:

1. `| keep ...` controls returned fields.
2. CLI `--fields` overrides `| keep ...` when both are present.
3. Regex patterns are quoted Rust regex strings, for example `provider =~ "(?i)wmi"`.
4. Regex patterns may also use slash-delimited literals, for example `provider =~ /wmi/i`.
5. `cidr_contains` and `ip_in_cidr` support IPv4 and IPv6 CIDR membership checks.
6. Timestamp comparisons use typed RFC3339 parsing for normalized timestamp fields.
7. Offset-less timestamp strings default to UTC.

## Local Windows Log Evaluation

Live logs at:

```text
/mnt/c/Windows/System32/winevt/Logs
```

were visible but not directly readable from WSL because Windows exposed them with mode `0000`.

Temporary exported logs used for smoke testing were deleted at the stop point and should not be assumed to exist:

```text
/mnt/c/Users/44jmn/AppData/Local/Temp/stitch-system.evtx
/mnt/c/Users/44jmn/AppData/Local/Temp/stitch-application.evtx
```

Recreate them from Windows PowerShell:

```powershell
wevtutil epl System $env:TEMP\stitch-system.evtx
wevtutil epl Application $env:TEMP\stitch-application.evtx
```

Or recreate them from WSL if Windows executable interop is available:

```bash
/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile -Command 'wevtutil epl System $env:TEMP\stitch-system.evtx; wevtutil epl Application $env:TEMP\stitch-application.evtx; Write-Output $env:TEMP'
```

The previous Windows temp path resolved to:

```text
C:\Users\44jmn\AppData\Local\Temp
```

which maps to:

```text
/mnt/c/Users/44jmn/AppData/Local/Temp
```

Security export may require elevated Windows privileges:

```powershell
wevtutil epl Security $env:TEMP\stitch-security.evtx
```

Validated smoke queries:

```bash
cargo run -- -i /mnt/c/Users/44jmn/AppData/Local/Temp/stitch-system.evtx \
  search -q 'event.id in (6005, 6006)' \
  --limit 2 --fields provider --fields computer --fields timestamp
```

```bash
cargo run -- -i /mnt/c/Users/44jmn/AppData/Local/Temp/stitch-application.evtx \
  search -q 'provider =~ "(?i)wmi" | keep timestamp, provider, event.id, computer' \
  --limit 1
```

```bash
cargo run -- -i /mnt/c/Users/44jmn/AppData/Local/Temp/stitch-application.evtx \
  search -q 'timestamp >= "2026-03-21T06:41:00" and timestamp < "2026-03-21T06:42:00"' \
  --limit 1 --fields timestamp --fields provider
```

## Important Findings

The `evtx` crate's JSON shape varies for common fields:

1. `TimeCreated.SystemTime` may appear as `TimeCreated.#attributes.SystemTime`.
2. `EventID` may appear as `EventID.#text`.

Both shapes are currently handled in normalized metadata.

The exported `System.evtx` demonstrated that one EVTX can contain events from multiple machines:

1. `WIN-H5M91PI2VT5`
2. `DESKTOP-4N8OHFD`
3. `Bifrost`

This validates the source identity requirement in `docs/project-spec.md`.

## Verification Baseline

The following commands passed at stop time:

```bash
cargo fmt --all -- --check
cargo check --all-targets --all-features
cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic
cargo test --all-targets --all-features
```

Current test count: 87 unit tests and 30 integration tests passed.

## Next Work

Continue Post-MVP hardening:

1. Continue Rayon hardening beyond file-level search, dump, and non-correlation hunt.
2. Build deeper rule/query plans.
3. Add metadata and keyword prefilters.
4. Add benchmark harness and memory-focused measurements.
5. Continue keeping dump output streaming and buffered where practical.

## Files To Read First Next Session

1. `AGENTS.md`
2. `docs/project-spec.md`
3. `docs/project-log.md`
4. `docs/handoff.md`
5. `docs/stql.md`
6. `docs/dump.md`
7. `docs/performance.md`
8. `docs/output.md`
9. `docs/ci.md`
10. `src/query/mod.rs`
11. `src/runtime/mod.rs`
12. `src/event/mod.rs`
13. `src/sigma/mod.rs`
