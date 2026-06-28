# Stitch Handoff

Last updated: 2026-06-28

## Current State

Current milestone: Milestone 3, Hunt With Correlation.

Milestone 0 is functionally complete:

1. `clap` CLI exists with `hunt`, `search`, and `dump`.
2. Shared global options exist for input paths, path-list files, recursive discovery control, worker count, timestamp bounds, include/exclude globs, strict mode, quiet mode, and stats.
3. EVTX path discovery supports single files and recursive directory trees by default.
4. Include/exclude glob filtering is implemented.
5. `dump` remains a placeholder command.

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
4. Source identity is preserved and displayed so one EVTX file can contain multiple machine names safely.
5. Non-strict parse failures are counted and a bounded sample is shown in `--stats` output.
6. Detailed non-strict parse failures can be written as JSONL with `search --errors <FILE>`.
7. Common CLI options are global and may appear before or after subcommands.
8. Generated EVTX fixture integration tests now cover search against normalized metadata, raw EventData paths, projections, CIDR helpers, regex matching, limits, stats, and recursive discovery.

Milestone 2 is functionally complete for the current supported subset:

1. Sigma YAML loading uses `noyalib`, not deprecated `serde_yaml` or `serde_yml`.
2. `hunt` loads `.yml` and `.yaml` rules from files or directories.
3. Multi-document Sigma files can contain base rules and correlation documents.
4. `hunt` evaluates the first supported Sigma subset: field equality/list matching with boolean conditions over named selections.
5. Supported Sigma modifiers currently include `contains`, `startswith`, `endswith`, `all`, `cased`, `re`, and `cidr`.
6. Supported Sigma condition patterns include `1 of selection_*`, `all of selection_*`, and `1/all of them`.
7. Hunt output supports pretty, JSON, and JSONL match rendering for supported rules.
8. Bare Windows Sigma fields now map to EVTX `Event.EventData` by default, while common metadata aliases such as `EventID`, `Channel`, `ProviderName`, and `Computer` resolve through normalized fields.
9. Sigma string equality and string modifiers are case-insensitive by default unless `cased` is present.
10. `hunt` now applies `--rule-status`, `--level`, `--tag`, `--min-level`, and `--exclude-rule`.
11. Sigma detection support now includes condition lists as OR, lists of maps as OR alternatives, keyword search identifiers, `|all` keyword lists, `null` field values, and `*`/`?` string wildcards.
12. Non-correlation Sigma modifiers now cover `all`, `cased`, `contains`, `startswith`, `endswith`, `exists`, `neq`, `lt`, `lte`, `gt`, `gte`, `re` with `i/m/s`, `cidr`, `windash`, Base64/UTF-16 encodings, `fieldref`, and time extractors. `expand` is rejected because placeholder configuration is not implemented.
13. Initial Sigma `event_count`, `value_count`, `temporal`, and `temporal_ordered` correlation support is implemented with grouped streaming windows, `condition` thresholds where applicable, `timespan`, rule references by `name`/`id`/`title`, `--correlation-scope`, and JSONL/pretty output.
14. Parser-focused Sigma syntax fixtures now cover valid base rules, valid correlation rules, malformed base rules, malformed correlation rules, and broken YAML.
15. Correlation output can include selected contributing-event fields with `--correlation-event-field`; pretty output bounds those details with `--correlation-event-limit`.

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

Current test count: 70 unit tests and 13 integration tests passed.

## Next Work

Continue Milestone 3, Hunt With Correlation:

1. Add more fixture-backed correlation runtime coverage.
2. Continue hardening max-state behavior under low-buffer and out-of-order event streams.
3. Expand syntax fixtures as unsupported Sigma grammar is intentionally added or rejected.

## Files To Read First Next Session

1. `AGENTS.md`
2. `docs/project-spec.md`
3. `docs/project-log.md`
4. `docs/handoff.md`
5. `docs/stql.md`
6. `src/query/mod.rs`
7. `src/runtime/mod.rs`
8. `src/event/mod.rs`
9. `src/sigma/mod.rs`
