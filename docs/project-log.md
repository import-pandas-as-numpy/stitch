# Stitch Project Log

## 2026-06-28

Current milestone: Milestone 3, Hunt With Correlation.

Completed:

1. Added synthetic generated EVTX fixtures under `tests/fixtures/evtx`.
2. Added readable JSONL sources under `tests/fixtures/source` and regeneration notes in `tests/fixtures/README.md`.
3. Covered Security authentication/process events, System service-control events, PowerShell engine/module/script-block events, Sysmon process/network/file/DNS events, Microsoft Defender detection/remediation/configuration events, WMI Activity query/permanent-consumer events, and Task Scheduler registration/action events.
4. Used only fictional hostnames, the `EXAMPLE` domain, `example.invalid`, and documentation IP ranges.
5. Added integration tests that validate normalized metadata queries, raw `Event.EventData.*` field queries, CIDR helpers, regex matching, Defender detection context, WMI consumer context, Task Scheduler action context, and recursive nested collection discovery against the generated EVTX files.
6. Added built-in Windows Sigma field resolution for unqualified EventData fields while preserving normalized metadata aliases.
7. Added fixture-backed Sigma hunt rules for Sysmon, WMI Activity, Task Scheduler, and Defender events.
8. Added integration coverage proving `stitch hunt` can match generated EVTX fixtures through common Sigma field names.
9. Added an ad hoc `stitch search --query` integration regression using fixture data, regex matching, `contains`, `| keep`, `--limit`, and stats.
10. Added `docs/sigma.md` to document the currently supported Sigma subset and EVTX field resolution behavior.
11. Made Sigma string equality and string modifiers case-insensitive by default, with `cased` for explicit case-sensitive matching.
12. Wired `hunt` rule filters: `--rule-status`, `--level`, `--tag`, `--min-level`, and `--exclude-rule`.
13. Added unit and fixture-backed integration tests for Sigma case handling and hunt rule filtering.
14. Added broader Sigma grammar support for condition lists, lists of map alternatives, keyword searches, `|all` keyword lists, `null` values, and `*`/`?` string wildcards.
15. Added `tests/fixtures/sigma-grammar` to validate broader Sigma grammar against generated EVTX fixtures.
16. Implemented the remaining local-evaluable non-correlation Sigma modifiers: `exists`, `neq`, numeric comparisons, regex `i/m/s`, `windash`, Base64/UTF-16 encodings, `fieldref`, and time extractors.
17. Kept `expand` as a clear unsupported rule-load diagnostic because Sigma placeholder expansion requires environment-specific placeholder configuration.
18. Published a private GitHub backup at `https://github.com/import-pandas-as-numpy/stitch` and pushed the initial `main` branch.
19. Began Sigma correlation support by parsing multi-document Sigma files, retaining correlation metadata in the loader, and surfacing correlation document counts in `hunt` summaries.
20. Implemented initial streaming Sigma `event_count` correlation with grouped windows, `condition` thresholds, `timespan` parsing, rule references by `name`/`id`/`title`, and `--correlation-scope`.
21. Added JSONL and pretty correlation match rendering from `stitch hunt`.
22. Added a weave-generated Sysmon correlation EVTX fixture and fixture-backed CLI test coverage for correlation output.
23. Added Sigma `value_count` correlation support with distinct value counting from the condition `field`.
24. Added Sigma `temporal` and `temporal_ordered` correlation support over grouped streaming windows.
25. Added hunt correlation dependency planning so referenced base rules can feed correlation state even when filtered from normal alert output, while unrelated alert rules do not feed correlation state.
26. Made `--correlation-max-state` eviction deterministic by removing the oldest state group and added `correlation_state`/`correlation_evicted` hunt stats.
27. Added parser-focused Sigma syntax fixtures for valid base rules, valid correlation rules, malformed base rules, malformed correlation rules, and broken YAML.
28. Added loader regression tests that validate the syntax fixture corpus and assert readable diagnostics for common typos and malformations.
29. Added selected contributing-event details for Sigma correlation output with `--correlation-event-field` and bounded pretty rendering via `--correlation-event-limit`.

Verification:

1. `PYTHONPATH=../weave python3 -m weave ...` for all seven fixture files.
2. `cargo run -- search -i tests/fixtures/evtx --query 'event.id in (4624, 4104, 7036, 22, 1116, 5861, 200)' --format jsonl --stats`
3. `cargo run -- search -i tests/fixtures/evtx/security-auth.evtx --query 'Event.EventData.TargetUserName == "service-build"' --fields Event.EventData.IpAddress --fields computer --format jsonl --stats`
4. `cargo run -- search -i tests/fixtures/evtx/sysmon-activity.evtx --query 'event.id == 3 and cidr_contains(Event.EventData.DestinationIp, "203.0.113.0/24") and Event.EventData.Image =~ /powershell\.exe$/i' --fields Event.EventData.DestinationIp --fields Event.EventData.DestinationHostname --format jsonl --stats`
5. `cargo run -- search -i tests/fixtures/evtx/defender-operational.evtx --query 'event.id == 1116 and Event.EventData.Path contains "payload.bin"' --fields Event.EventData.Path --fields channel --format jsonl --stats`
6. `cargo run -- search -i tests/fixtures/evtx/wmi-activity.evtx --query 'event.id == 5861 and Event.EventData.CONSUMER contains "ExampleInventoryConsumer"' --fields Event.EventData.Namespace --fields Event.EventData.CONSUMER --format jsonl --stats`
7. `cargo run -- search -i tests/fixtures/evtx/task-scheduler-operational.evtx --query 'event.id == 200 and Event.EventData.ActionName contains_ci "powershell.exe"' --fields Event.EventData.TaskName --fields Event.EventData.EnginePID --format jsonl --stats`
8. `cargo run -- search -i tests/fixtures/collections/example-case --query 'event.id == 7036 and computer == "LAB-SRV-002"' --fields source.collection_root --fields source.file_path --format jsonl --stats`
9. `cargo test --test sigma_hunt_fixtures -- --nocapture`
10. `cargo test runtime::tests::hunt_rule_filters -- --nocapture`
11. `cargo test sigma::tests:: -- --nocapture`
12. `cargo fmt --all -- --check`
13. `cargo check --all-targets --all-features`
14. `cargo test --all-targets --all-features`
15. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
16. `PYTHONPATH=../weave python3 -m weave tests/fixtures/source/sysmon-correlation.jsonl tests/fixtures/correlation-evtx/sysmon-correlation.evtx --seed 1010`
17. `cargo test correlation -- --nocapture`
18. `cargo fmt --all -- --check`
19. `cargo test --all-targets --all-features`
20. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
21. `cargo test sigma_syntax -- --nocapture`
22. `cargo fmt --all -- --check`
23. `cargo test --all-targets --all-features`
24. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
25. `cargo check --all-targets --all-features`

## 2026-06-27

Current milestone: Milestone 2, Hunt MVP Without Correlation.

Completed:

1. Created the initial CLI structure with `hunt`, `search`, and `dump` subcommands.
2. Added shared CLI options for input paths, path-list files, recursion control, workers, timestamp bounds, include/exclude globs, strict mode, quiet mode, and stats.
3. Implemented EVTX path discovery for single files and recursive directory trees.
4. Added include/exclude glob filtering for discovered inputs.
5. Added command dispatch scaffolding and placeholder runtime behavior.
6. Added strict crate-level unsafe prohibition.
7. Added dependency review documentation.
8. Added tests for recursive discovery, shallow discovery, glob filtering, and query source labeling.

Remaining in Milestone 0:

1. Replace placeholder runtime behavior with richer command summaries if needed.
2. Add integration tests for CLI help output once the command text stabilizes.
3. Decide whether `hunt` and `dump` placeholders should exit successfully or fail until their milestones begin.

Verification:

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
3. `cargo test --all-targets --all-features`

Notes:

1. `rustfmt` and `clippy` were installed into the active Rust toolchain.
2. System C build tools are required for dependency build scripts.

Milestone 1 progress:

1. Added the local normalized `Event` model with source identity and common EVTX metadata.
2. Added EVTX streaming through the `evtx` crate.
3. Implemented initial `stql` parsing and evaluation for boolean expressions, comparisons, `contains`, `contains_ci`, and `exists`.
4. Wired `stitch search` to discover inputs, parse EVTX records, evaluate one compiled query, honor `--limit`, and emit pretty or JSON output.
5. Added `--explain` support for search query plans.
6. Added `/docs/stql.md` to document current query semantics and limitations.
7. Added dependency review entries for `evtx` and `serde_json`.
8. Added `stql` `in (...)` list matching.
9. Added quoted regex matching with `=~` and `!~`, compiled during query parsing.
10. Added typed RFC3339 timestamp comparisons for normalized timestamp fields.
11. Split search JSON output behavior so `jsonl` remains compact and `json` is pretty-printed.
12. Timestamp comparisons now treat offset-less timestamp strings as UTC.
13. Added `stql` `| keep field, field.two` projection support for search result fields.
14. Improved non-strict search parse-error reporting by including bounded skipped-record samples in `--stats` output.
15. Added slash-delimited regex literals such as `/powershell/i`.
16. Expanded STQL tests to cover the documented syntax, lexer tokens, all current operators, literals, boolean precedence, pipeline projections, and invalid syntax cases.
17. Added explicit STQL tests and documentation for chained `and`/`or` precedence and nested parenthetical grouping.
18. Added `search --errors <FILE>` to write detailed skipped parse errors as JSONL in non-strict mode.
19. Added STQL CIDR helper functions with IPv4/IPv6 coverage: `cidr_contains(field, "CIDR")` and `ip_in_cidr(field, "CIDR")`.
20. Made common CLI options global so they can appear before or after subcommands.

Milestone 2 progress:

1. Added initial Sigma YAML rule discovery/loading with `noyalib`.
2. Detect and skip Sigma correlation rules with an explicit skipped-rule count.
3. Wired `hunt` to load rules and stream EVTX events through supported rules.
4. Added first Sigma detection evaluation slice for `condition: selection` rules with field equality and list matching.
5. Added boolean Sigma condition evaluation for selection references with `and`, `or`, `not`, and nested parentheses.
6. Added common Sigma string modifiers: `contains`, `startswith`, `endswith`, and `all`.
7. Added Sigma condition patterns `1 of ...`, `all of ...`, wildcard selection matching, and `them`.
8. Added JSON and JSONL hunt match rendering with rule metadata and event source identity.
9. Added Sigma `re` and `cidr` modifiers with rule-load validation and compiled regex/CIDR matching.

Remaining in Milestone 1:

1. Add integration tests against a real or generated EVTX fixture when a suitable fixture source is available.

Local Windows log evaluation:

1. Live logs under `/mnt/c/Windows/System32/winevt/Logs` were visible but not directly readable from WSL because they were exposed with mode `0000`.
2. Exported `System` and `Application` logs through Windows `wevtutil` into the Windows user temp directory.
3. Validated `stitch search` against exported `System.evtx` and `Application.evtx`.
4. Found and fixed EVTX JSON shape differences:
   1. `TimeCreated.SystemTime` may appear as `TimeCreated.#attributes.SystemTime`.
   2. `EventID` may appear as `EventID.#text`.
5. Confirmed a single exported `System.evtx` can contain multiple machine names and that search output distinguishes them from event metadata.
6. Example validated query: `event.id == 6005`, which returned `WIN-H5M91PI2VT5`, `DESKTOP-4N8OHFD`, and `Bifrost` from the same EVTX file.
7. Validated `event.id in (6005, 6006)` against exported `System.evtx`.
8. Validated `provider =~ "(?i)wmi"` against exported `Application.evtx`.
9. Validated `timestamp >= "2026-03-21T06:41:00Z"` and pretty JSON output against exported `Application.evtx`.
10. Validated `| keep timestamp, provider, computer` style projections against exported local logs.

Stop point:

1. Work intentionally paused after adding Sigma `re` and `cidr` modifiers and validating the current Hunt MVP slice.
2. A fresh-session handoff exists at `/docs/handoff.md`.
3. Next session should continue Milestone 2 with broader Sigma modifier support, built-in Windows EVTX mapping, and Chainsaw-compatible mapping files.
4. Exported temporary EVTX files under the Windows temp directory were deleted after validation; recreate them with `wevtutil epl` before future local-log smoke tests.
5. Latest verification: `cargo fmt --all -- --check`, `cargo check --all-targets --all-features`, `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`, and `cargo test --all-targets --all-features`.
6. Current unit test count: 51 passed.
