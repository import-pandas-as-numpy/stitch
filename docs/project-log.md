# Stitch Project Log

## 2026-06-28

Current milestone: Post-MVP Hardening.

Milestone 3 status: Complete for the current supported subset.
Milestone 4 status: Complete for the current supported subset; XML output is intentionally out of scope.

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
30. Wired `--correlation-lateness` into Sigma correlation as an event-time watermark, with stale-state pruning and unit coverage for bounded out-of-order and too-late matches.
31. Added mixed-host correlation scope regressions proving default `host` scope does not mix computers while `global` scope can correlate across hosts.
32. Started Milestone 4 by implementing `stitch dump` JSONL output for generated EVTX fixtures.
33. Added dump JSONL support for default normalized-plus-raw records, `--fields` projection, `--raw`, `--output <FILE>`, `--stats`, `--fail-fast`, and `--errors`.
34. Added `dump --format json` array output with compact/pretty rendering, stdout and output-file support, and generated-fixture integration coverage.
35. Added projected `dump --format csv` output with CSV escaping, output-file support, and a clear error when `--fields` is omitted to avoid schema discovery.
36. Closed Milestone 4 by documenting XML as intentionally out of scope and rejecting unsupported CSV option combinations instead of silently ignoring them.
37. Added Rayon as a runtime dependency for file-level parallel processing.
38. Wired Rayon for no-limit `search`, `dump`, and non-correlation `hunt`, preserving deterministic discovery-order output.
39. Kept correlation-enabled `hunt` sequential because correlation state is event-order and watermark sensitive.
40. Added timeout-guarded concurrency integration tests comparing `--jobs 1` and `--jobs 4`.
41. Added `docs/performance.md` to record local Rayon timing notes and measurement commands.
42. Recorded local repeated-fixture Rayon timings: dump CSV improved from `real 9.02` to `2.55`, quiet search from `8.91` to `2.21`, and quiet non-correlation hunt from `8.48` to `2.22` when moving from `--jobs 1` to `--jobs 4`.
43. Clarified Rayon execution policy: concurrency is the default via `--jobs 0` using Rayon's system-sized worker pool; sequential execution is explicit with `--jobs 1` or reserved for single-file input, `search --limit`, and correlation-enabled `hunt`.
44. Beautified default human output: unprojected pretty `search` now shows the full raw event as a YAML-like nested block, projected search stays concise, non-correlation `hunt` renders Chainsaw-inspired Unicode tables with event context and payload columns, and pretty correlation output renders selected contributing-event fields in an in-table payload column.

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
26. `cargo test correlation_lateness -- --nocapture`
27. `cargo fmt --all -- --check`
28. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
29. `cargo check --all-targets --all-features`
30. `cargo test --all-targets --all-features`
31. `cargo test scoped_correlation -- --nocapture`
32. `cargo test --test generated_evtx_fixtures dump_jsonl -- --nocapture`
33. `cargo fmt --all -- --check`
34. `cargo check --all-targets --all-features`
35. `cargo test --all-targets --all-features`
36. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
37. `cargo test --test generated_evtx_fixtures dump_json -- --nocapture`
38. `cargo fmt --all -- --check`
39. `cargo check --all-targets --all-features`
40. `cargo test --all-targets --all-features`
41. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
42. `cargo test --test generated_evtx_fixtures dump_csv -- --nocapture`
43. `cargo fmt --all -- --check`
44. `cargo check --all-targets --all-features`
45. `cargo test --all-targets --all-features`
46. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
47. `cargo test --test generated_evtx_fixtures dump_csv -- --nocapture`
48. `cargo fmt --all -- --check`
49. `cargo check --all-targets --all-features`
50. `cargo test --all-targets --all-features`
51. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
52. `cargo test --test generated_evtx_fixtures parallel_jobs -- --nocapture`
53. `cargo test --test sigma_hunt_fixtures jobs -- --nocapture`
54. Local timing commands recorded in `docs/performance.md`.
55. `cargo fmt --all -- --check`
56. `cargo check --all-targets --all-features`
57. `cargo test --all-targets --all-features`
58. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
59. `cargo run --quiet -- search -i tests/fixtures/evtx/security-auth.evtx -q "event.id == 4625" --limit 1`
60. `cargo run --quiet -- search -i tests/fixtures/evtx/security-auth.evtx -q "event.id == 4625 | keep timestamp, event.id, computer, Event.EventData.TargetUserName" --limit 1`
61. `cargo run --quiet -- hunt -i tests/fixtures/evtx/sysmon-activity.evtx --rules tests/fixtures/sigma/sysmon_powershell_network.yml --summary`
62. `cargo run --quiet -- hunt -i tests/fixtures/correlation-evtx/sysmon-correlation.evtx --rules tests/fixtures/sigma-correlation/sysmon_process_activity_count.yml --correlation-event-field Event.EventData.ProcessGuid --correlation-event-field Event.EventData.Image --correlation-event-limit 2`
63. `cargo test --test generated_evtx_fixtures search_parallel_jobs_match_single_worker_with_timeout -- --nocapture`
64. `cargo test --test sigma_hunt_fixtures -- --nocapture`
65. `cargo fmt --all -- --check`
66. `cargo check --all-targets --all-features`
67. `cargo test --all-targets --all-features`
68. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
69. Corrected pretty `hunt`/correlation output from table-like rows to bordered tables, then reran `cargo test --all-targets --all-features`, `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`, `cargo fmt --all -- --check`, and `git diff --check`.
70. Reworked pretty `hunt` and correlation tables after reviewing Chainsaw's `src/cli.rs` implementation: context and payload now live inside Unicode table columns with wrapped/truncated field content.
71. Hardened pretty table rendering so column widths are computed centrally with explicit caps, raw newlines are normalized before wrapping, long tokens are split by the renderer, and a unit regression verifies table alignment with embedded newlines and Unicode rule text.
72. Added `hunt --full` as the explicit escape hatch for expanded pretty tables: default hunt output stays compact, while full output restores source columns such as channel/file and disables payload truncation without bypassing table wrapping.
73. `cargo fmt --all -- --check`
74. `cargo check --all-targets --all-features`
75. `cargo test --all-targets --all-features`
76. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
77. `git diff --check`
78. `cargo run --quiet -- hunt -i tests/fixtures/evtx/sysmon-activity.evtx --rules tests/fixtures/sigma/sysmon_powershell_network.yml --format pretty --summary`
79. `cargo run --quiet -- hunt -i tests/fixtures/evtx/sysmon-activity.evtx --rules tests/fixtures/sigma/sysmon_powershell_network.yml --format pretty --full --summary`
80. Began Post-MVP search hardening by adding safe STQL metadata prefilters for globally required `and` predicates on timestamp, event ID, channel, provider, and computer.
81. `cargo test query::tests::search_query -- --nocapture`
82. `cargo fmt --all -- --check`
83. `cargo check --all-targets --all-features`
84. `cargo test --all-targets --all-features`
85. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
86. `git diff --check`
87. Added conservative Sigma metadata prefilters for required positive detection predicates on timestamp, event ID, channel, provider, and computer, while skipping `or`, `not`, and multi-alternative selections.
88. `cargo test sigma::tests::sigma_ -- --nocapture`
89. `cargo fmt --all -- --check`
90. `cargo check --all-targets --all-features`
91. `cargo test --all-targets --all-features`
92. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
93. `git diff --check`
94. Added a reusable per-event Sigma match context so hunt can cache raw event text once per event for keyword-heavy rule evaluation.
95. `cargo test sigma::tests::sigma_event_context -- --nocapture`
96. `cargo fmt --all -- --check`
97. `cargo check --all-targets --all-features`
98. `cargo test --all-targets --all-features`
99. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
100. `git diff --check`
101. Added conservative Sigma `logsource.service` channel prefilters for common Windows services while leaving unknown services unfiltered.
102. `cargo test sigma::tests::sigma_logsource -- --nocapture`
103. `cargo fmt --all -- --check`
104. `cargo check --all-targets --all-features`
105. `cargo test --all-targets --all-features`
106. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
107. `git diff --check`
108. Added `scripts/bench-local.sh`, a repeatable local benchmark harness that builds the requested profile, runs the local binary directly, and writes `target/benchmarks/report.md`.
109. `bash -n scripts/bench-local.sh`
110. `STITCH_BENCH_PROFILE=dev STITCH_BENCH_REPETITIONS=1 scripts/bench-local.sh`
111. `cargo fmt --all -- --check`
112. `cargo check --all-targets --all-features`
113. `cargo test --all-targets --all-features`
114. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
115. `git diff --check`
116. Added CLI error-path regressions for failed dump output-file creation and failed search parse-error file creation.
117. `cargo test --test generated_evtx_fixtures create_errors -- --nocapture`
118. `cargo fmt --all -- --check`
119. `cargo check --all-targets --all-features`
120. `cargo test --all-targets --all-features`
121. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
122. `git diff --check`
123. Streamed sequential dump records directly through `DumpOutput` and documented the remaining deterministic per-input buffering used by parallel dump/search.
124. Added hunt-plan event-ID indexing so rules with required Event IDs can be skipped as a group before full Sigma evaluation.
125. Added a correlation stress regression proving lateness watermark advancement prunes stale state across groups.
126. Added a parallel malformed-EVTX search regression that verifies readable failure without hanging.
127. Added `docs/output.md` with examples for search, hunt, `hunt --full`, correlation output, dump output, and parallelism.
128. `cargo test --test generated_evtx_fixtures dump_ -- --nocapture`
129. `cargo test runtime::tests::hunt_plan_indexes_rules_by_required_event_id -- --nocapture`
130. `cargo test sigma::tests::correlation_lateness -- --nocapture`
131. `cargo test --test generated_evtx_fixtures malformed -- --nocapture`
132. `bash -n scripts/bench-local.sh`
133. `cargo fmt --all -- --check`
134. `cargo check --all-targets --all-features`
135. `cargo test --all-targets --all-features`
136. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
137. `git diff --check`
138. Added segmented GitHub Actions CI and security workflows with least-privilege permissions, pinned official actions, disabled checkout credential persistence, Cargo registry/git caching, benchmark smoke coverage, and `zizmor` workflow auditing.
139. Added `docs/ci.md` documenting the CI/CD security posture and workflow layout.
140. `zizmor --persona pedantic .github/workflows`
141. `bash -n scripts/bench-local.sh`
142. `cargo fmt --all -- --check`
143. `cargo check --all-targets --all-features`
144. `cargo test --all-targets --all-features`
145. `cargo clippy --all-targets --all-features -- -D warnings -W clippy::pedantic`
146. Audited code smells/security/performance hot paths and pinned GitHub Actions runners to `ubuntu-24.04` for more reproducible CI.
147. Benchmarked a candidate Sigma case-insensitive matching optimization before/after and rejected it because it did not improve performance (`real 3.73s` before, `real 3.88s` after on the audit fixture loop).
148. Added a performance-only quiet search/hunt fast path that scans EVTX records as JSON bytes when match results are not observable (`--quiet` without `--stats`, and without `--limit` for search).
149. Benchmarked the quiet fast path with `STITCH_BENCH_REPETITIONS=1000 scripts/bench-local.sh`: search quiet improved from `real 0.38` to `0.23`, non-correlation hunt quiet improved from `real 0.39` to `0.36` at `--jobs 1` and from `0.11` to `0.06` at `--jobs 4`, while dump stayed effectively flat.
150. Added Dependabot grouped updates for Cargo runtime dependencies, Cargo development dependencies, and GitHub Actions.
151. Configured CI to skip documentation-only changes while still running for code, tests, Cargo metadata, scripts, workflows, and Dependabot configuration.
152. Changed input discovery so omitted input paths default to the current working directory, making commands like `stitch search -q 'event.id == 4625'` valid.
153. Added a dependency-free static documentation website under `site/`, with a Vercel build configuration for publishing `site/dist` to `stitch.sudorem.dev`.
154. Adapted the docs website styling from `site-v3`: dark navy security palette, neon green/cyan accents, shield favicon, glassy header, and docs-focused layout surfaces.

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
