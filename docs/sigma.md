# Sigma Support

`stitch hunt` loads Sigma YAML rules from files or directories and evaluates the
currently supported detection and correlation subset against EVTX input.

## Supported Rule Types

Supported:

1. Regular Sigma rules with a `detection` mapping.
2. Rules with named selections and a string `condition`.
3. Rules with a list of condition strings, evaluated as OR.
4. Multi-document Sigma YAML files.
5. Sigma `event_count`, `value_count`, `temporal`, and `temporal_ordered`
   correlation documents with `rules`, `group-by`, `condition`, and `timespan`.

Skipped:

1. Correlation types other than `event_count`, `value_count`, `temporal`, and
   `temporal_ordered` are rejected as unsupported.

Unsupported rule shapes fail at load time with the rule path and a diagnostic.

During rule loading, `stitch` builds conservative metadata prefilters for
required `and`/`all of` predicates on normalized fields such as event ID,
channel, provider, timestamp, and computer. `or`, `not`, and multi-alternative
selection branches are not extracted because they are not globally required.
Windows `logsource.service` values for common channels such as Security, System,
Sysmon, PowerShell, Defender, WMI Activity, and Task Scheduler also compile into
channel prefilters. Unknown services are left unfiltered.
Hunt evaluation also reuses a per-event Sigma context so keyword rules can share
one cached raw-event string across all rule checks for that event.

## Human Output

Pretty `hunt` output uses Chainsaw-inspired Unicode tables. Single-event matches
include timestamp, detections, event ID/record ID, level, host, and concise
event-data payload in the default table. Long cells are wrapped and truncated.
`--full` expands pretty tables with source columns such as channel and file, and
prints full payload content while preserving renderer-controlled wrapping. Raw
newlines are normalized before rendering, and table wrapping is controlled by
the table renderer so cell content cannot desynchronize row widths.

Pretty correlation output uses a correlation table with timestamp, correlation
rule, match count, level, group, and payload columns. `--full` also includes the
window column and disables payload truncation. The payload uses only the
contributing-event fields requested with `--correlation-event-field`, bounded by
`--correlation-event-limit`.

## Conditions

Supported condition syntax:

```text
selection
selection_a and selection_b
selection_a or selection_b
not filter
(selection_a or selection_b) and not filter
1 of selection_*
all of selection_*
1 of them
all of them
```

If `condition` is a YAML list, `stitch` evaluates the listed condition strings
as an OR expression.

## Correlation

Initial correlation support is streaming and windowed. `event_count`
correlation documents count matching base Sigma rule results over a `timespan`.
`value_count` correlation documents count distinct values from the condition
`field` over the same window. `temporal` correlation documents match when every
referenced rule appears within the window. `temporal_ordered` additionally
requires the listed `rules` order. Correlation matches are emitted when the
correlation requirement is reached.

Supported correlation condition operators:

```text
gt
gte
eq
lte
lt
>
>=
==
<=
<
```

Examples:

```yaml
type: correlation
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    gte: 5
  timespan: 10m
```

```yaml
type: correlation
correlation:
  type: value_count
  rules:
    - failed_logon
  group-by:
    - TargetUserName
  condition:
    field: IpAddress
    gte: 3
  timespan: 10m
```

```yaml
type: correlation
correlation:
  type: temporal_ordered
  rules:
    - process_start
    - process_network
    - process_file_write
  group-by:
    - ProcessGuid
  timespan: 5m
```

Supported timespan suffixes:

```text
s
m
h
d
```

`rules` entries can reference base rules by Sigma `name`, `id`, or `title`.
`group-by` fields use the same EVTX field alias behavior as detections.
Correlation state is scoped by `--correlation-scope`, defaulting to `host`.
Use `--disable-correlation` to load only base detection rules.

Correlation output always includes contributing event metadata such as
timestamp, record ID, channel, event ID, computer, source file, and contributing
base rule. To include selected event details, repeat
`--correlation-event-field FIELD`. The field names use the same Sigma alias
resolution as detections, so fields such as `Image`, `CommandLine`,
`DestinationIp`, `TargetFilename`, and `Event.EventData.TargetUserName` work.

Pretty correlation output prints at most `--correlation-event-limit` contributing
events per correlation match when selected event fields are present. The default
limit is `3`; set it to `0` to hide contributing-event details in pretty output.
JSON and JSONL output include the selected fields for every contributing event.
`stitch` intentionally stores only selected event fields in correlation state,
not full raw EVTX payloads, to keep correlation memory bounded.

`--correlation-max-state` bounds the number of active correlation state groups.
When the limit is exceeded, `stitch` evicts the oldest state group by latest
event timestamp. Hunt stats include `correlation_state` and
`correlation_evicted` when correlation rules are loaded.

`--correlation-lateness` controls how far behind the newest observed event time
a correlation match may arrive. The default is `2m`. Events older than the
current watermark are ignored for correlation, and state outside each rule's
`timespan` relative to the watermark is pruned. This allows bounded
out-of-order EVTX streams without expanding a rule's correlation window.

## Field Matching

Supported value types:

1. Strings
2. Unsigned numbers
3. Booleans
4. Lists of those values
5. `null` for missing or null fields

Supported modifiers:

```text
all
base64
base64offset
cased
cidr
contains
endswith
exists
fieldref
gt
gte
hour
day
lt
lte
minute
month
neq
re
s
m
i
startswith
utf16
utf16be
utf16le
week
wide
windash
year
```

`expand` is intentionally rejected unless placeholder configuration exists.
Sigma requires tools to handle placeholders explicitly; `stitch` does not guess
environment-specific placeholder values.

Examples:

```yaml
detection:
  selection:
    EventID: 3
    Image|endswith: powershell.exe
    DestinationIp|cidr: 203.0.113.0/24
  condition: selection
```

String equality and string modifiers are case-insensitive by default. Add the
`cased` modifier when a rule requires case-sensitive matching:

```yaml
detection:
  selection:
    Image|endswith|cased: powershell.exe
  condition: selection
```

Regex matching uses the regex pattern as written. Use inline regex flags such as
`(?i)` when a regex should be case-insensitive, or Sigma regex sub-modifiers:

```yaml
detection:
  selection:
    ScriptBlockText|re|i|s: invoke-webrequest.+payload\.bin
  condition: selection
```

String equality supports Sigma-style `*` and `?` wildcards:

```yaml
detection:
  selection:
    CommandLine: '*-NoProfile*'
  condition: selection
```

Selections may also be lists. A list of maps is evaluated as OR:

```yaml
detection:
  selection:
    - EventID: 1
      Image|endswith: powershell.exe
    - EventID: 11
      TargetFilename: '*payload.bin'
  condition: selection
```

String search identifiers are treated as keyword searches against the raw event
JSON text. Keyword lists are OR by default and AND when the key is `|all`:

```yaml
detection:
  keywords:
    '|all':
      - powershell.exe
      - Invoke-WebRequest
  condition: keywords
```

Generic and typed modifiers are evaluated directly:

```yaml
detection:
  selection:
    OptionalField|exists: false
    CommandLine|neq: cmd.exe
    ProcessId|gte: 1000
    ProcessId|lt: 6000
    SubjectUserName|fieldref: TargetUserName
    TimeCreated|hour: 10
  condition: selection
```

Encoding modifiers transform the rule value before matching. UTF-16 modifiers
produce lowercase hex strings so they can match hex-rendered command or payload
fields. `base64offset` expands to the three positional Base64 variants.

## Rule Filtering

`stitch hunt` applies rule filters after loading supported rules:

```text
--rule-status <STATUS>
--level <LEVEL>
--tag <TAG>
--min-level <LEVEL>
--exclude-rule <GLOB>
```

`--rule-status`, `--level`, and `--tag` are case-insensitive exact filters.
Repeated values match any listed value.

`--min-level` accepts:

```text
informational
low
medium
high
critical
```

`info` is accepted as an alias for `informational`.

`--exclude-rule` matches either the rule path or rule title with a glob.

## Windows EVTX Field Resolution

`stitch` resolves normalized aliases first for common event metadata:

```text
EventID          -> event.id
Channel          -> channel
Provider_Name    -> provider
ProviderName     -> provider
Computer         -> computer
```

Unqualified Sigma field names are treated as EVTX `Event.EventData` fields. For
example:

```text
Image            -> Event.EventData.Image
CommandLine      -> Event.EventData.CommandLine
DestinationIp    -> Event.EventData.DestinationIp
TargetUserName   -> Event.EventData.TargetUserName
```

Fully qualified raw paths are left unchanged:

```text
Event.EventData.TargetUserName
Event.System.EventID
```

This built-in mapping is intentionally small and direct. Chainsaw-compatible
mapping files and broader field normalization remain planned work.
