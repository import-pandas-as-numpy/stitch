# Stitch Query Language

`stql` is the query language used by `stitch search`.

The language is intentionally small at this stage. Its purpose is fast event filtering with readable syntax, not full aggregation or SIEM query compatibility.

## Current Support

### Boolean Logic

```text
event.id == 4625 and channel == "Security"
event.id == 4625 or event.id == 4624
not exists(Event.EventData.TargetUserName)
```

Precedence:

1. Parentheses
2. `not`
3. `and`
4. `or`

Parentheses may be nested to any practical depth supported by the process stack.
Operators at the same precedence level are evaluated left to right. For example,
`event.id == 123 or event.id == 456 and user.name == "alice.admin"` is evaluated
as `event.id == 123 or (event.id == 456 and user.name == "alice.admin")`.

`stitch search` plans safe metadata prefilters for globally required `and`
predicates on normalized fields such as `timestamp`, `event.id`, `channel`,
`provider`, and `computer`. `or` and `not` branches are not extracted into
prefilters because doing so could change query semantics.

For memory-constrained searches, use `--jobs 1` when large pretty/JSON output is
expected. Parallel search buffers each input's rendered matches before merging
results in discovery order; `--limit` also runs sequentially so early
termination remains predictable.

### Comparisons

Supported operators:

```text
==
!=
<
<=
>
>=
contains
contains_ci
in
=~
!~
```

Examples:

```text
event.id == 4625
record_id > 1000
Event.EventData.TargetUserName contains "admin"
Event.EventData.CommandLine contains_ci "powershell"
event.id in (4624, 4625)
provider =~ "(?i)powershell"
provider !~ "(?i)defender"
timestamp >= "2026-06-27T00:00:00Z"
```

Numeric comparisons require a numeric literal. String values that contain digits can be compared to numeric literals when they parse cleanly.

Timestamp comparisons parse RFC3339 timestamps when the field is a normalized timestamp field such as `timestamp`, `event.timestamp`, or `winlog.timestamp`.

Examples:

```text
timestamp >= "2026-03-21T06:00:00Z" and timestamp < "2026-03-21T07:00:00Z"
timestamp >= "2026-03-21T01:00:00-05:00"
timestamp >= "2026-03-21T06:00:00"
```

Offset-less timestamp values default to UTC. For example, `"2026-03-21T06:00:00"` is interpreted as `"2026-03-21T06:00:00Z"`.

Other string fields use lexicographic comparison.

Regex operators use quoted Rust regex patterns. Inline flags such as `(?i)` can be used for case-insensitive matching.

Regex operators also support slash-delimited regex literals. The `i` flag enables case-insensitive matching:

```text
provider =~ /powershell/i
Event.EventData.CommandLine =~ /cmd\.exe \/c/
```

`in (...)` supports strings, numbers, and booleans:

```text
event.id in (4624, 4625)
channel in ("Security", "System")
```

### Existence

```text
exists(field.name)
not exists(field.name)
```

`exists` returns true when a normalized alias or raw event field can be resolved.

### IP And CIDR Helpers

```text
cidr_contains(Event.EventData.SourceIp, "10.0.0.0/8")
ip_in_cidr(Event.EventData.SourceIp, "192.168.1.0/24")
cidr_contains(Event.EventData.SourceIpV6, "2001:db8::/32")
```

`cidr_contains` and `ip_in_cidr` are aliases. They parse the field value as an
IP address and return true when it is inside the supplied IPv4 or IPv6 CIDR
range. Invalid IP field values do not match. Invalid CIDR literals are query
parse errors.

### Pipelines

`stql` supports a `keep` projection stage after the filter expression:

```text
event.id == 4624 | keep timestamp, event.id, computer, Event.EventData.TargetUserName
```

`keep` controls the additional fields returned for each matching event. The
standard source identity fields are still shown in pretty output.

When neither `| keep` nor CLI `--fields` is supplied, pretty search output shows
the full raw event record as a YAML-like nested block. Use `| keep` when the
terminal output should stay focused on a small set of fields.

If both `| keep ...` and CLI `--fields` are provided, `--fields` takes precedence.

## Field Lookup

`stitch` checks normalized aliases first, then falls back to raw JSON paths.

Normalized aliases currently include:

```text
timestamp
event.timestamp
record_id
event.record_id
channel
event.channel
provider
event.provider
event.id
event_id
winlog.event_id
computer
host
host.name
source.computer
source.file_path
source.collection_root
```

Raw paths use dot notation against the parsed EVTX JSON shape:

```text
Event.System.EventID
Event.System.Channel
Event.EventData.TargetUserName
```

## Literals

Supported literals:

```text
"quoted strings"
12345
true
false
```

String escapes currently preserve the escaped character directly.

## Current Limitations

The following are planned but not implemented yet:

1. Pipeline stages for sorting, limiting, aggregation, and renaming fields.
