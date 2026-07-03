# Stitch Query Language

STQL is the filter language used by `stitch search`. It is designed for fast
event filtering over normalized Windows Event Log metadata and raw EVTX fields.

STQL is not an aggregation language. The only supported pipeline command today
is `keep`, which projects fields in search output.

## Query Shape

```text
<filter expression>
<filter expression> | keep <field>, <field>, ...
```

Examples:

```text
event.id == 4625
event.id == 4624 and channel == "Security"
Event.EventData.CommandLine contains_ci "powershell"
provider =~ /powershell/i | keep timestamp, event.id, computer
```

## Fields

Field lookup checks normalized aliases first, then falls back to dot paths in
the parsed EVTX JSON.

Normalized aliases:

| Alias | Meaning |
| --- | --- |
| `timestamp`, `event.timestamp`, `winlog.timestamp` | Event timestamp. |
| `record_id`, `event.record_id` | Event record ID. |
| `channel`, `event.channel`, `winlog.channel` | Event log channel. |
| `provider`, `event.provider`, `winlog.provider_name` | Event provider name. |
| `event.id`, `event_id`, `winlog.event_id` | Event ID. |
| `computer`, `host`, `host.name`, `source.computer` | Computer name. |
| `source.file_path` | EVTX file path. |
| `source.collection_root` | Discovery root that produced the input. |

Raw EVTX paths use dot notation:

```text
Event.System.EventID
Event.System.Channel
Event.EventData.TargetUserName
Event.System.TimeCreated.#attributes.SystemTime
```

Field names may contain ASCII letters, numbers, `_`, `.`, `-`, and `#`. They
must start with an ASCII letter or `_`.

## Literals

| Literal | Examples | Notes |
| --- | --- | --- |
| String | `"Security"`, `"alice.admin"` | Double-quoted. Backslash escapes preserve the escaped character. |
| Number | `4624`, `1000` | Unsigned integer values only. |
| Boolean | `true`, `false` | Case-insensitive keyword parsing. |
| List | `(4624, 4625)`, `("Security", "System")` | Used only with `in`. |
| Regex | `/(?i)powershell/`, `/powershell/i` | Used only with `=~` and `!~`. |

## Boolean Operators

| Operator | Meaning |
| --- | --- |
| `and` | Both sides must match. |
| `or` | Either side may match. |
| `not` | Negates the following expression. |
| `(...)` | Groups expressions. |

Precedence, from strongest to weakest:

1. Parentheses
2. `not`
3. `and`
4. `or`

Operators at the same precedence level are evaluated left to right. This query:

```text
event.id == 123 or event.id == 456 and user.name == "alice.admin"
```

is evaluated as:

```text
event.id == 123 or (event.id == 456 and user.name == "alice.admin")
```

Keywords are case-insensitive.

## Comparison Operators

| Operator | Meaning | Literal types |
| --- | --- | --- |
| `==` | Equal. | String, number, boolean. |
| `!=` | Not equal. | String, number, boolean. |
| `<` | Less than. | String, number, timestamp string. |
| `<=` | Less than or equal. | String, number, timestamp string. |
| `>` | Greater than. | String, number, timestamp string. |
| `>=` | Greater than or equal. | String, number, timestamp string. |
| `contains` | Case-sensitive substring match. | String only. |
| `contains_ci` | Case-insensitive substring match. | String only. |
| `in` | Field equals one value in a list. | List of strings, numbers, or booleans. |
| `=~` | Regex matches field text. | Quoted regex string or slash regex literal. |
| `!~` | Regex does not match field text. | Quoted regex string or slash regex literal. |

Examples:

```text
event.id == 4625
record_id > 1000
Event.EventData.TargetUserName contains "admin"
Event.EventData.CommandLine contains_ci "powershell"
event.id in (4624, 4625)
channel in ("Security", "System")
Event.EventData.Enabled == true
```

Number comparisons require a numeric literal. Field values stored as strings can
match numeric comparisons when they parse cleanly as unsigned integers.

String comparisons are lexicographic except for timestamp fields described
below.

## Timestamp Comparisons

Timestamp comparison is enabled for normalized timestamp fields and raw
`TimeCreated.SystemTime` paths:

```text
timestamp
event.timestamp
winlog.timestamp
*.TimeCreated.SystemTime
*.TimeCreated.#attributes.SystemTime
```

Timestamp literals are strings parsed as RFC 3339:

```text
timestamp >= "2026-03-21T06:00:00Z"
timestamp >= "2026-03-21T01:00:00-05:00"
timestamp >= "2026-03-21T06:00:00"
```

Offset-less timestamp literals are interpreted as UTC. For example,
`"2026-03-21T06:00:00"` is treated as `"2026-03-21T06:00:00Z"`.

## Regex Operators

Regex matching uses Rust regex syntax.

Quoted regex strings are passed to the regex compiler as written:

```text
provider =~ "(?i)powershell"
provider !~ "(?i)defender"
```

Slash-delimited regex literals are also supported:

```text
provider =~ /powershell/i
Event.EventData.CommandLine =~ /cmd\.exe \/c/
```

The only supported slash-literal flag is `i` for case-insensitive matching.
Unsupported flags are parse errors.

## Functions

### `exists`

```text
exists(<field>)
not exists(<field>)
```

Returns true when a normalized alias or raw event field can be resolved. Fields
with explicit JSON `null` values do not resolve to a scalar search value.

### `cidr_contains`

```text
cidr_contains(<field>, "<cidr>")
```

Parses the field value as an IP address and returns true when it is inside the
IPv4 or IPv6 CIDR range.

### `ip_in_cidr`

```text
ip_in_cidr(<field>, "<cidr>")
```

Alias for `cidr_contains`.

Examples:

```text
cidr_contains(Event.EventData.SourceIp, "10.0.0.0/8")
ip_in_cidr(Event.EventData.DestinationIp, "192.168.1.0/24")
cidr_contains(Event.EventData.SourceIpV6, "2001:db8::/32")
```

Invalid IP field values do not match. Invalid CIDR literals or invalid prefix
lengths are query parse errors.

## Pipeline Commands

### `keep`

```text
<filter expression> | keep <field>, <field>, ...
```

`keep` selects additional fields for each matching event.

```text
event.id == 4624 | keep timestamp, event.id, computer, Event.EventData.TargetUserName
```

Pretty output still includes source identity. JSON and JSONL output keep
normalized metadata and source identity, then place projected values under
`fields`.

If both `| keep ...` and CLI `--fields` are supplied, CLI `--fields` takes
precedence.

Unsupported pipeline commands, such as `table`, `sort`, `limit`, `stats`, and
`rename`, fail with an explicit `unsupported pipeline command` error.

## Query Planning

`stitch search` builds safe metadata prefilters for globally required `and`
predicates on these normalized fields:

```text
timestamp
event.timestamp
winlog.timestamp
channel
event.channel
winlog.channel
provider
event.provider
winlog.provider_name
event.id
event_id
winlog.event_id
computer
host
host.name
source.computer
```

Prefilter operators:

```text
==
<
<=
>
>=
in
```

`or` and `not` branches are not extracted into prefilters because doing so could
change query semantics. Safe sibling `and` predicates may still be extracted
beside a `not` branch.

Use `stitch search --explain --query '<query>'` to print the parsed query and
planned prefilters.

## Search Output Controls

`| keep` and `--fields` only control which event fields are shown. They do not
change which events match.

When neither `| keep` nor `--fields` is supplied:

- pretty output includes the full raw event record as a YAML-like nested block;
- JSON and JSONL output include the full raw event record under `raw`.

Use projections for large searches to keep terminal output and JSONL rows
focused.

## Current Limitations

STQL currently does not support aggregation, sorting, renaming, joins, arithmetic
expressions, relative time literals, bare strings, negative numbers, floating
point numbers, or multiple pipeline stages.
