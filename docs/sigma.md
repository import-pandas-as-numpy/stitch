# Sigma Support

Status: Draft  
Last updated: 2026-06-28

`stitch hunt` loads Sigma YAML rules from files or directories and evaluates the
currently supported non-correlation detection subset against EVTX input.

## Supported Rule Types

Supported:

1. Regular Sigma rules with a `detection` mapping.
2. Rules with named selections and a string `condition`.
3. Rules with a list of condition strings, evaluated as OR.

Skipped:

1. Correlation rules are detected and counted as skipped.

Unsupported rule shapes fail at load time with the rule path and a diagnostic.

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
