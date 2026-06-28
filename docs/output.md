# Output Guide

`stitch` has human-readable output for analyst workflows and stable machine
formats for scripting.

## Search

Pretty search output prints source metadata plus event fields. When no `| keep`
pipeline or `--fields` projection is supplied, pretty output includes the full
raw event record as a YAML-like nested block.

Projected search:

```bash
stitch search -i tests/fixtures/evtx/security-auth.evtx \
  --query 'event.id == 4625 | keep timestamp, event.id, computer, Event.EventData.TargetUserName'
```

Machine output:

```bash
stitch search -i tests/fixtures/evtx/security-auth.evtx \
  --query 'event.id == 4625' \
  --format jsonl
```

## Hunt

Pretty hunt output is compact by default. It includes timestamp, detection,
event ID/record ID, level, host, and payload.

```bash
stitch hunt -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma/sysmon_powershell_network.yml
```

Use `--full` when source columns and untruncated payloads are needed:

```bash
stitch hunt -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma/sysmon_powershell_network.yml \
  --full
```

JSONL hunt output is the stable scripting format:

```bash
stitch hunt -i tests/fixtures/evtx/sysmon-activity.evtx \
  --rules tests/fixtures/sigma \
  --format jsonl
```

## Correlation

Correlation output is emitted by `hunt` when correlation rules are enabled.
Pretty correlation output uses a table with timestamp, detection, match count,
level, group, and payload. `--full` adds the window column and disables payload
truncation.

```bash
stitch hunt -i tests/fixtures/correlation-evtx/sysmon-correlation.evtx \
  --rules tests/fixtures/sigma-correlation \
  --correlation-event-field Event.EventData.ProcessGuid \
  --correlation-event-field Event.EventData.Image \
  --correlation-event-limit 2
```

Machine-readable correlation output:

```bash
stitch hunt -i tests/fixtures/correlation-evtx/sysmon-correlation.evtx \
  --rules tests/fixtures/sigma-correlation \
  --format jsonl
```

## Dump

Dump defaults to JSONL records containing normalized metadata, source identity,
and raw EVTX JSON.

```bash
stitch dump -i tests/fixtures/evtx/security-auth.evtx
```

Projected CSV requires explicit fields:

```bash
stitch dump -i tests/fixtures/evtx/security-auth.evtx \
  --format csv \
  --fields timestamp \
  --fields event.id \
  --fields computer
```

## Parallelism

`--jobs 0` is the default and uses Rayon's system-sized worker pool where the
mode can parallelize safely. Use `--jobs 1` for sequential execution, lower peak
memory, or deterministic debugging.

Examples:

```bash
stitch -j 4 --paths-from /tmp/stitch-paths.txt search \
  --query 'event.id in (4624, 4625)' \
  --format jsonl
```

```bash
stitch -j 1 --paths-from /tmp/stitch-paths.txt dump \
  --format csv \
  --fields timestamp \
  --fields event.id \
  --fields computer
```
