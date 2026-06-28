# Getting Started

Build Stitch locally, point it at EVTX input, and run a query.

## Build

```bash
cargo build --release
```

Use the local binary directly when benchmarking or validating behavior:

```bash
target/release/stitch --help
```

## Search the current directory

When no path is supplied, Stitch recursively searches the current working
directory as if `-i .` had been passed.

```bash
stitch search --query 'event.id == 4625'
```

## Search a specific collection

```bash
stitch search \
  -i cases/acme/windows \
  --query 'event.id == 4625 and Event.EventData.TargetUserName contains_ci "admin"'
```

## Hunt with Sigma rules

```bash
stitch hunt \
  -i cases/acme/windows \
  --rules rules/windows \
  --summary
```

## Dump records

```bash
stitch dump \
  -i cases/acme/windows/security.evtx \
  --format jsonl \
  --output /tmp/security.jsonl
```

Projected CSV requires explicit fields:

```bash
stitch dump \
  -i cases/acme/windows/security.evtx \
  --format csv \
  --fields timestamp \
  --fields event.id \
  --fields computer \
  --output /tmp/security.csv
```

## Next steps

- Read [Basics](/basics/) for input and output behavior.
- Read [STQL](/stql/) for query syntax.
- Read [Sigma](/sigma/) for supported rule behavior.
