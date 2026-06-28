# Stitch Documentation

Stitch is a fast, offline CLI for Windows Event Log analysis. It searches EVTX
collections, hunts with Sigma rules, runs supported correlation rules, and emits
human-readable or machine-readable output for incident response workflows.

## Start here

| Path | Use it for |
| --- | --- |
| [Getting Started](/getting-started/) | Build the binary and run the first search, hunt, and dump commands. |
| [Basics](/basics/) | Understand input discovery, output formats, parallel execution, and defaults. |
| [STQL](/stql/) | Learn the query language used by `stitch search`. |
| [Sigma](/sigma/) | Review detection syntax, Windows field mappings, and correlation behavior. |

## Why a dedicated site

Stitch has a command surface, a query language, Sigma compatibility behavior,
and output schemas that analysts need to trust before using it in an
investigation. The site is generated directly from repository documentation so
the public reference stays close to the implementation.

## Current shape

- Search uses STQL predicates over normalized metadata and raw event paths.
- Hunt loads Sigma rules directly and renders compact analyst tables by default.
- Correlation rules are supported for the implemented Sigma subset.
- Dump exports JSONL, JSON, and projected CSV.
- Parallel execution is the default where ordering and correlation semantics are safe.

## Deployment

The docs build is static. Vercel should run `npm run docs:build` and publish
`site/dist` for `stitch.sudorem.dev`.
