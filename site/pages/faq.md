# FAQs

## Does Stitch scan the current directory by default?

Yes. If no input path is supplied, Stitch recursively scans the current working
directory as if `-i .` had been passed.

## Is XML output supported?

No. XML output is intentionally unsupported. Use JSONL, JSON, or projected CSV
depending on the downstream tool.

## Is concurrency enabled by default?

Yes. `--jobs 0` is the default and uses Rayon's system-sized worker pool where a
mode can safely parallelize. Use `--jobs 1` when sequential behavior is needed.

## Why is correlation sequential?

Correlation rules are order-sensitive. Event-time watermarks, lateness handling,
and bounded state eviction need deterministic processing to preserve Hunt
behavior.

## Can Stitch run Sigma rules directly?

Yes, for the supported subset. Stitch loads Sigma rules directly, resolves common
Windows EVTX field aliases, and documents unsupported behavior in the Sigma
reference.

## How is the docs site generated?

The site is generated from in-repository Markdown with:

```bash
npm run docs:build
```

The static output is written to `site/dist`.
