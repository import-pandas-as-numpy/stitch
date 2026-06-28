# About

Stitch is built for offline Windows Event Log analysis when an analyst has EVTX
files on disk and needs fast answers without a heavyweight service.

## Goals

- Correct EVTX parsing and predictable query behavior.
- Fast scans over realistic case folders.
- Bounded memory behavior in constrained environments.
- Readable terminal output for humans.
- Stable JSONL, JSON, and CSV output for scripts.
- Sigma support that is explicit about what is implemented.

## Non-goals

Stitch is not trying to become a SIEM, a live endpoint collector, or a complete
replacement for every Sigma backend. Unsupported behavior should fail clearly or
be documented plainly.

XML output is intentionally out of scope for now. EVTX records are preserved in
structured JSON-oriented forms that are easier to query and export consistently.

## Design bias

The CLI should be useful in a shell pipeline, but the default human output should
still be pleasant to read. Search and hunt output favor concise tables and
pretty nested payloads, while machine formats remain explicit and stable.
