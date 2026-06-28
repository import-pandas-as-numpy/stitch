# CI/CD

Status: Draft  
Last updated: 2026-06-28

GitHub Actions workflows live under `.github/workflows`.
Dependabot configuration lives at `.github/dependabot.yml`.

## Security Posture

The workflows are designed with these defaults:

1. Top-level `permissions: contents: read`.
2. No `pull_request_target` workflows.
3. Official actions are pinned to immutable commit SHAs.
4. `actions/checkout` runs with `persist-credentials: false`.
5. Jobs use explicit timeouts.
6. Stale runs are cancelled with `concurrency`.
7. The security workflow runs `zizmor --persona pedantic` against workflows.
8. Hosted runners are pinned to `ubuntu-24.04` rather than the moving
   `ubuntu-latest` label.

The current pinned actions are:

1. `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5`
2. `actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830`

## CI Workflow

`.github/workflows/ci.yml` is segmented into focused jobs:

1. `fmt`: installs `rustfmt` and runs `cargo fmt --all -- --check`.
2. `clippy`: installs `clippy`, restores Cargo registry/git cache, and runs strict clippy.
3. `test`: restores Cargo registry/git cache, runs `cargo check`, then runs tests.
4. `benchmark-smoke`: validates and smoke-runs the local benchmark harness.

Documentation-only changes under `docs/**`, top-level Markdown files, and
`README*` files skip the full CI workflow. Static documentation site changes
under `site/**`, `package.json`, `package-lock.json`, and `vercel.json` also
skip the Rust binary CI jobs because Vercel owns the docs-site build and preview
checks. Code, tests, Cargo metadata, scripts, workflows, and Dependabot
configuration still run CI.

Cargo cache reuse is limited to `~/.cargo/git` and `~/.cargo/registry`.
`target/` is intentionally not cached because compiled build artifacts are
larger, less portable across job shapes, and less attractive for a security-first
baseline.

## Security Workflow

`.github/workflows/security.yml` runs when workflow/action files change and on
manual dispatch. It installs pinned `zizmor==1.23.1` and audits workflows in
pedantic mode.

Local audit command:

```bash
zizmor --persona pedantic .github/workflows
```

## Dependency Updates

`.github/dependabot.yml` runs weekly grouped update checks:

1. Cargo runtime dependencies are grouped as `rust-runtime`.
2. Cargo development dependencies are grouped as `rust-development`.
3. GitHub Actions updates are grouped as `github-actions`.

Grouped updates keep PR volume low while still letting CI, Clippy, tests,
benchmark smoke coverage, Socket, and Zizmor evaluate each update set together.
