# Changelog

## [0.5.0] — 2026-09-12

### Added

- `barq bounty` one-command orchestration for authorized recon, triage, and optional controlled authorization verification
- Route-level endpoint prioritization for object access, server-side fetch inputs, redirects/callbacks, file/path inputs, privileged routes, API introspection, file workflows, and identity flows
- Nuclei signal ingestion into the same ranked bounty board
- Optional merge of `barq verify` results so controlled `verified` authorization failures rank above scanner signals and recon leads
- Stable lead IDs and `state.json` delta tracking to separate new results from previously seen leads
- `bounty-board.json` and `bounty-report.md` artifacts plus an authorized example campaign and operating guide

### Hardened

- Bounty mode requires `authorized_testing=true`, `policy.active_testing=true`, and explicit policy rules for both the root domain and wildcard subdomains
- Target-facing `httpx`, `katana`, and `nuclei` request rates are bound to the supplied policy's lowest `max_rps`
- Bounty manifest inputs are directory-confined and recon environment overrides are allowlisted
- Recon still excludes intrusive/bruteforce/DoS Nuclei templates and controlled verification remains read-only

## [0.4.0] — 2026-09-12

### Added

- `barq verify` for bounded, read-only authorization verification using
  researcher-controlled accounts and resources
- Controlled-resource aliases so evidence can model ownership without storing
  raw live identifiers in findings
- OpenAPI-assisted read-only verification templates with explicit resource
  parameter bindings and skip reasons for unresolved operations
- Evidence strength (`verified` / `likely`) based on normalized response
  equality, protected-value fingerprints, and protected-schema similarity
- Anonymous, cross-principal, cross-tenant, and privileged-route verification
- Sanitized verification evidence, plan, SARIF, summary, Markdown report, and
  hash-chained evidence ledger artifacts
- Secret-free authorized-verification examples and dedicated operating guide
- Stable candidate `kind` in campaign top-candidate summaries

### Hardened

- OpenAPI authorization drift now preserves OR alternatives and AND scheme
  requirements instead of flattening security semantics
- Detects weaker OR alternatives, removed required schemes/scopes, security
  scheme removal/type changes, and new sensitive anonymous operations
- Ignores common 2xx denial bodies and strips volatile response fields before
  authorization comparison to reduce false positives
- Live verifier refuses state-changing methods and reuses explicit allowlists,
  no-redirect behavior, RPS/request/body/timeout budgets, and destructive-path
  blocks
- Verification matrix budget is checked before network access
- Critical engines are type-checked and correctness-linted in CI
- CI now enforces branch coverage, synthetic ground-truth benchmark, package
  build, CLI smoke tests, pinned GitHub Actions, and dependency audit

## [0.3.0] — 2026-09-12

### Added

- Dependency-free Android binary AXML decoder and bounded APK reader
- Android manifest, deep-link, network policy, WebView, TLS, storage, and
  embedded-secret fingerprint analysis
- Deterministic OpenAPI test plans for authorization, BOLA, mass assignment,
  parameter pollution, schema boundaries, canonicalization, and replay
- `barq hunt` campaign orchestration with Markdown, JSON, SARIF, test-plan,
  summary, and hash-chained ledger artifacts
- Optional scope-gated read-only collection within a campaign
- Synthetic Android fixture and ground-truth benchmark v2

### Hardened

- Campaign input paths cannot escape the manifest directory
- APK entry, expanded-size, entry-size, and compression-ratio limits
- Raw embedded credential values are replaced by SHA-256 fingerprints
- State-changing API cases remain isolated, human-approved plans

## [0.2.0] — 2026-09-11

### Added

- Scope-gated live collector for `GET`, `HEAD`, and `OPTIONS`
- Environment-bound controlled identity profiles and ownership maps
- HAR and Burp Suite XML ingestion with request headers discarded
- OpenAPI producer/consumer graph and bounded stateful sequences
- End-to-end live-matrix authorization regression test
- Operational templates and documentation

### Hardened

- Five-request-per-second policy ceiling
- Redirect, request-count, response-size, and timeout boundaries
- Header injection rejection
- Missing OpenAPI reference tolerance

## [0.1.0] — 2026-09-11

- Authorization differential, contract drift, patch-seeded variant, and state
  collision engines
- Signal fusion, evidence ledger, CTF triage, SARIF export, CLI, CI, and
  synthetic ground-truth benchmark
