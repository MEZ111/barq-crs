# Changelog

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
