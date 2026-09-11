# Roadmap

## 0.1 — deterministic core (implemented)

- Authorization and tenant differential analysis
- OpenAPI effective-security drift
- Python patch-seeded variant analysis
- State-transition collision modeling
- Evidence fusion and tamper-evident ledger
- Offline CTF challenge triage and flag oracle
- Explicit scope and human-approval gates

## 0.2 — validation lab

- Docker-only vulnerable fixtures with seeded ground truth
- Precision, recall, time-to-signal, and review-cost metrics
- OpenAPI producer/consumer dependency graph
- SARIF import/export and CodeQL correlation
- Coverage-import adapter for Fuzz Introspector

## 0.3 — private campaign runtime

- Signed scope snapshots and expiry checks
- Encrypted credential broker with per-adapter least privilege
- Rate-limit leases and global kill switch
- Manual request approval queue
- Redacted disclosure bundle generator

## Research bets

1. Patch-derived invariants will outperform generic prompts for variant mining.
2. Cross-identity response lattices will surface authorization bugs with fewer
   requests than payload-centric fuzzing.
3. State-machine collisions ranked by shared invariants will reduce race-testing
   noise versus endpoint-by-endpoint concurrency.
4. Independent evidence fusion will improve reviewer yield more than increasing
   raw agent count.

Each bet must graduate through a labeled fixture set before it enters the
private runtime.
