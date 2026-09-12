# Verification record

Verified on 2026-09-12 with Python 3.12.

## Automated suite

```text
........................................................................ [ 71%]
.............................                                            [100%]
101 passed
```

The suite includes SARIF contract tests. CI is the authoritative count for the
current commit.

## Ground-truth fixture

```json
{
  "fixture": "barq-ground-truth-v2",
  "counts": {
    "authorization": 3,
    "contract_drift": 2,
    "patch_variants": 1,
    "state_collisions": 1,
    "har_observations": 1,
    "burp_observations": 1,
    "api_sequences": 1,
    "schema_test_cases": 7,
    "mobile_candidates": 11,
    "campaign_candidates": 18,
    "campaign_artifacts": 6,
    "ledger_valid": true
  },
  "passed": true
}
```

## CLI smoke checks

The APK/binary-AXML, Android code-pattern, OpenAPI test-plan, campaign,
traffic-ingestion, API-sequence, authorization, OpenAPI drift, patch-variant,
state-collision, and CTF-triage paths completed on synthetic fixtures.
`compileall` and `pip check` also completed with exit code 0. Live collector
behavior is covered with an injected transport so CI sends no network traffic.

This record proves deterministic behavior on included fixtures. It does not
claim performance on an unseen program or confirm a live vulnerability.
