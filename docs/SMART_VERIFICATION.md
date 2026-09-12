# Smart verification

BARQ v0.6 can turn authorized recon output into a small set of live, read-only authorization checks without replaying discovered third-party identifiers.

## What it does

`barq bounty` still performs the v0.5 recon and ranking pipeline. When `smart_verification` is enabled, it also:

1. reads the scoped URLs produced by the recon run;
2. finds object-reference routes using exact controlled fixture values, explicit query bindings, or a resource-kind path pattern such as `/users/<id>`;
3. replaces the discovered identifier with `{resource}` before any live verification request is planned;
4. ranks and deduplicates those templates;
5. accounts for existing templates, OpenAPI templates, controlled-resource expansion, and the identity matrix;
6. admits only the highest-value templates that fit `limits.max_requests`;
7. executes the existing GET/HEAD/OPTIONS verifier with controlled identities and controlled resources; and
8. merges `verified` / `likely` authorization findings back into the main bounty board.

The goal is to remove the slow manual step between “this route looks like IDOR/BOLA” and “test this same route across my own two accounts and fixtures.”

## Campaign configuration

```json
{
  "name": "authorized-program",
  "domain": "example.test",
  "policy": "policy.json",
  "authorized_testing": true,
  "smart_verification": {
    "enabled": true,
    "manifest": "smart-verification.json",
    "max_templates": 50,
    "parameter_bindings": {
      "user_id": "user",
      "account_id": "account"
    }
  }
}
```

The verification manifest is the same secret-free format used by `barq verify`. Profiles reference environment variables for credentials, and resources contain only researcher-controlled fixture IDs.

`parameter_bindings` are optional. They are useful when recon finds a route such as `?user_id=...` but the discovered value is not one of your fixtures. BARQ never replays that value; it substitutes each configured controlled resource of the bound kind.

## Request budget

A generated template is not free: a `user` template with two controlled user fixtures and three identities (Alice, Bob, anonymous) costs six requests. Smart mode calculates this expansion before network access. Existing manual templates and OpenAPI-derived templates are charged first; discovered routes are then added from highest score downward until the request budget is full.

The exact selection is written to `smart-verification-plan.json`.

## Output

The normal bounty artifacts remain the primary output:

- `bounty-board.json`
- `bounty-report.md`
- `state.json`

Smart mode adds:

- `smart-verification-plan.json`
- `smart-verification/summary.json`
- the normal sanitized verification evidence/report/SARIF/ledger set under `smart-verification/`

A `verified` item means the controlled differential engine reproduced an authorization boundary failure using the configured identities/resources. A scanner or recon lead remains a lead until separately verified.

## Safety envelope

Smart verification is intentionally bounded:

- explicit authorized scope is required;
- only researcher-controlled resource values are sent in synthesized object swaps;
- discovered third-party IDs are not replayed;
- synthesized live requests are GET-only;
- redirects remain disabled;
- destructive paths remain blocked;
- request/body/timeout/RPS budgets remain enforced;
- the matrix is rejected before network access if it exceeds the configured request budget.

Use it only where the target program explicitly permits the testing being performed.
