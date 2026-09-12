# Active authorization verification

BARQ v0.4 adds a read-only verifier for authorization boundaries. It is designed for systems you own, isolated labs, or bug-bounty targets where the exact requests are permitted by written scope.

The verifier is intentionally different from an internet scanner. It never discovers arbitrary identifiers, crawls foreign accounts, follows redirects, or sends state-changing methods. Every live request must be derived from an explicit target allowlist and an explicitly supplied controlled session/resource fixture.

## What it can prove

The verifier builds a matrix from:

- two or more researcher-controlled session profiles;
- zero or more harmless resources owned by those profiles;
- read-only request templates, supplied directly or derived from OpenAPI;
- an optional anonymous identity.

For an object template such as `GET /api/users/{resource}`, BARQ requests Alice's controlled object and Bob's controlled object using each controlled identity. The ownership truth comes from `resources.json`, not from inference. If Bob receives Alice's protected response, BARQ can produce a high-confidence BOLA/IDOR finding. The same mechanism can verify cross-tenant access and privileged-route response parity.

A finding is marked `verified` only when BARQ has strong differential evidence, such as the same normalized response or the same sensitive values after hashing. A `likely` result can be produced when protected schemas strongly match but values differ. The evidence records field names, fingerprints, statuses, ownership aliases, and tenant labels; it does not copy raw response values into findings.

## Safety gates

Live verification inherits the `ScopePolicy` controls:

- explicit hostname/IP allowlist;
- allowed scheme, port, method, and per-target RPS;
- `active_testing: true` required;
- GET/HEAD/OPTIONS only;
- redirect following disabled;
- destructive path terms blocked;
- hard request, response-size, and timeout ceilings.

Credentials are loaded only through environment bindings in the profile file. Do not put bearer tokens, cookies, passwords, API keys, or session material in versioned JSON.

Controlled resource values are used only to render the outgoing request. BARQ stores a separate safe alias (`key`) in evidence and reports instead of the raw identifier.

## Minimal configuration

`policy.json`:

```json
{
  "name": "owned-lab",
  "active_testing": true,
  "human_approval_required": true,
  "targets": [{
    "pattern": "lab.example.test",
    "schemes": ["https"],
    "ports": [443],
    "methods": ["GET", "HEAD", "OPTIONS"],
    "max_rps": 0.5
  }]
}
```

`profiles.json` binds secrets to the environment:

```json
[
  {
    "principal": "alice",
    "role": "user",
    "tenant": "red",
    "header_env": {"Authorization": "BARQ_ALICE_AUTH"}
  },
  {
    "principal": "bob",
    "role": "user",
    "tenant": "blue",
    "header_env": {"Authorization": "BARQ_BOB_AUTH"}
  }
]
```

`resources.json` contains only resources created for the research campaign:

```json
[
  {
    "key": "alice-user",
    "kind": "user",
    "value": "alice-controlled-fixture",
    "owner": "alice",
    "tenant": "red"
  },
  {
    "key": "bob-user",
    "kind": "user",
    "value": "bob-controlled-fixture",
    "owner": "bob",
    "tenant": "blue"
  }
]
```

`templates.json` defines exactly what BARQ may read:

```json
[
  {
    "name": "read-user",
    "method": "GET",
    "url": "https://lab.example.test/api/users/{resource}",
    "route": "/api/users/{id}",
    "resource_kind": "user"
  }
]
```

Run:

```bash
export BARQ_ALICE_AUTH='Bearer <controlled-account-token>'
export BARQ_BOB_AUTH='Bearer <controlled-account-token>'
barq verify verification.json --output barq-verification
```

The repository example uses the reserved `.test` domain and is a configuration template, not a live target.

## OpenAPI-assisted verification

Instead of writing every template by hand, add an `openapi` section to the manifest:

```json
{
  "openapi": {
    "spec": "openapi.json",
    "base_url": "https://lab.example.test/api",
    "resource_parameters": {"id": "user"},
    "include_public": false,
    "max_templates": 100
  }
}
```

BARQ considers read-only operations only. A route without path parameters becomes an identity-swap test. A route with exactly one path parameter becomes a resource-swap test only when that parameter is explicitly mapped to a controlled resource kind. Routes with unresolved or multiple path parameters are skipped rather than guessed.

## Output

`barq verify` emits seven artifacts:

- `report.md` — ranked human review report;
- `findings.json` — structured candidates with verification strength;
- `evidence.json` — sanitized observation metadata and response fingerprints;
- `verification-plan.json` — exact bounded plan without resource values or credentials;
- `results.sarif` — SARIF 2.1.0 output;
- `evidence-ledger.jsonl` — hash-chained evidence events;
- `summary.json` — campaign counts and top findings.

## Limits

BARQ does not prove that an application is secure when it reports no finding. It cannot infer business authorization rules that are absent from the supplied fixture, and it deliberately refuses automatic destructive validation. POST/PUT/PATCH/DELETE scenarios remain offline plans or human-approved isolated tests.
