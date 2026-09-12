# Campaign operations

`barq hunt` runs the available evidence engines from one manifest:

```bash
barq hunt campaign.json --output barq-output
```

The example at `examples/demo/hunt-campaign.json` combines every offline
engine. A campaign may include any subset of the inputs below, but paths must
remain inside the manifest directory.

```json
{
  "name": "owned-lab",
  "inputs": {
    "observations": "observations.jsonl",
    "openapi": "openapi.json",
    "openapi_before": "openapi-before.json",
    "openapi_after": "openapi-after.json",
    "security_patch": "security-fix.diff",
    "source_root": "source",
    "transitions": "transitions.json",
    "mobile": "application.apk"
  },
  "limits": {
    "api_sequence_depth": 3,
    "max_schema_cases": 250
  }
}
```

`openapi_before` and `openapi_after` are a pair. `security_patch` and
`source_root` are also a pair. This prevents a partial configuration from
silently producing misleading results.

## Optional live read-only matrix

A campaign can collect `GET`, `HEAD`, and `OPTIONS` evidence from an explicitly
authorized target before running the authorization differential engine:

```json
{
  "name": "authorized-read-matrix",
  "inputs": {
    "collection": {
      "policy": "policy.json",
      "requests": "requests.json",
      "profiles": "profiles.json",
      "limits": {
        "max_requests": 40,
        "max_body_bytes": 250000,
        "timeout_seconds": 8
      }
    }
  }
}
```

Session headers in `profiles.json` refer to environment-variable names. Their
values never belong in the file:

```json
[
  {
    "principal": "owner",
    "role": "user",
    "header_env": {"Authorization": "BARQ_OWNER_AUTH"},
    "owned_resource_ids": ["record-a"]
  },
  {
    "principal": "reviewer",
    "role": "user",
    "header_env": {"Authorization": "BARQ_REVIEWER_AUTH"},
    "owned_resource_ids": ["record-b"]
  }
]
```

The scope policy is the execution boundary: no implicit targets, no redirects,
no state-changing verbs, and bounded requests, response bodies, timeouts, and
rate. Use only researcher-controlled accounts and objects.

## Generated artifacts

| File | Purpose |
|---|---|
| `summary.json` | Run counts and top-ranked queue |
| `report.md` | Human review report with evidence fingerprints |
| `candidates.json` | Machine-readable evidence candidates |
| `test-plan.json` | OpenAPI tests, dependency sequences, and mobile inventory |
| `results.sarif` | GitHub Code Scanning-compatible results |
| `evidence-ledger.jsonl` | Redacted, verified SHA-256 hash chain |

State-changing schema cases are plans only and carry `isolated_only: true`.
They are intentionally not fired against a live program by the public engine.
Run them in a disposable local fixture first, then follow the exact rules of
the authorized program for any manual confirmation.
