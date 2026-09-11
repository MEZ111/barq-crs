# Architecture

## Design objective

BARQ-CRS maximizes **validated information gain per review minute**. Scanner
volume is not the objective. Every finding must retain a source fingerprint,
deterministic score, safe next step, and remediation direction.

## Trust boundaries

| Boundary | Accepted | Rejected by design |
|---|---|---|
| Scope | Exact host, wildcard subdomain, or CIDR in a signed-off policy | Implicit internet-wide target expansion |
| Identity | Researcher-controlled principals and tenants | Third-party accounts or harvested sessions |
| Actions | Offline analysis and reviewable plans | Unattended state-changing execution |
| Evidence | Fingerprints, schemas, status, controlled labels | Cookies, tokens, raw personal data in reports |
| CTF | Local challenge files and explicit flag oracle | Reuse against unrelated live systems |

## Pipeline

1. Ingest immutable, versioned inputs.
2. Normalize routes, principals, objects, and security declarations.
3. Run independent deterministic engines.
4. Attach minimal evidence fingerprints.
5. Deduplicate and reward corroboration across engines.
6. Generate a human-reviewable plan only if evidence and scope gates pass.
7. Record decisions in a hash-chained, redacted ledger.

## Public/private split

| Public `barq-crs` | Private campaign core |
|---|---|
| Engines and data contracts | Program-specific adapters |
| Synthetic fixtures | Scope documents and credentials |
| Tests and benchmark | Live observations and reports |
| CLI and reproducible examples | Research heuristics under evaluation |
| Architecture and responsible-use policy | Disclosure timelines and vendor correspondence |

This separation keeps the portfolio technically inspectable without publishing
campaign data or turning the repository into a copy-paste offensive kit.

## Scoring

Candidate score is a fixed weighted sum:

`10 × (0.35 confidence + 0.30 impact + 0.15 novelty + 0.20 reproducibility)`

Fusion adds a bounded bonus for independent engines and distinct evidence on
the same normalized target. IDs and sort order are deterministic, so CI can
detect ranking drift.

## Extension contract

New engines should:

- accept offline or researcher-controlled input;
- return `Candidate` objects with at least one `Evidence` object;
- never store a raw credential in evidence metadata;
- include a safe next step and remediation hint;
- ship with a positive fixture, negative fixture, and regression test.
