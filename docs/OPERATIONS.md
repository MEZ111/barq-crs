# Authorized operations

BARQ 0.3 closes the gap between captured traffic and analysis while keeping the
live boundary narrow and reviewable.

## Workflow A — existing browser or Burp traffic

Export traffic from a session you control, then attach an identity label:

```bash
barq ingest-har owner.har --principal owner --role user --tenant red \
  > owner.jsonl
barq ingest-burp reviewer.xml --principal reviewer --role user --tenant blue \
  > reviewer.jsonl
```

Combine the JSONL files and run the authorization differential engine. Request
and response headers are deliberately discarded during import.

```bash
barq authz observations.jsonl > candidates.json
barq sarif candidates.json barq-results.sarif
```

Optional `_barq` fields in a HAR entry can label `route`, `resource_id`,
`owns_resource`, and `resource_tenant`. This turns a traffic capture into an
ownership-aware authorization matrix instead of a loose response diff.

## Workflow B — bounded live collection

Copy the three files under `examples/authorized-collection/`, replace the fake
host with the exact asset listed by the program, and bind credentials through
environment variables. Do not write cookies or tokens into JSON.

```bash
barq collect policy.json requests.json profiles.json > observations.jsonl
barq authz observations.jsonl > candidates.json
```

The collector:

- requires `active_testing: true` and an explicit host/scheme/port/method;
- executes only `GET`, `HEAD`, and `OPTIONS`;
- disables automatic redirects;
- enforces the policy rate limit and a 100-request matrix budget;
- caps every response body at 1 MB;
- never writes request headers into an observation;
- blocks destructive path terms before the network call.

## Workflow C — stateful API planning

```bash
barq api-sequences openapi.json --depth 3 > sequences.json
barq api-plan openapi.json --max-cases 250 > test-plan.json
```

BARQ resolves local schema references, normalizes names such as `userId` to
`user_id`, infers which operations produce fields required by later operations,
and emits bounded producer/consumer sequences. It does not execute mutating
operations; the sequence graph is input for an isolated harness or manual
review.

## Workflow D — APK and full campaign

```bash
barq mobile application.apk > mobile-findings.json
barq hunt campaign.json --output barq-output
```

APK inspection is static and bounded. The package is never extracted or
executed, and embedded credential values are represented only by fingerprints.
`barq hunt` can combine this result class with saved observations, OpenAPI
contracts, source patches, and transition models. It can also invoke Workflow B
when a campaign explicitly contains a `collection` block. See
`docs/MOBILE.md` and `docs/CAMPAIGNS.md`.

## Evidence discipline

Use two researcher-controlled accounts when testing ownership boundaries. Do
not access a third party's object, retain personal data, or assume a public host
is in scope. The written program scope remains the authority.
