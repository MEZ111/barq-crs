# BARQ Bounty Autopilot

BARQ v0.5 adds a one-command orchestration layer for authorized bug-bounty and security-research work. It combines bounded reconnaissance, endpoint prioritization, Nuclei signals, optional controlled authorization verification, and delta tracking into one ranked board.

## What it does

`barq bounty` runs `scripts/bb-pipeline.sh` against one explicitly authorized root domain, then collapses the noisy URL output into route-level leads. It prioritizes object-access surfaces, server-side fetch inputs, redirects/callbacks, file/path inputs, privileged/debug routes, API introspection, file workflows, and identity flows.

If a `verification_manifest` is supplied, BARQ also runs the v0.4 controlled identity/resource matrix and places verified authorization failures above scanner signals and recon leads.

The final queue has three evidence levels:

- `verified`: BARQ reproduced an authorization boundary failure using researcher-controlled identities/resources.
- `scanner-signal`: a high-value automated scanner signal that still requires researcher confirmation.
- `high-value-lead`: deduplicated reconnaissance worth focused manual review; it is not a vulnerability claim.

## Safety and scope gates

Bounty mode refuses to run unless `authorized_testing` is explicitly `true`, the supplied `ScopePolicy` has `active_testing=true`, and the policy explicitly contains both the root domain and `*.root-domain` rules. The recon pipeline always includes the root host and discovered subdomains, so requiring both rules prevents accidental scope expansion.

Target-facing RPS values for `httpx`, `katana`, and `nuclei` are automatically capped by the lowest `max_rps` declared for those policy rules. State-changing BARQ verification remains disabled; the verifier only issues `GET`, `HEAD`, and `OPTIONS` requests against controlled resources.

## Dependencies

The recon stage expects these command-line tools to be installed and available on `PATH`:

- `subfinder`
- ProjectDiscovery `httpx`
- `katana`
- `gau`
- `uro`
- `nuclei`

BARQ itself has no new Python runtime dependency for bounty mode.

## Minimal campaign

```json
{
  "name": "my-authorized-program",
  "domain": "example.com",
  "policy": "policy.json",
  "authorized_testing": true,
  "max_leads": 100,
  "recon": {
    "update_templates": false,
    "env": {
      "HTTPX_RPS": "1",
      "KATANA_RPS": "1",
      "NUCLEI_RPS": "1"
    }
  }
}
```

Run it with:

```bash
barq bounty campaign.json --output barq-bounty
```

BARQ writes:

- `bounty-board.json`: machine-readable ranked queue.
- `bounty-report.md`: human-readable priority board.
- `state.json`: stable lead IDs used to distinguish new results from previously seen ones.
- `recon-runs/`: raw bounded recon artifacts from the existing pipeline.
- `verification/`: present when controlled authorization verification is enabled.

## Adding controlled authorization verification

Place the verification manifest and its referenced policy/profile/resource/template files in the same campaign directory, then add:

```json
{
  "verification_manifest": "verification.json"
}
```

The verification manifest remains secret-free. Session credentials are still read from environment variables through BARQ session profiles; they are not persisted into the bounty board.

This is the part that turns an object-access lead into stronger evidence: with two controlled accounts and controlled object IDs, BARQ can compare owner vs non-owner vs anonymous responses and label sufficiently strong authorization failures as `verified`.

## Why the board is smaller than the raw recon output

Bug-bounty recon often produces thousands of URL variants that differ only in object IDs or query values. BARQ normalizes likely IDs and query names into route signatures and keeps the highest-value representative for each route/class pair. The goal is to spend researcher time on distinct security boundaries rather than duplicate URLs.

## What it intentionally does not do

Bounty mode does not enumerate arbitrary victim object IDs, perform credential attacks, issue destructive/state-changing requests, disable the scope policy, or turn a heuristic lead into a vulnerability claim. High-confidence exploitation still requires explicit, authorized researcher confirmation.
