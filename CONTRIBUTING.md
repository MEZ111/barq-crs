# Contributing

Contributions should improve signal quality, determinism, or evidence safety.

1. Create a focused branch.
2. Add a ground-truth fixture and a regression test.
3. Run `python -m pytest`.
4. Use Conventional Commits, for example:
   `feat(authz): detect cross-tenant object reuse`.
5. Open a pull request describing the invariant, false-positive controls, and
   authorization assumptions.

Do not submit live credentials, scraped target data, destructive payloads, or
code designed to evade program controls.
