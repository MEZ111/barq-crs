# Research brief: the frontier BARQ-CRS is built against

## Executive conclusion

The strongest public evidence does **not** support a single magical scanner.
The systems at the frontier combine narrow, testable reasoning with classical
program analysis, execution feedback, strict validation, and bounded search.
BARQ-CRS therefore uses four high-information seeds—identity differences,
contract changes, security patches, and shared state invariants—then requires
evidence before a candidate can reach human review.

This report separates published results from design inference. Benchmark claims
belong to their cited authors unless explicitly labeled as a BARQ inference.

## What the frontier demonstrates

| System / work | Published result | Durable lesson |
|---|---|---|
| DARPA AIxCC | Finalists found 54 of 63 synthetic vulnerabilities and patched 68%; Team Atlanta ranked first with 43 vulnerabilities and 31 patches.[1] | Hybrid discovery and verified repair can operate at repository scale. |
| Atlantis | The winning CRS integrates LLM reasoning with symbolic execution, directed fuzzing, and static analysis.[2] | Models should orchestrate specialized analyzers, not replace them. |
| FuzzingBrain | Its published architecture combines coverage-guided fuzzing, suspicious-point reasoning, dynamic PoV verification, and delta scans.[3] | Report a sanitizer-backed crash, not a plausible story. |
| SHERPA | The team reports reducing 127+ raw crashes to 27 high-signal candidates and 18 validated findings.[4] | Triage and human validation are first-class stages. |
| Big Sleep | Project Zero described an AI-assisted, exploitable SQLite stack-underflow found from a commit diff; broad fuzzing had not reproduced it after 150 CPU-hours.[5] | A patch can collapse the search space into a concrete invariant. |
| MAPTA | The paper reports 80/104 benchmark tasks (76.9%), but 0% on blind SQL injection, with a median 143.2 seconds and 25.1 tool calls.[6] | Capability varies sharply by class; budgets and validators matter. |
| D-CIPHER | The reported solve rates were 22% on NYU CTF, 22.5% on Cybench, and 44% on Hack The Box.[7] | Autonomous CTF skill is useful but far from universal. |
| EnIGMA | Interactive debugger and remote-server tools materially improved agent performance.[8] | Tool feedback loops beat prose-only reasoning. |
| RESTler | Stateful request sequencing inferred producer-consumer dependencies; Microsoft reports 28 confirmed and fixed GitLab bugs in its evaluation.[9] | API state and sequence are part of the attack surface. |
| Single-packet race research | HTTP/2 single-packet synchronization achieved a reported median spread near 1 ms and sharply improved reproduction of a real race.[10] | Model transitions and synchronization, not just endpoints. |
| CodeQL variant analysis | GitHub documents security queries finding related occurrences after one vulnerability pattern is understood.[11] | One trusted fix can seed systematic sibling search. |
| Fuzz Introspector | The project exposes reachability, blockers, and uncovered functions from fuzzing data.[12] | Coverage gaps should decide where expensive reasoning is spent. |

## Recent directions

A 2026 multi-agent Java harness-generation study reports a median 26% coverage
improvement over OSS-Fuzz baselines and three bugs found during its experiment;
it also reports an average ten-minute generation cost of about US$3.20.[13]
PromptFuzz earlier reported roughly 1.6× branch coverage over two baselines and
33 genuine new bugs from 49 crashes.[14] These results support generation as a
force multiplier, but both still depend on conventional coverage and crash
oracles.

Commercial claims need separate treatment. XBOW states that an autonomous
system reached the top of HackerOne's US leaderboard and describes a separate
validator and swarm architecture.[15] That is relevant product evidence, not an
independent guarantee that the same outcome transfers to a new account,
program, or target class.

## BARQ design decisions

The following are **BARQ inferences** from the evidence above:

1. **Start from a changed invariant.** Patch diffs and API security changes are
   higher-information seeds than generic “find a bug” prompts.
2. **Build an authorization lattice.** Comparing anonymous, owner, non-owner,
   privileged, and cross-tenant controlled identities targets a class where
   semantic context matters more than payload volume.
3. **Represent state explicitly.** Race hypotheses should arise only when two
   transitions share a resource invariant and at least one mutates it.
4. **Separate discovery from proof.** A candidate, a safe plan, and a validated
   disclosure are different artifacts with different permissions.
5. **Measure reviewer yield.** Precision, reproducibility, and time-to-signal
   are more useful than raw finding count.
6. **Keep target adapters private.** Public code should prove engineering depth;
   credentials, live observations, and program-specific strategies should not
   be part of the portfolio.

## Safety and program fit

Bugcrowd's documentation and disclose.io safe-harbor guidance emphasize an
explicit, exhaustive in-scope list.[16] Intigriti's researcher guidance likewise
anchors testing in permission and avoidance of disruption.[17] Saudi BugBounty
publishes platform terms and program-specific rules that must govern any live
campaign.[18] BARQ's policy layer therefore denies any host, scheme, port, or
method not explicitly listed and never performs unattended live execution.

## Limits

- Synthetic and CTF benchmarks do not predict bounty acceptance rates.
- Static variant matches remain hypotheses until a regression harness confirms
  the invariant and reachability.
- Response similarity can reflect intentional product behavior; controlled
  object ownership and tenant labels are required.
- A modeled race says where to investigate, not that a race is exploitable.
- No responsible system can guarantee a vulnerability, reward, leaderboard
  position, or conference result.

## Sources

1. [DARPA AI Cyber Challenge — final competition results and archive](https://aicyberchallenge.com/)
2. [Atlantis: A Hybrid Cyber Reasoning System for AIxCC](https://arxiv.org/abs/2509.14589) and [Team Atlanta repository](https://github.com/Team-Atlanta/aixcc-afc-atlantis)
3. [FuzzingBrain AIxCC CRS repository](https://github.com/fuzzingbrain/afc-crs-all-you-need-is-a-fuzzing-brain)
4. [SHERPA AIxCC CRS repository](https://github.com/AIxCyberChallenge/sherpa)
5. [Project Zero — From Naptime to Big Sleep](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)
6. [MAPTA: Multi-Agent Programmatic Tooling Architecture](https://arxiv.org/abs/2508.20816)
7. [D-CIPHER: A Dynamic Collaborative Intelligent Multi-Agent Framework](https://arxiv.org/abs/2502.10931)
8. [EnIGMA: Enhanced Interactive Generative Model Agent](https://arxiv.org/abs/2409.16165)
9. [Microsoft Research — RESTler: Stateful REST API Fuzzing](https://www.microsoft.com/en-us/research/publication/restler-stateful-rest-api-fuzzing/)
10. [PortSwigger Research — Smashing the state machine](https://portswigger.net/research/smashing-the-state-machine)
11. [GitHub Security Lab — Security research with CodeQL](https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/)
12. [Fuzz Introspector documentation](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
13. [Multi-Agent LLM-Based Fuzzing Harness Generation for Java](https://arxiv.org/abs/2603.08616)
14. [PromptFuzz: Harnessing LLMs for Fuzz Driver Generation](https://arxiv.org/abs/2312.17677)
15. [XBOW product and research claims](https://xbow.com/)
16. [Bugcrowd documentation](https://docs.bugcrowd.com/) and [disclose.io safe harbor](https://disclose.io/)
17. [Intigriti researcher code of conduct](https://www.intigriti.com/researchers/code-of-conduct)
18. [BugBounty Saudi](https://bugbounty.sa/)
