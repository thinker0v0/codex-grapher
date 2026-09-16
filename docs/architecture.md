# Verified Adaptive Project Graph architecture

Status: local-fixture implementation candidate; release `NOT_PASS`

## Surface and route boundary

Hermes native Buzz is the sole final active operator surface. The router accepts
exactly `nomad`, `opensource`, `business`, and `hynix`; ambiguity, an unknown
route, or cross-route continuation fails closed. Slack and `fin-global` are frozen
legacy compatibility artifacts and sit outside the active graph.

The local ingress implementation is a fixture-key native-like adapter. It models
the envelope, identity/channel/thread binding, replay behavior, and four-route
dispatch without network delivery or a service action. It is not a real Buzz
relay, real key, installed gateway, staging, or production boundary.

## Trust and data flow

```text
Hermes native Buzz (final, not locally proven)
                 |
fixture-key native-like adapter (current local boundary)
                 v
Hermes planner -> VAPG SQLite schema v5 -> isolated builder attempt
                                            |
                                            v
                         manifest v4: <task>/attempt-<n>
                                            |
                         content-addressed immutable ingress
                                            |
                    expiring + heartbeated evaluator claim
                                            |
                      signed schema-v3 immutable outcome ID
                                            |
                             ID-only deterministic integrator
                                            |
                  SHA publication + graph-bound journal/head CAS
                                            |
                         human gate for consequential action

Frozen legacy only: Slack, fin-global (no active edge into this graph)
```

Builder, evaluator, and integrator use different identities, permissions, and
state. A builder cannot claim/evaluate its artifact or promote a commit. An
evaluator cannot modify source, integration state, or the rubric. The integrator
does not accept inline evidence or model judgment; it resolves immutable IDs and
verifies their entire binding chain.

## Database lifecycle

The complete on-disk graph format is identified by SQLite VAPG `application_id`
and `user_version=5`. Schema ownership is centralized: graph, coordinator,
evidence, publication, and Buzz tables do not depend on constructor order.

Bootstrap inspection is read-only. Creation or recognized migration requires an
explicit apply action against an offline database with no journal/WAL sidecars.
Exact clean v0 through v4 databases are recognized predecessors only when each
event chain has version-0 genesis, contiguous and adjacent runtime-valid
transitions, and a final node-head match. Unknown, future, partial, foreign,
ambiguous, or sensitive legacy state fails closed without changing database
bytes. Runtime
constructors require an existing v5 database and never create or migrate it
implicitly. V5 adds durable `integration_attempts.affected_graph_*` binding and
database-level no-replace enforcement for immutable evaluator outcomes.

## Attempt and evaluator identity

Artifact manifest v4 includes a positive attempt number. A successful producer
publishes a new namespace `<task>/attempt-<n>` without replacement. The manifest,
bundle, path-check, contract, candidate, and required-test outputs are immutable
regular files with recorded byte lengths and hashes. The artifact ID is derived
from validated manifest content, not its caller-provided path.

An evaluator claim binds artifact, node, graph version, evaluator, and expiry.
Only an authenticated heartbeat can extend the exact active claim. Recovery
expires stale claims explicitly. Evaluation-result schema v3 binds both
`artifact_id` and `claim_id`; after signature and ledger verification, its
canonical bytes are stored once under a content-derived `outcome_id`.

## Required-test boundary

The manifest records the exact ordered command list, candidate SHA, integer-zero
exit, output byte length, and output SHA-256. The runner checks a clean candidate
before and after every command, allows at most 8 MiB combined suite output, and
uses a single suite deadline. A dedicated Linux child-subreaper is pinned by
pidfd before command launch, contains new sessions and double forks, signals exact
descendant identities through pidfds, and accepts only after `waitpid` proves
`ECHILD`. Timeout, overflow, mutation, leaks, missing kernel support, or missing
cleanup proof fail closed. External same-UID service delegation outside the
command ancestry remains `UNPROVEN`. Integration revalidates these records through
immutable artifact/outcome IDs.

## Publication, promotion, and rollback

Each publication generation is an immutable directory named by its exact commit
SHA. Existing generations are verified rather than replaced. Readers are pinned
to a SHA generation, never a mutable shared checkout.

Promotion and rollback are project-scoped, graph-bound operations. Their phases
append to one project-global hash-chain journal. Each entry binds the affected
goal/node/integration attempt and graph projection. A singleton journal-tail row
tracks the last global sequence/hash; a versioned head row per project tracks its
accepted SHA/generation/integration attempt. CAS and exact-operation replay make
recovery deterministic. Rollback can select only the predecessor recorded by the
integrated graph chain. Completed entries require exact forward and reverse
closure through their attempt, integrated node, artifact, outcome, canonical
manifest location, and reverified durable bytes before startup or dispatch
effects. Candidate promotion also validates both paths of a NUL-framed no-rename
diff, preventing forbidden-source rename bypass.

## Project and financial separation

- `nomad`: point-in-time research, models, backtests, stress, and paper evidence.
- `opensource`: user problem, implementation, tests, security/license, and docs.
- `business`: evidence, economics, bounded prototype, and experiment plan.
- `hynix`: dated sources, reproducible data/analysis, contradictions, and refresh.

Research, paper, and any future live system remain separate. Hermes and Codex do
not receive live broker credentials. Buzz cannot activate live trading, increase
risk, withdraw funds, or disable a risk service.

## Evidence level

During the active NQ window, only no-cost, secret-free local fixture/controller
work is authorized. No network/external APIs, credentials, sudo, install/deploy/
restart action, staging, or real project worker is allowed. A complete exact local
evidence packet may support `LOCAL_FIXTURE_PASS` only. Active producer wiring and
deployed/native/real-worker/restart/final-user evidence are absent, so release is
`NOT_PASS` under the unchanged rubric.
