# Clean-Session Handoff

> Current cycle: [2026-09-21 public developer reliability](docs/cycles/20260921-reliability/HANDOFF.md).
> The user authorized research and local implementation, and selected developer
> installation/execution/verification/recovery as the target. This supersedes the
> historical NQ stop for this work. Legacy release gates remain unchanged; no
> production deployment, external messages or publication are automated tests.


Status: local code integration/evidence pending; release `NOT_PASS`

## Objective

Finish one clean, secret-free local Verified Adaptive Project Graph candidate for
the exact routes `nomad`, `opensource`, `business`, and `hynix`, then produce its
exact machine evidence packet. Hermes native Buzz is the sole final active surface.
This handoff authorizes neither deployment nor a release pass.

## Authoritative artifacts

Read in order: `PROJECT.md`, `PROBLEM.md`, `RESEARCH.md`, `SOLUTION.md`,
`DECISIONS.md`, `SCAFFOLDING.md`, `RUBRIC.md`, then `AGENTS.md` and `OPERATIONS.md`.

## Repository map and constraints

- Existing controller/router: `control_plane/`.
- Existing workers/installers: `scripts/`, `deploy/systemd/`.
- Existing task/evidence schemas: `schemas/`.
- Existing Hermes prompts: `prompts/hermes/`.
- Preserve all current isolation, signed authorization, path guards, and forbidden
  consequential actions.
- Do not use live trading or real external side effects as tests.
- Final operator decision D019: use Hermes native Buzz and exactly the four active
  routes `nomad`, `opensource`, `business`, and `hynix`. Treat Slack and
  `fin-global` as legacy/frozen; do not extend them or count them as active routes.
- Active-cycle decision D020: while NQ is active, use only no-cost, secret-free
  local fixtures/controller code. Do not use network/external APIs, credentials,
  sudo, installers, deploy/restart/service actions, staging, or real project
  workers.

## Frozen local code contract

- VAPG SQLite schema v5; explicit offline-only bootstrap/migration from exact clean
  v0-v4 predecessors; no implicit creation or migration from runtime constructors.
  Migration requires version-0 genesis, contiguous/adjacent valid transitions,
  and exact final node state/version, otherwise bytes remain unchanged.
- Artifact manifest v4; immutable `<task>/attempt-<n>` namespaces;
  content-addressed immutable evaluator ingress.
- Expiring evaluator claims with authenticated heartbeat/recovery semantics.
- Evaluation-result schema v3 bound to `artifact_id` and `claim_id`; signature-
  verified canonical results stored once as immutable content-derived outcome IDs.
- Evaluation and integration accept IDs only and reject inline/mutable evidence.
- Required tests bind exact ordered command, clean candidate SHA, zero integer
  exit, byte length, and output hash; combined output is bounded to 8 MiB; one
  suite timeout applies. A pidfd-pinned Linux subreaper terminates and reaps the
  whole descendant tree, including new sessions/double forks, and `ECHILD` is the
  acceptance proof; unsupported containment fails closed. External same-UID
  service delegation outside the ancestry remains `UNPROVEN`.
- Immutable SHA-named publication generations; graph-bound project promotion and
  rollback recorded in one project-global append-only hash chain with singleton
  tail and per-project CAS head projection. Completed journals close exactly over
  attempt/node/artifact/outcome/manifest identities and durable bytes before any
  startup/dispatch effect.
- Candidate write sets validate both sides of NUL-framed, no-rename diffs.
- Native-like Buzz adapter uses fixture keys only, denies non-contract identity or
  routing, and maps exactly four fixture channels. Current/legacy durable route
  rows close over that same enum. A canonical outcome in any later state, a
  PASSED/INTEGRATING/INTEGRATED node, any integration attempt, or a completed
  journal requires type-exact same-graph/project coordinator and integrator
  coverage before any service or Buzz effect. Every project outcome's inventory,
  signature, manifest-derived bundle, ref, and binding is reverified;
  missing/tampered/extra immutable evidence freezes adapter replay state, audit,
  and graph mutation. It is not real Buzz staging.
- Current event chains close exactly over the node head; exceptional recovery or
  same-state rebase events require durable claim/journal proof. Evaluated claims,
  outcomes, and the global ledger close exactly, completed origins retain their
  attempt base, and new/incomplete rollback ownership follows the head's exact
  attempt ID while completed operation replay remains immutable.

## Integration and evidence order

1. Combine the bounded local component work without weakening any invariant above.
2. Confirm schema and API versions, attempt namespace, immutable ID flow, test
   runner bounds, publication/journal projections, and exact four-route fixture.
3. Run only authorized deterministic local checks in one clean final candidate.
4. Produce a machine evidence packet that records the exact final Git SHA,
   commands, exits, complete output hashes, schema/configuration hashes, and clean
   status. Do not reuse component-branch evidence as final-candidate evidence.
5. Record the resulting evidence in the research/evaluation trail. If every local
   contract passes, use only the label `LOCAL_FIXTURE_PASS`.
6. Stop. A later explicit operator decision is required before any installation,
   deployment, service/restart, staging, external integration, or real-worker run.

## Acceptance

The current cycle can satisfy only the local validation contract in
`SCAFFOLDING.md`. `LOCAL_FIXTURE_PASS` does not satisfy the frozen release rubric.
Active producer wiring, deployed SHA/config/service evidence, native Buzz
credentials and relay E2E, real project workers, restart/host recovery,
representative four-route operation, and blind final-user evidence are absent.
The fixture adapter now commits router graph/audit and its final `COMPLETE`
response in one `BEGIN IMMEDIATE` transaction and rolls back deterministic
pre-commit faults. Native transport and deployed restart behavior remain
`UNPROVEN`.

Release remains `NOT_PASS`. In a separately authorized future cycle, all deferred
commands in `SCAFFOLDING.md` must pass at the evaluated Git SHA and a separate
`independent-ai-judge` must score the unchanged `RUBRIC.md` at least 95/100 with
every section minimum and hard gate passing. Never edit the rubric to obtain a pass.
