# Agent Scaffolding

> Current cycle: [2026-09-21 portable workers](docs/cycles/20260921-portable-workers/HANDOFF.md).
> The user authorized generic repository tasks, real Codex subscription execution,
> OS role separation, disposable guest restart/backup validation and SQLite support,
> followed by a separate `claude-grapher` repository and OSS publication. Claude
> live execution is explicitly deferred until the user obtains an account.
> This supersedes historical NQ restrictions for the authorized cycle. Preserve
> all legacy rubrics. No production changes, purchases or protected merges are
> authorized; publication and owner delivery are separate actions, never tests.


Status: frozen local-fixture contract; release `NOT_PASS`

## Surface and current authorization

Hermes native Buzz is the sole final active surface. Its route enum is exactly
`nomad`, `opensource`, `business`, and `hynix`; no default or fifth route exists.
Slack and `fin-global` are frozen legacy compatibility artifacts.

During the active NQ window, roles may read repository state and build/test only
no-cost, secret-free local fixtures and controller code. They may not use network
or external APIs, credentials, sudo, installers, deployment, service restart,
staging, or real project workers. A local role cannot turn this restriction into
release evidence by relabeling a fixture.

## Roles

- **Hermes planner:** intake, decomposition, graph routing, operator reports.
- **Codex builder:** one scoped graph node in an isolated attempt worktree.
- **Evaluator:** read-only rubric/evidence assessment, append-only ledger output,
  result signing with an evaluator-only private key, and controller transitions.
- **Integrator:** deterministic verified patch promotion; no model reasoning.
- **Risk reviewer:** finance/security/licensing hard-gate evidence.
- **Human operator:** taste, authority, live capital, external actions.

## Durable paths

- `control_plane/project_graph.py`: graph/checkpoint/state machine.
- `control_plane/project_integrator.py`: verified atomic promotion.
- `schemas/project-goal.schema.json`, `schemas/project-node.schema.json`: interfaces.
- `config/project-graphs.json`: stdlib-validated domain templates and concurrency.
- `prompts/hermes/buzz-supervisor.md`: channel/command contract.
- `/var/lib/ai-ops-graph/graphs.sqlite`: future root-owned runtime state; not
  touched in this local cycle.
- `<local-evidence-root>/<task>/attempt-<n>/`: immutable manifest-v4 attempt
  namespace used by fixtures. Future runtime roots must preserve the same shape.
- `/srv/hermes/evaluator/source/` and `artifacts/`: read-only evaluator inputs.
- `/srv/hermes/<profile>/runtime/integration/`: staged promotion/rollback evidence.

The `/srv` paths describe the future authorized runtime contract. They are not
evidence that those paths are installed, wired, or deployed.

## Database construction contract

- The SQLite file has VAPG `application_id` and `user_version=5`.
- The bootstrap command is read-only planning by default. Creation or migration
  requires an explicit apply flag while the database is offline and has no
  journal/WAL sidecars.
- Only the exact empty/new schema or an exact clean v0-v4 predecessor may be
  created or migrated. Unknown, future, partial, foreign, ambiguous, or safety-
  sensitive legacy contents fail closed for authenticated recovery. Schema v5
  durably stores `integration_attempts.affected_graph_*` and rejects replacement
  of an immutable evaluation outcome at the database boundary. Legacy node
  histories migrate only when event versions are exactly `0..node.version`, the
  genesis old state is NULL, every old/new pair is adjacent and allowed by the
  runtime transition contract, and the final event equals the node state/version.
  Any goal outside the exact four-route enum or any sensitive old/new event state
  rejects before migration. Rejection leaves the database byte-for-byte unchanged.
- Graph, coordinator, evidence, Buzz, and service constructors open an existing
  schema v5 only. Constructor order cannot define schema, and ordinary runtime
  never creates or migrates a database.

## Node contract

Required: graph/project/node IDs, requester, objective, dependency IDs, value and
risk class, repo/base SHA, write set, acceptance criteria, tests, tools, forbidden
actions, model/effort policy, compute ceiling, stagnation rule, evidence schema,
evaluator contract, integration policy, deadline, cancellation and idempotency IDs.

Attempt identity is `(node_id, attempt)` and each attempt has at most one immutable
artifact. A node explicitly points to its active artifact; no later mutable path
lookup may change what is evaluated or integrated.

## State transitions

The implemented local VAPG state enum is exactly `BLOCKED`, `READY`, `LEASED`,
`RUNNING`, `EVIDENCE_PENDING`, `EVALUATING`, `PASSED`, `INTEGRATING`,
`INTEGRATED`, `NEEDS_HUMAN`, `CANCELLED`, and `FAILED_GATE`. Its implemented
transition relation is:

- `BLOCKED -> READY | CANCELLED`
- `READY -> LEASED | CANCELLED | NEEDS_HUMAN`
- `LEASED -> RUNNING | READY | CANCELLED`
- `RUNNING -> EVIDENCE_PENDING | READY | FAILED_GATE | CANCELLED`
- `EVIDENCE_PENDING -> EVALUATING | FAILED_GATE | READY`
- `EVALUATING -> PASSED | READY | FAILED_GATE | NEEDS_HUMAN`
- `PASSED -> INTEGRATING | FAILED_GATE`
- `INTEGRATING -> INTEGRATED | PASSED | FAILED_GATE`
- `NEEDS_HUMAN -> READY | CANCELLED | FAILED_GATE`

`INTEGRATED`, `CANCELLED`, and `FAILED_GATE` are the implemented local terminal
states. `NEEDS_HUMAN` is a resumable local pause, not proof of the full approval
workflow described by the release rubric. Leases expire and recover through the
implemented transitions above.

`DONE`, `REWORK`, `PIVOT`, `HUMAN_GATE`, `FAILED_STAGNATION`, and
`FAILED_PERMANENT` are not implemented VAPG states. Adaptive attempt allocation,
root-cause pivot/stagnation terminalization, a full durable human gate, and a
post-integration `DONE` transition remain release targets and are `UNPROVEN`.

Evaluator claims are separate expiring leases. Claim creation binds artifact,
node, evaluator identity, graph version, and expiry. An authenticated heartbeat
extends only that exact active claim. Stale recovery records expiration and returns
the node to a bounded retry/disposition path; it never invents a signed result.
Claim IDs are deterministic, each claim binds the exact
`EVIDENCE_PENDING -> EVALUATING` event and payload, and an evaluated artifact has
no active pointer or active claim. Its one resolved claim, signed result, canonical
outcome, graph node, contract, and content-derived ledger row form one closed
identity chain. Ledger predecessor hashes are exact row-to-row adjacency from a
NULL genesis.

## Release-target adaptive compute policy — UNPROVEN

The following policy remains the intended supervisor behavior; it is not current
local VAPG state-machine evidence:

- Default one strong attempt for well-specified nodes.
- Add fresh-context refinement after actionable verifier feedback.
- Use 2–4 diverse candidates for high-value uncertain design/research nodes.
- Compare candidates with tests first and an independent list-wise evaluator next.
- Never repeat an identical failed strategy more than twice.
- Maintain current maximum policy ceilings but record actual marginal progress.

## Required evidence

- Bound Git SHA and contract hash.
- Artifact-manifest schema v4, explicit attempt number, and immutable namespace
  `<task>/attempt-<n>`.
- Full ordered required-test commands, candidate SHA, integer-zero exits, output
  byte lengths and hashes, and clean candidate checks before/after every command.
- Evidence that combined required-test output stayed within 8 MiB, the single
  suite timeout held, and no descendant survived failure/completion, including a
  new-session double fork that closed its inherited descriptors. The Linux runner
  must acquire its dedicated subreaper supervisor by pidfd before command launch,
  signal descendants through identity-checked pidfds, and require `waitpid` to
  prove `ECHILD`; unsupported containment capabilities fail closed.
- Workspace path-check result.
- Patch/artifact manifest and hashes.
- Controller event-chain verification.
- Content-addressed evaluator ingress plus active claim/heartbeat evidence.
- Evaluation-result schema v3 bound to `artifact_id`, `claim_id`, rubric,
  candidate, contract, ledger, evaluator identity, signature, and immutable
  content-derived `outcome_id`.
- Integration commit, previous/new binding, rollback reference.
- ID-only integration request; caller-supplied inline manifest/result is rejected.
- SHA-named immutable publication generation, global hash-chain tail, per-project
  head projection, and graph-bound promotion/rollback journal entries.
- Exact completed-journal forward/reverse closure through one completed attempt,
  integrated node, immutable artifact, signed outcome, canonical manifest path,
  and reverified durable bytes before startup or dispatch effects.
- Candidate diff evidence with rename inference disabled and both NUL-framed
  source deletion and destination addition checked against the write set.
- Restart/recovery and duplicate-suppression traces (release evidence; not
  authorized or produced in the current NQ cycle).

## Accepted baseline materialization contract

For each active project, `refs/ai-ops/accepted/<project>` is the deterministic
accepted Git reference. The integrator advances that ref with compare-and-swap,
ensures an immutable publication directory whose generation name is the exact
accepted SHA, and only then atomically replaces the worker-readable binding. The
binding schema remains
exactly `{ "repo": <name>, "base_sha": <40-hex commit> }`, owned by root,
group-readable by the matching worker, mode `0440`. A binding SHA is invalid if
the accepted ref, SHA generation, or materialized bytes do not match it.

Promotion and rollback also update graph state. Each multi-phase operation is
identified once and appended to a single project-global hash-chain journal. The
singleton tail projection must equal the last journal sequence/hash, and the
CAS-protected project head must equal the integrated graph projection. Replay is
idempotent only for the exact same graph-bound operation. Rollback selects the
recorded predecessor; a caller cannot name an arbitrary commit. Completed origin
nodes retain the attempt's exact base SHA. New or incomplete rollback work can
proceed only while the current publication head's integration-attempt ID equals
the supplied attempt, preventing an old attempt from crossing a same-SHA
repromotion; an already-completed operation remains an immutable replay.

Every current event chain is exact through the node head. Internal expired-claim
recovery and same-state publication rebase events are not public transitions and
are valid only with their exact durable claim or completed-journal affected-node
proof. A matching reason string alone grants nothing.

## Human gates

Mandatory for live trading, credentials, capital/risk changes, payment, contract,
external message, protected merge, release, external publication, and production
deployment.
Gate requests persist indefinitely and are resumable; timeout never means approval.

## Failure handling

- Transport success with unknown task state triggers reconciliation, not failure.
- Invalid/missing evidence triggers `FAILED_GATE`.
- Repeated-root-cause detection, automatic strategy pivot, stagnation accounting,
  and third-identical-launch denial are release targets and `UNPROVEN`. The current
  state machine exposes bounded `READY` retry/disposition, `NEEDS_HUMAN`,
  `CANCELLED`, and `FAILED_GATE` paths only.
- Stale base SHA triggers replan/rebase before build or integration.
- Unexpected executor orphan is terminalized or safely resumed from checkpoint.
- Credentials or prohibited paths in evidence quarantine the attempt.

## Current-cycle validation contract

The final local integrating owner may run deterministic secret-free unit and
fixture checks and must preserve a machine evidence packet with exact command,
exit, complete output hash, candidate SHA, relevant schema/configuration hashes,
and clean Git status. The packet must cover database bootstrap v5, artifact and
required-test boundaries, ingress/claim/outcome ID flow, publication/journal
recovery fixtures, and the fixture-key native-like Buzz adapter. Only a complete
packet at the final integrated candidate may support `LOCAL_FIXTURE_PASS`.

Buzz mutations always run DB-static closure. Any canonical outcome regardless of
current node state, PASSED/INTEGRATING/INTEGRATED node, integration attempt, or
completed journal requires complete project coverage by type-exact, same-graph,
same-project `ProjectCoordinator` and type-exact `ProjectIntegrator` instances.
The shared gate reverifies every exact immutable artifact inventory, signed
outcome, manifest-derived bundle, publication materialization, accepted ref, and
worker binding; missing, empty, partial, mismatched, or shadowed coverage freezes
ingress/audit/graph writes. Fresh graphs without sensitive/evidence rows accept
`None` or an empty map. Adapter replay-state and completion gates are rechecked
inside the same `BEGIN IMMEDIATE` transaction as router mutation/audit and the
final `COMPLETE` response. Deterministic pre-commit faults roll back the entire
unit; incomplete replay is denied. This local property cannot support a deployed,
native-transport, production, or release claim.

This local hardening worktree performs only deterministic, secret-free fixture
checks. It does not run real-worker, restart, service, staging, or deployment
validation.

Launching a same-UID external service that deliberately reparents work outside
the required-test ancestry is not proven by the local subreaper fixture and
remains `UNPROVEN`.

## Deferred release acceptance commands

```bash
bash scripts/verify-foundation.sh
python3 -m unittest discover -s tests -v
bash scripts/verify-project-graph-e2e.sh
bash scripts/verify-buzz-routing.sh
bash scripts/verify-finance-safety-boundary.sh
bash scripts/verify-restart-recovery.sh
```

No command may place a live trade, publish externally, pay, release, or message an
external party as part of automated acceptance. The commands above are retained as the
frozen future release contract, but the active NQ cycle does not authorize heavy
E2E, service/restart, staging, or real-worker execution. Consequently their
absence is a release blocker, not permission to mark them passed.

## Verdicts and missing wiring

- Local: `LOCAL_FIXTURE_PASS` only after the final exact evidence packet; otherwise
  local status is `UNPROVEN`.
- Release: `NOT_PASS` until the unchanged rubric independently passes every hard
  gate.
- Known absent: active manifest-v4 producer wiring, installed/deployed SHA and
  configuration/service hashes, real project-worker results, native Buzz staging
  and credentials, restart/host recovery, representative four-route operation,
  and blind final-user evidence.
