# Solution

> Current cycle: [2026-09-21 portable workers](docs/cycles/20260921-portable-workers/HANDOFF.md).
> The user authorized generic repository tasks, real Codex subscription execution,
> OS role separation, disposable guest restart/backup validation and SQLite support,
> followed by a separate `claude-grapher` repository and OSS publication. Claude
> live execution is explicitly deferred until the user obtains an account.
> This supersedes historical NQ restrictions for the authorized cycle. Preserve
> all legacy rubrics. No production changes, purchases or protected merges are
> authorized; publication and owner delivery are separate actions, never tests.


Status: frozen local implementation contract; release `NOT_PASS`

## Chosen mechanism: Verified Adaptive Project Graph (VAPG)

Retain Hermes as planner/supervisor and Buzz as the native human-agent channel.
Replace the fixed timer campaign with a durable, project-aware graph that advances
one verified value node at a time. Codex builders operate in isolated worktrees;
an independent evaluator scores immutable evidence; a deterministic integrator
promotes only passed commits and updates the root-owned repository binding.

Hermes native Buzz is the sole final active operator surface and exposes exactly
`nomad`, `opensource`, `business`, and `hynix`. Slack and `fin-global` are frozen
legacy compatibility artifacts, not alternate active paths.

## Cycle boundary and evidence meaning

While NQ is active, implement and validate only no-cost, secret-free local fixture
and controller behavior. Network/external APIs, credentials, sudo, installation,
deployment, service restart, staging, and real project workers are forbidden.

`LOCAL_FIXTURE_PASS` is the highest possible result in this cycle. It means a
machine evidence packet binds deterministic local checks to the exact clean final
candidate. It does not mean native Buzz, active worker production, deployed
recovery, or release readiness. The release verdict remains `NOT_PASS` until the
unchanged frozen rubric independently passes with all required evidence.

## Graph

```text
INTAKE -> SPECIFY -> PLAN -> BUILD -> TEST -> EVALUATE
                    ^                  |         |
                    |                  |         +-- FAIL -> DIAGNOSE -> PIVOT/REWORK
                    |                  +-- invalid evidence -> FAIL_GATE
                    +-- next value node <- INTEGRATE <- PASS

Consequential node -> HUMAN_GATE -> approved execution or durable pause
```

Every node has typed input/output, immutable attempt ID, idempotency key, bound
Git SHA, owner identity, deadline, policy, evidence hashes, and retry lineage.
SQLite VAPG schema v5 stores graph/checkpoint state; Git stores accepted project
state. Database creation and recognized migration are explicit offline bootstrap
operations. Exact clean v0 through v4 databases are recognized migration
predecessors. Every migrated node must have genesis event version 0 with a NULL
old state, contiguous versions through the node version, adjacent states, only
the runtime transition relation, and a final event matching the node head.
Runtime constructors open only an already bootstrapped current schema and never
create or migrate it implicitly. V5 makes the affected graph binding durable on
each integration attempt and rejects replacement of an immutable outcome at the
database boundary. Both legacy verification and current runtime integrity use the
same exact four-route enum; legacy sensitive event history is not authenticated by
migration and therefore fails without changing the database.

## Immutable local evidence pipeline

1. Artifact manifest v4 assigns an explicit attempt number and publishes a new,
   immutable `<task>/attempt-<n>` namespace. Required path-check, bundle, contract,
   candidate, and test evidence is hash-bound within the manifest.
2. Evaluator ingress validates the complete manifest and files, then identifies
   the artifact by content. It never treats a caller-controlled mutable path as
   durable identity.
3. Only the evaluator may take a bounded claim. A claim has an expiry and must be
   heartbeated; recovery expires stale claims without fabricating an evaluation.
4. Evaluation-result schema v3 binds the exact `artifact_id` and `claim_id` as
   well as the candidate, contract, rubric, ledger, evaluator identity, verdict,
   and signature. The canonical signed result is persisted once under an immutable
   content-derived `outcome_id`.
5. Evaluation and integration APIs accept durable IDs only. They reject inline
   evidence manifests, inline evaluation results, stale claim identities, and any
   attempt to substitute bytes after ingress.

Recovery verifies the complete destination file/directory inventory, not only
named-file hashes. The graph binds every deterministic claim to its exact claim
event, requires an evaluated artifact's active pointer to be NULL, and closes
canonical outcomes over the adjacent content-derived ledger from a NULL genesis.
Node histories are exact through their current state/version; the two internal
exception families require their durable expired-claim or completed-journal proof.

Required tests are part of the evidence boundary, not an unverified builder note.
The runner checks the exact clean candidate before and after every ordered command,
binds integer-zero exit and output byte length/hash to that command and SHA, caps
combined suite output at 8 MiB, enforces one suite timeout, and terminates/reaps the
entire descendant tree on timeout, overflow, mutation, or lingering children. A
dedicated Linux helper becomes a child subreaper before command launch; its parent
first pins the helper with a pidfd, and the helper uses kernel direct-child
accounting, pidfd signals, and `waitpid`/`ECHILD` as the quiescence proof. New
sessions and double forks remain descendants and cannot outlive acceptance.
Missing subreaper, pidfd, or `/proc` child-accounting support fails closed. A test
that delegates work to an external same-UID service outside its ancestry remains
outside this local runner boundary and is `UNPROVEN`.

## Portfolio routing

- Run different project routes concurrently up to host capacity.
- Within one repository, run only graph nodes whose declared write sets do not
  intersect and whose dependencies passed.
- Allocate additional attempts based on value, uncertainty, verifier feedback,
  observed progress, and failure class—not remaining token budget.
- High token/time limits remain ceilings. Two repeated failures with no new
  evidence force a strategy pivot or human pause rather than identical retry.

## Domain graphs

### Finance (`nomad`)

`QUESTION -> POINT_IN_TIME_DATA -> DATA_QA -> BASELINE -> MODEL/STRATEGY ->
LEAKAGE_AUDIT -> WALK_FORWARD -> COST/SLIPPAGE_STRESS -> PAPER -> RISK_REVIEW`

The graph cannot reach `LIVE_CANDIDATE` without a human-signed, expiring grant.
No live order is an automated test. Broker secrets belong only to a dedicated
execution service; Hermes/Ox/Codex receive capability results, never credentials.

### Open source

`USER_PROBLEM -> ISSUE/SPEC -> IMPLEMENT -> UNIT/INTEGRATION -> SECURITY/LICENSE ->
DOCS -> USER_SIMULATION -> RELEASE_CANDIDATE -> HUMAN_RELEASE_GATE`

### Business

`HYPOTHESIS -> MARKET/USER_EVIDENCE -> ALTERNATIVES -> OFFER/ECONOMICS ->
BOUNDED_PROTOTYPE -> USER_SIMULATION -> EXPERIMENT_PLAN -> HUMAN_EXTERNAL_GATE`

### Hynix

`QUESTION -> SOURCE/DATE CHECK -> DATASET -> ANALYSIS -> CONTRADICTION REVIEW ->
REPRODUCIBLE REPORT -> EXPIRY/REFRESH PLAN`

## Buzz operator experience

- One control channel and four project channels.
- Commands: `goal`, `status`, `evidence`, `approve`, `reject`, `cancel`, `resume`.
- Replies include graph/node ID, bound SHA, state, blocker, tests, evaluator score,
  artifact hashes, next action, and whether human input is truly required.
- Cron sends concise portfolio digests and immediate human-gate alerts.
- Channel identity never grants authority by text alone; account/key mapping and
  signed controller policy decide authority.

## Evaluator and integrator

- Evaluator mounts sources/evidence read-only, cannot build or integrate, and alone
  holds the private key used to sign its immutable result. The graph/integrator
  receives only the corresponding public verification key.
- Deterministic tests and guards run before LLM judgment.
- Evaluator returns section scores, hard gates, defects, and evidence references in
  a schema-v3 signed result bound to the active artifact and claim. A verified
  result is an immutable outcome; it cannot be overwritten or silently reissued.
- Integrator is deterministic/root-controlled and ID-only: resolve the artifact
  and signed outcome by immutable IDs; verify their bindings, PASS signature, base
  SHA, allowed paths, clean candidate, exact required-test evidence, and current
  graph head; then promote by compare-and-swap. Caller-provided manifests or
  result documents cannot authorize integration. Candidate write-set validation
  disables rename detection and checks the NUL-framed delete and add paths
  independently, so renaming a forbidden tracked source into an allowed
  destination cannot bypass policy.

## Publication and rollback

Every accepted commit has an immutable publication generation named by its exact
Git SHA. Generation creation fails closed on a dirty or mismatched source and
never replaces an existing generation. Readers pin that SHA generation; no shared
mutable checkout is the evidence identity.

Promotion and rollback are project-scoped and graph-bound, but all phases append
to one project-global publication hash chain. Each entry binds the affected goal,
node, integration attempt, graph projection, before/after SHA and generation, and
version. A singleton journal-tail projection anchors the global sequence and hash;
one CAS-protected head projection per project records its current accepted state.
Every completed entry must have exact forward and reverse closure through its
completed attempt, integrated node, artifact, outcome, manifest path/hash, and
signed durable bytes. That closure is revalidated before dispatch/startup effects
or physical publication checks. Replay must either finish the same prepared
operation or fail closed. Rollback may select only the predecessor authorized by
the integrated graph history, and new/incomplete rollback work may proceed only
while the current head still names that exact integration attempt. Completed
rollback replay is immutable historical output. Completed origin nodes retain the
attempt's base SHA.

The local implementation of these mechanics is not proof that an active worker
produces manifest-v4 attempts or that a deployed binding consumes the publication.
That wiring and its machine evidence are absent in this cycle.

## Buzz implementation boundary

The approved destination remains Hermes native Buzz. This cycle exercises only a
native-like adapter with local fixture keys and injected fixture verification. It
must deny unknown identities/channels, bind event/channel/thread/request identity,
suppress replays, and map exactly four fixture channels to the four final routes.
Fresh graphs with no outcome, sensitive node, attempt, or completed journal use
DB-static validation and may have no coordinator map. Once any canonical outcome
(even after a later state change), PASSED/INTEGRATING/INTEGRATED node, integration
attempt, or completed journal exists, every Buzz write requires a type-exact
same-graph/project coordinator and type-exact integrator. The shared gate first
closes DB state and complete map coverage, then reverifies every project outcome's
exact inventory, signature, manifest-derived bundle bindings, physical ref, and
worker binding before and inside replay-state write transactions. It performs no
network delivery or service action. Router graph/audit work and the final
`COMPLETE` response commit in one `BEGIN IMMEDIATE` transaction, with deterministic
pre-commit fault rollback and complete-only replay. It does not test real Nostr
cryptography, relay transport, Hermes gateway configuration, credentials, mention
or thread behavior, approvals, cron delivery, staging, or production; HG10 remains
`UNPROVEN`.

## Alternatives considered

1. **Keep fixed 24-hour timer loop.** Rejected: observed false failures, no
   cumulative promotion, fixed stages unrelated to current user value.
2. **Use Buzz Desktop to launch unrestricted local agents.** Rejected: auto-approved
   desktop tools weaken the VPS isolation and unattended safety boundary.
3. **Adopt LangGraph immediately.** Deferred: its principles are useful, but the
   current control plane is stdlib-only and already has signed state machinery.
   Add a dependency only if local eval shows the in-house graph is less reliable.
4. **Give each route a fully autonomous live account.** Rejected: a model/tool/data
   error could turn a research failure into irreversible financial loss.
5. **One giant agent/session.** Rejected: poor restart recovery, context drift,
   self-evaluation, and no conflict-safe portfolio concurrency.

## Economics

Optimize expected verified value, not minimum tokens. Track model/API spend and
VPS capacity as constraints and diagnostics. Escalate expensive parallel rollouts
only when expected value and uncertainty justify them. This produces more accepted
outcomes from the available compute without making thrift the objective.

## Failure modes and controls

- False success/failure: controller state + signed evidence are authoritative.
- Context loss: node checkpoints, handoff artifact, Git baseline.
- Duplicate side effect: idempotency and transactional node leases.
- Bad evaluator: deterministic gates, frozen rubric, blind final simulation.
- Merge conflict: write-set locks and base-SHA compare-and-swap.
- Prompt injection: channel/source text untrusted; authority is out-of-band.
- Secret leakage: dedicated secret service, redaction tests, no prompt/env echo.
- Finance overfit: point-in-time data and staged out-of-sample/paper gates.
- Runaway compute: progress/stagnation controls, not low nominal token caps.
- VPS restart: systemd + SQLite recovery + orphan terminalization/resume policy.

## Stop/pivot conditions

- Stop a node on verified pass, human gate, invalid specification, or safety block.
- Pivot after two attempts with the same root cause and no measurable evidence gain.
- Reassess architecture if matched local evals fail to improve verified completion
  or restart recovery over the current baseline.
- Stop this NQ cycle after the exact final local evidence packet is recorded. Do
  not cross into installation, staging, service action, real workers, or external
  integration without a new explicit operator authorization.

## Validation progression

1. Finalize one clean local candidate and record its exact SHA/hashes and bounded
   deterministic outputs. If every local contract holds, label it
   `LOCAL_FIXTURE_PASS`.
2. Retain release `NOT_PASS` and list absent producer, deployment, native Buzz,
   real-worker, restart, representative-route, and final-user evidence.
3. In a separately authorized future cycle, collect the missing safe environment
   evidence and submit the unchanged rubric to an independent evaluator. Only that
   evaluator may award release `PASS`.
