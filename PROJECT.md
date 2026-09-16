# Project

Status: local-fixture implementation candidate; release `NOT_PASS`

## Durable objective

Build and operate a maximum-results, unattended Hermes + Buzz + Codex system
that advances four isolated project portfolios while the operator is away:

- `nomad`: finance research, point-in-time datasets, AI/model experiments,
  reproducible backtests, and paper-safe trading-system development;
- `opensource`: useful open-source products with tests, documentation, license,
  security, and release readiness;
- `business`: evidence-backed business discovery, validation assets, and bounded
  prototypes;
- `hynix`: isolated company/domain research and analytical tooling.

Hermes is the planner and operator interface, Buzz is the human-agent workspace,
Codex is the isolated builder, an independent evaluator owns scoring, and a
deterministic integrator promotes only verified results.

## Final interface and route boundary

The operator approved Hermes' native Buzz gateway as the final active human-agent
interface. The active project graph has exactly four routes: `nomad`, `opensource`,
`business`, and `hynix`. Slack configuration and the `fin-global` profile remain
legacy, frozen compatibility artifacts; new control-plane work must not extend or
route active graph work through them. This is an approved scope decision, not
evidence that Buzz staging, deployment, or the frozen rubric has passed.

## Current NQ cycle

This cycle is deliberately local. While NQ is active, authorized work is limited
to no-cost, secret-free local fixtures and controller code. It excludes network
and external APIs, credentials, sudo, installation, deployment, service restart,
staging, and real project workers. The scope boundary remains in force even when
more work might improve a release score.

The strongest available cycle verdict is `LOCAL_FIXTURE_PASS`, and only after a
final evidence packet binds deterministic local results to the exact integrated
Git SHA and artifact/configuration hashes. The release verdict is `NOT_PASS`.
Native Buzz operation, active producer wiring, deployment, real-worker behavior,
restart recovery, and the frozen rubric's final-user and deployed gates have not
been proven.

## Bounded local implementation contract

The final local candidate is required to enforce all of the following as one
coherent contract. This prose states the contract; it is not implementation
evidence.

- SQLite uses VAPG graph schema v5. Creation and migration from an exact clean v0
  through v4 predecessor occur only through an explicit offline bootstrap/apply
  path. Legacy events must have a NULL-old-state version-0 genesis, contiguous
  versions, adjacent allowed transitions, and a final state/version equal to the
  node head; rejection does not alter database bytes.
  Runtime constructors neither create nor migrate a database and fail closed on
  incompatible state. V5 durably binds `integration_attempts.affected_graph_*`
  and adds database-level rejection of outcome replacement.
- Artifact manifest v4 creates immutable attempt namespaces at
  `<task>/attempt-<n>`. Evaluator ingress is immutable and content-addressed.
- Evaluator claims expire unless heartbeated. Evaluation-result schema v3 binds
  both `artifact_id` and `claim_id`; a verified signed result becomes an immutable,
  content-derived outcome ID.
- Evaluation, integration, promotion, and rollback use durable IDs rather than
  caller-supplied inline evidence or mutable paths.
- Required-test evidence binds exact ordered commands, candidate SHA, integer-zero
  exits, byte lengths, and output hashes; enforces clean candidate state before
  and after commands; caps aggregate combined output at 8 MiB; applies a single
  suite timeout; and uses a pidfd-pinned Linux subreaper to terminate/reap the
  whole descendant tree through an `ECHILD` proof. This includes setsid/double-
  fork children; unavailable containment fails closed, while external same-UID
  service delegation outside the ancestry remains `UNPROVEN`.
- Repository publications are immutable SHA-named generations. Project-scoped,
  graph-bound promotion and rollback append to one project-global hash-chain
  journal whose durable tail and per-project head projection advance by CAS.
  Completed publications must have exact journal/attempt/node/artifact/outcome/
  manifest closure and reverified durable bytes before startup or dispatch effects.
- Candidate write-set checks disable rename inference and validate the NUL-framed
  source deletion and destination addition independently.
- The Buzz ingress exercised here is a fixture-key native-like adapter only. It
  enforces exactly the four final routes but provides no real relay, credential,
  staging, installed-service, or production proof.

## Target actor

The primary actor is one operator who issues goals before or during work, leaves
the computer, and expects auditable progress and concise reports through Buzz.

## Measurable outcomes

- Every accepted goal becomes a durable graph with explicit acceptance tests.
- After process or host restart, the graph resumes from the last committed node
  without duplicating consequential work.
- All four routes can progress independently; same-repository concurrency is
  limited to non-conflicting task nodes.
- A builder result never counts as complete at `EVIDENCE_PENDING`; an independent
  evaluator and deterministic tests must pass before integration.
- Passed changes are promoted atomically to the bound project baseline and are
  visible to the next task.
- `router_rc=0` with valid evidence cannot be classified as a generic failure.
- Buzz can request goals, status, approvals, cancellation, and reports without
  exposing credentials.
- The final frozen rubric scores at least 95/100 with every hard gate passing.

## Constraints

- Prefer maximum verified progress over token minimization; high budgets are
  ceilings, not utilization targets.
- Use current VPS and isolated Linux identities where practical.
- Preserve project separation, signed authorization, path guards, audit hashes,
  idempotency, and human approval for consequential actions.
- External sources and channel messages are untrusted input.
- Real integrations are preferred, but destructive or financial validation uses
  sandbox, staging, backtest, or paper environments.

## Human approval boundaries

Only the human operator may approve live capital, broker credentials, strategy
activation, capital/risk-limit increases, payments, contracts, external messages,
publication, merge to protected branches, releases, or production deployment.

## Non-goals

- Giving Ox Alpha, Hermes, Buzz, or Codex unrestricted control of the laptop.
- Measuring success by tokens, hours, sessions, generated files, or rhetoric.
- Fully autonomous live trading or using live losses as an automated experiment.
- Letting an agent grade or integrate its own work.
- Replacing deterministic project tests with an LLM score.

## Current stage

The design and frozen rubric remain authoritative. Local controller hardening is
being integrated and may be evaluated only as a secret-free local fixture at its
final merged SHA. Active producer wiring and deployment evidence are absent, so
release evaluation cannot pass in this cycle and remains `NOT_PASS`.
