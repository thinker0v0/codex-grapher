# Decision Log

> Current cycle: [2026-09-21 portable workers](docs/cycles/20260921-portable-workers/HANDOFF.md).
> The user authorized generic repository tasks, real Codex subscription execution,
> OS role separation, disposable guest restart/backup validation and SQLite support,
> followed by a separate `claude-grapher` repository and OSS publication. Claude
> live execution is explicitly deferred until the user obtains an account.
> This supersedes historical NQ restrictions for the authorized cycle. Preserve
> all legacy rubrics. No production changes, purchases or protected merges are
> authorized; publication and owner delivery are separate actions, never tests.


- **D010 · 2026-08-28 · Accepted:** Optimize maximum *verified value*, not token
  consumption. High budgets are ceilings. Reconsider only with local evidence that
  fixed maximum-length runs yield more accepted outcomes.
- **D011 · Accepted:** Use Hermes native Buzz gateway on the VPS so approvals,
  memory, sessions, and cron remain in Hermes. Reject Buzz Desktop auto-approval for
  unattended privileged work.
- **D012 · Accepted:** Replace fixed campaign stages with a durable SQLite task DAG
  and Git accepted-state baseline.
- **D013 · Accepted:** Separate planner, builder, evaluator, and deterministic
  integrator identities. No role may self-certify and self-promote.
- **D014 · Accepted:** Parallelize independent routes/nodes only; enforce dependency
  and write-set locks within a repository.
- **D015 · Accepted:** A controller state plus signed evidence is authoritative;
  router return code alone is transport status, not task outcome.
- **D016 · Accepted:** Finance automation may autonomously research, backtest, and
  paper-test. Live capital and risk changes require explicit expiring human grants.
- **D017 · Deferred:** LangGraph dependency. Revisit only after a matched reliability
  comparison against the stdlib graph implementation.
- **D018 · Rejected:** Unrestricted laptop, broker, merge, release, payment, or
  publication authority for Hermes/Ox/Codex.
- **D019 · 2026-08-30 · Accepted and final:** Hermes native Buzz is the sole active
  operator interface and the active VAPG surface has exactly four routes:
  `nomad`, `opensource`, `business`, and `hynix`. Slack and `fin-global` are
  legacy/frozen compatibility artifacts only. Do not add new active behavior to
  either without a new explicit decision cycle. This decision does not claim an
  implementation, staging, security, or release pass.
- **D020 · 2026-08-30 · Accepted for the active NQ cycle:** Authorize only no-cost,
  secret-free local fixture and controller work; forbid network/external APIs,
  credentials, sudo, install/deploy/restart actions, staging, and real project
  workers. Freeze the local contract at VAPG SQLite schema v5 with explicit
  offline-only bootstrap/migration from recognized clean v3/v4 predecessors;
  artifact manifest v4 immutable
  `<task>/attempt-<n>` namespaces; content-addressed ingress; expiring heartbeated
  evaluator claims; evaluation-result schema v3 bound to `artifact_id` and
  `claim_id`; immutable signed outcome IDs; ID-only integration; exact clean-SHA
  required-test exit/output bindings with an 8 MiB aggregate limit, suite timeout,
  and process-group termination; immutable SHA publication generations; and a
  project-global graph-bound promotion/rollback hash chain with tail and
  per-project head projections. Buzz evidence is fixture-key native-like only.
  A conforming final evidence packet may yield `LOCAL_FIXTURE_PASS`; release stays
  `NOT_PASS` because active producer wiring and deployed/native/real-worker evidence
  are absent. This does not amend `RUBRIC.md` or authorize the missing evidence work.
- **D021 · 2026-08-30 · Accepted P1 hardening of D020:** Preserve schema v5 and
  strengthen, without relaxing, four local gates: exact v0-v4 legacy histories
  migrate only with contiguous/adjacent runtime-valid event semantics; candidate
  write sets validate both sides of no-rename NUL-framed diffs; required tests run
  beneath a pidfd-pinned Linux child-subreaper and accept only after `ECHILD`
  proves descendant quiescence; and every completed publication has exact
  journal/attempt/node/artifact/outcome/manifest closure plus durable-byte
  revalidation before startup, dispatch, or physical effects. External same-UID
  service delegation outside the command ancestry remains `UNPROVEN`; release
  remains `NOT_PASS` and the frozen rubric is unchanged.
- **D022 · 2026-08-30 · Accepted local closure hardening of D019-D021:** Preserve
  VAPG schema v5, artifact manifest v4, and evaluation-result v3 while requiring
  the exact four-route enum in legacy and current durable rows; exact proof-bound
  node/event, evaluator-claim, and global-ledger closure; exact immutable artifact
  inventory during recovery; full physical/durable coordinator verification for
  every Buzz mutation once completed evidence exists; and rollback ownership by
  the current head's exact integration-attempt ID. Legacy sensitive event history
  is not migrated. The fixture adapter still spans separate transactions for
  ingress `PROCESSING`, router mutation/audit, and response `COMPLETE`; crash
  atomicity across that boundary remains P1/`UNPROVEN`. Release remains
  `NOT_PASS`, and the frozen rubric and all format versions remain unchanged.
- **D023 · 2026-08-30 · Accepted external-evidence coverage hardening of D022:**
  Preserve every schema/manifest/result version while moving completed promotion
  origin closure into DB-only graph integrity and requiring exact external
  coordinator/integrator coverage for any canonical outcome, sensitive node,
  integration attempt, or completed journal. Reverify every project outcome's
  exact inventory, signed canonical result, manifest-derived bundle, physical ref,
  and worker binding before startup, status, service, or Buzz effects; require the
  prospective project before its first PASS. Fresh graphs without these rows may
  use no coordinator map. Retain the newer atomic Buzz adapter transaction for
  router graph/audit plus final `COMPLETE` response, superseding D022's recorded
  cross-transaction fixture residual. Release remains `NOT_PASS` and the frozen
  rubric is unchanged.

- **D024 · 2026-09-21 · Accepted:** The current user-selected completion target is
  another developer installing, executing, verifying and recovering local work.
  Private VPS/Buzz deployment is not a prerequisite for this separate developer
  cycle. The historical NQ stop is superseded for authorized research and local
  implementation; original operational release gates remain unchanged.
- **D025 · 2026-09-21 · Accepted:** Preserve legacy release evaluation v3 and add
  explicit task evaluation v4 under a trusted, immutable, separately hashed policy.
  Task acceptance cannot imply product release acceptance or choose its own policy.
- **D026 · 2026-09-21 · Accepted:** Adapt bounded retry, durable replay/history and
  worker lifecycle mechanisms identified in the [upstream review](docs/UPSTREAM.md)
  inside the existing stdlib core. Do not add a parallel orchestration framework.
- **D027 · 2026-09-21 · Accepted:** Freeze the [developer cycle contract](docs/cycles/20260921-reliability/RUBRIC.md)
  before implementation. Independent design review approved starting implementation
  at 97/100; implementation/final-user evidence is evaluated separately.
