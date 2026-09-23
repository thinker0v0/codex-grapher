# Open-Source Project Operations

> Current cycle: [2026-09-21 portable workers](docs/cycles/20260921-portable-workers/HANDOFF.md).
> The user authorized generic repository tasks, real Codex subscription execution,
> OS role separation, disposable guest restart/backup validation and SQLite support,
> followed by a separate `claude-grapher` repository and OSS publication. Claude
> live execution is explicitly deferred until the user obtains an account.
> This supersedes historical NQ restrictions for the authorized cycle. Preserve
> all legacy rubrics. No production changes, purchases or protected merges are
> authorized; publication and owner delivery are separate actions, never tests.


Status: local-fixture implementation candidate; release `NOT_PASS`

## Active surface, routes, and cycle authorization

Hermes native Buzz is the sole final active operator surface. The complete active
route set is exactly `nomad`, `opensource`, `business`, and `hynix`. Slack and
`fin-global` are preserved as frozen legacy compatibility artifacts; operators,
planners, prompts, and new configuration must not send active graph work through
them.

During the active NQ window, the authorized execution envelope is no-cost,
secret-free, local fixture and controller work only. Network and external API
access, credentials, sudo, install/deploy/restart actions, staging, and real
project workers are outside this cycle. Maximum-results policy applies within
that envelope and does not enlarge it.

## Evidence classes

- `LOCAL_FIXTURE_PASS` is a bounded engineering result. It requires a clean final
  candidate plus a machine evidence packet recording the exact Git SHA, commands,
  exits, output hashes, schema hashes, and fixture configuration hashes.
- Release remains `NOT_PASS`. Local fixtures do not prove native Buzz relay and
  identity behavior, active producer wiring, deployed services/configuration,
  real project workers, restart recovery, representative four-route operation,
  or the final-user simulation required by the frozen rubric.
- A pre-integration run, prose statement, builder report, or native-like fixture
  must not be promoted to `LOCAL_FIXTURE_PASS` for a different final SHA. Only an
  independent release evaluation may later return release `PASS`.

## Maximum-results operating policy

The operator preference is explicit: **optimize for maximum results, not
efficiency**. Do not reduce Codex work to conserve tokens. `FAILED_BUDGET` must
not be the normal end state of valid work. Use the high-throughput policy,
continue across fresh contracts when a context ends, and stop only for verified
completion, a real safety boundary, repeated stagnation, missing authority, or a
required human decision.

## Knowledge database mandate

Project knowledge is a required operational asset, not optional agent memory.
Continuously preserve important requirements, maintainer decisions, architecture
reasons, user feedback, incidents, releases, and evaluation evidence. Chat is
intake only and is never authoritative by itself.

Use Git-tracked Markdown as the human-readable source of truth and lightweight
SQLite FTS as a rebuildable search index. Do not add a vector database until a
measured retrieval benchmark shows that FTS is insufficient.

## Required knowledge areas

- `knowledge/requirements/`: user problems, use cases, constraints, and acceptance criteria.
- `knowledge/architecture/`: ADRs, interfaces, dependencies, and rejected alternatives.
- `knowledge/users/`: sanitized feedback, support patterns, and adoption evidence.
- `knowledge/operations/`: releases, incidents, regressions, migrations, and recovery lessons.
- `knowledge/sources/`: upstream documentation, licenses, advisories, and provenance metadata.
- `knowledge/inbox/`: quarantined, unreviewed Buzz or external material.
- `DECISIONS.md`: concise index of approved decisions and links to their evidence.

Every durable record must include project ID, stable record ID, owner, status,
source, source date, retrieval date, effective date, review or expiry date,
classification, trust level, and content hash. Preserve superseded records and
link replacements; never silently rewrite history.

## Curation and retrieval loop

1. Put Buzz messages, issues, attachments, and external documents in the inbox.
2. Treat them as untrusted; scan, normalize, deduplicate, and verify provenance.
3. A designated curator checks factual support, license, privacy, scope, and freshness.
4. Promote approved facts and decisions to the proper knowledge area and commit them.
5. Rebuild the disposable search index from approved records only.
6. Retrieve by project and classification, cite record IDs, and expose uncertainty.
7. After each stage, release, incident, or material decision, update the knowledge base.

The agent-governance owner is accountable for retrieval quality; each component
maintainer owns its records. Review active work weekly, dependencies and security
advisories weekly, and the full knowledge inventory at every release. Expired,
unlicensed, ownerless, cross-project, or unapproved content must not be retrieved.

## Quality gates

- No material claim or decision without a traceable approved record.
- No secret, credential, unnecessary personal data, or incompatible licensed content.
- No retrieval from `knowledge/inbox/` or another project.
- Measure citation accuracy, stale-result rate, retrieval recall, and unresolved conflicts.
- A release is incomplete while its decisions, evidence, migration notes, and lessons are missing.

## Local controller invariants

- SQLite graph format is VAPG schema v5. Creation and recognized migrations are
  explicit, offline-only bootstrap operations; exact clean v0 through v4
  databases are recognized predecessors. Their node histories must begin at
  version 0/NULL old state, remain contiguous and transition-valid, and end at
  the exact durable node head. A predecessor containing a route outside the exact
  four-route set, or any sensitive state in either side of any historical event,
  rejects without changing database bytes. Ordinary runtime opens fail closed on
  an absent, old, future, partial, foreign, ambiguous, or route-corrupt database.
- Artifact manifest v4 publishes each immutable attempt under
  `<task>/attempt-<n>`. Evaluator ingress is content-addressed; expiring claims
  require heartbeats; evaluation-result schema v3 binds `artifact_id` and
  `claim_id`; immutable signed outcomes receive content-derived IDs. Recovery
  revalidates the exact manifest-named file and directory inventory, rejecting
  missing, modified, or extra entries. Evaluated artifacts have no active claim
  pointer; their one deterministic resolved claim is bound to the exact claim
  event, and every canonical outcome is adjacent in the content-derived ledger.
- Integration accepts identifiers only. Required-test evidence binds the exact
  ordered commands, candidate SHA, zero exits, byte lengths, and output hashes;
  the candidate is clean before and after each command; aggregate output is at
  most 8 MiB; the suite has one timeout. A dedicated Linux subreaper is pidfd-
  pinned before launch and must terminate/reap all descendants—including
  setsid/double-fork children—until `waitpid` proves `ECHILD`; missing kernel
  support or cleanup proof fails closed. External same-UID service delegation
  outside that ancestry remains `UNPROVEN`.
- Publications are immutable SHA-named generations. Promotion and rollback are
  graph-bound, project-scoped operations recorded in one project-global append-
  only hash chain with a durable tail and per-project head projection. Completed
  entries must close exactly over their completed attempt, integrated node,
  artifact, outcome, canonical manifest path, and reverified durable bytes before
  startup/dispatch effects.
- Current node event histories are exact versions `0..node.version`, with valid
  genesis, adjacency, transition, hash, and head bindings. The only internal
  recovery/rebase exceptions require their matching durable expired claim or
  completed affected-graph journal proof. Completed promotion origins retain the
  exact attempt base SHA. New or incomplete rollback work requires that the
  current publication head names the supplied integration attempt, including
  same-SHA repromotion cases; an already-completed rollback remains an immutable
  historical replay.
- Integrator candidate diffs disable rename inference and validate both NUL-
  framed source deletion and destination addition against the write set.
- The native-like Buzz adapter is fixture-key-only. It must retain the exact four
  routes and must report local fixture semantics, never staging or production.
  Every Buzz write performs DB-static integrity verification. Any canonical
  outcome (regardless of later node state), PASSED/INTEGRATING/INTEGRATED node,
  integration attempt, or completed journal makes that project externally
  sensitive: a type-exact, same-graph/project `ProjectCoordinator` with a
  type-exact `ProjectIntegrator` must reverify every durable inventory, signed
  outcome, bundle, physical ref, and binding before and within owned write
  transactions. A missing, partial, mismatched, or shadowed coordinator freezes
  the write; a fresh graph with no such rows may use no coordinator map.

The fixture adapter commits router graph/audit work and the final `COMPLETE`
response in one `BEGIN IMMEDIATE` transaction; every injected pre-commit fault
rolls the whole unit back, and only a fully bound `COMPLETE` replay is accepted.
This local atomicity does not prove native transport, deployed restart behavior,
or production operation.

Active worker producer wiring and deployed evidence are absent. A future cycle
needs explicit operator authorization before installation, service action,
staging, external integration, or real-worker validation.
