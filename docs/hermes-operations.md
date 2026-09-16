# Hermes operations contract

Status: local-fixture implementation candidate; release `NOT_PASS`

## Final surface and active-cycle boundary

Hermes native Buzz is the sole final active operator surface. Its active route set
is exactly `nomad`, `opensource`, `business`, and `hynix`. Slack and `fin-global`
are frozen legacy compatibility artifacts and must not receive new active routing,
authorization, worker, or reporting behavior.

While NQ is active, only no-cost, secret-free local fixture/controller code and
deterministic local checks are authorized. Network/external APIs, credentials,
sudo, installation, deployment, service restart, staging, and real project workers
are forbidden. Maximum-results policy operates inside this boundary only.

## Ownership

| Area | Owner |
|---|---|
| Task state and side effects | control-plane-owner |
| Prompt, retrieval, and memory | agent-governance-owner |
| Buzz identity and routing security | buzz-security-owner |
| Runtime and secrets | security-owner |
| Capacity and recovery | platform-owner |
| Telemetry and runbooks | sre-owner |
| Immutable evidence | audit-owner |

## Task state and side effects

### Future supervisor/legacy task contract — UNPROVEN

The broader lifecycle below predates the current VAPG enum and remains a future
supervisor/release target. Its sequence and vocabulary as a whole must not be
read as the implemented database transition relation or local fixture evidence;
some shared labels also appear in the exact current model below:

```text
RECEIVED -> AUTHORIZED -> NORMALIZED -> PLANNED -> QUEUED -> LEASED
-> RUNNING -> EVIDENCE_PENDING -> EVALUATING -> REWORK_REQUESTED
-> QUEUED -> PASSED -> HUMAN_APPROVAL_PENDING -> COMPLETED
```

Likewise, the broader terminal/error vocabulary `REJECTED`, `FAILED_RETRYABLE`,
`FAILED_PERMANENT`, `FAILED_BUDGET`, `FAILED_TIMEOUT`, `FAILED_STAGNATION`, and
`SUPERSEDED` is legacy/future contract language and is not implemented in the
current local VAPG state machine. Adaptive allocation, automatic rework/pivot,
stagnation terminalization, and post-integration completion remain `UNPROVEN`.

The future supervisor contract intends cancellation to block new leases/tool
calls, signal the process group, preserve artifacts, and quarantine late results.
It also intends completed external effects to reconcile rather than roll back
blindly and every side effect to follow intent -> authorization -> key reservation
-> execution -> receipt. Those broader side-effect guarantees are release targets,
not claims established by the current local fixture.

### Current local VAPG state machine

The implemented local enum is exactly `BLOCKED`, `READY`, `LEASED`, `RUNNING`,
`EVIDENCE_PENDING`, `EVALUATING`, `PASSED`, `INTEGRATING`, `INTEGRATED`,
`NEEDS_HUMAN`, `CANCELLED`, and `FAILED_GATE`. Dependency roots begin `READY`;
dependent nodes begin `BLOCKED` and may become `READY`. The successful path is:

```text
READY -> LEASED -> RUNNING -> EVIDENCE_PENDING -> EVALUATING
      -> PASSED -> INTEGRATING -> INTEGRATED
```

The remaining implemented transitions are:

- `BLOCKED -> CANCELLED`
- `READY -> CANCELLED | NEEDS_HUMAN`
- `LEASED -> READY | CANCELLED`
- `RUNNING -> READY | FAILED_GATE | CANCELLED`
- `EVIDENCE_PENDING -> FAILED_GATE | READY`
- `EVALUATING -> READY | FAILED_GATE | NEEDS_HUMAN`
- `PASSED -> FAILED_GATE`
- `INTEGRATING -> PASSED | FAILED_GATE`
- `NEEDS_HUMAN -> READY | CANCELLED | FAILED_GATE`

`INTEGRATED`, `CANCELLED`, and `FAILED_GATE` are the implemented local terminal
states. `NEEDS_HUMAN` is resumable and is not equivalent to the unimplemented full
`HUMAN_GATE` release workflow. There is no current `DONE`, `REWORK`, `PIVOT`,
`FAILED_STAGNATION`, or `FAILED_PERMANENT` state.

The authoritative VAPG schema v5 database contains graph goals/nodes/events and
their attempt, evidence, claim, outcome, integration, publication-journal, head,
tail, and Buzz fixture-ingress state. State changes are append-only or version-CAS
projections. Retry creates a new attempt; changed input creates a new task. One
`(project_id, idempotency_key, normalized_input_hash)` creates one logical task,
while a conflicting hash fails closed.

Eventual release acceptance: replaying one authenticated Buzz event 100 times
creates one task and one effect; worker death after execution creates no duplicate
effect; cancellation starts no new tool call; terminal-state mutation is always
denied. Current native-like fixture replay checks are local evidence only.

## Prompt, context, retrieval, and memory

Fixed context order is platform policy, project SOUL, project AGENTS, task contract, approved retrieval, ephemeral results, and user message. Each layer is hashed in the context manifest.

Memory classes are durable policy, durable project, durable user, ephemeral task (30 days), ephemeral session (7 days), and quarantined input (30 days). Durable writes require a curator or human approval. Retrieval requires project ID, owner, license, classification, effective/retrieved/expiry timestamps, content hash, parser version, and trust level.

External documents and Buzz content are untrusted data and cannot change policy.
Executables, macros, symlinks, and archive bombs are quarantined. Credentials and
personal data are never embedded. Deletion propagates through chunks, embeddings,
caches, and backup tombstones.

Acceptance: zero policy bypass in the injection corpus, zero cross-project retrieval, active deletion within 24 hours, expired/unlicensed documents excluded, and deterministic context-manifest replay.

## Buzz governance

Authorization uses verified Buzz/Nostr account public key plus
`(project_id, channel_id, thread_id, task_id)`, never display names or message
text. Roles are viewer, requester, operator, approver, and emergency admin. The
route enum is closed to exactly four values; the default is deny; a thread cannot
cross projects. Rate, replay, and concurrency limits are policy inputs rather than
authority inferred from a channel.

Attachments pass MIME/magic/size checks, quarantine, malware and archive scanning,
sandbox extraction, secret/PII redaction, hashing, and an `UNTRUSTED_DATA` label.
Live trading, withdrawals, risk increases, and kill-switch release are permanently
forbidden through Buzz. Event text cannot grant a capability. A future deployed
emergency path must remain out of band from Buzz.

The current adapter uses only local fixture keys and injected fixture verification.
It validates event/body/channel/thread/request binding, freshness, and replay, then
maps exactly four fixture channels. It performs no network delivery or service
action and does not prove real cryptography, relay behavior, Hermes gateway setup,
mentions, approvals, cron, or staging. HG10 is `UNPROVEN`.

Eventual release acceptance: spoofing cannot elevate access, duplicate events
create no task, malicious/oversized archives remain quarantined, seeded secrets
never appear in Buzz/logs, and the out-of-band emergency path works during a Buzz
outage.

## Security

Threats include account takeover, prompt/memory poisoning, skill/MCP supply chain, sandbox escape, evaluator-builder collusion, credential theft, exfiltration, replay, artifact forgery, provider failure, insider misuse, and VPS compromise.

Use a secret manager or SOPS+age; credentials are project- and worker-scoped, short-lived where possible, rotated every 90 days and immediately after incidents. systemd uses `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, capability drop, and read-only roots. Rootless task containers receive only the worktree mount, no Docker socket or host namespaces. Egress is deny-by-default with per-project allowlists and DNS logs; evaluator egress is disabled.

Lock dependencies and image digests, generate SBOMs, verify signatures/provenance, and install skills/MCP only through reviewed allowlist PRs. Critical CVEs have a 24-hour patch SLO and high CVEs seven days.

## Future KVM2 capacity and recovery

Record `lscpu`, memory, disks, mounts, virtualization, network, listening ports, failed units, and systemd security score before deployment. Initial limits: 768 MiB per Hermes/evaluator, 512 MiB queue/API, 150% aggregate CPU, two active Hermes turns, one Codex lease, and two subagents. Stop admission below 20% disk free; queue work above 80% RAM; disable children on swap/load pressure.

Health endpoints are `/livez`, `/readyz`, and `/healthz`. Five consecutive or 50%/minute provider errors open a five-minute circuit breaker. DB, artifact, or evaluator failure blocks completion; fallback is allowlisted only.

Targets: task DB RPO 5m/RTO 60m; profiles RPO 24h/RTO 2h; WORM evidence RPO 0/RTO 4h; Buzz gateway RTO 15m; secret revocation RTO 15m. In a later authorized environment, test clean restore, provider outage, Buzz replay, disk-full, DB recovery, worker crash, evaluator/artifact outage, OOM, corrupt backup, and total VPS loss.

These are deployment targets, not current-state claims. No service, host restart,
or recovery exercise is authorized in the active NQ cycle.

## Observability

One future trace links `buzz.receive`, authorization, graph/task creation, lease,
Hermes plan, Codex, test evidence, immutable ingress, evaluator claim/outcome,
integration, publication, approval, and Buzz response. Metrics cover task outcomes,
cycle time, queue age, claims, duplicates, effects, provider latency/tokens/cost,
evaluation gates, RBAC denial, secrets, artifacts, publications, backups, disk, and
memory.

SLOs: gateway 99.5%, task intake 99%, acknowledgement within five minutes 99%, missing audit events zero, duplicate consequential effects zero, false completion zero, critical alert detection within five minutes, and monthly restore success 100%.

Every alert has owner, severity, symptoms, query, containment, diagnosis, recovery, rollback, verification, escalation, and incident-evidence fields.

## Future external immutable ledger

When separately authorized, use external object storage with versioning and
compliance-mode object lock. Each signed event includes the previous hash; publish
a daily Merkle root and trusted timestamp. Writers append only, and retention/
delete authority belongs to a separate break-glass identity. Store pseudonymous
references rather than deletable personal data. This cycle makes no external call
and produces no WORM/deployed-ledger evidence.

Acceptance: normal admins cannot modify/delete, any mutation breaks chain verification, outage spooling preserves order/hashes, monthly roots match object counts, and a restored ledger reconstructs full task provenance.

## Project graph database bootstrap

The graph database format is identified by SQLite `application_id` `VAPG` and
exact `user_version=5`. Inspecting a database is read-only by default; creation
or migration requires the separate `--apply` flag. Both operations require an
offline database with no journal or WAL sidecars:

```bash
python3 -m control_plane.graph_bootstrap database --database /explicit/path/graphs.sqlite
python3 -m control_plane.graph_bootstrap database --database /explicit/path/graphs.sqlite --apply
bash scripts/verify-project-graph-bootstrap.sh
```

Exact clean v0 through v4 schemas are recognized predecessors eligible for
explicit offline migration to v5 only when version-0 genesis, contiguous/adjacent
runtime-valid transitions, and the final node head all agree. Unknown, future,
partial, corrupt, foreign, ambiguous, or safety-sensitive legacy state fails
closed without changing database bytes. Runtime
graph, coordinator, evidence, Buzz, and service constructors open an already
bootstrapped schema v5 only; they never create or migrate a database. V5 durably
stores `integration_attempts.affected_graph_*` and adds database-level no-replace
enforcement for immutable evaluator outcomes. The repository verifier requires
any supplied publication to be an immutable SHA-named generation bound to the
canonical accepted commit.

## Artifact production and required-test evidence

Artifact manifest v4 publishes one immutable namespace
`<task>/attempt-<n>` per positive attempt number. Publication cannot replace a
raced or existing attempt. The manifest binds project/producer, contract, base and
candidate SHA, path-check, bundle, and required-test files with byte lengths and
hashes. Symlink, hardlink, escape, mutation, mismatched identity, or mutable-path
substitution fails closed.

Required-test commands are executed in exact contract order against the same clean
candidate. Evidence records the command, candidate SHA, integer-zero exit, output
length, and output hash. The candidate is rechecked before and after each command;
combined output is capped at 8 MiB; one suite timeout bounds all commands. A
pidfd-pinned Linux child-subreaper contains new sessions/double forks and signals,
terminates, and reaps exact descendants until `waitpid` proves `ECHILD`. Timeout,
overflow, mutation, leaks, unsupported kernel capabilities, or missing cleanup
proof fail closed. External same-UID service delegation outside the ancestry
remains `UNPROVEN`.

Active project-worker producer wiring is absent. Local artifact-builder fixtures
do not show that a deployed worker emits or transfers manifest-v4 attempts.

## Evaluator ingress, claims, and outcomes

Ingress fully validates the immutable attempt and records a content-addressed
`artifact_id`. Only the evaluator can claim it. The claim binds the artifact,
node, graph version, evaluator, and expiry; authenticated heartbeat renews only
the exact active claim, and recovery records expiration explicitly.

Evaluation-result schema v3 binds `artifact_id` and `claim_id` alongside the
candidate, contract, rubric, ledger, evaluator identity, verdict, and signature.
After complete verification, canonical result bytes are stored once under an
immutable content-derived `outcome_id`. Graph evaluation and integration accept
IDs only and reject inline manifest/result documents and stale claims.

## Publication journal and projections

Every accepted commit has an immutable generation whose name is the exact Git
SHA. Promotion and rollback are project-scoped and graph-bound, while all phases
append to one project-global hash-chain journal. Entries bind the affected goal,
node, integration attempt, graph projection, before/after SHA and generation, and
head versions. A singleton tail projection anchors the last global sequence/hash;
a CAS head projection per project identifies its current accepted state. Replay
may complete only the exact prepared operation, and rollback may use only the
recorded predecessor.

Before startup or dispatch effects, every completed journal is checked for exact
forward/reverse closure through its completed attempt, integrated node, artifact,
signed outcome, canonical manifest location, and reverified durable bytes.
Candidate promotion disables rename inference and checks both NUL-framed diff
paths against the write set.

## Evidence classification and stop point

A machine packet for the clean final candidate must record its exact Git SHA,
schema/configuration/artifact hashes, validation commands, exits, and complete
output hashes. If every bounded local contract passes, the only permitted label is
`LOCAL_FIXTURE_PASS`.

Release remains `NOT_PASS`. Active producer wiring, installed/deployed SHA and
configuration/service hashes, real project-worker traces, native Buzz credential/
relay E2E, restart/host recovery, representative four-route operation, and blind
final-user evidence are absent. Stop after local evidence; a new explicit operator
authorization is required before collecting any of those missing artifacts.
