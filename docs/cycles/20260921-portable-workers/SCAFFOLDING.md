# Agent ownership and implementation scaffold

Status: candidate for independent design review; acceptance contract frozen at commit.
Record: `opensource.portable-workers.scaffold.v1`; owner: cycle integrator.
Date: 2026-09-21 UTC; public; review on interface/ownership change; hash at freeze.
Normative authority/interface correction: [Design amendment v2](DESIGN_AMENDMENT_V2.md).
No builder starts until its independent design reevaluation passes.

## Bounded work units

All builders start fresh from this cycle's approved HANDOFF and exact freeze SHA.
Each task has project `opensource`, a unique task/idempotency ID, owner, write set,
input/output hashes, deadline, explicit limits and durable progress/evidence.
The root integrator coordinates shared files and commits approved boundaries.
No evaluator edits source, rubric, tests or artifacts it evaluates.

| Unit / owner role | Exclusive proposed paths | Inputs → deliverable | Completion evidence |
| --- | --- | --- | --- |
| G: generic workflow builder | `control_plane/repository_workflow.py`, `control_plane/repository_task.py`, new repository task/check schemas, `tests/test_repository_workflow.py` | Frozen task/profile interfaces and graph APIs → initialize/run/status/recover/rollback generic lifecycle | Three representative tasks, source preservation, bad task/check/profile/base/path/test/evaluation/replay cases |
| P: provider builder | `control_plane/worker_provider.py`, `tests/test_worker_provider.py` | Frozen WorkerRequest/Receipt and Codex capability report → bounded adapter | JSONL malformed/missing/duplicate failure, bounds/cleanup/reservation, actual invocation via integration harness |
| I: isolation builder | `control_plane/execution_profile.py`, `control_plane/isolated_runner.py`, `control_plane/evaluation_broker.py`, profile schema, `tests/test_execution_profile.py`, `scripts/verify-role-isolation.py` | Four-role table and immutable check contract → OS launch/broker/signing interfaces | Actual UID/socket/key/policy/state/cross-project denials and legitimate signed flow |
| B: backup/VM builder | `control_plane/workspace_backup.py`, `tests/test_workspace_backup.py`, `scripts/verify-guest-recovery.py`, `scripts/verify-workspace-backup.py` | Quiescent v1 inventory and five barriers → backup/restore plus bounded disposable guest harness | Whole-state closure, fresh same-root restore, corruption/traversal/key exclusion and five restart/reset cases |
| S: SQLite builder | `control_plane/sqlite_runtime.py`, `scripts/provision-sqlite-runtime.sh`, `tests/test_sqlite_runtime.py` | Signed provenance and selected support rules → safe connection policy, doctor facts, explicit local runtime provisioning | DELETE/EXTRA readback/owner lock, unpatched and unknown WAL denial, fixed WAL/FULL positive, existing WAL no silent mutation |
| R: root integration | `control_plane/cli.py`, shared existing core files, packaging, README/docs/CI, boot pointers, evidence inventory | Reviewed component APIs → installed public command/package and coherent implementation | Full foundation at final candidate; installed wheel/sdist; exact source/data/runtime/evidence hashes |
| E: independent evaluator | Assessment/evidence output only, outside builder paths | Frozen rubric + exact candidate + machine evidence → adversarial review, score, blockers | Independent-ai-judge report; cannot self-certify builder work |
| U: fresh developer | New temporary install/workspace and assessment only | Public archive/docs only → normal-entrypoint user simulation | No originating chat/private paths/test helpers; source unchanged, accepted consumer, recovery/restore/rollback |

Root accepted these ownership targets; they do not claim the files already exist.
Builders request shared-file edits through R; do not race on `artifact_builder.py`,
`project_graph.py`, `task_controller.py`, `project_coordinator.py`, `graph_service.py`,
runtime configuration or package inventories. Root may assign one explicit owner
for a shared edit and record that assignment before mutation.

Root's explicit shared-file exception: G owns the narrow `artifact_builder.py`
`test_runner` callback hook in `build`/`produce_required_test_results`; I owns
the isolated runner and broker-sealed receipt API. Both required tests and later
independent checks execute under the untrusted test role. Default legacy/demo
execution remains compatible. No other builder edits that file concurrently.

## Inter-module contracts

- G owns parsing/canonical immutable identity, workspace metadata and lifecycle.
  It passes only validated IDs/paths/bounds to P/I/B; it cannot bypass their
  admission. `workflow.json` uses kind `repository-workflow`, version 1.
- P accepts task/attempt/base/checkout/prompt+hash/limits and trusted profile.
  Reservation callback is durable before child start. It returns bounded raw
  process/protocol receipts; G alone packages and graph-admits evidence.
- I owns profile validation, real role launch, restricted candidate-test broker
  and receipt sealing. The signer verifies the broker-owned receipt and active
  graph claim; it never imports or executes candidate-controlled modules.
  I also owns the explicit privileged bootstrap, narrow AF_UNIX launcher and
  root-held `.broker-receipts`; R wires its root-only installed entrypoint.
- B consumes an explicit quiescent owner lease, exact profile and closure APIs;
  it cannot fake quiescence from files or silently reconcile under another owner.
- S owns the shared writable-connection policy/attestation and read-only runtime
  facts. Root wires every existing graph/controller/coordinator connection through
  it, with intentional backward-compatible diagnosis updates.
- R owns public command dispatch and installs only public resources. No installed
  command depends on enclosing-project research/private evidence paths.

Interface values include exact bytes/hashes and explicit error classes:
`INVALID_TASK`, `CONFIG_CHANGED`, `AUTH_REQUIRED`, `PROVIDER_MISSING`,
`UNSUPPORTED_PROTOCOL`, `BUDGET_UNSUPPORTED`, `ISOLATION_UNAVAILABLE`,
`WORKER_INTERRUPTED_UNSEALED`, `LEASE_EXPIRED`, `TEST_FAILED`,
`EVALUATION_REJECTED`, `SQLITE_UNSUPPORTED`, `MAINTENANCE_REQUIRED`,
`BACKUP_NOT_QUIESCENT`, `RESTORE_INVALID` and `DURABLE_STATE_INVALID`.
These are public result classifications, not new graph-state enum members.

## OS authority and resources

The table describes four dropped child roles. Amendment v2 adds the explicit
root bootstrap trust domain that constructs namespaces/launches roles, validates
root-owned frozen inputs and seals receipts; it never executes candidate code.
Graph has no general launch privilege and connects to the helper after UID drop.
Private key stays outside workspace; only signer sees its read-only mount.
Workspace top/root receipt directory cannot be renamed/replaced by graph. Public
receipt bytes are read-only to graph/signer, invisible to worker/test and included
by B in backup closure. Runtime sockets and private keys remain excluded.

| Resource | Worker | Candidate tests | Signer | Graph/integrator |
| --- | --- | --- | --- | --- |
| Own attempt | Read/write only scoped checkout/output | Fresh candidate scratch only | Immutable receipt/input only | Verify/copy |
| Frozen policy/check/profile | Read permitted subset, never write | Read necessary checks, never write | Read/hash verify | Trusted store and pinned startup hash |
| Private signing key | Denied | Denied | Read under private protected directory | Denied; public key only |
| Graph DB/sidecars and accepted Git/binding | Denied; read selected immutable generation only | Denied | Authenticated evaluation API only | Exclusive mutable owner |
| Ingress/signature output | No post-admission mutation | No mutation or signer submission | Read/append own trusted receipt | Verify/append authority |
| Other project / host secrets / host sockets | Denied | Denied | Explicit own inputs only | Configured project scope only |
| Control socket | Scoped worker actions | Absent | Scoped evaluator actions | Integrate/recover/rollback authority |

SO_PEERCRED and trusted UID mapping determine roles; payload roles are ignored or
rejected. Guest-only accounts or fixture numeric UIDs may implement this mapping;
never create host accounts for validation. Actual roles must have distinct real
UIDs, not merely display aliases mapping to one privileged identity. Record UIDs,
GIDs, namespaces, mount list, capability masks, no-new-privileges, errno and
unchanged authority-object hashes, without including secret bytes.

Trusted graph/signer Python and dependencies are immutable installed code or
read-only mounts, never worker-writable source. Actual Codex profile is UID 1000,
model `gpt-5.6-sol`, reasoning `medium`, tier `default`, explicit despite ignored
user configuration. Vendor CLI uses its actual home/login without copying auth;
offline test runners have neither that auth home nor provider/network capability.

One guest, one heavy test job at a time. Recheck free RAM/disk before expanding
local work. Guest 1 vCPU/1 GiB, no host share, loopback-only temporary SSH control,
verified immutable base plus disposable overlay. Generated fixture SSH keys stay
in ignored runtime and are deleted with the fixture; provider credentials never
enter the guest. QEMU/task dependencies are downloaded/verified/extracted locally,
not installed as host packages. Guest root may manage guest-only services/users.

## Time, spend and attempts

Task defaults/maxima are in SOLUTION. Acceptance commands have an outer 900-second
limit; individual guest scenarios at most 600 seconds and boot at most 180 seconds.
Product-configured worker ceilings up to 3600 seconds are tested with controlled
fixtures/timeouts; they do not authorize an acceptance command to run unbounded.
Do not repeat successful unchanged tests or full suites. After changed code, run
focused checks, then one integrated full suite; rerun only for new relevant input.
Record each actual model launch; default one, maximum three explicitly configured.
No new paid API use or purchase. Stop/redirect after three failed attempts with no
new evidence or meaningful changed approach; retain history across workers.

## Failure, rollback and gates

Malformed task/profile/runtime admission fails before state or provider effects.
Worker/test/evaluation failure leaves accepted baseline unchanged. Unsealed crash
retains quarantined inspection data and reservation, never automatic re-execution.
Invalid historical closure freezes writes; do not reset refs, reseed DB or rewrite
signatures to recover. Rollback uses the exact authorized predecessor/attempt
and existing CAS/journal semantics. Restore failure never activates a partial root.

Checkpoint boundaries: independent design review → freeze commit → fresh builders
→ focused evidence → integrated clean candidate → full machine packet → independent
adversarial evaluation → fresh user → Phase 1 verdict → separate Phase 2 contract.
The root must preserve any FAIL/UNPROVEN item. Actual authentication intervention
or unauthorized consequential action is a human boundary; elapsed time is not
approval. Already authorized implementation/staging/publication needs no renewed
permission merely because a historical cycle restricted those activities.
