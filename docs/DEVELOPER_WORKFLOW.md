# Local developer workflow

Install the package and run `codex-grapher doctor --json` as described in the
[README](../README.md). The installed command works outside the source checkout.
`python -m control_plane` is equivalent.

## A complete task

```bash
codex-grapher demo --workspace /tmp/grapher-task --json
codex-grapher demo --workspace /tmp/grapher-task --operation status --json
```

Use a new directory for a new task. The command owns only this explicit local
workspace. It uses separate worker, evaluator and accepted repositories, a
frozen task policy, a SQLite graph and immutable evidence. It runs real required
tests before the producer admits an artifact. A separate deterministic sample
evaluator checks the task's actual acceptance assertions before signing.

The sample is trusted local development. Its processes share a Unix user and
must not be used as a sandbox for hostile code. Private sample signing material
stays inside the selected workspace and is never a production credential.
Do not commit that workspace or copy its keys into another project.

## Stage boundaries and recovery

You can stop after `built`, `evaluated` or `promoted` and resume from another
process:

```bash
codex-grapher demo --workspace /tmp/grapher-staged --stop-after evaluated --json
codex-grapher recover --workspace /tmp/grapher-staged --json
codex-grapher recover --workspace /tmp/grapher-staged --json
codex-grapher rollback --workspace /tmp/grapher-staged --json
```

The repeated recovery is idempotent. Accepted state is identified by the
publication journal, immutable artifact/outcome IDs and Git SHA. A process exit
code alone never means that a task passed. Rollback restores the recorded prior
accepted SHA while keeping historical evidence.

For an intentional process termination during a local promotion, use a new
workspace. The first command is expected to exit nonzero:

```bash
codex-grapher demo --workspace /tmp/grapher-crash --crash-at after_binding --json
codex-grapher recover --workspace /tmp/grapher-crash --json
```

This tests recovery across an actual local process exit. It does not prove host
power-loss recovery or production service operation.

Recovery also resumes journaled rollback and expired evaluator claims. If a worker
was interrupted before publishing an immutable artifact, recovery stops for
inspection; it does not repeat arbitrary worker side effects. An existing worker
artifact can enter ingress only while that attempt's original lease is still
valid. Preserve the failed workspace and inspect it before starting a new one.

Failure injection is available with `--failure required-test` and
`--failure evaluator`, each in a new workspace. The candidate must not become an
accepted baseline when either gate fails. These are local examples, not a way to
bypass validation.

## Inspect state without running work

```bash
codex-grapher status --database /path/to/graph.sqlite --policy /path/to/task-policy.json --json
codex-grapher inspect NODE_ID --database /path/to/graph.sqlite --policy /path/to/task-policy.json --json
codex-grapher events --database /path/to/graph.sqlite --node NODE_ID --policy /path/to/task-policy.json --json
```

For a legacy graph, omit `--policy`. A custom-policy graph requires its exact
frozen policy file. Inspection verifies local database/event structure on a
temporary snapshot and never repairs, migrates or changes the original database.
It does not verify all external evidence signatures or deployments.

Offline inspection refuses a symlink, multiply linked database, or database with
WAL/SHM/journal sidecars. Close its owner cleanly first; never delete sidecars to
force inspection. For a running
configured graph service, use `codex-grapher status --socket /path/to/control.sock
--json`. Normal service authorization still applies.

## Task policy and independent evaluation

Task policy is a trusted input established before execution. A version-1 JSON
policy defines exact section names, their minimum/maximum scores, required gate
names and a threshold of at least 95. Section maxima total 100. Unknown fields,
nonfinite numbers, booleans in numeric fields and duplicate JSON keys are denied.

A version-4 task result signs the exact policy/rubric digest, task and contract,
candidate Git SHA, artifact ID, active evaluator claim ID, evidence hash and
ledger predecessor. Graph and integrator must share the selected policy and
verification key. Replacing a policy after work begins invalidates the binding.
The builder's result cannot select a different policy or downgrade to legacy
verification. Private signing keys belong only to the evaluator role.

Legacy version-3 results still use the unchanged product release score contract.
Do not use the sample evaluator to sign a product release or unrelated task.
Task PASS means its declared task assertions passed; product release remains a
separate independent review.

## Worker retries and human gates

The default allows at most three leased attempts, including the first, with a
five-second initial delay, multiplier two, and a 300-second delay cap. Two
identical failures stop another identical automatic launch. Policy values are
frozen in the node specification. Retry timestamps and classified failures are
stored in the event chain, and reopening or lease recovery does not reset them.

Safety/permanent failures and cancellation do not automatically retry. Transport
success with unknown controller state remains uncertain, never task success.
A worker can renew its own exact live lease through `heartbeat`; stale or
cross-project leases cannot be renewed. The service `node` action provides the
current version needed for an authorized worker to resume.

Nodes with `human_gate: true` are unexecutable in this developer workflow. It does
not implement a consequential-action approval capability. No command-line flag,
free-text message or elapsed timeout counts as human approval.

## Use your own repository and worker

The packaged `produce_worker_artifact` helper runs an explicitly selected trusted
worker command in a clean local checkout. It returns the normal immutable
artifact-builder result; it cannot evaluate or promote its own output.

```python
from pathlib import Path
from control_plane.local_workflow import produce_worker_artifact

artifact = produce_worker_artifact(
    workspace=Path("/tmp/my-clean-attempt"),
    contract_path=Path("/tmp/my-task-contract.json"),
    output_dir=Path("/tmp/my-task-artifacts"),
    attempt_number=1,
    worker_command=["python3", "/path/to/my-trusted-worker.py"],
)
print(artifact["candidate_sha"])
```

Freeze `task_id`, `project_id`, `base_sha`, `builder_identity`, `allowed_paths`,
`required_tests`, `timeout_seconds`, `idempotency_key` and `budget` in the contract
before invocation. The checkout must be clean at that exact base SHA. The worker
changes allowed files; the producer creates the candidate commit and runs the
required tests. Do not point this helper at your only working copy. It is an
explicit local execution API, not a network worker service.

For the complete graph protocol, the installed
[`control_plane.local_workflow`](../control_plane/local_workflow.py) is a runnable
reference using these public core operations:

1. Explicitly bootstrap the local database; create `ProjectGraph` with the
   evaluator public key, frozen policy digest and `evaluation_policy` object from
   `load_task_policy`. Create the goal and node before leasing/starting the worker.
2. Run the producer and `EvidenceIngress.ingest` with exact task, attempt, project,
   base SHA, contract digest and required commands. Record the returned immutable
   artifact using `graph.record_ingressed_evidence`.
3. A separate evaluator takes `graph.claim_evidence`, reconstructs the candidate,
   checks your declared assertions, and signs its version-4 result. Submit it with
   `graph.record_evaluation`. The sample evaluator deliberately only understands
   the greeting task; supply your own evaluator for other work.
4. Configure `ProjectIntegrator` and `ProjectCoordinator` with the same public key
   and exact policy. Integrate using the durable artifact/outcome IDs and a unique
   integration attempt ID. Pin the resulting accepted publication for the next
   worker. Keep the original source and evidence available for verification.
5. Reopen those same bindings to reconcile a journaled interrupted integration;
   use the recorded predecessor and project-head version for rollback. Never
   replace an outcome, reconstruct a PASS from an exit code, or invent a new
   operation identity to retry a partially completed promotion.

The deterministic local example's stable files are `graph.sqlite`,
`task-policy.json`, `task-contract.json`, `binding.json`, `evaluation.json`,
`evaluator-checks.json`, immutable `evidence/sha256/.../manifest.json`, and
`publications/<accepted_sha>/src/greeting.py`. Its task ID is `greeting-fix` and
successor is `consume-greeting`. For example:

```bash
codex-grapher inspect greeting-fix --database /tmp/grapher-task/graph.sqlite --policy /tmp/grapher-task/task-policy.json --json
```

Keep task success, source integration and product release as separate facts.
This API does not automatically grant OS identity separation, network isolation,
or authority for consequential actions.
