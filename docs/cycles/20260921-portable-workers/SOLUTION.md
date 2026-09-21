# Portable workflow solution contract

Status: candidate for independent design review; acceptance contract frozen at commit.
Record: `opensource.portable-workers.solution.v1`; owner: cycle integrator.
Date: 2026-09-21 UTC; review at freeze or changed interface. Public; hash at freeze.
Decisions: [DECISIONS.md](DECISIONS.md). Evidence: [RESEARCH.md](RESEARCH.md).
Normative interface correction: [Design amendment v2](DESIGN_AMENDMENT_V2.md)
defines explicit privileged bootstrap, restricted launcher and exact sealed
test/evaluation/signing requests; it supersedes conflicting v1 descriptions.

## Lifecycle and source preservation

Add `repository_workflow.py` over the existing graph, artifact, ingress, task
policy, signer and coordinator mechanisms. Keep `demo` and sample metadata
compatible. Dispatch generic recovery by exact `workflow.json` kind/version;
never catch an error and fall back to demo handling.

```text
validate task/profile/source -> initialize owned snapshot -> reserve invocation
-> isolated worker -> scoped candidate + required tests -> immutable ingress
-> committed graph admission -> independent sandbox checks -> trusted signature
-> verified ID-only promotion -> inspect accepted generation / recover / rollback
```

Initialization accepts an exact clean source commit, creates a new private copy
without hardlinks/external alternates, removes remotes and execution hooks, and
freezes task/profile/policy/check bytes. Reject dirty source, symlink roots,
source/workspace ancestry overlap, moving base refs and incomplete object closure.
Never copy credential helpers or arbitrary source Git configuration. Record and
compare the original worktree/index/refs/config/remotes/hooks/untracked inventory
after success and failure. Promotion changes only the owned canonical repository
and binding. Return accepted SHA and immutable generation path for the user.

One workspace initially binds one source baseline and task. Successor work uses
a new explicit task/base from the accepted generation. External `project_id`
stays workspace metadata; internally map to graph `opensource`, producer `oss`,
actor `hermes-oss`, ref `refs/ai-ops/accepted/opensource`. No fifth graph route.

## Strict public contracts

Introduce `schemas/repository-task.schema.json`, separate from the full signed
Hermes task schema. Strict JSON parsing rejects duplicate/unknown keys and bools
used as numbers before creating state. Version 1 has the following fields:

| Field | Frozen meaning |
| --- | --- |
| `schema_version` | Integer 1 |
| `project_id`, `task_id`, `idempotency_key` | Nonempty bounded safe identifiers; exact values bind all attempts |
| `base_sha` | Exact 40-hex commit, equal to initialized source baseline |
| `objective`, `acceptance_criteria` | Nonempty objective and nonempty list of nonempty behavior criteria |
| `allowed_paths` | Nonempty relative Git paths/patterns under existing allowlist semantics; reject absolute paths, `..`, `.git` and escape |
| `required_tests` | Nonempty ordered exact command strings using trusted pinned tools; existing producer receipts bind each string |
| `worker` | Exactly `{backend: "codex"}` in Phase 1; deployment profile chooses executable/model/identity |
| `limits` | Optional bounded invocation/time/output values; defaults and ceilings below; no unsupported token/dollar guarantee |
| `evaluation` | Exactly relative `policy` and `checks` file paths, resolved and frozen once at initialization |

Checks v1 are exactly `{schema_version: 1, checks: [{id, argv: [string, ...]}]}`.
IDs are nonempty and unique; checks and argv are nonempty ordered arrays; reject
unknown fields/duplicate keys and unfrozen external check programs. Inline Python
in the exact argv is permitted. Checks execute from a freshly reconstructed
candidate under the test role. Freeze bytes, argv, tool identities and policy
mapping outside all worker/test writable roots.

Execution profile v1 is trusted operator configuration, never task authority.
It selects `trusted-local` or `isolated-linux`, absolute resolved provider and
test tools with version/hash, explicit model/service settings, role UID/GID
mapping and actual account auth home, runtime and SQLite support mode. The profile
schema/loader must reject unknown keys and unsupported combinations. Task content
cannot choose UID, executable, home, environment, key, socket or credential path.
Freeze exact profile bytes and semantic tool/runtime identities and revalidate
before every reopen or side effect. `trusted-local` explicitly reports no
hostile-code OS separation and cannot satisfy this cycle's isolation gate.

The exact profile dictionary keys are frozen below. Objects reject additional
keys; `Tool` means `{path: absolute-string, sha256: 64-lower-hex-string,
version: nonempty-string}` and `Role` means `{uid: nonnegative-integer,
gid: nonnegative-integer}`. Numbers reject booleans. Paths are canonical and
symlink-safe; private paths remain trusted configuration, never public telemetry.

```text
ExecutionProfile = {
  schema_version: 1,
  mode: "trusted-local" | "isolated-linux",
  tools: {python: Tool, git: Tool, provider: Tool, openssl: Tool,
          bwrap: Tool|null, setpriv: Tool|null},
  provider: {backend: "codex", model: string,
             reasoning_effort: string, service_tier: string},
  roles: {worker: Role, test_runner: Role, signer: Role, graph: Role},
  auth: {kind: "existing-cli-login", account: string},
  paths: {trusted_code_root: absolute-string, trusted_code_sha256: hex64,
          signer_private_key: absolute-string, signer_public_key: absolute-string},
  sqlite: {profile: "delete-extra" | "wal-full", attestation: null | absolute-string}
}
```

Resolve auth home/UID/GID through the actual account database; account must equal
the configured worker role. Never accept a home override or arbitrary environment
map. In isolated mode all four real UIDs are distinct and greater than zero in
the SO_PEERCRED credential domain, with no host-root mapping; required tool/code/key
permissions are checked. Bootstrap is an explicit fifth root authority; graph
is dropped before connecting to its SO_PEERCRED-authenticated launcher. `bwrap`
and `setpriv` may be null only in trusted-local. Keys live outside the workspace;
root owns protected receipt storage. Exact rules are in amendment v2.
`wal-full` requires a valid exact loaded-runtime
attestation; `delete-extra` does not claim a patch. Missing private key is allowed
only for explicit read-only/verify-only operation, never execution or signing.

`limits` has only `worker_invocations`, `worker_timeout_seconds`,
`required_test_timeout_seconds`, `evaluation_timeout_seconds`, and
`max_output_bytes`; omitted fields use the defaults below. Exact request objects
between G and P also reject additional keys:

```text
WorkerRequest = {
  schema_version: 1, project_id: string, task_id: string,
  idempotency_key: string, attempt_id: string, attempt_number: positive-integer,
  base_sha: hex40, checkout: absolute-string,
  task_sha256: hex64, profile_sha256: hex64,
  prompt: string, prompt_sha256: hex64,
  limits: {worker_invocations: integer, worker_timeout_seconds: integer,
           max_output_bytes: integer}
}
```

`launch_worker(request, profile)` receives a validated `ExecutionProfile`
separately; request strings never override it. G persists/fsyncs a reservation
with this exact request hash and current invocation count before invoking P.
P validates the checkout/base/profile/request binding and is called once for
that reservation; recover never calls it for an existing unsealed reservation.
WorkerReceipt v1 has exact keys `schema_version`, `attempt_id`, `request_sha256`,
`task_sha256`, `profile_sha256`, `prompt_sha256`, `provider`, `cli_version`,
`executable_sha256`, `model`, `session_id`, `completion`, `usage_observed`,
`exit_code`, `signal`, `elapsed_seconds`, `stdout_sha256`, `stderr_sha256`,
`stdout_bytes`, `stderr_bytes`, `descendants_reaped`. Optional telemetry uses
explicit nulls. `completion` is a typed success/failure classification, usage
is a bounded map of observed numeric vendor counters, and no receipt is acceptance.

The existing artifact builder also executes required tests before evaluation.
The generic path must inject the trusted isolated test runner there; protecting
only later independent checks would leave candidate code in the graph role.
Add a keyword-only `test_runner` seam to `artifact_builder.build` and
`produce_required_test_results`, preserving existing return evidence fields.
The unchanged legacy default keeps the greeting behavior; generic
`isolated-linux` admission rejects a missing isolated runner before test launch.
G owns only these targeted shared-file hook edits; I owns runner and broker.

The injected callable accepts `CandidateTestRequest` and the already validated
profile, returning a broker-owned `SealedTestReceipt`. Request exact keys:
`schema_version`, `run_id`, `kind` (`required` or `independent`), `candidate_sha`,
`candidate_root`, `task_sha256`, `profile_sha256`, `commands_sha256`, `commands`,
`checks`, `timeout_seconds`, `max_output_bytes`. `commands` is the exact ordered
string list for required tests with `checks=[]`; independent tests have
`commands=[]` and the exact checks-v1 array. The broker validates request hash,
tool bindings, actual test UID, clean candidate before/after, exact commands,
exit/output hashes and lengths, limits and descendant quiescence. It seals those
results in trusted storage keyed by run/request hash; neither test nor worker
can supply/replace a sealed receipt. The artifact adapter translates verified
required-test results to the existing manifest fields; signer consumes only
broker-verified receipt identity/content, never a candidate-writable report.
These are trusted internal requests derived from frozen startup inputs, not raw
launcher arguments. Amendment v2 fixes the receipt wire, broker authority and
restricted evaluation/signing flow; graph cannot construct a trusted receipt.

Limits are enforced and audited: worker invocations default 1, explicit maximum
3; worker timeout default 900 seconds, maximum 3600; evaluation/test suite timeout
default 300 seconds, maximum 900; combined output maximum 8 MiB per bounded suite
or provider stream. Positive user values can lower defaults, not exceed maxima.
Persist reservation before launch so crashes cannot reset the count. Hard token
or USD ceilings unsupported by the CLI fail `BUDGET_UNSUPPORTED`; subscription
authentication is not a guarantee of zero cost or unlimited allowance.

The derived producer contract retains current fields and budget validation. Bind
both its hash and the full public task/profile/check/policy hash to the graph
node and all receipts; do not omit provider identity or acceptance inputs from
recovery integrity.

## CLI and Python seams

```text
codex-grapher init --repo SOURCE --task TASK.json --workspace STATE --profile PROFILE.json --json
codex-grapher run --workspace STATE [--stop-after built|evaluated|promoted] --json
codex-grapher status --workspace STATE --json
codex-grapher recover --workspace STATE --json
codex-grapher rollback --workspace STATE --json
codex-grapher backup --workspace STATE --output BACKUP --json
codex-grapher restore --backup BACKUP --workspace ORIGINAL_ROOT --profile PROFILE.json --json
codex-grapher doctor --profile PROFILE.json --json
```

These are target interfaces to implement, not commands that already pass.
Read-only help/status/doctor do not bootstrap/migrate/change graph bytes or modes.
Unavailable checks report specific evidence limits, never a blanket successful
diagnosis. Live owner status uses authenticated RPC; stopped inspection uses a
verified read-only snapshot so diagnostics do not become extra DB writers.

Python seams: `initialize_repository_workflow(source, task_path, root, profile)`,
`run_repository_workflow(root, operation, stop_after=None)`,
`load_frozen_task(root)`, `launch_worker(request, profile)`,
`evaluate_artifact(request, profile)`, `backup_workspace(root, destination)` and
`restore_workspace(backup, destination, profile)`. The first two return a
`WorkflowSummary`: workflow/project/task IDs and hash, durable state, attempts,
baseline/candidate/accepted SHA, artifact/outcome IDs, evidence scope and next
safe action. Other seams return typed, hash-bound receipts and explicit failure
classifications, not a truthy process exit substitute.

## Provider boundary

Codex 0.155.1 is available under existing non-root UID 1000. Bind model
`gpt-5.6-sol`, reasoning `medium` and service tier `default` explicitly while
ignoring user configuration; never alter that user configuration.
Resolve/version/capability/auth preflight before reservation, then invoke through
argv with stdin prompt, fixed cwd, close-fds, a narrowly allowed environment and
descendant supervision. Use the researched `--ask-for-approval never exec`,
`--ignore-user-config`, `--ephemeral`, `--sandbox workspace-write`, `--json`,
explicit model and controller-owned result schema/output. Validate against actual
installed help before launch. Do not silently drop security flags or use sandbox
bypass, ambient API keys, arbitrary inherited home/configuration or another
provider on failure.

Require process success and a single valid successful terminal provider record.
Malformed/truncated/contradictory terminal output, missing completion, refusal or
blocked permissions, timeout, output overflow, nonzero exit and failed cleanup
are failures. Worker leaves scoped uncommitted edits: unexpected HEAD change,
no-op, escaping path/mode/symlink changes and failed tests never promote.

Worker receipt binds schema/attempt/task/config/prompt hashes, provider/version,
resolved executable hash, observed model/session, completion classification,
observed usage or explicit unavailable fields, monotonic duration, output hashes
and lengths, exit/signal and descendant cleanup. No credentials or account IDs
enter receipts. A receipt cannot score, sign, promote or publish.

## OS roles and independent acceptance

The trusted graph/integrator owns DB, canonical accepted refs/binding, admitted
evidence and publication state. The worker owns only its attempt checkout/output.
An untrusted test UID receives a fresh candidate and frozen test inputs; it owns
neither policy nor signing capability. The signer alone reads its private key
and validates broker-owned, sealed test receipts bound to artifact/claim/candidate,
task/profile/policy/check hashes, required-test evidence and prior ledger hash.
It never executes candidate code or signs worker-writable reports.

Trusted graph/signer code and dependencies must be read-only installed artifacts
or protected mounts. The current source checkout is writable by the Codex UID;
merely dropping privilege does not stop it altering a later evaluator import.
Never import evaluator code from candidate/source-controlled writable paths.
OS evidence proves the listed boundaries, not a blanket hostile-kernel claim.

Use actual kernel identities, denied mounts, restricted sockets with SO_PEERCRED,
no-new-privileges, dropped capabilities/groups, sanitized environment, private
PID/mount/IPC/network policy and bounded descendants. Request JSON cannot select
a role or forge kernel identity. Mount only necessary binaries and explicit role
files; exclude host `/run`, homes, agent/Docker/D-Bus sockets and unrelated state.
The provider's required login/transport allowance is explicit and separate from
offline candidate tests. Test both least privilege and legitimate successful flow.

Task-policy acceptance is 100 only when all frozen declared independent checks,
required tests, clean exact candidate and allowed-path gates pass; otherwise it
fails. That is a deterministic task result, not a general quality or release score.
Keep existing signed v4 task policy and legacy v3 evaluation separate.

## Recovery and five fault boundaries

Reserve and fsync attempt identity/configuration before the provider starts.
`artifact-sealed` means complete immutable EvidenceIngress AND a committed
`record_ingressed_evidence` for that artifact under a live lease, with durable
EVIDENCE_PENDING pointer/event. Worker-owned files or an unadmitted ingress
directory are quarantined inspection material, not resumable graph authority.

| Boundary | Required recovery behavior |
| --- | --- |
| B1: launch reservation; no graph-admitted artifact | Prove descendants dead, preserve inspection data, report interrupted pause; no automatic launch, lease revival or model resume |
| B2: admitted artifact / EVIDENCE_PENDING | Reverify complete inventory; claim and independently evaluate same artifact |
| B3: committed signed outcome / PASSED | Verify exact outcome/ledger/claim closure and integrate its immutable IDs |
| B4: promotion binding replacement before final logical completion | Reconcile the original prepared attempt and physical closure before new dispatch; one integration journal operation |
| B5: pending rollback after physical change | Complete/reconcile the exact recorded rollback and authorized predecessor; duplicate recovery adds no operation |

Test disposable service restart and actual guest reset at these five barriers.
Record guest boot ID changes for actual reboot/reset, service identity, accepted
SHA, journal count/tail, full closure, invocation count and successor visibility.
Also observe an orderly guest reboot and an abrupt QEMU loss; a child process
exit alone cannot satisfy host-restart proof. Completed recovery performs no
model/test rerun. Expired evaluation claims follow existing reclaim rules;
never rewrite/sign historical bytes to fit a new claim.

## SQLite durability and full-state backup

Default writable connections in graph, TaskController and coordinator use
DELETE/EXTRA with readback and one OS-locked owner; preserve stdlib Python.
Doctor reports actual source/library identity and separate `FIXED|UNPATCHED|
UNPROVEN` patch status and support verdict (`SUPPORTED_AVOIDANCE` for verified
default conditions). Unknown attestations never become fixed by a flag.

Optional WAL/FULL requires a verified patched runtime and pinned provenance.
Ship explicit task-local 3.53.4 provisioning; no system upgrade or automatic
installation. Scope loader settings to graph processes and strip them from
worker environments. Existing WAL state requires explicit offline maintenance
through the fixed runtime after a coherent backup; reject otherwise before
schema/task effects. Preserve DB/sidecars intact on failure, never delete them.
Runtime constructors still never create or migrate schemas implicitly.

Backup v1 is offline/quiescent: exclusive owner lock, no active worker leases or
evaluation claims, no unfinished promotion/rollback, complete closure checked,
writers closed and no unexplained WAL/SHM/journal sidecars. A sidecar is evidence
to reconcile, not a file to remove. Atomically publish a hashed full inventory
only after copying and fsyncing all durable state and verifying a restored copy.

Include frozen task/profile/policy/checks, public key/fingerprint, all graph/event/
claim/outcome/journal records, all admitted artifacts including unevaluated and
disposed entries, self-contained canonical Git objects/custom accepted/candidate/
rollback refs, every retained SHA generation including Git metadata, binding and
sealed worker receipts. Reject external Git alternates/linked worktrees without
complete closure. Exclude private keys, provider homes/auth, sockets and locks.

Restore only into an empty original absolute root on a fresh guest with original
runtime inaccessible. Verify archive entries/types/modes/hashes, reject traversal,
absolute names, duplicate/extra entries, links and special files in v1, restore
semantic role ownership from trusted profile, then schema/static/all-artifact/
signed-outcome/Git/binding/all-generation/coordinator closure before dispatch.
Reject relocation and any mismatch without rewriting signatures or frozen
commands. Public-key-only verification remains possible; future signing requires
separate provisioning of the matching private key, never an automatically
substituted identity. Recreate sockets/locks; preserve failed restore for diagnosis.

## Economics, validation and stop conditions

Use existing subscription execution and one small guest, measure actual bounded
launch/time/output and observed usage. No purchase or profit assumption supports
the design. Reuse verified core code rather than add another orchestration stack.
The value hypothesis is fewer manual lifecycle steps with truthful accepted work;
the three tasks and fresh installed-user test can falsify that hypothesis.

Validate focused changed components, then full foundation once at integration,
then independent adversarial/user evidence. Stop/redirect after three unchanged
failed approaches; no new attempt resets history or spending boundaries. Escalate
actual missing authority/auth or conflicting evidence; never relax gates, use a
mock as real-provider proof or enter Phase 2 before Phase 1 passes.
