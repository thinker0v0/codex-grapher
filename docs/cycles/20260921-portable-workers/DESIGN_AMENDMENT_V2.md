# Design amendment v2: privileged launch and sealed evaluation

Status: candidate for independent design reevaluation; no DESIGN_READY claim.
Record: `opensource.portable-workers.design-amendment.v2`; date: 2026-09-21 UTC.
Owner: root integrator; public; freeze identity is this amendment's Git/hash.
This additive correction addresses the evaluator's launcher-authority and
receipt/signing-interface gaps before product implementation. It supersedes
conflicting v1 interface descriptions only. RUBRIC thresholds/hard gates,
phase ordering, task criteria and all existing authority invariants are unchanged.

## Explicit privileged bootstrap

`isolated-linux` requires invoking the installed CLI as root. A fifth bootstrap
authority executes only root-owned, non-writable trusted code/dependencies and
frozen root-owned configuration. No host account/service/package installation
is implicit. Missing root, required capability or kernel feature fails closed;
`trusted-local` is never an automatic fallback. Bootstrap never executes or
imports candidate code; root remains an explicit privileged trusted computing
base and is not claimed isolated from keys or the four child roles.

Bootstrap creates namespaces, pins trusted tool/config identities and launches
four distinct real worker/test/signer/graph UIDs, each greater than zero in the
kernel credential domain used by SO_PEERCRED; reject mappings to host root.
The graph child drops privilege
and capabilities before connecting to the launcher; it cannot read the signer
key or acquire general privilege. Bootstrap alone creates the listening AF_UNIX
endpoint; validate actual accepted-connection `SO_PEERCRED` against configured
graph UID. A socketpair inherited from root has the creator's peer credentials
and MUST NOT authenticate the dropped graph role. Worker/test cannot mount,
connect to or inherit the launcher endpoint or privileged descriptors.

A separate graph-owned scoped control socket permits worker own-task status and
live-lease heartbeat only; forged roles, cross-task access and evaluate/integrate/
rollback actions reject. Bootstrap lifetime is bounded by the graph CLI/service;
parent death/disconnect shuts down admission, terminates/reaps child trees and
leaves durable interrupted reservations. It is not a persistent root service.

The workspace top directory and `.broker-receipts` entry are root-owned and not
renameable by graph/worker/test. Graph owns only dedicated mutable state children.
The root-held receipt store is read-only to graph/signer and invisible to worker/
test; use pinned directory descriptors, no symlink following, immutable exclusive
creation, fsync and atomic publication. Only public receipts/output inventories
enter backup closure; sockets/locks and credentials do not. Restore recreates
this ownership before dispatch. Operator-provisioned private key lives OUTSIDE
the workspace; bootstrap mounts it read-only only into signer. Missing matching
key remains verify-only; never mint a replacement or re-sign historical outcomes.

Profile `tools` adds pinned `openssl: Tool`, `bwrap: Tool|null` and
`setpriv: Tool|null` to existing python/git/provider. Nulls are allowed only for
the latter two in `trusted-local`. Validate all executable hashes/version/paths
and read-only provenance; isolated mode requires all six tools. No tool is
resolved from candidate PATH or mutable source configuration.

## Launcher wire and admission

Every object below rejects unknown/duplicate keys, booleans as numbers, nonfinite
numbers and invalid IDs/hashes. `hex64` is lowercase SHA-256; `hex40` a commit.
Canonical bytes are UTF-8 JSON, sorted keys, separators `,` and `:`, ASCII escaping,
no NaN/Infinity or trailing newline. Hash those exact bytes. All lengths/counts
are bounded by frozen task limits and existing transport limits before allocation.

```text
LauncherRequest = {schema_version: 1, action: Action, workspace_id: hex64,
                  request_id: string, request_sha256: hex64, payload: Payload}
Action = provider-preflight | worker-launch | candidate-tests |
         sign-evaluation | immutable-receipt-fetch | shutdown
Payload(provider-preflight | shutdown) = {}
Payload(worker-launch | candidate-tests) = {registered_request_id: string}
Payload(sign-evaluation) = EvaluationRequest
Payload(immutable-receipt-fetch) = {receipt_id: hex64}
```

`workspace_id` hashes the frozen startup descriptor binding canonical workspace
and task/config root; it must equal the running instance. `request_sha256` hashes
the envelope excluding itself. Named registered request IDs select prevalidated
immutable task/attempt data, never new authority. Existing WorkerRequest and
CandidateTestRequest are trusted internal structures derived/revalidated against
frozen task/profile/checks, NOT caller-supplied launcher payloads. Caller-selected
UID/env/executable/argv/output path is impossible through this wire. Validate
original hashes, fsynced invocation reservation, attempt count, deadline and
resource bounds before effects. Exact replay returns existing durable result;
changed payload under an old ID rejects; interrupted unsealed launch never reruns.

Bootstrap owns the private registry. For a named attempt/run, derive full
WorkerRequest/CandidateTestRequest from pinned task/profile, exact fsynced durable
reservation and verified candidate snapshot, then seal the entry before launch.
Graph-written proposals are untrusted data to validate/reconstruct, not authority;
there is no registration RPC. Bind dynamic SHA/path to the owned attempt root,
verified single-commit base and write scope. Provider prompt derives only from
frozen objective/criteria plus fixed hashed template; commands derive only from
frozen required/check arrays. A named ID reused with a different hash rejects.

## Exact sealed test receipt

```text
SealedTestReceipt = {
  schema_version: 1, receipt_id: hex64, request_id: string, request_sha256: hex64,
  run_id: string, kind: "required"|"independent", workspace_id: hex64,
  task_sha256: hex64, profile_sha256: hex64, commands_sha256: hex64,
  candidate_sha: hex40, pre_tree_sha256: hex64, post_tree_sha256: hex64,
  actual_uid: integer, actual_gid: integer,
  namespaces: {user: integer, mount: integer, pid: integer, ipc: integer, net: integer},
  capabilities: {inheritable: hex, permitted: hex, effective: hex, bounding: hex, ambient: hex},
  no_new_privs: true, results: [TestResult, ...], elapsed_ms: integer,
  limits: {timeout_seconds: integer, max_output_bytes: integer},
  descendants: {reaped: boolean, survivors: integer}, replayed: false
}
TestResult = {sequence: integer, id: string, command_sha256: hex64,
              exit_code: integer, stdout: Output, stderr: Output}
Output = {sha256: hex64, bytes: integer, relative_path: string}
```

`receipt_id` is SHA-256 of canonical receipt bytes excluding `receipt_id`.
`request_sha256` binds the full trusted CandidateTestRequest, and
`commands_sha256` binds its exact ordered commands/checks. Required IDs are
`required-0000`, etc.; independent IDs are the frozen checks IDs. Sequences start
at zero and are contiguous; command hashes bind the exact string or checks object.
Tree hashes bind canonical sorted tracked path/mode/content inventories observed
by trusted code before/after, both equal the exact clean candidate; also reject
untracked changes. Namespace integers are actual observed kernel namespace inodes;
capability masks and UID/GID are observed, never runner-supplied assertions.

Output paths are broker-derived safe relative inventory names, never candidate
paths. Hash/length verify their sealed bytes and combined output bounds. Timeout,
nonzero exit, wrong identity/isolation, mutation or incomplete descendant cleanup
cannot produce passing acceptance. Fetch/replay returns identical bytes with
`replayed:false`; replay telemetry belongs in the outer audit, not the receipt.
Graph cannot manufacture/replace a receipt. Signer fetches hash-verified canonical
bytes and outputs from the root-sealed store using matched IDs, not graph reports.

## Exact evaluation and signing requests

```text
EvaluationRequest = {
  schema_version: 1, workspace_id: hex64, task_sha256: hex64,
  profile_sha256: hex64, policy_sha256: hex64, checks_sha256: hex64,
  producer_contract_sha256: hex64, artifact_id: string, manifest_sha256: hex64,
  evaluation_id: string, evaluator_contract_id: string, claim_id: string,
  previous_ledger_hash: null|hex64, required_receipt_id: hex64
}
SigningRequest = {schema_version: 1, evaluation: EvaluationRequest,
                  evaluation_request_sha256: hex64,
                  independent_receipt_id: hex64, candidate_sha: hex40}
```

Broker validates the actual active graph claim and exact admitted artifact through
trusted read-only graph/coordinator verification, plus manifest/policy/check/task/
producer/ledger closure. It reconstructs the independent candidate from that
artifact, executes frozen checks under test UID, seals their receipt and constructs
SigningRequest internally. Neither public launcher nor graph supplies it directly.
Signer revalidates both receipts, all exact IDs/hashes and current claim, derives
the deterministic existing v4 outcome from frozen policy, and signs only when
every required test, independent check and scope gate passes. It accepts no
arbitrary message, serialized verdict or caller-selected signing bytes and never
executes candidate code. Return the canonical signed existing v4 outcome;
normal graph `record_evaluation` remains the authority for accepting it. Stale
claims/ledger, changed candidate or missing receipt reject before signing.

Failed checks seal a rejection rather than leaving an active claim unresolved:

```text
EvaluationRejection = {schema_version: 1, rejection_id: hex64,
  evaluation_request_sha256: hex64, artifact_id: string, claim_id: string,
  failed_receipt_id: null|hex64,
  reason: "CHECK_FAILED"|"ISOLATION_FAILED"|"LIMIT_EXCEEDED"|"STATE_INVALID"}
```

Its ID hashes canonical bytes excluding itself; storage/fetch protections equal
test receipts. Graph verifies it and calls existing `reject_evidence` for the
matching active claim with this reason hash, using frozen bounded disposition
rules (`FAILED_GATE` for failed acceptance). Exact replay is durable/idempotent;
a stale claim rejects without mutation. No unsigned PASS or signature is invented.

I owns bootstrap/launcher/store/schema validation/signer; G owns the narrow
required-test injection and graph request construction; R owns installed root
entrypoint/config admission; B includes public sealed receipts in backup closure.
Validation must deny non-root bootstrap, inherited socketpair identity, forged
actions/IDs/paths/receipts, writable trusted code and graph access to private key;
prove actual four-UID success and all preexisting isolation/acceptance gates.
