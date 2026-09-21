# Chosen mechanism

Extend the existing stdlib core, retaining its evidence and publication protocol.
Adopt documented upstream mechanisms through original implementation: classified,
bounded retry/backoff (LangGraph/Temporal family), durable idempotent replay (DBOS
family), and visible local lifecycle/diagnostics. Primary-source research is linked
from RESEARCH.md before the design gate. No upstream source is copied or vendored.

Compare three credible alternatives: keep manual API assembly (lowest change,
leaves the reproduced defects); replace the graph with a framework (migrations,
new dependency/identity boundary and license burden without comparative evidence);
or close the specific gaps inside existing APIs (chosen, bounded compatibility
surface with regression tests). Heavy framework adoption stays deferred.

1. Retry policy lives in immutable node specification and existing hash-chained
   events, without a schema migration. Conservative finite defaults apply to
   legacy nodes. Classify controller safety/permanent failures as terminal;
   unknown successful transport does not fabricate evidence or task success.
   Persist an exponential bounded retry deadline, reject early leases, and stop
   repeated identical no-progress failures before a third identical launch.
   Recovery and reopens must not reset attempt ceilings. Use existing valid
   transitions, including atomic READY -> NEEDS_HUMAN when intervention is needed.
2. Expose exact live-lease heartbeat to the authorized builder route. Bound service
   frame reading, handler lifetime and admitted connections; bound client timeout
   and response size. Validate JSON object framing and integer types strictly.
3. Provide a documented offline lifecycle example using production artifact,
   ingress, graph and coordinator APIs with temporary repositories and keys.
   Produce real test output, show successor consuming the accepted generation,
   recover an interrupted local promotion and prove exact replay/rollback. Label
   fixture keys and same-user execution explicitly; never infer a release pass.
4. Provide a stdlib CLI with prerequisite doctor and read-only graph status/event
   inspection, clear errors, JSON output and no automatic installation or repair.
   Separate database integrity from external evidence and deployment verification.

Economics: no added paid calls, service or framework dependency. Maintenance cost
is bounded by the four interfaces above. No moat or superiority claim is made.
Failure modes include policy bypass through recovery, timeout resource leaks,
secret-bearing error strings, misleading fixture pass labels and writable status
connections. Adversarial tests and independent review cover those explicitly.

Stop/pivot: after three attempts without new evidence, stop that branch and record
the blocker. Do not loosen the release rubric or convert absent deployment/native
Buzz evidence into local PASS. Production deployment and external communication
are not automated tests.

5. Enforce human_gate on the actual lease/start path; without a separate signed
   approval capability, these nodes cannot execute. Expose authorized exact node
   version/state for worker resume; do not leak another route's lease capability.
6. Add an explicit versioned task-evaluation policy for portable developer tasks.
   The legacy v3 result/default verifier and root release rubric remain unchanged.
   New task results are distinct version 4 and bind a trusted frozen JSON policy
   hash, exact section minima/maxima, threshold, mandatory gates, artifact, claim,
   candidate, evaluator and ledger signature. Policy selection is explicit and
   pinned in immutable node specification; no caller result can choose its policy.
   Reopen/recovery must reject policy substitution. Graph and integrator must agree
   before any effects. A task PASS is never a product release PASS. This enables
   a local deterministic sample evaluator to check real task assertions instead
   of fabricating unrelated product release gate scores.
7. Package a dependency-free installable Python distribution and console command.
   Verify installation in a temporary venv and execution from outside the checkout.
   Document adapting the lifecycle API to the developer's own repository/worker
   and supplying independent evaluator output. No hosted service is needed.

Before relying on immutable policy/retry specs, verify canonical spec_json hashes
against spec_hash and the genesis event payload on every static integrity check.
A stored hash without recomputation cannot prove policy immutability.

## Task-policy interface frozen before implementation

Use `load_task_policy(path)` to produce an immutable policy object whose digest
binds the exact JSON file bytes. Required policy format is version 1, with a named
nonempty section map (finite numeric `minimum`/`maximum`), nonempty unique gate
names and an aggregate threshold >=95 and <=100; section maxima sum to 100.
Reject unknown fields, booleans as numbers, NaN, duplicate JSON keys, malformed
hashes and empty/degenerate policies. The policy is a trusted planner/evaluator
input, never chosen from a builder's result.

Graph and integrator take an explicit optional `evaluation_policy` argument.
Legacy default behavior is unchanged. A custom policy must match the supplied
rubric SHA/file and be pinned by hash in each task node's immutable spec before
leasing. Reopening with a different/missing policy rejects mutation of custom
policy tasks. Version-4 task results contain an explicit `schema_version: 4` and
otherwise retain the signed task/artifact/claim/candidate/rubric/ledger bindings;
verification uses exactly the selected policy's score/gate names. Version-3
legacy results continue using the original exact release sections and HG1-HG11.
The result cannot mix versions or supply policy fields that alter verification.

Every graph evaluation, outcome re-verification, direct integrator promotion,
and coordinator integration/recovery preflight must enforce this same contract.
Coordinator construction or validation rejects disagreeing graph/integrator
public key, rubric hash or policy before any Git/binding/database mutation.
The local sample may sign only after its separate deterministic evaluator has
checked actual local acceptance assertions. Its task PASS and product release
NOT_PASS must be distinct in command output and documentation. Same-UID local
roles are for trusted development; do not describe them as a security sandbox.

The v4 signed field set additionally contains `policy_sha256`, equal to the exact
trusted task-policy bytes and `rubric_sha256`. V3 is forbidden in task mode and v4
is forbidden in legacy mode, with no fallback. Hash validation always recomputes
spec_json/spec_hash. Genesis/spec closure must preserve the exact recognized
legacy migration contract: require exact genesis binding for newly created runtime
nodes and explicit task/retry-policy nodes; do not reinterpret accepted legacy
fixture payloads as a new version of the database.

## Retry and human-gate contract

Default policy: max_attempts=3 (including first lease), initial_delay_seconds=5,
backoff_multiplier=2, max_delay_seconds=300, max_identical_failures=2. Validate
integers exactly; configured attempts are 1..100, identical failures 1..2, delay
1..3600 seconds and finite multiplier 1..10. The next eligible timestamp is
recorded once in the hash-chained event. Do not recompute it on restart.

Server classification uses exact validated controller state and integer return
code, never caller-supplied free-text fingerprints: FAILED_GATE, FAILED_PERMANENT,
FAILED_BUDGET and explicitly cancelled work never receive automatic retry.
Timeout/process/transport uncertainty can retry within policy; rc=0 without proven
controller evidence is UNKNOWN and never success. Fingerprint uses this canonical
failure class and exact terminal/controller state plus exit code; a changed prose
message cannot reset repeated-failure accounting. Repeated identical outcomes
pause before a third identical execution; total attempts cap all other failures.
Every lease consumes one persisted attempt, including expired LEASED/RUNNING work.
Recovery must record a classified lost-lease outcome and retain delay/count; raw
transition helpers must not permit bypassing lease admission or its attempt cap.

This cycle does not implement consequential approval capabilities. Every
human_gate=true task must remain unexecutable through lease/start/retry/recovery
and generic transition APIs, with an actionable pending-human explanation.
Malformed human_gate types fail closed. No string, CLI flag or timeout is approval.
