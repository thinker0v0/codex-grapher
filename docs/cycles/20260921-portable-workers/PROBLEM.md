# Problem and falsifiable outcome

Status: candidate for independent design review; acceptance contract frozen at commit.
Record: `opensource.portable-workers.problem.v1`; owner: cycle integrator.
Source/retrieval/effective date: 2026-09-21 UTC; review at freeze or changed scope.
Classification: public; evidence basis: source inspection and prior exact-SHA
review described in [RESEARCH.md](RESEARCH.md). Hash supplied at freeze.

## Actor, cost and mechanism

A developer can install the existing package and exercise a greeting example,
but cannot submit a frozen task for their own repository through one supported
end-to-end interface. They must manually connect worker execution, artifact
ingress, independent checks, signing, promotion and recovery. Manual connection
is the costly problem: it creates opportunities for false completion, lost
accepted work and accidental authority sharing.

The observable symptoms and their mechanisms differ:

| Symptom at the baseline | Causal mechanism | Current workaround |
| --- | --- | --- |
| Only the greeting lifecycle is usable from the public CLI | Task IDs, policy, paths, evaluation and successor assertions are embedded in `local_workflow.py` | Hand-wire production APIs or change the demonstration |
| A process boundary is presented without hostile-code key isolation | Candidate tests can execute under the signing identity | Trust candidate code and the local account |
| Process interruption examples cannot prove host recovery | No disposable guest service/reset or complete state restoration evidence | Preserve the original host and reconstruct manually |
| SQLite WAL confidence rests on runtime assumptions | Loaded distro binary lacks the published WAL-reset fix | Rely on ordinary tests that cannot disprove the rare race |

No evidence establishes market size, adoption, profit, general superiority or
the absence of every database defect. Those are not acceptance assumptions.

## Baseline

At `df9e0c31ffdb7e045a268b6b03b16ce33b623a49`, the independent previous-cycle
review reported 378 tests, a working installed greeting lifecycle, signed
task-policy evaluation, immutable ingress, promotion, replay and rollback.
Generic own-repository tasks, actual-provider completion, separate OS trust
domains, guest recovery and coherent full-state restore were unproven.

Research now identifies the loaded Ubuntu `3.45.1-1ubuntu2.8` SQLite as
`UNPATCHED` through signed source/binary provenance. No corruption was observed
or reproduced. Installed Codex 0.155.1 has an existing non-root subscription
login; this establishes preflight availability, not successful model inference.
Claude CLI and live-Claude verification remain absent.

## Success measurements and falsification

| Hypothesis | Required observation | Disproof or safe failure |
| --- | --- | --- |
| A generic workflow closes the developer's task lifecycle | Three unrelated pinned OSS snapshots with disclosed seeded regressions pass their frozen checks through installed normal entry points | Any task needs greeting constants, private test helpers or source mutation |
| Real CLI completion can be distinguished from transport success | At least one actual Codex run yields valid bounded terminal protocol, scoped diff, independent acceptance and promotion | Zero exit without a valid terminal result is accepted; model failure promotes |
| Role separation protects authority from candidate code | Actual worker and test UIDs cannot read signing key or mutate policy, trusted code, accepted state, graph, another project or unauthorized signer/integrator socket capabilities; legitimate scoped flow succeeds | Any denied capability succeeds or successful flow requires shared privileged UID |
| Durable evidence enables honest recovery | Service restart and actual guest reset at all five frozen boundaries preserve accepted state and suppress duplicate launch/integration | Unsealed worker blindly reruns, stale lease revives, or accepted state disappears |
| Backup captures the complete durable workflow | Same-root restore on a fresh guest, original runtime inaccessible, verifies all artifacts/Git/outcomes/generations and replays/rolls back | DB-only restore, hidden reads from original state, key inclusion or signature rewriting |
| Supported SQLite is identifiable before work | Default DELETE/EXTRA plus one owner; optional WAL/FULL requires verified fixed runtime; patch/support verdicts stay distinct | Unpatched WAL acceptance, mismatched library, silent journal migration or avoidance mislabeled patched |

Representative regressions are deliberately seeded test tasks, not claims of
undiscovered upstream bugs. Baseline failure and intended acceptance behavior
must be recorded before any worker edits. One actual-provider success cannot
be generalized to arbitrary repositories or all providers.

## Constraints, exclusions and remaining uncertainty

Source Git worktree/index/refs/config/remotes/hooks/untracked inventory must be
unchanged after success and rejection. Dirty source input is rejected clearly.
Tasks have immutable IDs, exact base SHA, policy, checks, budget semantics,
deadlines and audit records. No model may grade or promote its own work.

Arbitrary relocation, online backup, distributed filesystems, unrestricted
hostile-repository execution, automatic dependency installation, provider
failover and secret transfer are not this minimum contract. A real provider's
own credential accessibility is a separate observed limitation; role denial
evidence must not falsely certify all same-UID tool access to its login store.

Before freeze, seal the representative task inventory and public source packet
in [DECISIONS.md](DECISIONS.md). Runtime compatibility and profile/check shapes
have root decisions recorded there and require implementation evidence.
After freeze, failures change the earliest invalid design or implementation;
they never justify weakening an acceptance gate to fit current output.
