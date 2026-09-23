# Public usability and reliability cycle

Project: opensource. Record: reliability-20260921-problem-v1. Owner: maintainer.
Status: design candidate; developer usability scope confirmed by user. Source: public source at a442e971d0ed2f84265cf6e7fe68f7ed02f71ef1 and user request 2026-09-21.
Source/retrieval/effective date: 2026-09-21. Review: 2026-10-21.
Classification: public. Trust: directly inspected source; tests recorded separately.
Content hash: versioned Git blob.

The actor is a developer installing Codex Grapher, or an operator connecting a
worker through its local graph socket. They need a reproducible accepted change,
recoverable failures, and actionable state without reading test internals.

The public quickstart only reaches RUNNING/BLOCKED. Its user cannot observe the
artifact -> evaluation -> integration -> next accepted baseline mechanism.
`reconcile_worker` returns every failure to READY without delay or a finite retry
rule. `heartbeat` exists on ProjectGraph but is unreachable through the socket
dispatch API, while ingress requires a live lease. The socket handler and client
have no read deadline, and the server admits an unbounded pending connection queue.
These are observable failure mechanisms, not evidence of production incidents.

Current workaround: read and compose internal Python APIs, manually renew leases,
inspect SQLite, and interrupt repeated workers. Baseline commands are the public
offline demo and `bash scripts/verify-foundation.sh`; the baseline assessment
records their output separately. Existing unit passes do not disprove these gaps.

Success is falsifiable: a documented command must exercise real local Git commits,
artifact tests/ingress, signed fixture evaluation, promotion and successor baseline;
reopen/replay and rollback must preserve the accepted state. A stalled socket must
finish within its configured timeout, a valid worker can renew only its own live
lease, and retries must survive reopen without allowing early or unbounded launch.
Read-only diagnosis must not create/migrate/chmod a database or claim release PASS.

Constraints: preserve schema v5, immutable evidence and signed evaluator boundary,
four routes, existing frozen release rubric and unrelated work. No new runtime
dependencies or copied upstream code are necessary. Local fixture role separation
does not prove OS identity separation or production readiness. Native Buzz, deployed
worker operation, host restart and real credentials remain separate release gates.

Assumptions: these fixes improve reliability for local users; adoption and lower
production incident rates are unmeasured. Reject the design if a policy can be
bypassed by ordinary lease/recovery paths, a diagnostic mutates state, or the new
lifecycle example fabricates test output instead of running the artifact producer.

The user confirmed that completion means another developer can install, execute,
verify and recover work. Private VPS/Buzz deployment is not this cycle's target.
Additional reproduced blockers: human_gate specifications do not prevent leasing;
status omits CAS version needed to resume normal API calls; every task evaluation
is forced to claim the entire product release HG1-HG11, making an honest portable
local task evaluator impossible. These require explicit task-vs-release separation.
