# Frozen reliability cycle contract v1

Frozen before implementation on 2026-09-21. Threshold 95/100; each section minimum
is its maximum minus one. Lens: skeptical developer, reliability/security reviewer.
This supplements and does not replace or weaken root RUBRIC.md.

1. Problem, alternatives, primary sources and license traceability: 10.
2. Durable finite retry/backoff, permanent-failure denial and recovery safety: 25.
3. Authorized live heartbeat, bounded socket/client resources and denial cases: 20.
4. Explicit frozen per-task policy with signed results, real local lifecycle,
   successor visibility, replay and rollback, accurate fixture boundary: 20.
5. Installed console entrypoint, read-only doctor/status/events, errors and public
   instructions usable outside the checkout: 10.
6. Exact-SHA machine evidence, complete foundation and independent blind user: 15.

Hard gates: no consequential external test; no secrets; existing authorization,
immutable evidence and signature boundaries remain intact; human-gated nodes cannot execute without distinct authorization; legacy release
evaluation is unchanged and explicit task policy cannot be replaced on replay;
retries cannot become
an unbounded loop through normal APIs or recovery; no diagnostic state mutation;
examples run production APIs and real tests without importing test helpers; every
claim is scoped to its evidence; all baseline regression tests pass; no schema
migration or new runtime dependency; independent review and blind user succeed.

Verdict labels: LOCAL_IMPROVEMENT_PASS or NOT_PASS. Never imply operational PASS.
The independent evaluator must additionally list every remaining root release
FAIL/UNPROVEN gate. Missing evidence is UNPROVEN, not inferred success.
Maximum three unchanged attempts per defect; changed approaches require recorded
evidence. Material unresolved contradictions require HUMAN_JUDGMENT.

## Design-stage evaluation (before implementation)

A DESIGN_READY verdict scores only design completeness and readiness, never code or
release: problem/baseline 20, primary research/alternatives/licenses 20, concrete
mechanism/security contracts 30, ownership/handoff/acceptance 20, scope/claim
boundaries 10. Threshold 95; each minimum maximum minus one. Hard gates are a
falsifiable observed problem, preserved legacy authority/format semantics, exact
interfaces and failure cases, independent evaluation plan, and explicit remaining
release uncertainty. Implementation tests and blind-user outcomes stay UNPROVEN
until built; they are not evidence required to approve starting implementation.
This paragraph does not lower any implementation or root release criterion.
