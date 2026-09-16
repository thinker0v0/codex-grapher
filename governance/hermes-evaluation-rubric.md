# Hermes Planner and Codex Supervisor Rubric v1.0.0

## Scope and pass rule

This rubric evaluates a Hostinger KVM2 deployment in which a project-specific
Hermes instance plans, delegates to isolated Codex workers, verifies evidence,
and repeats bounded remediation until the requested outcome is met.

Pass requires all of the following:

- design score >= 95/100;
- implementation-evidence score >= 95/100;
- every section minimum is met for both scores;
- every hard gate passes;
- a blind second evaluator confirms the result within 4 points.

A high design score is not evidence that the system is deployed or operational.

## Scored sections

| Section | Weight | Minimum | Full-credit standard |
|---|---:|---:|---|
| Project-specific Hermes architecture and isolation | 12 | 11 | Each project has an explicit identity, repository allowlist, secrets scope, state store, budget, tool policy, and Codex worker pool; cross-project access is denied and tested. |
| Model selection and routing | 14 | 13 | Current candidates, including the applicable Z.AI subscription, are tested on a versioned task suite representative of planning, review, finance research, coding, and business work; routing uses measured quality, latency, availability, context limits, and total cost rather than brand claims. |
| Codex delegation and closed-loop supervision | 14 | 13 | Typed task contracts, acceptance criteria, bounded retries, independent verification, targeted remediation, escalation, cancellation, idempotency, and terminal states are defined; Hermes cannot self-certify Codex output. |
| Agent roles and independence | 8 | 7 | Planner, researcher, builder, verifier/evaluator, security/risk reviewer, and operator responsibilities are least-privileged; evaluator cannot edit artifacts or rubric and builder cannot forge evaluation evidence. |
| Prompt, context, memory, and provenance | 10 | 9 | Versioned project prompts, context budgets, retrieval policy, durable/ephemeral memory separation, citations, freshness, retention/deletion, poisoning defenses, and reproducible prompt/model/config hashes exist. |
| Slack control and human governance | 9 | 8 | Channel/project routing, identity binding, RBAC, confirmation for consequential actions, thread/task correlation, rate limits, injection-resistant attachment handling, redaction, audit logs, and an out-of-band emergency path are tested. |
| Security and secrets | 10 | 9 | Threat model, container/user isolation, egress and filesystem policy, secret manager, rotation, supply-chain verification, patching, abuse limits, and no direct Slack-to-trade path are enforced and tested. |
| Reliability, recovery, and KVM2 fit | 8 | 7 | Capacity budgets fit measured KVM2 resources; queues apply backpressure; timeouts, circuit breakers, health checks, restart policy, backups, restore drills, VPS-loss recovery, and provider/model outage handling meet declared objectives. |
| Observability, cost, and operations | 7 | 6 | Per-project/task/model traces, structured logs, metrics, cost attribution, SLOs, alerts, dashboards, immutable evidence linkage, and runbooks support diagnosis without exposing secrets. |
| Three-domain readiness | 8 | 7 | Separate executable profiles cover financial research, open-source delivery, and AI-native business validation; financial work preserves research/paper/live separation and point-in-time evidence; frameworks are routed per repository without global overlap. |
| **Total** | **100** | **95** | |

## Scoring anchors

Apply these anchors independently to every item, then multiply by its weight:

- 0%: absent, contradicted, or unsafe.
- 25%: aspiration or tool name only.
- 50%: detailed design with owners, interfaces, and acceptance criteria.
- 75%: implemented with automated happy-path evidence.
- 90%: reproducible tests include failure paths and operational telemetry.
- 100%: isolated deployment evidence plus adversarial and restore drills meet measurable targets.

The design score is capped at 100% of the design-only interpretation of each
item. The implementation-evidence score follows the anchors literally and is
zero where no machine-verifiable artifact exists.

## Model evaluation protocol

Full model-routing credit requires:

1. Candidate names, provider endpoints, exact model identifiers, subscription
   restrictions, pricing, rate limits, tool/function support, context limits,
   data-retention terms, and evidence dates from primary sources.
2. A frozen, versioned evaluation set with project-stratified tasks and hidden
   tests. At least 20 tasks per major project class and three runs per stochastic
   task are required before production selection.
3. Blind grading of correctness, instruction adherence, planning quality,
   evidence use, code/test quality, hallucination rate, latency percentiles,
   failure rate, and end-to-end cost per accepted task.
4. Quality-first routing with declared minimum thresholds, not a single global
   model. Planner, researcher, coder, reviewer, and fallback may differ.
5. Primary, secondary-provider fallback, cooldown/circuit-breaker behavior,
   context-degradation tests, budget ceilings, and a safe terminal failure state.
6. Re-evaluation on model/version or prompt changes and at least quarterly.

Marketing benchmarks alone earn no implementation evidence. A subscription is
not selected unless its actual API/agent compatibility and workload economics
are demonstrated under the user's account constraints.

## Hard gates

Any failure makes the result **NOT PASS**, regardless of score.

### Identity, isolation, and authority

- Hermes instances, Codex workers, repositories, secrets, memory, logs, and
  budgets are scoped by project; a tested deny path prevents cross-project use.
- Builder and evaluator use separate identities, credentials, state, and write
  permissions; evaluator evidence is append-only and builder cannot alter it.
- Every task has project ID, task ID, idempotency key, requester identity,
  bounded budget, timeout, allowed tools, acceptance criteria, and audit trail.
- No agent can change its own rubric, grant permissions, approve a consequential
  action, conceal failed attempts, or declare final success without evaluator evidence.

### Slack and financial safety

- Slack cannot directly place an order, enable live trading, raise risk limits,
  release a kill switch, change production credentials, or authorize withdrawal.
- Untrusted Slack text, links, files, web content, news, market data, repository
  content, and skill scripts cannot override system policy or gain tool authority.
- Research, paper, and live systems use separate hosts or equivalent hard
  security boundaries, accounts, credentials, networks, and artifact promotion.
- Stale, missing, conflicting, unauthorized, or provenance-free financial data
  fails closed; future leakage and point-in-time integrity are tested.

### Repeat-loop safety and correctness

- The loop has attempt, wall-clock, token/cost, concurrency, and API-rate limits;
  it detects non-improvement and repeated failure and escalates to a human.
- Retries are idempotent; cancellation stops descendants; duplicate Slack events
  and worker restarts cannot duplicate side effects.
- Acceptance relies on reproducible commands and machine evidence tied to commit,
  data, model, prompt, configuration, environment, and evaluator hashes.
- A second blind evaluator is required at >=95; disagreement >=5 points or any
  hard-gate disagreement requires human adjudication.

### Operations and recovery

- Secrets never enter prompts, repositories, Slack, general logs, or evaluator
  payloads; rotation and revocation are demonstrated.
- Restore from backup and total VPS-loss recovery are demonstrated against named
  RPO/RTO targets; a provider/model outage drill reaches a safe state.
- Resource exhaustion on KVM2 cannot disable authorization, auditing, cancellation,
  or emergency shutdown; measured headroom and backpressure are demonstrated.
- The existing foundation verifier passes and no selected global frameworks
  violate repository routing rules.

## Required evidence packet

An implementation score may exceed 50 only if the packet contains:

- deployment manifests and redacted effective configuration;
- identity/RBAC matrix and negative authorization test logs;
- model benchmark dataset manifest, runner version, raw results, and selection record;
- end-to-end Slack -> Hermes -> Codex -> evaluator trace with correlated IDs;
- retry, duplicate-event, cancellation, timeout, budget-exhaustion, and outage tests;
- prompt/context/memory provenance and poisoning/redaction tests;
- per-project cost/latency/quality dashboards or exported machine metrics;
- backup restore, VPS-loss, secret rotation, and incident-response drill reports;
- immutable artifact hashes and CI attestations for every claimed pass;
- financial isolation and no-direct-order-path test evidence where applicable.

## Evaluator output contract

The evaluator outputs only:

1. `DESIGN SCORE: n/100`
2. `IMPLEMENTATION EVIDENCE SCORE: n/100`
3. section score table for both dimensions;
4. hard gates as `PASS`, `FAIL`, or `UNPROVEN` with evidence references;
5. disqualifying defects;
6. prioritized remediation items with the exact acceptance evidence required;
7. final status: `PASS`, `NOT PASS`, or `HUMAN ADJUDICATION REQUIRED`.

The evaluator does not propose a replacement architecture, select models, edit
implementation artifacts, relax criteria, or award credit for unsupported claims.

## Evaluation-loop policy

- Maximum review/remediation rounds: 8.
- Maximum elapsed time per evaluation campaign: 24 hours.
- Stop and escalate after two consecutive rounds with <1 point improvement, the
  same hard-gate failure in three rounds, or exhausted budget/time.
- Never weaken a gate to reach 95.
- Stop automatically only when both scores are >=95, every section minimum and
  hard gate passes, and blind confirmation succeeds.
