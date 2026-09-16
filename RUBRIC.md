# Frozen Evaluation Rubric

Status: frozen-2026-08-28
Pass threshold: 95/100
Evaluator lens: skeptical operator, agent-systems reliability engineer, security
reviewer, and quantitative-research platform reviewer.

## Scored sections

1. **Problem and evidence — 10 points; minimum 8**
   Actor, costly failure, causal mechanism, baseline, falsification, primary
   research, uncertainty, alternatives, and decision traceability.
2. **Graph architecture and maximum-results policy — 18; minimum 17**
   Typed DAG, dependency/write-set concurrency, adaptive compute, pivot/stagnation,
   domain templates, and no token-consumption proxy objective.
3. **Durability and recovery — 12; minimum 11**
   Transactional checkpoints, leases, idempotency, restart/orphan recovery, replay,
   cancellation, and terminal-state integrity.
4. **Verification, evaluation, and cumulative integration — 18; minimum 17**
   Deterministic gates, independent evaluator, immutable evidence, atomic promotion,
   binding update, rollback, next-node visibility, and false-result reconciliation.
5. **Finance and consequential-action safety — 15; minimum 15**
   Point-in-time/leakage/overfit/cost/stress/paper stages; secret separation; live
   trade and risk-change human gates; proven denial paths.
6. **Buzz, identity, and security boundaries — 12; minimum 11**
   Native gateway, route/identity mapping, mention/access control, untrusted input,
   secret redaction, least privilege, channel commands, and approval provenance.
7. **Operator UX and observability — 8; minimum 7**
   Accurate portfolio status, blockers, evidence, score, next step, alerting,
   cancellation, audit search, and concise scheduled reports.
8. **Tests and representative evidence — 7; minimum 7**
   Deterministic suites, four-route safe E2E, adverse tests, restart test, finance
   denial test, actual deployed SHA/config/service evidence, and final-user test.

## Hard gates

- **HG1:** No live trade, payment, publication, release, protected merge, external
  message, credential grant, or production deployment occurs in automated tests.
- **HG2:** Broker/platform/channel secrets never enter prompts, Git, logs, evidence,
  or builder/evaluator-readable storage; machine redaction tests pass.
- **HG3:** Builder, evaluator, and integrator are technically separate; no builder
  can self-score or self-promote.
- **HG4:** Kill/restart recovery resumes without duplicate integration or lost
  accepted state.
- **HG5:** `router_rc=0` reconciliation is proven; unknown controller state does not
  become a repeated false failure.
- **HG6:** A passed artifact is atomically promoted and visible to the next node;
  failed artifacts never alter the accepted baseline; rollback is proven.
- **HG7:** Cross-project identity, path, repository, and state isolation passes.
- **HG8:** Finance workflow proves denial of live execution without a distinct,
  human-signed, expiring capability; backtest and paper evidence remain separate.
- **HG9:** Evidence, evaluator result, integration commit, and deployed service are
  bound by hashes/SHA and their audit chains verify.
- **HG10:** Buzz-native or faithful staging E2E proves goal, status, approval,
  cancellation, thread/route mapping, and scheduled report behavior. If real Buzz
  credentials are unavailable, this gate is `UNPROVEN`, not assumed.
- **HG11:** A blind final-user simulation succeeds using only normal entry points and
  repository artifacts, without evaluator hints.

## Evidence rules

- Design prose cannot prove implementation.
- Builder claims are unproven without machine output.
- Live inspection must record timestamp, deployed Git SHA, service/config hashes,
  and sanitized outputs.
- Any missing, stale, mutable, or inaccessible evidence is `UNPROVEN`.
- Evaluation defects do not justify relaxing a gate; correct the task/rubric only
  through a new explicitly versioned cycle before implementation, never mid-score.

## Verdict and disagreement

Pass requires score >=95, every section minimum, and every hard gate `PASS`.
Evaluator disagreement is resolved by reproducing evidence; material unresolved
disagreement yields `HUMAN_JUDGMENT`. A claimed 100 requires complete evidence.
