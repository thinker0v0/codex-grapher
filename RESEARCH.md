# Research Ledger

> Current cycle: [2026-09-21 public developer reliability](docs/cycles/20260921-reliability/HANDOFF.md).
> The user authorized research and local implementation, and selected developer
> installation/execution/verification/recovery as the target. This supersedes the
> historical NQ stop for this work. Legacy release gates remain unchanged; no
> production deployment, external messages or publication are automated tests.


Status: decision-critical evidence collected; final local and release evidence unproven
Access date for web sources: 2026-08-28.

## R001 — Long-running work requires incremental state handoff

- Source: Anthropic, “Effective harnesses for long-running agents,” 2025-11-26.
  https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents
- Evidence: compaction alone was insufficient; initializer state, one-feature
  increments, progress files, and Git history enabled continuation.
- Strength: strong first-party engineering evidence; model/harness-specific.
- Decision: fresh bounded tasks must use durable graph/Git state, not chat memory.
- Expiry: revisit on major Codex/Hermes context-management changes.

## R002 — Planner/generator/evaluator loops improve long application work

- Source: Anthropic, “Harness design for long-running application development,”
  2026-03-24. https://www.anthropic.com/engineering/harness-design-long-running-apps
- Evidence: tractable sprint decomposition, structured handoff, independent QA,
  and multiple generator/QA rounds caught functional gaps.
- Strength: strong case study, not a universal controlled comparison.
- Decision: separate planner, builder, evaluator, and deterministic integrator.

## R003 — More test-time compute helps, but adaptive allocation is stronger

- Source: Snell et al., “Scaling LLM Test-Time Compute Optimally,” 2024-08-06.
  https://arxiv.org/abs/2408.03314
- Evidence: prompt-difficulty-aware allocation outperformed simple best-of-N with
  approximately 2–4x less compute in studied settings.
- Strength: peer-reviewed-style primary research; not directly a coding harness.
- Decision: retain high ceilings while routing extra attempts to uncertain,
  high-value, verifier-improving nodes.

## R004 — Durable graphs require checkpoints and idempotent side effects

- Source: LangGraph official persistence and interrupt documentation, accessed
  2026-08-28. https://docs.langchain.com/oss/python/langgraph/persistence and
  https://docs.langchain.com/oss/python/langgraph/interrupts
- Evidence: step checkpoints support recovery, human interrupts, replay, and
  pending writes; side effects before interrupts must be idempotent.
- Strength: authoritative framework documentation; architectural principles do
  not require adopting the dependency.
- Decision: implement explicit node checkpoints, immutable attempt records,
  idempotency keys, and resumable human gates in the existing stdlib control plane.

## R005 — Buzz native gateway retains full Hermes behavior

- Source: Hermes Agent official Buzz integration docs, accessed 2026-08-28.
  https://hermes-agent.nousresearch.com/docs/integrations/buzz
- Evidence: native gateway supports channels, DMs, mention gating, threads,
  reactions, images, cron delivery, approvals, memory, and sessions; it uses a
  dedicated Nostr keypair and a scoped relay+pubkey lock.
- Strength: authoritative current product documentation.
- Decision: use native gateway, not Buzz Desktop auto-approval or relay-owned ACP,
  for the VPS supervisor.
- Freshness: verify against installed Hermes version immediately before deploy.

## R006 — Agent evaluations need multiple evidence types

- Source: Anthropic, “Demystifying evals for AI agents,” 2026-01-09.
  https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
- Evidence: multi-turn agents require evaluation of trajectories, environment
  state, outcomes, and failure modes rather than final text alone.
- Strength: first-party engineering guidance.
- Decision: combine deterministic tests, state transitions, trajectory evidence,
  security/adverse cases, and independent judgment.

## R007 — Coding test contracts themselves can be defective

- Source: OpenAI, “Separating signal from noise in coding evaluations,” 2026-07-08.
  https://openai.com/index/separating-signal-from-noise-coding-evaluations/
- Evidence: audits found underspecification, overly strict tests, low coverage,
  and misleading prompts in a substantial benchmark fraction.
- Strength: authoritative audit with human review.
- Decision: freeze rubrics but meta-evaluate task clarity, coverage, and false
  pass/fail risk before spending large compute.

## R008 — Finance validation must account for backtest overfitting

- Source: Bailey et al., “The Probability of Backtest Overfitting,” Journal of
  Computational Finance, 2016. SSRN 2326253.
  https://papers.ssrn.com/sol3/papers.cfm?abstract_id=2326253
- Evidence: repeated strategy selection on the same history raises the probability
  that the selected backtest is an overfit false discovery.
- Strength: established quantitative-finance research.
- Decision: require point-in-time data, leakage checks, walk-forward/holdout,
  realistic costs, multiple-testing records, stress tests, and paper evidence.

## R009 — Historical local/VPS evidence

- Source: live read-only inspection, 2026-08-27/28; repository commit `6a40935`.
- Evidence: active services and timer; three routes stopped with `router_rc_0` and
  `UNKNOWN`; OpenSource results remain `EVIDENCE_PENDING`; no Buzz configuration
  found; `run-codex-worker.sh` ends successful builds at `EVIDENCE_PENDING`.
- Strength: direct machine evidence, point-in-time.
- Decision: fix result semantics and implement evaluation/promotion before adding
  more autonomous workload.
- Freshness: historical baseline only. It does not describe service state after
  2026-08-28, and the active NQ cycle does not authorize refreshing live evidence.

## R010 — Final local implementation evidence is not yet available

- Source: the final integrated candidate's machine evidence packet, to be produced
  only after all local code is combined and the candidate worktree is clean.
- Required provenance: the packet records the exact candidate Git SHA; VAPG schema
  v5, artifact-manifest v4, and evaluation-result v3 hashes; exact validation
  commands, exits, and complete output hashes; immutable attempt/artifact/outcome
  identifiers; fixture configuration hashes; and the resulting Git status.
- Required coverage: explicit offline-only bootstrap/migration, including exact
  clean v0-v4 predecessor handling and semantic event continuity, with no runtime
  creation;
  `<task>/attempt-<n>` immutable artifacts; content-addressed ingress;
  expiring/heartbeat claims; artifact-and-claim-bound signed outcomes; ID-only
  integration; exact required-test bindings with clean-check, 8 MiB aggregate
  output, suite-timeout, and pidfd/subreaper descendant-quiescence controls; SHA
  publication generations;
  graph-bound promotion/rollback with a global journal tail, project heads, and
  completed attempt/artifact/outcome/durable-manifest closure; and
  the fixture-key native-like Buzz adapter over exactly four routes.
- Current strength: `UNPROVEN`. No SHA or hash is recorded here because no final
  evidence packet has been supplied. Evidence from a component branch or earlier
  candidate cannot be attributed to the final integrated candidate.
- Decision effect: a conforming packet may support `LOCAL_FIXTURE_PASS` only. It
  cannot support release `PASS`, native Buzz HG10, or deployed/real-worker claims.

## R011 — Known release evidence gap

- Source: repository artifact audit and the active-cycle authorization boundary,
  2026-08-30.
- Evidence: active manifest-v4 producer wiring, installed configuration/service
  hashes, deployed SHA, real-worker traces, native Buzz credentials/relay E2E,
  restart/host recovery, representative four-route operation, and blind final-user
  evidence are absent from the repository evidence set.
- Strength: direct absence finding for this repository snapshot; it does not claim
  that an uninspected external environment lacks these artifacts.
- Decision: release verdict is `NOT_PASS`; do not infer missing evidence from local
  fixture behavior.

## Contradictions and uncertainty

- Multi-agent breadth is strong for independent research, but coding has shared
  state and merge conflicts; concurrency must follow the dependency graph.
- Long continuous contexts can work on stronger models, while explicit resets and
  handoffs help weaker/older ones; the runtime should decide from observed context
  quality rather than force either globally.
- No public study proves one orchestration policy is globally optimal for these
  four projects. The deployed system therefore requires local matched-task evals.
- Native-like fixture behavior is useful for deterministic controller validation
  but is not evidence about real Buzz relay, keys, account authorization, delivery,
  or installed Hermes behavior.
