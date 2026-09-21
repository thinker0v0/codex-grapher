# Portable repository workers cycle

Status: candidate for independent design review; acceptance contract frozen at commit.
Implementation remains gated on independent DESIGN_READY.
Record: `opensource.portable-workers.project.v1`; owner: cycle integrator.
Source/effective/retrieval date: 2026-09-21 UTC; review at freeze or scope change.
Classification: public; authority: user scope, otherwise proposed design.
Content identity: the freeze commit and evidence manifest will supply file hashes.

## Objective and sequence

Complete all four developer follow-ups in `codex-grapher`: an own-repository CLI
with an actual Codex worker; OS-enforced worker/test/signer/graph separation;
disposable guest service and host-restart recovery with coherent backup/restore;
and a safe SQLite support profile with traceable patch provenance. Then start
the dedicated `claude-grapher` repository, complete its independent verification,
and publish the authorized open-source deliverables.

Phase 1 must pass this cycle's frozen independent gate before any Phase 2
implementation. Provider-neutral interfaces can be designed during Phase 1.
Phase 2 must freeze its own fresh acceptance contract before implementation;
Phase 1 scores do not certify Claude behavior or its publication readiness.
The user subsequently deferred live Claude verification until their later
subscription/authentication. Phase 2 must finish and publish with honest offline
evidence and `DEFERRED_USER_AUTH`, plus a ready bounded live-verification command.
Missing Claude authentication is not a Phase 2 delivery blocker.

The actor is a developer installing the public package and giving it a bounded
task against their own Git repository. Completion means usable accepted code,
verifiable evidence, truthful failure status, and recoverable owned state.

## Baseline and earliest unpassed stage

Source baseline: `df9e0c31ffdb7e045a268b6b03b16ce33b623a49` on the new
`feat/portable-workers-20260921` branch. A clean source tree was observed before
drafting. The prior independent review reports 378 passing tests and
`LOCAL_IMPROVEMENT_PASS` 98/100 for its narrower developer cycle; the original
operational rubric remains `NOT_PASS`. Those are historical, SHA-specific
observations, not a pass for this cycle.

The earliest unpassed stage is independent problem/research/solution/scaffold
approval. These documents confer no implementation or release verdict.
The old root rubric and previous cycle rubric remain unchanged.

## Authorized envelope

- Local implementation, public-source research, isolated staging and ephemeral
  guest validation, and an actual model smoke using existing subscription
  authentication are authorized. Final open-source publication is authorized
  as a separate delivery action after evidence review, never as a test.
- Use task-local tooling and at most one heavy guest: 1 vCPU and 1 GiB. Check
  actual memory/disk capacity before boot. No host package, account, service,
  or restart changes are validation targets.
- Existing secrets remain outside repositories, prompts, evidence, backups and
  guests. New paid API use, purchases, protected-branch merge, production
  deployment and unrelated external messages are not authorized by this cycle.
- Preserve source repositories and unrelated user changes. All accepted changes
  live in initialized, owned workspace copies until a separate user action.
- Finance, Buzz/native portfolio deployment, private production operation and
  live trading are excluded. Exactly four internal graph routes remain; a user
  repository identity is metadata, not an additional route.

## Completion claims

Only an independent evaluator may issue `PORTABLE_CODEX_PASS`, after the
threshold, section minima, every hard gate, exact-SHA evidence and a fresh
developer simulation pass. Otherwise use `NOT_PASS` and list `FAIL`/`UNPROVEN`.
This label proves the frozen public developer scope, not the legacy operational
release. Guest reset evidence is not physical-storage power-loss certification.

The final deliverable includes installed package/docs/CI, bounded reproducible
evidence, known limitations and provenance. Publication success requires an
actual remote receipt or inspected remote commit; a prepared archive is not
publication. The complete user goal remains unfinished until the separately
verified `claude-grapher` phase and authorized publication are handled.

## Freeze prerequisites

Root resolved the interface and source-packet decisions in [DECISIONS.md](DECISIONS.md).
The committed contract and pinned public task packet are ready for independent
design assessment. Record guest feasibility and independent `DESIGN_READY` with
the freeze commit/hash before builders start.
