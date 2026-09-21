# Portable Codex cycle evaluation contract v1

Status: candidate for independent design review; acceptance contract frozen at
commit before implementation. Owner: independent evaluator after freeze;
builders cannot edit to pass.
Date: 2026-09-21 UTC. Lens: skeptical installed-package developer, security
reviewer and reliability engineer. This supplements, never replaces or weakens,
the root operational rubric and the previous reliability cycle rubric.

## Design gate

Only design readiness is scored before implementation: falsifiable observed
problem/baseline 20; primary evidence/provenance/alternatives 20; concrete
mechanism/interfaces/security/recovery 30; ownership/handoff/commands 20;
authorization/phase ordering/claim scope 10. Threshold 95, each minimum maximum
minus one. Hard requirements: no unresolved critical interface or runtime
decision, three pinned representative tasks, machine guest feasibility prerequisite,
unchanged legacy authority/rubrics, independent evaluator and fresh-user plan.
Implementation outcomes remain UNPROVEN and are not prerequisites for design
approval. Only a separate independent-ai-judge evaluator may issue DESIGN_READY.

## Phase 1 implementation score

Pass requires at least 95/100, every section minimum, and every hard gate PASS.
Numeric totals cannot compensate for a failed or unproven gate.

| Section | Maximum | Minimum | Evidence necessary for credit |
| --- | ---: | ---: | --- |
| C1 Problem/research | 10 | 9 | Observed developer gap; falsifiable outcome; primary source/license/provenance and alternatives; representative seed claim boundary |
| C2 Generic repository workflow | 25 | 24 | Strict frozen task/check/profile; three pinned OSS snapshots; original-source preservation; independent tests/signing; accepted consumer; rejection/replay/rollback; installed usable CLI |
| C3 Actual provider | 15 | 14 | Actual bounded Codex subscription invocation with observed terminal protocol/provider/version/model/usage and full task/hash binding; negative protocol and budget/timeout/output/cleanup cases |
| C4 OS role isolation | 20 | 19 | Four actual trust domains, read-only trusted code, key/policy/DB/accepted/cross-project/socket denials; candidate tests cannot sign; legitimate flow succeeds |
| C5 Guest recovery and backup | 15 | 14 | Real disposable service restart and guest reset at all five boundaries; no duplicate launch/integration/lost accepted state; complete quiescent backup and fresh same-root restore, rollback and corruption denial |
| C6 SQLite support | 10 | 9 | Actual patch provenance; DELETE/EXTRA readback/single owner safe default; separate patch/support verdicts; verified fixed WAL/FULL positive; unsafe/unknown WAL and silent migration denied |
| C7 Exact-SHA and independent user | 5 | 5 | Clean candidate, full foundation, sealed command/artifact/environment packet, independent adversarial review and fresh installed-user simulation |

## Mandatory hard gates

- **HG01 Scope and sequencing:** No live trade, payment, purchase, production
  deployment/restart, host package/account/service mutation, protected merge or
  external message in automated tests. Publication is a separate authorized
  delivery action. No Phase 2 implementation before independent Phase 1 PASS.
- **HG02 Secret handling:** No credentials, private signing keys, provider login
  stores or unrelated private content in Git/prompts/logs/evidence/distributions/
  backups/guest images. Auth is read only by its intended vendor identity;
  parent API/environment secrets are not inherited.
- **HG03 Preserve authority:** Four routes, strict legacy v3/task v4 distinction,
  immutable IDs/claims/outcomes, task-policy hashes, required-test integrity,
  signed evaluation and deterministic CAS integration remain intact. Original
  rubrics are unchanged; runtime never implicitly creates/migrates graph schema.
- **HG04 Own repository:** Installed normal entry points complete all three
  pinned full-tree OSS snapshots with disclosed seeded regressions and intended
  failing prechecks. Source worktree/index/refs/config/remotes/hooks/untracked
  state remains unchanged. New seeded base commit differs from upstream pin;
  no upstream history/seed answer leaks into the worker fixture.
- **HG05 Strict task and acceptance:** Duplicate/unknown JSON fields, bool bounds,
  invalid paths/base, mutable checks/profile/policy, unsafe authority selection,
  missing tests and unsupported budgets reject before effects. Every declared
  check and required test must pass; rc=0 alone never proves acceptance.
- **HG06 Actual Codex:** At least one actual Codex worker completes through
  ingress, independent acceptance and promotion under the explicit approved
  provider profile. Mocks/help/login status are insufficient. Receipt binds
  terminal result, version/model, task/prompt/profile hash, observed usage or
  explicit telemetry absence, launch count, bounded output/time and cleanup.
- **HG07 Enforced OS separation:** Actual worker and candidate-test identities
  cannot read signer key, alter trusted code/policy/checks/graph/accepted state,
  access another project, forge evaluator receipts or invoke unauthorized signer/
  integration/rollback socket actions. Positive scoped worker requests succeed.
  Signer executes only trusted fixed read-only code and never candidate code.
  Required tests in artifact production also use the isolated test role;
  isolating independent checks alone cannot pass.
- **HG08 Bounds and denied failures:** Durable invocation count defaults 1,
  maximum explicit 3; limits cannot reset on reopen/retry. Missing/duplicate/
  malformed provider completion, timeout, overflow, surviving descendants,
  changed HEAD/no-op, failed tests/evaluation, scope escape and stale base preserve
  accepted state. Hard unsupported USD/token ceilings reject truthfully.
- **HG09 Promotion and rollback:** Exact accepted candidate is visible to a
  separately executed consumer; failed/rejected candidates do not advance binding.
  Replay adds no provider launch or publication operation. Authorized predecessor
  rollback is proven and cannot cross a later head's attempt.
- **HG10 Five recovery boundaries:** Disposable service restart AND actual guest
  reset cover B1 reservation/unsealed, B2 graph-admitted artifact, B3 committed
  signed outcome, B4 promotion binding window, B5 pending rollback. Record guest
  boot IDs, service identity, exact source/config/runtime and durable closure.
  Orderly reboot and abrupt VM loss are both observed. Unsealed recovery pauses
  honestly; no blind rerun/expired lease revival. Process exit alone is insufficient.
- **HG11 Complete backup/restore:** Offline exclusive quiescence excludes active
  leases/claims/operations; inventory covers all admitted artifacts and retained
  generations, graph/Git/custom refs/binding/frozen inputs/public key/receipts.
  Same original root/tools restored on fresh guest with original inaccessible;
  status, idempotent recovery, accepted consumer and rollback verify. Traversal,
  links/special entries, duplicates/extras, corruption/missing bytes, relocation,
  mismatched key/profile and incomplete closure reject. Keys/auth/sockets excluded;
  absent signer remains verify-only until separately provisioned matching key.
- **HG12 SQLite truth and preservation:** Default new writable connections use
  verified DELETE/EXTRA and one OS owner; second owner denied. Patch status stays
  `UNPATCHED` for proven binary and `UNPROVEN` for unknown backports. Avoidance may
  be supported without claiming patched. WAL/FULL requires verified fixed loaded
  runtime/attestation; mismatch/unknown/unpatched WAL denied before effects.
  Existing WAL requires explicit backed-up fixed-runtime maintenance; no silent
  switch/schema migration/install, sidecar deletion or host package change.
- **HG13 Regression/distribution:** Complete foundation passes at clean evaluated
  SHA, including prior 378-test behavior and meaningful new adverse cases.
  Source archive/wheel contains required schemas/docs/scripts/public resources,
  excludes private/runtime material, and works outside the checkout without
  private enclosing-project paths or test-helper imports.
- **HG14 Independent completion:** Independent-ai-judge adversarial assessment
  and a separate fresh developer simulation pass using frozen criteria and
  exact machine evidence. No builder selfscore; evaluator edits no judged artifact.
  All remaining original operational rubric FAIL/UNPROVEN gates are listed.

## Machine evidence and verdict

Each assertion cites exact command/argv/cwd, exit/signal/duration, full output
hash/length, source/freeze/rubric/data/task/check/profile/dependency/runtime hashes,
relevant immutable IDs and evaluator identity. Guest evidence also binds image,
kernel, boot/service identity and before/after journal closure. Evidence must be
sanitized, accessible, immutable and tied to the evaluated SHA. Earlier evidence
may be reused only with explicit unchanged-byte/path justification reviewed by
the evaluator. Missing, stale, indirect or inaccessible evidence is UNPROVEN.

Verdicts: `DESIGN_READY` for design only; `PORTABLE_CODEX_PASS` or `NOT_PASS` for
Phase 1. Never label this a legacy operational PASS or a Claude pass. A passing
report enumerates limitations, including physical power-loss scope and any
provider-auth-store boundary not proven by role isolation.

Maximum three consecutive unchanged failed approaches per defect. Record changed
inputs/approach before another attempt. Preserve explicit launch/spend/time caps,
use one guest and one heavy test at a time, commands at most 900 seconds and guest
scenarios at most 600 seconds. Do not repeat successful unchanged evidence runs.
Fix earliest invalid artifact, then focused tests, then independent reevaluation.
Material evidence disagreement yields HUMAN_JUDGMENT; never change this frozen
rubric merely to pass. Phase 2 gets a separately frozen contract with dedicated
repository/package/CLI/CI/docs/provenance, honest offline acceptance and publication
proof. The user's later-auth clarification explicitly labels real Claude
verification `DEFERRED_USER_AUTH`; provide its bounded live command, do not infer
live success, and do not make that deferred criterion block the authorized build
and publication. This exception does not relax actual Codex HG06.
