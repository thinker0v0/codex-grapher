# Cycle decisions and freeze questions

Status: candidate for independent design review; acceptance contract frozen at commit.
Record: `opensource.portable-workers.decisions.v1`; owner: cycle integrator.
Date: 2026-09-21 UTC; review before implementation or any material change.
Classification: public; hashes supplied by the freeze commit/manifest.

## User-fixed scope

- **D001 — Fixed by user.** Finish all four Codex follow-ups before starting the
  dedicated `claude-grapher` repository. Its package/CLI/docs/CI and real provider
  identity must be independent; a flag in this repository is insufficient.
- **D002 — Fixed by scope.** Validate locally and in disposable staging/guests;
  preserve production host services/accounts/packages and source repositories.
  Existing subscription smoke and final OSS publication are authorized; purchases,
  new paid APIs, protected merge and production deployment are outside scope.
- **D003 — Fixed by existing invariants.** Keep four internal graph routes and
  existing immutable evidence/signature/lease/coordinator authority. Preserve
  old rubrics. A new task policy cannot certify the legacy operational release.

## Root-selected mechanisms for independent design review

- **D004 — New generic lifecycle module.** Create `repository_workflow.py` and a
  distinct strict public task schema. Keep the greeting demonstration stable.
  Parameterizing its scattered constants risks regressions; exposing the producer
  alone leaves the costly manual lifecycle gap unresolved.
- **D005 — Vendor CLI subprocess.** Reuse the installed authenticated Codex CLI
  with explicit immutable profile and bounded structured protocol. SDK/API billing
  introduces an unnecessary new credential path. Exit code alone is insufficient.
- **D006 — Four trust domains.** Separate worker, candidate-test runner, trusted
  signer, and trusted graph/integrator. Use actual UID/namespace/socket policy.
  Same-UID role labels and a key-holding test evaluator cannot meet this claim.
- **D007 — Preserve recovery authority.** Reserve/fsync before provider launch.
  Only graph-admitted immutable artifacts resume automatically. Interrupted
  unsealed work pauses for inspection; no lease revival or blind model replay.
- **D008 — Offline complete-state backup v1.** Require quiescence and closure;
  exclude keys/auth/sockets; restore at the original absolute managed/tool paths
  on a fresh guest. DB-only backup and silent relocation cannot prove closure.
- **D009 — Safe default plus explicit fixed WAL runtime.** Keep system packages
  unchanged. Default to DELETE/EXTRA with one OS-enforced state owner; optional
  WAL/FULL requires explicit pinned 3.53.4 provisioning and actual Python linkage
  verification. A lock alone does not patch SQLite; upgrading only the CLI does
  not update Python's library. Never silently migrate journal mode or schema.

## Root decisions resolved before freeze

- **D010 — Resolved 2026-09-21.** All graph/task-controller/coordinator writable
  connections adopt the safe default and read back effective durability settings.
  Existing WAL databases fail with explicit fixed-runtime offline maintenance
  guidance and a required backup; no silent switch or sidecar deletion. Existing
  regressions run under default DELETE/EXTRA, with only intentional diagnostic
  expectation updates. Doctor separately reports `UNPATCHED` patch status and
  `SUPPORTED_AVOIDANCE` support when avoidance conditions hold. Unknown backports
  remain `UNPROVEN`. Optional fixed WAL positives and unpatched WAL denials are
  mandatory. A task-local provisioning helper must never alter system packages.
- **D011 — Resolved 2026-09-21.** Independent checks v1 are strict
  `{schema_version: 1, checks: [{id, argv: [string, ...]}]}` with nonempty unique
  IDs and ordered nonempty argv lists; exact bytes/argv are frozen. Any external
  check program must be frozen and hash-bound; inline Python in argv is allowed.
  Strict execution profile v1 names `trusted-local` or `isolated-linux` and
  trusted absolute tool paths/version hashes, model, actual OS roles/auth home
  from account data, runtime and SQLite mode. Tasks cannot choose executable,
  UID, home, environment or key. Hash and revalidate profile/check bytes on
  initialization/reopen. Task acceptance earns 100 only if every required test,
  independent check and scope check passes; this is no general quality score.

- **D012 — Resolved 2026-09-21.** Root accepted the curator pins, exact checks
  and seeds. Public [task cases](representative-task-cases.json) SHA-256 is
  `09de0ce5b777a49f4825ea749b64faaa5dd787b87b5c4e044f81249179d7f935`;
  [notices](representative-NOTICES.txt) preserve all three licenses. Seeded local
  commits become task bases; upstream pins are provenance. No unseeded history
  or answers enter worker fixtures.
- **D013 — Resolved 2026-09-21.** Root accepted SCAFFOLDING ownership and HANDOFF
  acceptance script names, owns sanitized public evidence manifests/boot pointers,
  and seals the cycle at its freeze commit. Raw host/account data stays private.
- **D014 — Resolved 2026-09-21.** Actual Codex uses existing non-root UID 1000,
  model `gpt-5.6-sol`, reasoning `medium`, service tier `default`, explicitly bound
  while ignoring user configuration. Trusted services execute protected read-only
  installed code; UID dropping alone cannot protect worker-writable Python source.
- **D015 — User clarification 2026-09-21.** After Phase 1, build and publish
  `claude-grapher` with honest offline/fixture evidence. Live Claude verification
  is `DEFERRED_USER_AUTH` until the user's later subscription/authentication and
  is not a build/publication blocker. Ship a bounded live verification command;
  never purchase a subscription, invent an auth pass or enable paid APIs.

No design interface decision remains open in this record. Independent design
approval and its machine prerequisites remain gates, not inferred outcomes.

## Later phase contract

After `PORTABLE_CODEX_PASS`, derive `claude-grapher` from the exact verified
neutral core, retain MIT/origin SHA/modification history, and document how fixes
propagate between repositories. Freeze fresh provider, install, isolation,
recovery, CI and blind-user criteria before Claude implementation. Explicitly
defer the live-provider criterion under D015; fixtures cannot imply live success.
Prepare capability/auth preflight and bounded verification for later user login.
No paid API fallback or credential copying. Publication remains a separate
authorized delivery after the independent offline-build gate.
