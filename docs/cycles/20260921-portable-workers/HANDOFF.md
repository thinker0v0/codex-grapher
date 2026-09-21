# Clean implementation handoff

Status: candidate for independent design review; acceptance contract frozen at commit.
Record: `opensource.portable-workers.handoff.v1`; owner: root integrator.
Date: 2026-09-21 UTC; public; review before any fresh builder starts.
Baseline: `df9e0c31ffdb7e045a268b6b03b16ce33b623a49`.

This handoff records user-fixed scope and root-set decisions. SOLUTION/SCAFFOLDING
become implementation instructions after independent design review and the root
freeze commit. This status is not DESIGN_READY or an implementation/release pass.
Read [Design amendment v2](DESIGN_AMENDMENT_V2.md) with SOLUTION before building.
It repairs the independent review's launcher and sealed-signing gaps, retains
the rubric unchanged and requires independent design reevaluation.
Read [Design amendment v3](DESIGN_AMENDMENT_V3.md) for observed Codex 0.155.1
nested-sandbox incompatibility. P/I may implement its isolated-only fixed strategy
only after root commits it and independent design review approves; trusted-local
retains workspace-write, with no fallback or outer-permission relaxation.

## Approved scope and decisions

Finish the four Codex follow-ups, then begin the separately named
`claude-grapher` repository, independently verify it, and publish the authorized
OSS deliverables. Phase 2 implementation is blocked until Phase 1 passes.
No protected merge, host package/account/service changes, production restart,
new paid API use, purchase, credential copying or unrelated external message.
Use local staging/ephemeral guests and existing authenticated subscription for
actual model proof. Prior NQ constraints do not revoke this newer authorization.
User clarification: Phase 2 live Claude proof is `DEFERRED_USER_AUTH` until later
subscription/authentication. Complete and publish the dedicated repository with
honest offline verification and a prepared bounded live-verification command;
the auth deferral does not block that delivery or affect actual Codex requirements.

Default SQLite: DELETE/EXTRA with readback, one OS-locked owner and truthful
`UNPATCHED` versus `SUPPORTED_AVOIDANCE` fields. Optional WAL/FULL requires
verified patched runtime, supported pinned SQLite 3.53.4 task-local provisioning.
Existing WAL fails pending explicit offline fixed-runtime maintenance and backup;
never silently switch mode/migrate schema/delete sidecars.

Checks v1: strict `{schema_version: 1, checks: [{id, argv: [string, ...]}]}`;
nonempty unique IDs/argv and exact frozen bytes. Trusted profile v1 selects
`trusted-local` or `isolated-linux`, executable/version/hash/model/OS roles/auth
home/runtime. Tasks cannot select privilege, executable, environment or key.
All candidate execution belongs to the test sandbox, never the signing UID.
This includes required tests inside `artifact_builder.build`, before independent
evaluation. G owns the narrow injected runner hook; I owns execution/receipt
sealing. Generic isolated mode must refuse a missing runner, never fall back to
the graph/controller identity.
Isolated mode starts through an explicit root CLI bootstrap using only root-owned
read-only installed code/config. It launches four distinct dropped role UIDs;
graph connects after dropping UID to the narrow authenticated launcher. There is
no implicit host account/service installation or trusted-local fallback. I owns
the helper/root-sealed receipt store and exact amendment-v2 wire/signing schemas.
Private signer key is operator-provisioned outside workspace; graph never reads it.

Actual Codex smoke uses existing non-root UID 1000 with explicit model
`gpt-5.6-sol`, reasoning `medium`, service tier `default`, and
`--ignore-user-config`; leave user configuration unchanged. Authentication is
read by the vendor CLI under its actual account, never copied. Prove authority
denials under that worker UID before inference. Trusted signer/graph Python must
come from immutable/read-only installed code, not the worker-writable checkout.

## Start after freeze

1. Read cycle PROJECT, PROBLEM, RESEARCH, DECISIONS, SOLUTION, SCAFFOLDING and
   RUBRIC, then applicable repository AGENTS/OPERATIONS. Inspect Git status and
   freeze evidence; preserve unrelated changes. Never infer readiness from chat.
2. Take one bounded work unit from SCAFFOLDING with an explicit path owner and
   task/idempotency IDs, timeout and evidence output. Keep implementation and
   evaluator identities separate; request shared-file edits through root.
3. Build the new generic workflow rather than replacing demo behavior. Preserve
   four internal routes, exact immutable artifact/claim/outcome/coordinator
   semantics, source repository isolation and no runtime schema creation.
4. Coordinate typed provider, profile/broker, backup and SQLite interfaces before
   connecting the CLI. Keep records durable before effects. No automatic replay
   before graph-admitted artifact sealing, no expired lease revival.
5. Run focused meaningful changed tests and record output/hash/exit/limits. Root
   integrates once and produces a clean exact-SHA full candidate packet.
6. Independent adversarial reviewer and a fresh installed developer evaluate the
   frozen contract. Only their complete passing evidence can unlock Phase 2.

## Representative task contract

The public [task-curation manifest](representative-task-cases.json), SHA-256
`09de0ce5b777a49f4825ea749b64faaa5dd787b87b5c4e044f81249179d7f935`,
is the frozen builder input. [Notices](representative-NOTICES.txt) retain the
three exact verified licenses. The original research digest is preserved in the
manifest's `source_record_sha256`; sanitized metadata omits temporary paths and
raw host output. Do not depend on ephemeral research clones or copy seed answers
into worker-visible fixtures.

| Repository | Exact upstream commit | Task / permitted source path |
| --- | --- | --- |
| more-itertools/more-itertools, MIT | `1da45ae4b61a832ed080f08a8833784aad0a9534` | strict chunk remainder; `more_itertools/more.py` |
| python-humanize/humanize, MIT | `2a141c7f5b51e09c8c4d6e00903101932aef4d11` | ordinal teen suffixes; `src/humanize/number.py` |
| pallets/itsdangerous, BSD-3-Clause | `672971d66a2ef9f85151e53283113f33d642dabd` | minimal integer encoding; `src/itsdangerous/encoding.py` |

Trusted preparation verifies original source/license/test hashes, applies each
single seed to a full-tree disposable snapshot, and creates a NEW seeded base
commit. Public task `base_sha` is that seeded commit, never the upstream SHA.
Do not expose unseeded upstream history, reverse patches or answers to the worker.
Keep upstream license notices and operator provenance. Both required and
independent checks must fail for the intended assertion before a worker runs;
an import/setup failure does not count. Then freeze dependency/tool/check hashes.
Pristine positive controls already passed; seeded negatives and worker success
remain unproven. Task-specific limits: one launch, 300 seconds worker, 60 seconds
required tests, 60 seconds evaluator, 262,144 combined output bytes. At least one
actual Codex invocation is mandatory; report actual-provider versus deterministic
adapter fixture coverage separately for all three tasks.

## Frozen target acceptance commands

Root accepted these target commands and owners. They must exist with bounded
help/usage and machine JSON before acceptance; they are not already implemented.
Run from the public
repository, use absolute task-local Python where required, and capture stdout,
stderr, exit, monotonic duration, exact argv/cwd/environment descriptor and hashes.

```sh
timeout 900s bash scripts/verify-foundation.sh
timeout 900s python3 -m unittest discover -s tests -p 'test_repository_workflow.py' -v
timeout 900s python3 -m unittest discover -s tests -p 'test_worker_provider.py' -v
timeout 900s python3 -m unittest discover -s tests -p 'test_execution_profile.py' -v
timeout 900s python3 -m unittest discover -s tests -p 'test_workspace_backup.py' -v
timeout 900s python3 -m unittest discover -s tests -p 'test_sqlite_runtime.py' -v
timeout 900s python3 scripts/verify-role-isolation.py --profile PROFILE.json --output ROLE_EVIDENCE.json
timeout 900s python3 scripts/verify-guest-recovery.py --scenario SCENARIO --output GUEST_EVIDENCE.json
timeout 900s python3 scripts/verify-workspace-backup.py --profile PROFILE.json --output BACKUP_EVIDENCE.json
```

Focused commands precede integration; the foundation is run once on the final
candidate and includes the old baseline plus new tests. The literal placeholders
are bound to frozen profile and scenario records before execution. Guest scenarios
are B1–B5 service restart and actual guest reset, orderly reboot, abrupt loss and
fresh same-root restore; each is at most 600 seconds with at most one guest.
Archive/install/fresh-user and actual-provider commands are exact recorded public
CLI invocations, using SOLUTION's command sequence and frozen task files.

Default SQLite tests use DELETE/EXTRA. Provision 3.53.4 explicitly in an ignored
task-local prefix before optional WAL-positive validation; record actual loaded
library/source identity in the Python process executing those cases. Do not
rerun successful unchanged suites merely to create more evidence.

## Required packet and independent gate

The packet binds candidate/freeze SHA, all tracked source and rubric hashes,
task/source/seed/dependency/profile/check/policy hashes, OS/guest/runtime/image
identities, command results/output lengths+hashes, actual provider metadata and
observed usage, signature/artifact/outcome/journal closure, source-preservation
inventories, installed distribution hashes and independent evaluator identity.
No raw credential/account data. All five boundary results must distinguish safe
unsealed pause from resumed admitted evidence and prove no duplicate invocation.

Root approved exact interfaces/ownership/acceptance scripts and sealed the public
task packet. Record the disposable guest feasibility pilot and freeze commit/
hashes, then obtain independent DESIGN_READY before a fresh builder starts.
Root owns public boot pointers and evidence manifests. No implementation or
release score is awarded by this handoff author.
