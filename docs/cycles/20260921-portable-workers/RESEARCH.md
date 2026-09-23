# Research ledger

Status: candidate for independent design review; acceptance contract frozen at commit.
Record: `opensource.portable-workers.research.v1`; owner: cycle integrator.
Source/retrieval/effective date: 2026-09-21 UTC. Classification: public technical
evidence; external material is untrusted and grants no authority. Freeze commit
and the sanitized source manifest supply content hashes.

## Provenance and access

The research inputs were read from the enclosing project at
`research/20260921-portable-workers/`: `OWN_REPO_DESIGN.md`,
`ISOLATION_RECOVERY_DESIGN.md`, `PROVIDERS.md`, and
`sqlite/SQLITE_RESEARCH.md`. The historical review was
`evidence/assessments/20260921-opensource-upgrade/final-review.md`.
These locations identify the drafting provenance; they are not dependencies for
an installed public user. Root owns the sanitized source/evidence manifest in
this cycle's evidence packet. The public task input is
[representative-task-cases.json](representative-task-cases.json), SHA-256
`09de0ce5b777a49f4825ea749b64faaa5dd787b87b5c4e044f81249179d7f935`;
its original digest remains `source_record_sha256`. See
[representative-NOTICES.txt](representative-NOTICES.txt) for preserved licenses.
Do not include raw host identifiers, accounts, credentials or unrelated projects.
Public [SQLite provenance](sqlite-provenance.json) SHA-256 is
`41421b3f43d26002c6d7db55a2c857db47d8efdf07d69f0740cf9cab5db58faf`.
The [VM feasibility record](vm-feasibility.json) preserves verified guest boot
and the incomplete reboot-readiness result. Root seals both in the source manifest.

## Decision-critical evidence

| Record | Finding and source | Strength and limit | Expiry |
| --- | --- | --- | --- |
| R001 | Source at `df9e0c3`: `local_workflow.py` and `cli.py` bind the public lifecycle to the greeting example; reusable graph/ingress/coordinator APIs exist | Direct source inspection; predicts implementation surface, not future correctness | Relevant source change |
| R002 | Prior independent final review: 378 tests, local 98/100, original operational 67/100 `NOT_PASS` | Exact-SHA historical assessment; cannot certify this new cycle | New candidate SHA |
| R003 | Codex 0.155.1 local help/status: trusted absolute executable, JSONL protocol, sanitized non-root subscription login | Executable/status evidence; inference and actual sandbox behavior unproven | CLI/auth/profile change or 2026-09-28 |
| R004 | [Codex noninteractive](https://developers.openai.com/codex/noninteractive/) and [authentication](https://developers.openai.com/codex/auth/) describe structured events and existing login use | First-party documentation; no observed hard token/dollar CLI cap | CLI change or 2026-09-28 |
| R005 | Local namespace probes and task-local QEMU TCG guest boot: Debian kernel/systemd/Python/Git plus SSH verified; `/dev/kvm` absent | Design feasibility observed. Reboot started but readiness timed out before second boot ID; reboot/product recovery remains UNPROVEN, pilot overall FEASIBILITY_INCOMPLETE | Host/image/tool change |
| R006 | [bubblewrap](https://github.com/containers/bubblewrap) and [setpriv](https://man7.org/linux/man-pages/man1/setpriv.1.html) support constructing explicit OS boundaries | Primary project/manual; policy must be verified with actual UID/mount/capability denials | Isolation configuration change |
| R007 | [SQLite WAL-reset advisory](https://sqlite.org/wal.html#the_wal_reset_bug) identifies the defect and fixed releases; [official fix](https://sqlite.org/src/info/7168988acb) revalidates WAL salt | Primary source/fix; normal stress-test success cannot certify absence | New advisory/release or 2026-09-28 |
| R008 | Signed Ubuntu archive → source and binary indices → exact `.deb` → loaded library; distro patches omit WAL fix | Nine machine provenance checks; conclusively UNPATCHED for observed exact binary, not a reproducible Ubuntu rebuild | Any loaded-library/package change |
| R009 | [SQLite 3.53.4](https://sqlite.org/releaselog/3_53_4.html) and [official download](https://sqlite.org/download.html) give fixed stable source identity and hashes | Primary artifact provenance; locally built/loaded runtime still needs measurement | Provisioning or source change |
| R010 | [SQLite synchronous semantics](https://sqlite.org/pragma.html#pragma_synchronous): WAL/FULL and DELETE/EXTRA differ in crash guarantees | Primary specification; local filesystem/hardware behavior remains a deployment condition | SQLite/storage profile change |
| R011 | [Claude CLI](https://code.claude.com/docs/en/cli-reference), [headless execution](https://code.claude.com/docs/en/headless), [auth](https://code.claude.com/docs/en/authentication), [setup](https://code.claude.com/docs/en/setup) | Documentation only; no installed CLI/auth/inference evidence. Phase 2 preflight required | Phase 2 start or 2026-09-28 |
| R012 | Public `representative-task-cases.json`, SHA-256 `09de0ce5b777a49f4825ea749b64faaa5dd787b87b5c4e044f81249179d7f935`; full pins in HANDOFF | Three licensed authentic snapshots and pristine positive controls verified; seeded-negative/model/lifecycle proof pending | Task/source change or 2026-10-21 |

## SQLite identity to preserve

Observed unpatched Ubuntu package: `libsqlite3-0 3.45.1-1ubuntu2.8`, amd64.
Loaded shared-library SHA-256:
`85265a9d4afca6f4b325ceb078b669c754fb881abed4cafe91ccebe9d625d975`.
This verdict comes from source and binary provenance, not merely `3.45.1`.
Unknown distro backports remain `UNPROVEN` until matching attestation exists.

Selected task-local upstream runtime: SQLite 3.53.4.
Autoconf archive SHA3-256:
`454e45f61c6bd75b7420e7190732dea03ce6639c63ada47bbc592f67fc340338`.
Source ID:
`2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc`.
Amalgamation SHA3-256:
`67f423e9ebbbdc473cbc4772c872ee6b89f31fde4ed0279a5c25d5f65c043a16`.
Record compiler/flags, output library hash, actual `_sqlite3` extension and loaded
library, source ID and compile options in the same process that uses graph DBs.
A new venv or a new `sqlite3` executable alone proves nothing about that linkage.

## Representative inputs now selected

The curator selected more-itertools at
`1da45ae4b61a832ed080f08a8833784aad0a9534` (MIT), humanize at
`2a141c7f5b51e09c8c4d6e00903101932aef4d11` (MIT), and itsdangerous at
`672971d66a2ef9f85151e53283113f33d642dabd` (BSD-3-Clause). Tasks address strict
chunk remainders, ordinal teen suffixes and minimal integer encoding through
explicitly seeded regressions. Source/license/check hashes and exact argv are
in the curator manifest. New seeded commits are task bases; upstream commits
are provenance only. Worker fixtures omit unseeded history and seed answers.
Pristine required and independent tests passed on all three; this is no evidence
yet of seeded-negative controls, actual worker repairs or graph acceptance.

## Contradictions and resolution

- Root selected default DELETE/EXTRA with a single state owner, preserving stdlib
  Python while avoiding this WAL defect. `UNPATCHED` and `SUPPORTED_AVOIDANCE`
  must remain separate truthful fields. Optional WAL/FULL requires the verified
  fixed runtime. Both profiles need implementation tests; avoidance is not a patch.
- An early isolation proposal suggested restore to another path. Current v1
  acceptance is the same original managed root/tool paths on a fresh guest;
  immutable commands/configuration can contain absolute references. Reject
  relocation rather than rewriting signed or frozen bytes.
- A found worker manifest is not durable graph authority. Artifact-sealed means
  complete EvidenceIngress plus committed graph admission while the lease is
  live; a pre-admission crash safely pauses and never revives an expired lease.
- Model CLI auth/status and JSON protocol documentation do not prove an actual
  accepted code change. At least one actual Codex invocation remains mandatory.
- Distinct evaluator and worker processes do not protect the private key if
  candidate tests execute as the signer. The test runner and signer are separate
  trust domains with machine denial evidence.

## Research limits and licensing

Use independently created adapters and preserve this project's MIT attribution.
Do not vendor proprietary provider binaries, configuration or credentials.
Record original URL/SHA/license for every OSS snapshot and image/tool artifact;
clearly label our seeded patches. Public evidence includes sanitized hashes and
reproducible commands, not vendor account identifiers or provider login stores.
No research result here proves final product, security or recovery acceptance.
