# Codex Grapher

A Python control plane for turning worker changes into verified, recoverable Git
state. Grapher stores task graphs in SQLite, produces immutable test artifacts,
checks independent evaluator signatures, and promotes accepted commits through a
recoverable journal.

Run tasks against your own clean Git repository through the Codex CLI, inspect
the resulting evidence, recover interrupted integration, and roll back an
accepted change. Each task freezes its allowed paths, required tests, independent
checks, evaluation policy and execution profile before a worker starts.

The deterministic demonstration needs no model account. Real repository tasks
require an existing Codex CLI login and an explicit provider profile.
**Experimental: the broader Hermes/Buzz operational release remains `NOT_PASS`.**
Task acceptance and the separately evaluated portable-worker cycle do not
certify that broader deployment.

## Install

Supported target: Linux with `/proc` and pidfd support, Python 3.12+, Git, Bash,
and OpenSSL with Ed25519 support. Ubuntu 24.04 / Python 3.12 is the CI target.
macOS and Windows are not validated. Python runtime dependencies are stdlib only;
installation needs pip and a build backend. Source/dependency downloads need a
network connection; the commands below execute locally after installation.

```bash
git clone https://github.com/thinker0v0/codex-grapher.git
cd codex-grapher
python3.12 -m venv --copies .venv
source .venv/bin/activate
python -m pip install .
codex-grapher doctor --json
codex-grapher demo --json
```

The full example creates actual local Git changes, runs required tests, ingests
immutable evidence, obtains a signed task result from a separate deterministic
sample evaluator, and promotes the accepted commit. Its successor reads the
accepted generation. The default temporary workspace is removed afterwards.
The sample evaluator checks this example's task assertions; it is not a general
code reviewer. Local roles share a user account and are for trusted development.

## Run your own repository task

Follow the [repository workflow guide](docs/REPOSITORY_WORKFLOW.md) to provision
an evaluation key, create a pinned execution profile with `profile create`, and
write a task using the [example](examples/repository-workflow/README.md).
The lifecycle commands are:

```bash
codex-grapher init --repo /absolute/source --task /absolute/task.json \
  --profile /absolute/profile.json --workspace /absolute/new-workspace --json
codex-grapher run --workspace /absolute/new-workspace --json
codex-grapher status --workspace /absolute/new-workspace --json
codex-grapher recover --workspace /absolute/new-workspace --json
codex-grapher backup --workspace /absolute/new-workspace --output /absolute/backup.tar --json
codex-grapher rollback --workspace /absolute/new-workspace --json
```

Source admission requires a clean, self-contained repository at the declared
commit. Work happens in a separate checkout; promotion updates the workspace's
accepted generation. Required tests and independent checks must both pass before
the signer approves integration. Recovery reuses sealed evidence; an interrupted
unsealed worker reservation pauses for operator attention.

`trusted-local` runs trusted development roles under one non-root user.
`isolated-linux` requires x86-64 Linux, an explicit root bootstrap in the initial
kernel UID domain, four distinct non-root role identities and Linux namespaces.
Candidate tests run without the signer's
private key or network access. Root remains trusted; this is not isolation from
the host administrator. In this mode Codex delegates sandbox enforcement to the
outer runner; its inner CLI setting is explicitly `danger-full-access`, admitted
only after the runner's boundary checks. Trusted local execution keeps Codex's
`workspace-write` setting. Neither mode runs the actual provider as root.

Backups include graph state, Git objects and custom refs, frozen inputs, all
retained evidence and publication generations. Restore requires the original
absolute workspace/tool paths and matching profile. Private keys and provider
login data are excluded; a restore without the matching private signing key
supports verification until the operator provisions it separately.

## Pause and recover a task

Choose a new workspace outside this checkout so generated keys and state remain
outside the source tree:

```bash
codex-grapher demo --workspace /tmp/grapher-example --stop-after built --json
codex-grapher recover --workspace /tmp/grapher-example --json
codex-grapher demo --workspace /tmp/grapher-example --operation status --json
codex-grapher rollback --workspace /tmp/grapher-example --json
```

Recovery reuses the durable artifact and journal instead of treating a second
invocation as a new accepted change. Rollback restores the recorded predecessor;
it does not delete the prior evidence or immutable generation.

For interruption, failure, database inspection, task-policy configuration, and
adapting the producer to your own work, see the [developer workflow](docs/DEVELOPER_WORKFLOW.md).

## What is enforced

- Exact live worker leases and route-scoped heartbeat renewal.
- Classified, persisted retry delays and finite attempt/stagnation limits;
  permanent/safety failures do not retry automatically.
- Human-gated tasks cannot execute without a separate approval mechanism; this
  developer cycle does not implement consequential approval capabilities.
- Immutable artifact/claim/outcome identities, clean-SHA test evidence, signature
  verification, allowed-path checks, compare-and-swap promotion and rollback.
- Explicit task-evaluation policies for local work. Legacy release evaluation
  retains its original sections and hard gates.
- Bounded socket framing, admission and network waits; offline read-only state
  and event inspection with clear limits on what has been verified.
- Durable worker invocation reservations, bounded execution time and combined
  output, and process cleanup before candidate handoff.
- SQLite DELETE/EXTRA with one OS writer owner by default. Optional WAL/FULL
  requires a verified fixed library actually loaded by the process. Patch status
  and supported operating mode are reported separately by `doctor`.

The database remains schema v5; runtime constructors never create or migrate it
implicitly. The inherited route set is `nomad`, `opensource`, `business`, and
`hynix`; use `opensource` for development tasks. Hermes native Buzz remains the
intended remote operator interface. Slack and `fin-global` are legacy artifacts.

## Development checks

```bash
python -m pip install -r requirements-dev.txt
PYTHONDONTWRITEBYTECODE=1 bash scripts/verify-foundation.sh
python examples/verified_lifecycle.py
```

Foundation checks require ripgrep (`rg`), run the unit suite, validate schemas and
configuration, check shell syntax, and inspect installer dry runs. They do not
install services. The original `python examples/offline_demo.py` remains a small
scheduling-only example that stops at `RUNNING/BLOCKED`.

## Evidence and limits

The [portable-worker contract](docs/cycles/20260921-portable-workers/RUBRIC.md)
requires installed-package tasks, actual Codex execution, observed role denials,
guest restart/reset recovery and a fresh backup restore. Unit tests alone do not
prove these gates. The [guest harness](examples/guest-recovery/README.md) runs in
a disposable VM; it does not reboot or provision the host.

The [reliability cycle](docs/cycles/20260921-reliability/HANDOFF.md) records the
problem, frozen contract and [upstream research](docs/UPSTREAM.md). Improvements
adapt mechanisms from LangGraph, DBOS, Temporal, OpenHands and mini-SWE-agent
without adding those frameworks as dependencies.

The broader [operational rubric](RUBRIC.md) still requires deployed service and
identity evidence, native Buzz, real project workers and host recovery. A local
sample or unit test cannot prove those. Deployment scripts are separate operator
facilities and are not part of installation or the quickstart. Neither commands
nor documentation grant permission to deploy, publish, send messages or trade.

Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[publication provenance](docs/PUBLICATION.md). Licensed under [MIT](LICENSE).
