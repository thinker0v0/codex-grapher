# Codex Grapher

An experimental Python control plane for durable task graphs, isolated Codex
work, independent evaluation, and verified Git integration. The local core uses
SQLite for task state and Git for accepted source state. It is intended to sit
between a Hermes planner and separate builder, evaluator, and integrator roles.

**Status: experimental local snapshot; operational release `NOT_PASS`.** The
quickstart runs entirely offline after dependencies are installed. It needs no
model account, credentials, service, or external API.

## Quickstart

Requirements: Linux with `/proc` and pidfd support, Python 3.12 with `venv` and
pip, Git, Bash, OpenSSL with Ed25519 support, and ripgrep (`rg`). Ubuntu 24.04 is
the CI target. The local test runner relies on Linux process containment, so
macOS and Windows are not validated targets. Tests use temporary fixture keys;
do not supply personal keys.

```bash
git clone https://github.com/thinker0v0/codex-grapher.git
cd codex-grapher
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
export PYTHONDONTWRITEBYTECODE=1
python examples/offline_demo.py
bash scripts/verify-foundation.sh
```

Cloning and installing development dependencies require network access. The demo
and foundation checks run locally with no model calls or services. Foundation
checks run the unit suite, validate schemas/configuration, check shell syntax,
and inspect installer dry-run output; they do not apply an installation.

The demo explicitly bootstraps a temporary database, creates `build → review`,
and shows `build` move through `READY → LEASED → RUNNING`. `review` remains
`BLOCKED`: its prerequisite must be independently evaluated and integrated first.
The output reports `NOT_PASS`; the demo does not run a worker or create evaluation
evidence. Temporary database files are removed on exit.

To run just the tests:

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
```

## How it fits together

```text
Hermes planner / native Buzz interface (intended integration)
  → durable SQLite project graph
  → isolated Codex attempt
  → immutable artifact ingress
  → independent evaluator and signed outcome
  → deterministic Git integration and accepted baseline
  → human approval for consequential actions
```

- `control_plane/project_graph.py` handles task states, leases, dependencies,
  and event-chain integrity. Runtime opens an explicitly bootstrapped schema;
  it never silently creates or migrates a database.
- Artifact and evidence modules bind immutable attempt contents, evaluator
  claims, signed outcomes, and exact test outputs to durable identifiers.
- Integration and publication modules check evidence and write scope before
  updating accepted Git state, with a durable promotion/rollback journal.
- `tests/` exercises local fixtures and denial paths. `schemas/`, `config/`, and
  the design documents preserve the contracts those fixtures implement.

The inherited active route set is exactly `nomad`, `opensource`, `business`, and
`hynix`. Hermes native Buzz is the intended operator surface; its current adapter
is a local fixture. Slack and `fin-global` remain frozen compatibility artifacts.

## Limits and next work

This is a local core for inspection and development. Active worker producer
wiring, native Buzz transport, deployed service/configuration evidence, real
worker operation, host restart recovery, representative four-route operation,
and final-user validation remain unproven. Deployment scripts describe future
operation and are not part of this quickstart. Legacy deployment/sync helpers
require explicit `HERMES_PROJECTS_ROOT` configuration; remote sync also requires
`HERMES_VPS_HOST` and `HERMES_VPS_SSH_KEY`. They are separate opt-in operations.

The next development stages are to connect the artifact producer and accepted
baseline consumer, validate independent identities in an authorized sandbox,
exercise native Buzz and restart recovery, and collect representative evidence
for an independent review against the frozen [rubric](RUBRIC.md). Adaptive retry
and stagnation policies also remain release targets. These are development
goals, not promised capabilities or dates.

`LOCAL_FIXTURE_PASS` requires independent review of exact-SHA machine evidence.
It never implies an operational `PASS`. The operational release verdict stays
`NOT_PASS` until every frozen hard gate passes; publication does not waive them.

Read [publication provenance](docs/PUBLICATION.md) for source history and evidence
limits, [CONTRIBUTING.md](CONTRIBUTING.md) before making changes, and
[SECURITY.md](SECURITY.md) for private vulnerability reporting guidance. The code
is licensed under [MIT](LICENSE).
