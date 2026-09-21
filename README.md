# Codex Grapher

A Python control plane for turning worker changes into verified, recoverable Git
state. Grapher stores task graphs in SQLite, produces immutable test artifacts,
checks independent evaluator signatures, and promotes accepted commits through a
recoverable journal.

The developer workflow runs locally without a model account, hosted service or
API key. Use it to inspect the protocol, run a complete example, and build a
trusted local worker integration. **Experimental: the broader Hermes/Buzz
operational release remains `NOT_PASS`.** Local task acceptance does not certify
production isolation or deployed operation.

## Install

Supported target: Linux with `/proc` and pidfd support, Python 3.12+, Git, Bash,
and OpenSSL with Ed25519 support. Ubuntu 24.04 / Python 3.12 is the CI target.
macOS and Windows are not validated. Python runtime dependencies are stdlib only;
installation needs pip and a build backend. Source/dependency downloads need a
network connection; the commands below execute locally after installation.

```bash
git clone https://github.com/thinker0v0/codex-grapher.git
cd codex-grapher
python3.12 -m venv .venv
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
