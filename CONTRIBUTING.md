# Contributing

Codex Grapher is an experimental local control-plane snapshot. Start with the
[README](README.md), then read `AGENTS.md` and its document boot sequence before
changing controller behavior. Open an issue describing the observable problem,
expected behavior, and a small reproduction before proposing a major redesign.

Use Python 3.12 and install the package and `requirements-dev.txt` in a virtual
environment. Run:

```bash
PYTHONDONTWRITEBYTECODE=1 bash scripts/verify-foundation.sh
PYTHONDONTWRITEBYTECODE=1 python3 examples/offline_demo.py
PYTHONDONTWRITEBYTECODE=1 python3 examples/verified_lifecycle.py
codex-grapher doctor --json
```

Keep changes bounded and include a regression when changing a safety or state
boundary. Test with temporary repositories, databases, and fixture identities.
Never test by sending external messages, installing services, publishing,
trading, or using real credentials. Keep generated runtime state out of Git.

Pull requests should describe the problem, changed behavior, commands run, and
remaining limitations. Preserve the MIT license and provenance of copied code.
Builder and evaluator roles remain separate. Do not weaken `RUBRIC.md` or label
local test results as an operational release pass. Independent review is required
for stage and release evaluations.

The [developer reliability cycle](docs/cycles/20260921-reliability/HANDOFF.md)
adds installed local workflows and explicit task evaluation while preserving the
legacy operational release rubric. Consult [upstream provenance](docs/UPSTREAM.md)
before reusing external implementations; no upstream runtime is required.
