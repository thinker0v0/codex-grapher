# Clean builder handoff

Read repository AGENTS.md and root boot documents, then this directory's PROBLEM,
RESEARCH, SOLUTION, SCAFFOLDING and RUBRIC. This new user-authorized cycle replaces
the historical NQ stopping instruction for research and local implementation.
It does not grant publication, credentials or production deployment authority.

Build the assigned work unit only after the independent design gate. Preserve
SQLite schema v5, active routes, evidence formats, signed evaluator checks, exact
integration closure, immutable manifests and all existing denial tests. The user
asked for working open-source improvements, not a changed definition of PASS.

Each unit reports changed files, exact focused commands/exits, remaining limitations
and compatibility effects. Use new regression tests for real failure modes.
Do not run the full suite concurrently; the integrating owner schedules it once
after integration. Do not commit other agents' work. No external side effects.

Final commands from repository root:

```bash
PYTHONDONTWRITEBYTECODE=1 bash scripts/verify-foundation.sh
python3 examples/offline_demo.py
python3 examples/verified_lifecycle.py
python3 -m control_plane doctor --json
python3 -m control_plane --help
```

Release readiness is still evaluated using the unchanged root RUBRIC.md, including
every native/deployed/identity/real-worker hard gate. A local feature pass cannot
substitute for operational release. Document missing evidence honestly.

The exact task-policy, retry defaults/classification and human-gate deny behavior
are frozen in SOLUTION.md. Read its final three sections before coding. Do not
infer new approval capability semantics or task-vs-legacy fallback. Preserve
recognized legacy migration fixtures when adding genesis/spec integrity checks.
