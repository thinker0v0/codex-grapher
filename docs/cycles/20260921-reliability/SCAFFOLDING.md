# Work units

Project ID: opensource. Cycle/task prefix: reliability-20260921.
Idempotency: cycle ID + work unit + immutable input SHA. Audit: Git diffs/commits,
focused command logs, final exact-SHA evidence and independent reviews.

Builders start fresh from HANDOFF.md. File ownership:

- retry: control_plane/retry_policy.py, control_plane/project_graph.py,
  tests/test_retry_policy.py and necessary graph test compatibility edits; also
  human gate enforcement and status version projection. Evaluation-policy builder
  supplies a separate patch for its narrow project_graph.py hook changes.
- transport: control_plane/graph_service.py, control_plane/graph_client.py,
  tests/test_graph_transport.py and tests/test_graph_service.py.
- lifecycle: control_plane/local_workflow.py, examples/verified_lifecycle.py,
  tests/test_verified_lifecycle.py. No imports from tests in examples.
- CLI/package: control_plane/__main__.py, control_plane/cli.py, tests/test_cli.py,
  pyproject.toml and package installation smoke.
- task-policy: control_plane/evaluation_policy.py, control_plane/project_integrator.py,
  control_plane/project_coordinator.py, schemas/task-evaluation-result.schema.json,
  tests/test_evaluation_policy.py; narrow graph constructor/verify hooks coordinated
  with retry owner, never overwrite concurrent work.
- integrating owner: docs, README, installer module list, CI and evidence only;
  coordinate any shared-file change before editing.
- evaluator: read-only product/rubric; write review artifacts separately.

No builder edits another unit's files or awards a pass. Up to five code builders;
tests sequential where needed, no heavy parallel suites on the shared VPS.
Each unit budget: at most three unchanged failed approaches, focused commands
timeout 300s, full foundation 900s, no paid API calls. Useful progress can continue
in bounded follow-ups. Do not install services, use secrets or alter production.

Rollback is a dedicated local commit reverting this cycle's files; preserve all
unrelated user changes. Do not push a protected branch or publish as validation.
Evidence lives outside the source snapshot until the candidate SHA is committed.
Final acceptance: foundation, original offline demo, new lifecycle, CLI doctor,
focused timeout/retry/recovery adversarial tests, blind user simulation and an
independent evaluation against both this cycle's contract and root RUBRIC.md.
