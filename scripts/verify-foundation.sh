#!/usr/bin/env bash
set -euo pipefail

required_files=(
  AGENTS.md
  README.md
  docs/architecture.md
  docs/hermes-operations.md
  docs/model-benchmark.md
  docs/credential-setup.md
  governance/evaluation-rubric.md
  governance/hermes-evaluation-rubric.md
  config/projects.example.yaml
  config/policy.example.yaml
  config/hermes-profiles.example.yaml
  config/model-routing.example.yaml
  config/slack-rbac.example.yaml
  config/slack-app-manifest.example.yaml
  config/task-state.example.yaml
  schemas/evaluation-contract.schema.json
  schemas/evidence-envelope.schema.json
  schemas/authorization-envelope.schema.json
  schemas/task-contract.schema.json
  schemas/evaluation-result.schema.json
  schemas/artifact-manifest.schema.json
  schemas/project-runtime.schema.json
  prompts/hermes/common.md
  prompts/hermes/fin-global.md
  prompts/hermes/fin-korea.md
  prompts/hermes/business.md
  prompts/hermes/oss.md
  prompts/hermes/evaluator.md
  scripts/collect-vps-discovery.sh
  scripts/run-hermes-profile.sh
  scripts/configure-hermes-credentials.sh
  scripts/install-hermes-foundation.sh
  scripts/audit-hermes-foundation.sh
  scripts/verify-vps-hermes-codex-e2e.sh
  deploy/systemd/hermes-profile@.service
  deploy/systemd/hermes-evaluator.service
  deploy/systemd/ai-ops-project-graph.service
  scripts/install-project-graph.sh
  scripts/verify-project-graph-bootstrap.sh
  control_plane/graph_state.py
  control_plane/graph_schema.py
  control_plane/graph_bootstrap.py
  control_plane/graph_service.py
  control_plane/publication_store.py
  control_plane/project_integrator.py
  control_plane/artifact_builder.py
  control_plane/evidence_ingress.py
  control_plane/evidence_store.py
  control_plane/runtime_config.py
  config/project-graphs.json
  config/project-runtime.example.json
  deploy/systemd/ai-ops-controller@.service
  tests/test_foundation.py
)

for required_file in "${required_files[@]}"; do
  test -s "$required_file"
done

python3 -m unittest discover -s tests -v
bash -n scripts/configure-hermes-profiles.sh
bash -n scripts/configure-codex-workers.sh
bash -n scripts/run-codex-worker.sh
bash -n scripts/deploy-project-bindings.sh
bash -n scripts/sync-projects-vps.sh
bash -n scripts/test-project-isolation.sh
bash -n scripts/verify-vps-authorization-boundary.sh
bash -n scripts/verify-vps-controller-isolation.sh
bash -n scripts/backup-hermes-config.sh
bash -n scripts/restore-hermes-config-drill.sh
bash -n scripts/audit-lightweight-laptop.sh
bash -n scripts/configure-hermes-credentials.sh
bash -n scripts/verify-vps-hermes-codex-e2e.sh
bash -n scripts/verify-project-graph-bootstrap.sh
python3 control_plane/runtime_config.py config/project-runtime.example.json >/dev/null
bash scripts/install-project-graph.sh --dry-run --runtime config/project-runtime.example.json >/dev/null

for schema_file in schemas/*.schema.json; do
  python3 -m json.tool "$schema_file" >/dev/null
  python3 -c 'import json, jsonschema, sys; jsonschema.Draft202012Validator.check_schema(json.load(open(sys.argv[1])))' "$schema_file"
done

for evidence_file in evidence/vps/*.json; do
  python3 -m json.tool "$evidence_file" >/dev/null
done

for yaml_file in config/*.yaml; do
  python3 -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$yaml_file"
done

if rg -n --hidden --glob '!scripts/verify-foundation.sh' --glob '!.git/**' \
  '(xox[baprs]-[A-Za-z0-9-]+|sk-[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' .; then
  echo "Potential secret detected" >&2
  exit 1
fi

echo "foundation verification passed"
