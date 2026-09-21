#!/usr/bin/env bash
set -euo pipefail

mode="--dry-run"
runtime_source=""
activate=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --dry-run|--apply)
      mode="$1"
      shift
      ;;
    --runtime)
      [[ "$#" -ge 2 ]] || { echo "--runtime requires a path" >&2; exit 64; }
      runtime_source="$2"
      shift 2
      ;;
    --activate)
      activate=true
      shift
      ;;
    *)
      echo "Usage: $0 [--dry-run|--apply] [--activate] --runtime /absolute/path/project-runtime.json" >&2
      exit 64
      ;;
  esac
done
[[ -n "$runtime_source" ]] || { echo "An explicit --runtime file is required" >&2; exit 64; }
[[ "$mode" != "--apply" || "$EUID" -eq 0 ]] || { echo "--apply requires root" >&2; exit 77; }
[[ "$activate" != true || "$mode" == "--apply" ]] || {
  echo "--activate requires --apply" >&2
  exit 64
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
installed_library=/usr/local/lib/ai-ops
installed_bootstrap="$installed_library/control_plane/graph_bootstrap.py"
graph_state_directory=/var/lib/ai-ops-graph
graph_database="$graph_state_directory/graphs.sqlite"
modules=(__init__.py artifact_builder.py graph_state.py graph_schema.py graph_bootstrap.py publication_store.py evidence_ingress.py evidence_store.py evaluation_policy.py retry_policy.py project_graph.py project_integrator.py project_coordinator.py graph_planner.py graph_transport.py graph_service.py graph_client.py runtime_config.py buzz_router.py buzz_native_adapter.py)
required_sources=(
  "$repo_root/config/project-graphs.json"
  "$repo_root/RUBRIC.md"
  "$repo_root/deploy/systemd/ai-ops-project-graph.service"
)
for module in "${modules[@]}"; do
  required_sources+=("$repo_root/control_plane/$module")
done
for source in "${required_sources[@]}"; do
  [[ -f "$source" ]] || { echo "missing install source: $source" >&2; exit 66; }
done
if [[ "$mode" == "--apply" ]]; then
  prerequisites=(python3 realpath install env getent groupadd usermod openssl chown chmod systemctl)
  if [[ "$activate" == true ]]; then
    prerequisites+=(sleep)
  fi
  for command_name in "${prerequisites[@]}"; do
    command -v "$command_name" >/dev/null || {
      echo "missing prerequisite: $command_name" >&2
      exit 69
    }
  done
  for account in hermes-oss hermes-fin-korea hermes-business hermes-hynix hermes-evaluator; do
    getent passwd "$account" >/dev/null || {
      echo "missing service account: $account" >&2
      exit 69
    }
  done
fi
runtime_validation=(python3 "$repo_root/control_plane/runtime_config.py" "$runtime_source")
if [[ "$mode" == "--apply" ]]; then
  runtime_validation+=(--require-root-owner)
fi
"${runtime_validation[@]}" >/dev/null
runtime_source="$(realpath -e -- "$runtime_source")"

# Schema bootstrap is deliberately offline. Refuse an active upgrade before
# the first install write unless this invocation also owns stop/restart.
if [[ "$mode" == "--apply" ]]; then
  if systemctl is-active --quiet ai-ops-project-graph.service; then
    [[ "$activate" == true ]] || {
      echo "active project graph requires --activate for an offline upgrade" >&2
      exit 75
    }
    systemctl stop ai-ops-project-graph.service
    if systemctl is-active --quiet ai-ops-project-graph.service; then
      echo "project graph service did not stop for offline schema bootstrap" >&2
      exit 75
    fi
  fi
else
  echo "DRY-RUN: preflight active ai-ops-project-graph.service before install writes"
  if [[ "$activate" == true ]]; then
    echo "DRY-RUN: systemctl stop ai-ops-project-graph.service if active"
  fi
fi

run() {
  if [[ "$mode" == "--dry-run" ]]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

run install -d -o root -g root -m 0755 /usr/local/lib/ai-ops/control_plane /usr/local/libexec/ai-ops /etc/ai-ops
for module in "${modules[@]}"; do
  run install -o root -g root -m 0644 "$repo_root/control_plane/$module" "/usr/local/lib/ai-ops/control_plane/$module"
done
run install -o root -g root -m 0755 "$repo_root/control_plane/graph_service.py" /usr/local/libexec/ai-ops/project-graph-service
run install -o root -g root -m 0755 "$repo_root/control_plane/graph_client.py" /usr/local/libexec/ai-ops/project-graph-client
run install -o root -g root -m 0644 "$repo_root/control_plane/graph_transport.py" /usr/local/libexec/ai-ops/graph_transport.py
run install -o root -g root -m 0644 "$repo_root/config/project-graphs.json" /etc/ai-ops/project-graphs.json
run install -o root -g root -m 0600 "$runtime_source" /etc/ai-ops/project-runtime.json
run install -o root -g root -m 0444 "$repo_root/RUBRIC.md" /etc/ai-ops/RUBRIC.md
run install -o root -g root -m 0644 "$repo_root/deploy/systemd/ai-ops-project-graph.service" /etc/systemd/system/ai-ops-project-graph.service

if [[ "$mode" == "--apply" ]]; then
  getent group ai-ops-graph >/dev/null || groupadd --system ai-ops-graph
  for account in hermes-oss hermes-fin-korea hermes-business hermes-hynix hermes-evaluator; do
    usermod -a -G ai-ops-graph "$account"
  done
fi

run install -d -o root -g ai-ops-graph -m 0700 "$graph_state_directory"
run env "PYTHONPATH=$installed_library" python3 "$installed_bootstrap" \
  database --apply --database "$graph_database"

if [[ "$mode" == "--apply" ]]; then
  if [[ ! -s /etc/ai-ops/evaluator-private.pem ]]; then
    openssl genpkey -algorithm ED25519 -out /etc/ai-ops/evaluator-private.pem
  fi
  chown hermes-evaluator:hermes-evaluator /etc/ai-ops/evaluator-private.pem
  chmod 0400 /etc/ai-ops/evaluator-private.pem
  openssl pkey -in /etc/ai-ops/evaluator-private.pem -pubout -out /etc/ai-ops/evaluator-public.pem
  chown root:root /etc/ai-ops/evaluator-public.pem
  chmod 0444 /etc/ai-ops/evaluator-public.pem
  if [[ "$activate" == true ]]; then
    systemctl daemon-reload
    systemctl enable ai-ops-project-graph.service
    systemctl restart ai-ops-project-graph.service
    for ((attempt=0; attempt<30; attempt++)); do
      [[ -S /run/ai-ops-graph/control.sock ]] && break
      sleep 0.1
    done
    [[ -S /run/ai-ops-graph/control.sock ]]
    systemctl is-active --quiet ai-ops-project-graph.service
    echo "Project graph service installed and active."
  else
    echo "Project graph files installed. Service activation was not requested."
  fi
else
  echo "Dry run complete. No system changes were made."
fi
