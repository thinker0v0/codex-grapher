#!/usr/bin/env bash
set -euo pipefail

legacy_compatibility=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --legacy-compatibility)
      legacy_compatibility=true
      ;;
    *)
      echo "Usage: $0 [--legacy-compatibility]" >&2
      exit 64
      ;;
  esac
  shift
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 77
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profiles=(fin-korea hynix business oss evaluator)
controller_profiles=(fin-korea hynix business oss)
if [[ "$legacy_compatibility" == true ]]; then
  profiles=(fin-global "${profiles[@]}")
  controller_profiles=(fin-global "${controller_profiles[@]}")
fi

command -v codex >/dev/null
command -v openssl >/dev/null
command -v bwrap >/dev/null || {
  echo "bubblewrap is required for Codex workspace-write sandboxing" >&2
  exit 69
}

# Ubuntu 24.04 restricts capabilities inside unprivileged user namespaces.
# Load Ubuntu's packaged, narrowly scoped bwrap profile instead of disabling
# the host-wide user-namespace protection.
if [[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" == "1" ]]; then
  apparmor_profile_source="/usr/share/apparmor/extra-profiles/bwrap-userns-restrict"
  command -v apparmor_parser >/dev/null || {
    echo "apparmor_parser is required while unprivileged user namespaces are restricted" >&2
    exit 69
  }
  [[ -s "$apparmor_profile_source" ]] || {
    echo "Install the Ubuntu apparmor-profiles package before configuring Codex workers" >&2
    exit 69
  }
  install -o root -g root -m 0644 "$apparmor_profile_source" /etc/apparmor.d/bwrap-userns-restrict
  apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
fi

install -d -o root -g root -m 0755 /etc/ai-ops
getent group ai-ops-controller >/dev/null || groupadd --system ai-ops-controller
getent group ai-ops-clients >/dev/null || groupadd --system ai-ops-clients
if [[ ! -s /etc/ai-ops/authorization-private.pem ]]; then
  openssl genpkey -algorithm ED25519 -out /etc/ai-ops/authorization-private.pem
fi
chmod 0600 /etc/ai-ops/authorization-private.pem
openssl pkey -in /etc/ai-ops/authorization-private.pem -pubout -out /etc/ai-ops/authorization-public.pem
chmod 0444 /etc/ai-ops/authorization-public.pem
install -m 0755 "$repo_root/scripts/run-codex-worker.sh" /usr/local/libexec/ai-ops/run-codex-worker
install -m 0755 "$repo_root/scripts/report-hermes-project-status.sh" /usr/local/libexec/ai-ops/report-hermes-project-status
install -o root -g ai-ops-controller -m 0750 "$repo_root/control_plane/task_controller.py" /usr/local/libexec/ai-ops/task-controller
install -m 0644 "$repo_root/control_plane/task_controller.py" /usr/local/libexec/ai-ops/task_controller.py
install -m 0755 "$repo_root/control_plane/codex_usage.py" /usr/local/libexec/ai-ops/codex-usage
install -m 0755 "$repo_root/control_plane/workspace_guard.py" /usr/local/libexec/ai-ops/workspace-guard
install -m 0755 "$repo_root/control_plane/artifact_builder.py" /usr/local/libexec/ai-ops/artifact-builder
install -m 0755 "$repo_root/control_plane/process_supervisor.py" /usr/local/libexec/ai-ops/process-supervisor
install -m 0700 "$repo_root/control_plane/authorization_issuer.py" /usr/local/libexec/ai-ops/authorization-issuer
install -o root -g ai-ops-controller -m 0750 "$repo_root/control_plane/controller_service.py" /usr/local/libexec/ai-ops/controller-service
install -o root -g root -m 0755 "$repo_root/control_plane/controller_client.py" /usr/local/libexec/ai-ops/controller-client
install -o root -g root -m 0644 "$repo_root/control_plane/controller_client.py" /usr/local/libexec/ai-ops/controller_client.py
install -o root -g root -m 0644 "$repo_root/control_plane/codex_usage.py" /usr/local/libexec/ai-ops/codex_usage.py
install -o root -g root -m 0644 "$repo_root/control_plane/controller_service.py" /usr/local/libexec/ai-ops/controller_service.py
install -o root -g root -m 0644 "$repo_root/control_plane/authorization_issuer.py" /usr/local/libexec/ai-ops/authorization_issuer.py
install -o root -g root -m 0644 "$repo_root/deploy/systemd/ai-ops-controller@.service" /etc/systemd/system/ai-ops-controller@.service
if [[ "$legacy_compatibility" == true ]]; then
  install -o root -g root -m 0755 "$repo_root/control_plane/project_router.py" /usr/local/libexec/ai-ops/project-router
  install -o root -g root -m 0755 "$repo_root/control_plane/project_router_client.py" /usr/local/libexec/ai-ops/project-router-client
  install -o root -g root -m 0755 "$repo_root/scripts/run-max-codex-campaign.py" /usr/local/libexec/ai-ops/run-max-codex-campaign
  install -o root -g root -m 0644 "$repo_root/deploy/systemd/ai-ops-project-router.service" /etc/systemd/system/ai-ops-project-router.service
  install -o root -g root -m 0644 "$repo_root/deploy/systemd/ai-ops-max-codex-campaign.service" /etc/systemd/system/ai-ops-max-codex-campaign.service
  install -o root -g root -m 0644 "$repo_root/deploy/systemd/ai-ops-max-codex-campaign.timer" /etc/systemd/system/ai-ops-max-codex-campaign.timer
fi
install -d -o root -g ai-ops-controller -m 0750 /var/lib/ai-ops

for profile_name in "${profiles[@]}"; do
  account_name="hermes-${profile_name}"
  profile_home="/srv/hermes/${profile_name}"
  install -d -o "$account_name" -g "$account_name" -m 0700 "${profile_home}/.codex"
  install -d -o "$account_name" -g "$account_name" -m 0750 "${profile_home}/workspace"
  install -d -o "$account_name" -g "$account_name" -m 0700 "${profile_home}/runtime/codex"
  install -d -o "$account_name" -g "$account_name" -m 0700 "${profile_home}/runtime/attempts"
  install -d -o "$account_name" -g "$account_name" -m 0700 "${profile_home}/runtime/evidence"
  install -d -o root -g "$account_name" -m 0550 "${profile_home}/runtime/authorizations"
  usermod -a -G ai-ops-clients "$account_name"
  if [[ "$profile_name" != "evaluator" ]]; then
    install -d -o root -g ai-ops-controller -m 0750 "/var/lib/ai-ops/${profile_name}"
  fi

  if [[ ! -d "${profile_home}/workspace/.git" ]]; then
    runuser -u "$account_name" -- git -C "${profile_home}/workspace" init --initial-branch=main --quiet
  fi
done

systemctl daemon-reload
for profile_name in "${controller_profiles[@]}"; do
  systemctl enable "ai-ops-controller@${profile_name}.service"
  systemctl restart "ai-ops-controller@${profile_name}.service"
  for _ in $(seq 1 20); do
    [[ -S "/run/ai-ops-${profile_name}/controller.sock" ]] && break
    sleep 0.1
  done
  [[ -S "/run/ai-ops-${profile_name}/controller.sock" ]]
done

if [[ "$legacy_compatibility" == true ]]; then
  systemctl enable ai-ops-project-router.service
  systemctl restart ai-ops-project-router.service
  systemctl enable --now ai-ops-max-codex-campaign.timer
fi

echo "Codex workers configured. Authentication is intentionally not provisioned."
