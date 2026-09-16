#!/usr/bin/env bash
set -euo pipefail

mode="dry-run"
legacy_compatibility=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --apply)
      mode="apply"
      ;;
    --dry-run)
      mode="dry-run"
      ;;
    --legacy-compatibility)
      legacy_compatibility=true
      ;;
    *)
      echo "Usage: $0 [--dry-run|--apply] [--legacy-compatibility]" >&2
      exit 64
      ;;
  esac
  shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profiles=(fin-korea hynix business oss evaluator)
if [[ "$legacy_compatibility" == true ]]; then
  profiles=(fin-global "${profiles[@]}")
fi

run() {
  if [[ "$mode" == "dry-run" ]]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

if [[ "$mode" == "apply" && "${EUID}" -ne 0 ]]; then
  echo "--apply must run as root" >&2
  exit 77
fi

if [[ "$mode" == "apply" ]]; then
  command -v hermes >/dev/null
  command -v systemctl >/dev/null
fi

run install -d -m 0755 /usr/local/libexec/ai-ops
run install -d -m 0755 /usr/local/share/ai-ops
run install -m 0755 "$repo_root/scripts/run-hermes-profile.sh" /usr/local/libexec/ai-ops/run-hermes-profile
run install -m 0755 "$repo_root/scripts/configure-hermes-credentials.sh" /usr/local/libexec/ai-ops/configure-hermes-credentials
if [[ "$legacy_compatibility" == true ]]; then
  run install -m 0755 "$repo_root/scripts/render-slack-profile-manifest.sh" /usr/local/libexec/ai-ops/render-slack-profile-manifest
  run install -m 0644 "$repo_root/config/slack-app-manifest.example.yaml" /usr/local/share/ai-ops/slack-app-manifest.example.yaml
fi
# Service users need directory traversal to reach their own group-readable env file.
# Secret file contents remain protected by per-profile 0640 ownership.
run install -d -m 0755 /etc/hermes

for profile_name in "${profiles[@]}"; do
  account_name="hermes-${profile_name}"
  profile_home="/srv/hermes/${profile_name}"

  if [[ "$mode" == "apply" ]] && ! getent passwd "$account_name" >/dev/null; then
    run useradd --system --user-group --home-dir "$profile_home" --create-home --shell /usr/sbin/nologin "$account_name"
  elif [[ "$mode" == "dry-run" ]]; then
    run useradd --system --user-group --home-dir "$profile_home" --create-home --shell /usr/sbin/nologin "$account_name"
  fi

  run install -d -o "$account_name" -g "$account_name" -m 0750 "$profile_home"
  run install -d -o "$account_name" -g "$account_name" -m 0750 "$profile_home/runtime"
  run install -d -o "$account_name" -g "$account_name" -m 0700 "$profile_home/.hermes"

  if [[ "$profile_name" == "evaluator" ]]; then
    run install -d -o "$account_name" -g "$account_name" -m 0750 "$profile_home/ledger-spool"
    run install -d -o root -g "$account_name" -m 0550 "$profile_home/source"
    run install -d -o root -g "$account_name" -m 0550 "$profile_home/artifacts"
    for route_name in nomad opensource business hynix; do
      run install -d -o root -g "$account_name" -m 0550 "$profile_home/artifacts/$route_name"
    done
  fi

  env_path="/etc/hermes/${profile_name}.env"
  if [[ "$mode" == "apply" && ! -e "$env_path" ]]; then
    run install -o root -g "$account_name" -m 0640 /dev/null "$env_path"
  elif [[ "$mode" == "dry-run" ]]; then
    run install -o root -g "$account_name" -m 0640 /dev/null "$env_path"
  fi
done

run install -m 0644 "$repo_root/deploy/systemd/hermes-profile@.service" /etc/systemd/system/hermes-profile@.service
run install -m 0644 "$repo_root/deploy/systemd/hermes-evaluator.service" /etc/systemd/system/hermes-evaluator.service
run systemctl daemon-reload

if [[ "$mode" == "apply" ]]; then
  echo "Foundation installed. Populate /etc/hermes/*.env and profile configuration before enabling services."
else
  echo "Dry run complete. No system changes were made."
fi
