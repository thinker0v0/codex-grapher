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
if [[ "$legacy_compatibility" == true ]]; then
  profiles=(fin-global "${profiles[@]}")
fi

for profile_name in "${profiles[@]}"; do
  account_name="hermes-${profile_name}"
  profile_home="/srv/hermes/${profile_name}"
  hermes_home="${profile_home}/.hermes"
  prompt_path="${repo_root}/prompts/hermes/${profile_name}.md"

  getent passwd "$account_name" >/dev/null
  install -d -o "$account_name" -g "$account_name" -m 0700 "$hermes_home"
  install -o "$account_name" -g "$account_name" -m 0600 \
    "$repo_root/config/hermes-runtime.example.yaml" "${hermes_home}/config.yaml"

  {
    sed -n '1,$p' "$repo_root/prompts/hermes/common.md"
    printf '\n\n'
    sed -n '1,$p' "$prompt_path"
  } >"${hermes_home}/SOUL.md"
  chown "$account_name:$account_name" "${hermes_home}/SOUL.md"
  chmod 0600 "${hermes_home}/SOUL.md"

  env_path="/etc/hermes/${profile_name}.env"
  if [[ ! -s "$env_path" ]]; then
    install -o root -g "$account_name" -m 0640 \
      "$repo_root/config/hermes-profile.env.example" "$env_path"
  fi

  install -d -o "$account_name" -g "$account_name" -m 0700 \
    "${hermes_home}/memories" "${hermes_home}/sessions"
done

echo "Hermes profiles configured without secrets. Fill /etc/hermes/*.env before starting services."
