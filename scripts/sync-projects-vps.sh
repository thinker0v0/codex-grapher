#!/usr/bin/env bash
set -euo pipefail

vps_host="${HERMES_VPS_HOST:?Set HERMES_VPS_HOST to your authorized user@host}"
projects_root="${HERMES_PROJECTS_ROOT:?Set HERMES_PROJECTS_ROOT to your local project directory}"
ssh_key="${HERMES_VPS_SSH_KEY:?Set HERMES_VPS_SSH_KEY to your SSH identity path}"
ssh_transport="ssh -i ${ssh_key} -o BatchMode=yes"

sync_builder() {
  local source_dir="$1"
  local profile_name="$2"
  local repo_name="$3"
  local base_sha
  base_sha="$(git -C "$source_dir" rev-parse HEAD)"
  rsync -az --exclude=.git --exclude=.env --exclude=.codex/auth.json \
    --chown="hermes-${profile_name}:hermes-${profile_name}" \
    -e "$ssh_transport" "${source_dir}/" \
    "${vps_host}:/srv/hermes/${profile_name}/workspace/"
  printf '{"base_sha":"%s","repo":"%s"}\n' "$base_sha" "$repo_name" | \
    ssh -i "$ssh_key" -o BatchMode=yes "$vps_host" \
      "install -o root -g hermes-${profile_name} -m 0440 /dev/stdin /srv/hermes/${profile_name}/runtime/repo-binding.json"
}

sync_evaluator_source() {
  local source_dir="$1"
  local project_name="$2"
  rsync -az --exclude=.git --exclude=.env --exclude=.codex/auth.json \
    --chown=root:hermes-evaluator --chmod=D550,F440 \
    -e "$ssh_transport" "${source_dir}/" \
    "${vps_host}:/srv/hermes/evaluator/source/${project_name}/"
}

sync_builder "${projects_root}/codex_finance" fin-global codex_finance
sync_builder "${projects_root}/codex_finance" fin-korea codex_finance
sync_builder "${projects_root}/codex_hynix" hynix codex_hynix
sync_builder "${projects_root}/codex_business" business codex_business
sync_builder "${projects_root}/codex_opensource" oss codex_opensource

sync_evaluator_source "${projects_root}/codex_finance" finance
sync_evaluator_source "${projects_root}/codex_hynix" hynix
sync_evaluator_source "${projects_root}/codex_business" business
sync_evaluator_source "${projects_root}/codex_opensource" opensource

echo "All project workspaces synchronized."
