#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
projects_root="${HERMES_PROJECTS_ROOT:?Set HERMES_PROJECTS_ROOT to your local project directory}"

deploy_one() {
  local template_name="$1"
  local target_dir="$2"

  test -d "${target_dir}/.git"
  install -m 0644 "${repo_root}/templates/projects/${template_name}/HERMES.md" "${target_dir}/HERMES.md"
  install -m 0644 "${repo_root}/templates/projects/common.gitignore" "${target_dir}/.gitignore"
  install -d -m 0755 "${target_dir}/scripts"
  install -m 0755 "${repo_root}/templates/projects/verify-project.sh" "${target_dir}/scripts/verify-project.sh"
  for method_file in PROJECT.md PROBLEM.md SOLUTION.md RESEARCH.md SCAFFOLDING.md HANDOFF.md RUBRIC.md DECISIONS.md; do
    if [[ ! -e "${target_dir}/${method_file}" ]]; then
      install -m 0644 "${repo_root}/templates/project-method/${method_file}" "${target_dir}/${method_file}"
    fi
  done
}

deploy_one finance "${projects_root}/codex_finance"
deploy_one hynix "${projects_root}/codex_hynix"
deploy_one business "${projects_root}/codex_business"

echo "Project bindings deployed."
