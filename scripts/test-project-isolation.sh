#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 77
fi

profiles=(fin-global fin-korea hynix business oss evaluator)
failed=0

for actor in "${profiles[@]}"; do
  for target in "${profiles[@]}"; do
    [[ "$actor" == "$target" ]] && continue
    if runuser -u "hermes-${actor}" -- test -r "/srv/hermes/${target}/.hermes/config.yaml"; then
      echo "FAIL hermes-${actor} can read ${target} config"
      failed=1
    else
      echo "PASS hermes-${actor} denied ${target} config"
    fi
    if runuser -u "hermes-${actor}" -- test -w "/srv/hermes/${target}/workspace"; then
      echo "FAIL hermes-${actor} can write ${target} workspace"
      failed=1
    else
      echo "PASS hermes-${actor} denied ${target} workspace write"
    fi
  done
done

# The evaluator receives explicit read-only copies, never builder homes.
for project_name in finance hynix business opensource; do
  if runuser -u hermes-evaluator -- test -r "/srv/hermes/evaluator/source/${project_name}/AGENTS.md"; then
    echo "PASS evaluator can read ${project_name} review source"
  else
    echo "FAIL evaluator cannot read ${project_name} review source"
    failed=1
  fi
  if runuser -u hermes-evaluator -- test -w "/srv/hermes/evaluator/source/${project_name}/AGENTS.md"; then
    echo "FAIL evaluator can modify ${project_name} review source"
    failed=1
  else
    echo "PASS evaluator denied ${project_name} review-source write"
  fi
done

exit "$failed"

