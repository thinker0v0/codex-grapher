#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root on the Hermes VPS" >&2
  exit 77
fi

profiles=(fin-global fin-korea hynix business oss)
for profile_name in "${profiles[@]}"; do
  systemctl is-active --quiet "ai-ops-controller@${profile_name}.service"
  test -S "/run/ai-ops-${profile_name}/controller.sock"
  test "$(stat -c '%a %U:%G' "/run/ai-ops-${profile_name}/controller.sock")" = "660 root:ai-ops-clients"
  test "$(stat -c '%a %U:%G' "/var/lib/ai-ops/${profile_name}/tasks.db")" = "600 root:ai-ops-controller"
  runuser -u "hermes-${profile_name}" -- test ! -r "/var/lib/ai-ops/${profile_name}/tasks.db"
done

set +e
runuser -u hermes-oss -- /usr/local/libexec/ai-ops/task-controller --help >/dev/null 2>&1
direct_exit="$?"
runuser -u hermes-oss -- /usr/local/libexec/ai-ops/controller-client \
  --socket /run/ai-ops-oss/controller.sock transition nonexistent 0 PASSED self-certify >/dev/null 2>&1
self_certify_exit="$?"
runuser -u hermes-business -- /usr/local/libexec/ai-ops/controller-client \
  --socket /run/ai-ops-oss/controller.sock get nonexistent >/dev/null 2>&1
cross_project_exit="$?"
runuser -u hermes-evaluator -- /usr/local/libexec/ai-ops/controller-client \
  --socket /run/ai-ops-oss/controller.sock usage nonexistent 0 0 >/dev/null 2>&1
evaluator_usage_exit="$?"
set -e

test "$direct_exit" -ne 0
test "$self_certify_exit" -eq 77
test "$cross_project_exit" -eq 77
test "$evaluator_usage_exit" -eq 77

python3 - "$direct_exit" "$self_certify_exit" "$cross_project_exit" "$evaluator_usage_exit" <<'PY'
import json, sys
print(json.dumps({
    "test": "vps-controller-isolation",
    "all_five_services_active": True,
    "all_databases_root_owned_0600": True,
    "all_sockets_root_owned_0660": True,
    "builder_database_read_denied": True,
    "direct_controller_denied": int(sys.argv[1]) != 0,
    "builder_self_certification_denied": int(sys.argv[2]) == 77,
    "cross_project_controller_denied": int(sys.argv[3]) == 77,
    "evaluator_usage_forgery_denied": int(sys.argv[4]) == 77,
    "pass": True,
}, sort_keys=True))
PY
