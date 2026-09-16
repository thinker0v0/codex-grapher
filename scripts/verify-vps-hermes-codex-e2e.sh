#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root on the Hermes VPS" >&2
  exit 77
fi
if [[ "${RUN_LIVE_E2E:-}" != "1" ]]; then
  echo "Set RUN_LIVE_E2E=1 to authorize one live Hermes and Codex subscription call" >&2
  exit 64
fi

profile="${HERMES_E2E_PROFILE:-oss}"
case "$profile" in
  fin-korea|hynix|business|oss) ;;
  *) echo "HERMES_E2E_PROFILE must be fin-korea, hynix, business, or oss" >&2; exit 64 ;;
esac
account="hermes-${profile}"
profile_home="/srv/hermes/${profile}"
controller_socket="/run/ai-ops-${profile}/controller.sock"
binding="${profile_home}/runtime/repo-binding.json"
task_suffix="$(date -u +%Y%m%dT%H%M%SZ)-$$"
task_id="hermes-codex-live-${task_suffix}"
artifact_name="hermes-codex-live-${task_suffix}.txt"
expected="HERMES_CODEX_LIVE_OK"
temp_dir="$(mktemp -d /tmp/hermes-codex-live.XXXXXX)"
trap 'rm -rf -- "$temp_dir"' EXIT
chown "$account:$account" "$temp_dir"
chmod 0700 "$temp_dir"

for required in hermes codex bwrap apparmor_parser python3 openssl; do
  command -v "$required" >/dev/null
done
test -S "$controller_socket"
test -r "$binding"
systemctl is-active --quiet "ai-ops-controller@${profile}.service"
grep -q '^profile bwrap ' /etc/apparmor.d/bwrap-userns-restrict
grep -q '^kernel.apparmor_restrict_unprivileged_userns = 1$' <(sysctl kernel.apparmor_restrict_unprivileged_userns)

python3 - "$binding" "$temp_dir/unsigned.json" "$task_id" "$artifact_name" "$profile" <<'PY'
import datetime as dt
import json
import sys

binding_path, output_path, task_id, artifact_name, profile = sys.argv[1:]
binding = json.load(open(binding_path))
now = dt.datetime.now(dt.timezone.utc)
contract = {
    "project_id": profile,
    "task_id": task_id,
    "requester_identity": "slack:U0BRMCQ33CP",
    "authorization": {"decision": "allow", "policy_version": "bounded-slack-v1"},
    "idempotency_key": task_id + "-idempotency",
    "repo": binding["repo"],
    "base_sha": binding["base_sha"],
    "objective": f"Create {artifact_name} containing exactly HERMES_CODEX_LIVE_OK followed by a newline.",
    "acceptance_criteria": [f"{artifact_name} has the exact required bytes"],
    "required_tests": [f"test \"$(cat {artifact_name})\" = HERMES_CODEX_LIVE_OK"],
    "allowed_paths": [artifact_name],
    "allowed_tools": ["apply_patch", "shell"],
    "forbidden_actions": ["network", "external writes", "secret access", "merge", "release", "deployment", "modify source files"],
    "budget": {"max_cost_usd": 1.0, "max_tokens": 100000},
    "deadline": (now + dt.timedelta(minutes=15)).isoformat(),
    "timeout_seconds": 300,
    "max_iterations": 1,
    "cancellation_token": "cancel-" + task_id,
    "builder_identity": "hermes-" + profile,
    "evaluator_contract_id": "live-e2e-" + profile + "-v1",
}
with open(output_path, "w") as handle:
    json.dump(contract, handle, sort_keys=True)
    handle.write("\n")
PY

runuser -u "$account" -- /usr/local/libexec/ai-ops/controller-client \
  --socket "$controller_socket" authorize "$temp_dir/unsigned.json" |
  install -o "$account" -g "$account" -m 0400 /dev/stdin "$temp_dir/final.json"

install -o "$account" -g "$account" -m 0400 "$temp_dir/final.json" \
  "${profile_home}/runtime/${task_id}.json"

set +e
timeout 360 runuser -u "$account" -- env \
  HOME="$profile_home" HERMES_HOME="${profile_home}/.hermes" \
  PATH=/usr/local/bin:/usr/bin:/bin \
  hermes --in "${profile_home}/workspace" -z \
  "Invoke /usr/local/libexec/ai-ops/run-codex-worker ${profile} with ${profile_home}/runtime/${task_id}.json on stdin. Do not implement the task yourself. Wait for the worker and report its exact state." \
  --usage-file "${profile_home}/runtime/${task_id}-hermes-usage.json" \
  >"$temp_dir/hermes.out" 2>"$temp_dir/hermes.err"
hermes_exit="$?"
set -e
if [[ "$hermes_exit" -ne 0 && "$hermes_exit" -ne 124 ]]; then
  sed -n '1,120p' "$temp_dir/hermes.err" >&2
  exit "$hermes_exit"
fi

deadline="$((SECONDS + 360))"
state=""
while (( SECONDS < deadline )); do
  state="$(runuser -u "$account" -- /usr/local/libexec/ai-ops/controller-client \
    --socket "$controller_socket" get "$task_id" 2>/dev/null |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' || true)"
  [[ "$state" == "EVIDENCE_PENDING" ]] && break
  case "$state" in
    FAILED_*|CANCELLED|REJECTED) echo "Task failed in state $state" >&2; exit 1 ;;
  esac
  sleep 2
done
[[ "$state" == "EVIDENCE_PENDING" ]]

artifact="$(find "${profile_home}/runtime/attempts" -maxdepth 2 \
  -path "*/${task_id}-*/${artifact_name}" -print -quit)"
test -n "$artifact"
[[ "$(cat "$artifact")" == "$expected" ]]
[[ "$(od -An -tx1 -v "$artifact" | tr -d ' \n')" == "4845524d45535f434f4445585f4c4956455f4f4b0a" ]]

path_check="$(find "${profile_home}/runtime/codex" -maxdepth 1 \
  -type f -name '*.path-check.json' -newer "${profile_home}/runtime/${task_id}.json" -print | sort | tail -1)"
test -n "$path_check"
python3 - "$path_check" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
assert result == {"valid": True, "violations": []}, result
PY

python3 - "$task_id" "$state" "$artifact" "$path_check" <<'PY'
import hashlib, json, sys
task_id, state, artifact, path_check = sys.argv[1:]
digest = hashlib.sha256(open(artifact, "rb").read()).hexdigest()
print(json.dumps({
    "artifact": artifact,
    "artifact_sha256": digest,
    "path_check": path_check,
    "state": state,
    "task_id": task_id,
    "valid": True,
}, sort_keys=True))
PY
