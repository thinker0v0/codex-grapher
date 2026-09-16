#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root on the Hermes VPS" >&2
  exit 77
fi

profile_name="oss"
profile_home="/srv/hermes/${profile_name}"
binding_path="${profile_home}/runtime/repo-binding.json"
issuer="/usr/local/libexec/ai-ops/authorization-issuer"
worker="/usr/local/libexec/ai-ops/run-codex-worker"
controller="/usr/local/libexec/ai-ops/task-controller"
run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
temp_dir="$(mktemp -d)"
trap 'rm -rf -- "$temp_dir"' EXIT

python3 - "$binding_path" "$temp_dir/draft.json" "$run_id" <<'PY'
import datetime as dt
import json
import sys

binding = json.load(open(sys.argv[1]))
now = dt.datetime.now(dt.timezone.utc)
contract = {
    "project_id": "oss",
    "task_id": f"auth-boundary-{sys.argv[3]}",
    "requester_identity": "operator:vps-boundary-test",
    "authorization": {"decision": "allow", "policy_version": "local-root-v1"},
    "idempotency_key": f"auth-boundary-{sys.argv[3]}",
    "repo": binding["repo"],
    "base_sha": binding["base_sha"],
    "objective": "authorization boundary test; never execute Codex",
    "acceptance_criteria": ["all negative cases fail before task submission"],
    "required_tests": ["signed envelope", "mutation denial", "SHA denial", "profile denial"],
    "allowed_paths": ["evidence/"],
    "allowed_tools": ["apply_patch"],
    "forbidden_actions": ["external writes"],
    "budget": {"max_cost_usd": 0.01, "max_tokens": 50},
    "deadline": (now + dt.timedelta(minutes=20)).isoformat(),
    "timeout_seconds": 30,
    "max_iterations": 1,
    "cancellation_token": f"cancel-auth-boundary-{sys.argv[3]}",
    "builder_identity": "hermes-oss",
    "evaluator_contract_id": "eval-auth-boundary-v1",
}
open(sys.argv[2], "w").write(json.dumps(contract, sort_keys=True))
PY

"$issuer" --authorization-dir "${profile_home}/runtime/authorizations" --ttl-seconds 300 \
  "$temp_dir/draft.json" >"$temp_dir/final.json"
evidence_hash="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authorization"]["evidence_sha256"])' "$temp_dir/final.json")"
envelope="${profile_home}/runtime/authorizations/${evidence_hash}.json"
signature="${profile_home}/runtime/authorizations/${evidence_hash}.sig"
"$controller" --db "$temp_dir/verify.db" verify-authorization "$temp_dir/final.json" "$envelope" >/dev/null
openssl pkeyutl -verify -rawin -pubin -inkey /etc/ai-ops/authorization-public.pem \
  -sigfile "$signature" -in "$envelope" >/dev/null

python3 - "$temp_dir/final.json" "$temp_dir/mutated.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
value["objective"] = "tampered after authorization"
open(sys.argv[2], "w").write(json.dumps(value))
PY

set +e
runuser -u hermes-oss -- "$worker" oss <"$temp_dir/mutated.json" >/dev/null 2>"$temp_dir/mutated.err"
mutation_exit="$?"
set -e
test "$mutation_exit" -eq 77
rg -q "not bound" "$temp_dir/mutated.err"

python3 - "$temp_dir/draft.json" "$temp_dir/wrong-sha-draft.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
value["task_id"] += "-wrong-sha"
value["idempotency_key"] += "-wrong-sha"
value["base_sha"] = "1" * 40
open(sys.argv[2], "w").write(json.dumps(value))
PY
"$issuer" --authorization-dir "${profile_home}/runtime/authorizations" --ttl-seconds 300 \
  "$temp_dir/wrong-sha-draft.json" >"$temp_dir/wrong-sha-final.json"
set +e
runuser -u hermes-oss -- "$worker" oss <"$temp_dir/wrong-sha-final.json" >/dev/null 2>"$temp_dir/wrong-sha.err"
sha_exit="$?"
set -e
test "$sha_exit" -eq 77
rg -q "base SHA" "$temp_dir/wrong-sha.err"

python3 - "$temp_dir/final.json" "$temp_dir/wrong-profile.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
value["project_id"] = "business"
value["builder_identity"] = "hermes-business"
open(sys.argv[2], "w").write(json.dumps(value))
PY
set +e
runuser -u hermes-oss -- "$worker" oss <"$temp_dir/wrong-profile.json" >/dev/null 2>"$temp_dir/wrong-profile.err"
profile_exit="$?"
set -e
test "$profile_exit" -eq 77
rg -q "does not match worker profile" "$temp_dir/wrong-profile.err"

python3 - "$run_id" "$evidence_hash" "$mutation_exit" "$sha_exit" "$profile_exit" <<'PY'
import json, sys
print(json.dumps({
    "test": "vps-authorization-boundary",
    "run_id": sys.argv[1],
    "authorization_evidence_sha256": sys.argv[2],
    "signature_verified": True,
    "mutation_denied_before_submit": int(sys.argv[3]) == 77,
    "wrong_sha_denied_before_submit": int(sys.argv[4]) == 77,
    "wrong_profile_denied_before_submit": int(sys.argv[5]) == 77,
    "pass": True,
}, sort_keys=True))
PY
