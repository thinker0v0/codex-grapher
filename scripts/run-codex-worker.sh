#!/usr/bin/env bash
set -euo pipefail

profile_name="${1:-}"
supplied_contract="${2:-}"
case "$profile_name" in
  fin-global|fin-korea|hynix|business|oss) ;;
  *) echo "Unknown profile" >&2; exit 64 ;;
esac

expected_user="hermes-${profile_name}"
if [[ "$(id -un)" != "$expected_user" ]]; then
  echo "Must run as ${expected_user}" >&2
  exit 77
fi

profile_home="/srv/hermes/${profile_name}"
log_dir="${profile_home}/runtime/codex"
evidence_dir="${profile_home}/runtime/evidence"
mkdir -p "$log_dir"
mkdir -p "$evidence_dir"

if [[ -n "$supplied_contract" ]]; then
  expected_prefix="${profile_home}/runtime/router-contracts/"
  [[ "$supplied_contract" == "${expected_prefix}"*.json ]] || { echo "Router contract path is outside the fixed spool" >&2; exit 77; }
  [[ -f "$supplied_contract" && ! -L "$supplied_contract" ]] || { echo "Router contract is absent or unsafe" >&2; exit 77; }
  [[ "$(stat -c '%U:%G:%a' "$supplied_contract")" == "root:${expected_user}:440" ]] || { echo "Router contract ownership or mode is unsafe" >&2; exit 77; }
  contract_path="$supplied_contract"
elif [[ ! -t 0 ]]; then
  contract_path="$(mktemp "${profile_home}/runtime/task-contract.XXXXXX.json")"
  trap 'rm -f -- "$contract_path"' EXIT
  install -m 0600 /dev/stdin "$contract_path"
else
  echo "Task contract JSON must be supplied on stdin" >&2
  exit 64
fi

controller_socket="/run/ai-ops-${profile_name}/controller.sock"
controller() {
  /usr/local/libexec/ai-ops/controller-client --socket "$controller_socket" "$@"
}
contract_project="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project_id"])' "$contract_path")"
contract_builder="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["builder_identity"])' "$contract_path")"
if [[ "$contract_project" != "$profile_name" || "$contract_builder" != "$expected_user" ]]; then
  echo "Contract project or builder does not match worker profile" >&2
  exit 77
fi
evidence_hash="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authorization"]["evidence_sha256"])' "$contract_path")"
signature_hash="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["authorization"]["signature_sha256"])' "$contract_path")"
authorization_path="${profile_home}/runtime/authorizations/${evidence_hash}.json"
signature_path="${profile_home}/runtime/authorizations/${evidence_hash}.sig"
public_key="/etc/ai-ops/authorization-public.pem"

if [[ ! -r "$authorization_path" ]]; then
  echo "Authorization evidence is absent" >&2
  exit 77
fi

if [[ "$(sha256sum "$authorization_path" | cut -d' ' -f1)" != "$evidence_hash" ]]; then
  echo "Authorization evidence hash mismatch" >&2
  exit 77
fi
if [[ ! -r "$signature_path" || ! -r "$public_key" ]]; then
  echo "Authorization signature or public key is absent" >&2
  exit 77
fi
if [[ "$(sha256sum "$signature_path" | cut -d' ' -f1)" != "$signature_hash" ]]; then
  echo "Authorization signature hash mismatch" >&2
  exit 77
fi
if [[ "$(stat -c '%U:%a' "$authorization_path")" != "root:440" || "$(stat -c '%U:%a' "$signature_path")" != "root:440" ]]; then
  echo "Authorization evidence ownership or mode is unsafe" >&2
  exit 77
fi
if ! openssl pkeyutl -verify -rawin -pubin -inkey "$public_key" -sigfile "$signature_path" -in "$authorization_path" >/dev/null; then
  echo "Authorization signature is invalid" >&2
  exit 77
fi
if ! controller verify-authorization "$contract_path" "$authorization_path" >/dev/null; then
  echo "Authorization envelope is not bound to this contract" >&2
  exit 77
fi

expected_repo="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repo"])' "$contract_path")"
expected_base_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["base_sha"])' "$contract_path")"
binding_path="${profile_home}/runtime/repo-binding.json"
if [[ ! -r "$binding_path" || "$(stat -c '%U:%a' "$binding_path")" != "root:440" ]]; then
  echo "Root-owned repository binding is absent or unsafe" >&2
  exit 77
fi
if ! python3 - "$binding_path" "$expected_repo" "$expected_base_sha" <<'PY'
import json, sys
binding = json.load(open(sys.argv[1]))
if binding != {"repo": sys.argv[2], "base_sha": sys.argv[3]}:
    raise SystemExit(1)
PY
then
  echo "Repository name or base SHA does not match deployed binding" >&2
  exit 77
fi
if [[ "$profile_name" == "fin-global" ]]; then
  # Frozen compatibility route.  It is outside the active four-project graph
  # and retains its legacy workspace until an explicit migration decision.
  publication_workspace="${profile_home}/workspace"
else
  publication_root="${profile_home}/runtime/publications"
  if ! publication_workspace="$(python3 /usr/local/lib/ai-ops/control_plane/publication_store.py \
    --root "$publication_root" --binding "$binding_path" \
    --expected-repo "$expected_repo" --expected-base-sha "$expected_base_sha")"; then
    echo "Bound immutable repository publication is absent or invalid" >&2
    exit 77
  fi
  if [[ "$publication_workspace" != "${publication_root}/${expected_base_sha}" \
        || -L "$publication_workspace" || ! -d "$publication_workspace/.git" ]]; then
    echo "Publication resolver returned an unsafe generation" >&2
    exit 77
  fi
fi

task_json="$(controller submit "$contract_path" "$authorization_path")"
task_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["task_id"])' <<<"$task_json")"
task_state="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' <<<"$task_json")"
task_version="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' <<<"$task_json")"
if [[ "$task_state" != "RECEIVED" ]]; then
  echo "Task is not newly received; refusing duplicate execution" >&2
  exit 65
fi

transition() {
  local target="$1"
  local reason="$2"
  task_json="$(controller transition "$task_id" "$task_version" "$target" "$reason")"
  task_version="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])' <<<"$task_json")"
  task_state="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])' <<<"$task_json")"
  [[ "$task_state" == "$target" ]]
}

transition AUTHORIZED "authorization evidence verified"
transition NORMALIZED "typed contract validated"
transition PLANNED "Hermes plan accepted"
transition QUEUED "admitted within contract budget"
transition LEASED "exclusive worker lease"
transition RUNNING "Codex process starting"

if ! attempt_number="$(python3 -c '
import json, sys
value = json.load(sys.stdin).get("attempt_count")
if type(value) is not int or not 1 <= value <= 1_000_000:
    raise SystemExit(1)
print(value)
' <<<"$task_json")"; then
  transition FAILED_GATE "Controller returned an invalid attempt number" || true
  exit 79
fi

attempt_workspace="${profile_home}/runtime/attempts/${task_id}-attempt-${attempt_number}"
mkdir -m 0700 "$attempt_workspace"
# The binding was read and validated before this copy.  Later promotions only
# replace the binding and add another generation, so this reader stays pinned
# to one complete Git repository for the entire attempt.
cp -a --reflink=auto "${publication_workspace}/." "${attempt_workspace}/"
baseline_manifest="${attempt_workspace}/.git/control-plane-baseline.json"
mkdir -p "${attempt_workspace}/.git"
/usr/local/libexec/ai-ops/workspace-guard snapshot "$attempt_workspace" "$baseline_manifest"

prompt="$(python3 - "$contract_path" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
print(c["objective"])
print("\nAcceptance criteria:")
for item in c["acceptance_criteria"]:
    print(f"- {item}")
print("\nRequired tests:")
for item in c["required_tests"]:
    print(f"- {item}")
print("\nAllowed paths:")
for item in c["allowed_paths"]:
    print(f"- {item}")
print("\nForbidden actions:")
for item in c["forbidden_actions"]:
    print(f"- {item}")
PY
)"

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
event_log="${log_dir}/${run_id}.jsonl"
sandbox="workspace-write"

export HOME="$profile_home"
export CODEX_HOME="${profile_home}/.codex"
umask 0077

timeout_seconds="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["timeout_seconds"])' "$contract_path")"
max_tokens="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["budget"]["max_tokens"])' "$contract_path")"
set +e
supervisor_json="$(/usr/local/libexec/ai-ops/process-supervisor \
  --socket "$controller_socket" --task-id "$task_id" --event-log "$event_log" \
  --timeout-seconds "$timeout_seconds" --max-tokens "$max_tokens" -- \
  codex exec --json --ephemeral -c 'approval_policy="never"' \
    --sandbox "$sandbox" -C "$attempt_workspace" "$prompt")"
exit_code="$?"
set -e
cat "$event_log"

if [[ "$exit_code" -eq 130 ]]; then
  exit 130
elif [[ "$exit_code" -eq 124 ]]; then
  transition FAILED_TIMEOUT "Codex exceeded contract timeout" || true
  exit 124
elif [[ "$exit_code" -eq 78 ]]; then
  transition FAILED_BUDGET "Codex exceeded contract token budget" || true
  exit 78
elif [[ "$exit_code" -eq 0 ]]; then
  path_check="${log_dir}/${run_id}.path-check.json"
  if /usr/local/libexec/ai-ops/workspace-guard check "$attempt_workspace" "$baseline_manifest" "$contract_path" >"$path_check"; then
    if ! /usr/local/libexec/ai-ops/artifact-builder --attempt "$attempt_workspace" --contract "$contract_path" \
      --path-check "$path_check" --output-dir "$evidence_dir" \
      --attempt-number "$attempt_number"; then
      transition FAILED_GATE "Codex produced no verifiable candidate artifact"
      exit 79
    fi
    transition EVIDENCE_PENDING "Codex exited successfully in isolated workspace; evidence required"
  else
    transition FAILED_GATE "Codex modified paths outside contract allowlist"
    exit 79
  fi
else
  transition FAILED_PERMANENT "Codex process failed" || true
  exit "$exit_code"
fi
