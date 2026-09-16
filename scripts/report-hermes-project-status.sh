#!/usr/bin/env bash
set -euo pipefail

profile_name="${1:-}"
case "$profile_name" in
  fin-global|fin-korea|hynix|business|oss) ;;
  *) echo "Unknown project profile" >&2; exit 64 ;;
esac

expected_user="hermes-${profile_name}"
if [[ "$(id -un)" != "$expected_user" ]]; then
  echo "Must run as ${expected_user}" >&2
  exit 77
fi

profile_home="/srv/hermes/${profile_name}"
binding_path="${profile_home}/runtime/repo-binding.json"
controller_socket="/run/ai-ops-${profile_name}/controller.sock"
controller_client="/usr/local/libexec/ai-ops/controller-client"

python3 - "$profile_name" "$profile_home" "$binding_path" "$controller_socket" "$controller_client" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

profile, home_s, binding_s, socket_s, client = sys.argv[1:]
home = Path(home_s)
binding_path = Path(binding_s)
controller_socket = Path(socket_s)

binding = None
if binding_path.is_file():
    try:
        candidate = json.loads(binding_path.read_text(encoding="utf-8"))
        if candidate.get("repo") and candidate.get("base_sha"):
            binding = candidate
    except (OSError, ValueError):
        pass

# The socket lives in the controller service's RuntimeDirectory, which systemd
# removes when the service stops. Do not open a raw probe connection: the
# controller socket carries a framed protocol and an empty connection can race
# the immediately following client request.
controller_reachable = controller_socket.is_socket()

codex_authenticated = False
try:
    result = subprocess.run(
        ["codex", "login", "status"],
        cwd=home / "workspace",
        env={**os.environ, "HOME": str(home), "CODEX_HOME": str(home / ".codex")},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10,
        check=False,
    )
    codex_authenticated = result.returncode == 0 and "logged in" in result.stdout.lower()
except (OSError, subprocess.TimeoutExpired):
    pass

latest_task = None
attempts = home / "runtime" / "attempts"
if attempts.is_dir():
    candidates = sorted(
        (p for p in attempts.iterdir() if p.is_dir()),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        name = candidates[0].name
        task_id, separator, version = name.rpartition("-")
        if separator and version.isdigit():
            try:
                result = subprocess.run(
                    [client, "--socket", str(controller_socket), "get", task_id],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if result.returncode == 0:
                    task = json.loads(result.stdout)
                    latest_task = {
                        "task_id": task.get("task_id"),
                        "state": task.get("state"),
                        "version": task.get("version"),
                    }
            except (OSError, subprocess.TimeoutExpired, ValueError):
                pass

print(json.dumps({
    "profile": profile,
    "project_registered": binding is not None,
    "repo": binding.get("repo") if binding else None,
    "base_sha": binding.get("base_sha") if binding else None,
    "workspace_present": (home / "workspace").is_dir(),
    "controller_reachable": controller_reachable,
    "codex_authenticated": codex_authenticated,
    "latest_task": latest_task,
}, sort_keys=True))
PY
