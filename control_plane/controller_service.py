#!/usr/bin/env python3
"""Root-owned Unix-socket service enforcing controller caller roles."""

from __future__ import annotations

import argparse
import datetime as dt
import grp
import json
import os
import pwd
import re
import socket
import struct
from pathlib import Path
from typing import Any

try:
    from authorization_issuer import issue
    from task_controller import TaskController, validate_contract, verify_authorization_envelope
except ModuleNotFoundError:
    from control_plane.authorization_issuer import issue
    from control_plane.task_controller import TaskController, validate_contract, verify_authorization_envelope


BUILDER_TARGETS = {
    "AUTHORIZED", "NORMALIZED", "PLANNED", "QUEUED", "LEASED", "RUNNING",
    "EVIDENCE_PENDING", "FAILED_PERMANENT", "FAILED_BUDGET", "FAILED_TIMEOUT",
    "FAILED_STAGNATION", "FAILED_GATE", "REJECTED",
}
EVALUATOR_TARGETS = {"EVALUATING", "REWORK_REQUESTED", "PASSED", "FAILED_GATE", "NEEDS_HUMAN"}
READ_ACTIONS = {"get", "verify-chain"}
AUTONOMY_POLICY = "bounded-slack-v1"
MAX_CODEX_POLICY = "max-codex-v1"
REQUIRED_FORBIDDEN_ACTIONS = {
    "external writes", "secret access", "merge", "release", "deployment",
}


def validate_bounded_authorization_request(profile: str, username: str, contract: dict[str, Any], binding: dict[str, Any]) -> None:
    """Fail closed before root signs an isolated, non-publishing Slack task."""
    if username != f"hermes-{profile}":
        raise PermissionError("bounded authorization requires project builder identity")
    if contract.get("project_id") != profile or contract.get("builder_identity") != username:
        raise PermissionError("contract does not match authorization profile or caller")
    if contract.get("repo") != binding.get("repo") or contract.get("base_sha") != binding.get("base_sha"):
        raise PermissionError("contract repository binding is stale or mismatched")
    if not re.fullmatch(r"slack:[A-Z0-9]+", str(contract.get("requester_identity", ""))):
        raise PermissionError("bounded authorization requires a Slack requester identity")
    authorization = contract.get("authorization")
    approved = {
        AUTONOMY_POLICY: {"max_cost": 1.0, "max_tokens": 100000, "max_timeout": 600, "max_iterations": 1, "hours": 1},
        MAX_CODEX_POLICY: {"max_cost": 1_000_000.0, "max_tokens": 1_000_000_000, "max_timeout": 21600, "max_iterations": 5, "hours": 24},
    }
    if not isinstance(authorization, dict) or authorization.get("decision") != "allow" or authorization.get("policy_version") not in approved:
        raise PermissionError("authorization draft must request an approved Slack policy")
    limits = approved[authorization["policy_version"]]
    paths = contract.get("allowed_paths")
    if not isinstance(paths, list) or not paths or len(paths) > 16:
        raise PermissionError("allowed paths must contain 1 to 16 entries")
    for raw in paths:
        path = Path(str(raw))
        if path.is_absolute() or ".." in path.parts or ".git" in path.parts or str(path) in {"", "."}:
            raise PermissionError("allowed paths must be scoped relative paths outside .git")
    if contract.get("allowed_tools") != ["apply_patch", "shell"]:
        raise PermissionError("bounded Slack tasks require the fixed isolated tool set")
    forbidden = set(contract.get("forbidden_actions") or [])
    if not REQUIRED_FORBIDDEN_ACTIONS.issubset(forbidden):
        raise PermissionError("bounded Slack task omits mandatory forbidden actions")
    budget = contract.get("budget") or {}
    if not (0 < float(budget.get("max_cost_usd", 0)) <= limits["max_cost"]):
        raise PermissionError("cost budget exceeds bounded policy")
    if not (0 < int(budget.get("max_tokens", 0)) <= limits["max_tokens"]):
        raise PermissionError("token budget exceeds bounded policy")
    if not (1 <= int(contract.get("timeout_seconds", 0)) <= limits["max_timeout"]):
        raise PermissionError("timeout exceeds bounded policy")
    if not (1 <= int(contract.get("max_iterations", 0)) <= limits["max_iterations"]):
        raise PermissionError("iteration count exceeds policy")
    try:
        deadline = dt.datetime.fromisoformat(str(contract["deadline"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        raise PermissionError("deadline is invalid") from None
    now = dt.datetime.now(dt.timezone.utc)
    if deadline.tzinfo is None or not now < deadline <= now + dt.timedelta(hours=limits["hours"]):
        raise PermissionError("deadline exceeds policy horizon")


def authorize(profile: str, username: str, request: dict[str, Any]) -> str:
    expected_builder = f"hermes-{profile}"
    role = "builder" if username == expected_builder else "evaluator" if username == "hermes-evaluator" else "denied"
    action = request.get("action")
    if role == "denied":
        raise PermissionError("caller identity is not authorized")
    if action in READ_ACTIONS:
        return role
    if action in {"authorize", "submit", "usage", "cancel", "verify-authorization"} and role != "builder":
        raise PermissionError(f"{action} requires project builder identity")
    if action == "transition":
        target = request.get("target")
        permitted = BUILDER_TARGETS if role == "builder" else EVALUATOR_TARGETS
        if target not in permitted:
            raise PermissionError(f"{role} cannot transition to {target}")
    elif action not in {"authorize", "submit", "usage", "cancel", "verify-authorization", *READ_ACTIONS}:
        raise PermissionError("unknown action")
    return role


def dispatch(
    controller: TaskController,
    profile: str,
    username: str,
    request: dict[str, Any],
    *,
    binding: dict[str, Any] | None = None,
    private_key: Path = Path("/etc/ai-ops/authorization-private.pem"),
    authorization_dir: Path | None = None,
) -> dict[str, Any]:
    authorize(profile, username, request)
    action = request["action"]
    if action == "authorize":
        if binding is None or authorization_dir is None:
            raise PermissionError("authorization service paths are not configured")
        contract = request["contract"]
        validate_bounded_authorization_request(profile, username, contract, binding)
        return issue(contract, private_key, authorization_dir, 300)
    if action == "submit":
        contract = request["contract"]
        if contract.get("project_id") != profile or contract.get("builder_identity") != username:
            raise PermissionError("contract does not match controller profile or caller")
        validate_contract(contract)
        verify_authorization_envelope(contract, request["envelope"])
        return controller.submit(contract)
    if action == "transition":
        return controller.transition(request["task_id"], int(request["version"]), request["target"], request["reason"])
    if action == "usage":
        return controller.record_usage(request["task_id"], float(request["cost_usd"]), int(request["tokens"]))
    if action == "cancel":
        return controller.cancel(request["task_id"], request["token"])
    if action == "get":
        return controller.get(request["task_id"])
    if action == "verify-chain":
        return {"task_id": request["task_id"], "valid": controller.verify_event_chain(request["task_id"])}
    contract = request["contract"]
    validate_contract(contract)
    verify_authorization_envelope(contract, request["envelope"])
    return {"valid": True}


def serve(profile: str, database: Path, socket_path: Path) -> None:
    controller = TaskController(database)
    controller.recover_orphaned_executions()
    profile_home = Path("/srv/hermes") / profile
    binding_path = profile_home / "runtime" / "repo-binding.json"
    authorization_dir = profile_home / "runtime" / "authorizations"
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chown(socket_path, 0, grp.getgrnam("ai-ops-clients").gr_gid)
    os.chmod(socket_path, 0o660)
    server.listen(32)
    while True:
        connection, _ = server.accept()
        with connection:
            try:
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                username = pwd.getpwuid(uid).pw_name
                payload = b""
                while not payload.endswith(b"\n") and len(payload) <= 1024 * 1024:
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    payload += chunk
                if len(payload) > 1024 * 1024:
                    raise ValueError("request exceeds 1 MiB")
                request = json.loads(payload)
                binding = json.loads(binding_path.read_text()) if request.get("action") == "authorize" else None
                result = dispatch(
                    controller, profile, username, request,
                    binding=binding, authorization_dir=authorization_dir,
                )
                response = {"ok": True, "result": result}
            except Exception as exc:  # Fail closed without exposing tracebacks.
                response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    serve(args.profile, args.db, args.socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
