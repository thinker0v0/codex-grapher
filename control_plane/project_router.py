#!/usr/bin/env python3
"""Narrow root broker routing one Slack Hermes to isolated project workers."""

from __future__ import annotations

import argparse
import concurrent.futures
import grp
import json
import os
import pwd
import socket
import struct
import subprocess
import uuid
from pathlib import Path
from typing import Any

try:
    from authorization_issuer import issue
    from controller_service import validate_bounded_authorization_request
except ModuleNotFoundError:
    from control_plane.authorization_issuer import issue
    from control_plane.controller_service import validate_bounded_authorization_request


ROUTES = {
    "nomad": "fin-korea",
    "fin-korea": "fin-korea",
    "opensource": "oss",
    "oss": "oss",
    "business": "business",
    "hynix": "hynix",
}
ROUTER_USER = "hermes-oss"
MAX_REQUEST = 1024 * 1024


def environment(profile: str) -> dict[str, str]:
    home = f"/srv/hermes/{profile}"
    return {
        **os.environ,
        "HOME": home,
        "CODEX_HOME": f"{home}/.codex",
        "HERMES_HOME": f"{home}/.hermes",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }


def systemd_prefix(profile: str, label: str) -> list[str]:
    unit = f"ai-ops-route-{profile}-{label}-{uuid.uuid4().hex[:10]}"
    return [
        "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect",
        f"--unit={unit}", f"--uid=hermes-{profile}", f"--gid=hermes-{profile}",
        f"--setenv=HOME=/srv/hermes/{profile}",
        f"--setenv=CODEX_HOME=/srv/hermes/{profile}/.codex",
        f"--setenv=HERMES_HOME=/srv/hermes/{profile}/.hermes",
        "--setenv=PATH=/usr/local/bin:/usr/bin:/bin",
        "--property=NoNewPrivileges=true", "--property=PrivateTmp=true",
    ]


def normalize_contract(route: str, contract: dict[str, Any], binding: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    profile = ROUTES.get(route)
    if profile is None:
        raise PermissionError("unknown project route")
    value = dict(contract)
    value["project_id"] = profile
    value["builder_identity"] = f"hermes-{profile}"
    value["repo"] = binding["repo"]
    value["base_sha"] = binding["base_sha"]
    validate_bounded_authorization_request(profile, f"hermes-{profile}", value, binding)
    return profile, value


def execute(route: str, contract: dict[str, Any]) -> dict[str, Any]:
    profile = ROUTES.get(route)
    if profile is None:
        raise PermissionError("unknown project route")
    home = Path("/srv/hermes") / profile
    binding = json.loads((home / "runtime/repo-binding.json").read_text())
    profile, normalized = normalize_contract(route, contract, binding)
    final = issue(
        normalized,
        Path("/etc/ai-ops/authorization-private.pem"),
        home / "runtime/authorizations",
        300,
    )
    payload = json.dumps(final, sort_keys=True).encode() + b"\n"
    account = pwd.getpwnam(f"hermes-{profile}")
    spool = home / "runtime/router-contracts"
    spool.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(spool, 0, account.pw_gid)
    os.chmod(spool, 0o750)
    contract_path = spool / f"contract-{uuid.uuid4().hex}.json"
    descriptor = os.open(contract_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)
    os.chown(contract_path, 0, account.pw_gid)
    os.chmod(contract_path, 0o440)
    try:
        completed = subprocess.run(
            systemd_prefix(profile, "worker") + ["/usr/local/libexec/ai-ops/run-codex-worker", profile, str(contract_path)],
            capture_output=True,
            timeout=min(int(normalized["timeout_seconds"]) + 60, 21660),
            check=False,
            env=environment(profile),
        )
    finally:
        contract_path.unlink(missing_ok=True)
    return {
        "profile": profile,
        "returncode": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", "replace")[-65536:],
        "stderr": completed.stderr.decode("utf-8", "replace")[-16384:],
        "task_id": normalized["task_id"],
    }


def status(route: str) -> dict[str, Any]:
    profile = ROUTES.get(route)
    if profile is None:
        raise PermissionError("unknown project route")
    try:
        completed = subprocess.run(
            systemd_prefix(profile, "status") + ["/usr/local/libexec/ai-ops/report-hermes-project-status", profile],
            capture_output=True, timeout=30, check=True, text=True,
            env=environment(profile),
        )
    except OSError as exc:
        raise RuntimeError(f"status launcher denied filename={exc.filename!r} errno={exc.errno}") from None
    return json.loads(completed.stdout)


def dispatch(username: str, request: dict[str, Any]) -> dict[str, Any]:
    if username != ROUTER_USER:
        raise PermissionError("only the Slack router identity is authorized")
    action = request.get("action")
    if action == "status":
        return status(str(request.get("route", "")))
    if action == "execute":
        contract = request.get("contract")
        if not isinstance(contract, dict):
            raise ValueError("execute requires a contract object")
        return execute(str(request.get("route", "")), contract)
    raise PermissionError("unknown router action")


def serve(socket_path: Path) -> None:
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chown(socket_path, 0, grp.getgrnam(ROUTER_USER).gr_gid)
    os.chmod(socket_path, 0o660)
    server.listen(16)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="project-route") as workers:
        while True:
            connection, _ = server.accept()
            workers.submit(handle_connection, connection)


def handle_connection(connection: socket.socket) -> None:
    with connection:
        try:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            username = pwd.getpwuid(uid).pw_name
            payload = b""
            while not payload.endswith(b"\n") and len(payload) <= MAX_REQUEST:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                payload += chunk
            if len(payload) > MAX_REQUEST:
                raise ValueError("request exceeds 1 MiB")
            response = {"ok": True, "result": dispatch(username, json.loads(payload))}
        except Exception as exc:
            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    serve(args.socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
