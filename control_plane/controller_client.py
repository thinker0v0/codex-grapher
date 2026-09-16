#!/usr/bin/env python3
"""Minimal client for the privileged task-controller service."""

from __future__ import annotations

import argparse
import json
import socket
from pathlib import Path


def request(socket_path: Path, payload: dict) -> dict:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(socket_path))
    client.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
    response = b""
    while not response.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            break
        response += chunk
    value = json.loads(response)
    if not value.get("ok"):
        raise PermissionError(value.get("error", "controller request denied"))
    return value["result"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("action", choices=["authorize", "submit", "transition", "usage", "cancel", "get", "verify-chain", "verify-authorization"])
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    values = args.arguments
    payload: dict = {"action": args.action}
    if args.action == "authorize":
        payload["contract"] = json.loads(Path(values[0]).read_text())
    elif args.action == "submit":
        payload["contract"] = json.loads(Path(values[0]).read_text())
        payload["envelope"] = json.loads(Path(values[1]).read_text())
    elif args.action == "transition":
        payload.update(task_id=values[0], version=int(values[1]), target=values[2], reason=values[3])
    elif args.action == "usage":
        payload.update(task_id=values[0], cost_usd=float(values[1]), tokens=int(values[2]))
    elif args.action == "cancel":
        payload.update(task_id=values[0], token=values[1])
    elif args.action in {"get", "verify-chain"}:
        payload["task_id"] = values[0]
    else:
        payload["contract"] = json.loads(Path(values[0]).read_text())
        payload["envelope"] = json.loads(Path(values[1]).read_text())
    print(json.dumps(request(args.socket, payload), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PermissionError, OSError, ValueError, IndexError, json.JSONDecodeError) as exc:
        print(f"DENIED: {exc}", file=__import__("sys").stderr)
        raise SystemExit(77)
