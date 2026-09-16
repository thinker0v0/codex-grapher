#!/usr/bin/env python3
"""Client for the bounded multi-project router."""

import argparse
import json
import socket
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, default=Path("/run/ai-ops-router/router.sock"))
    parser.add_argument("action", choices=["status", "execute"])
    parser.add_argument("route", choices=["nomad", "opensource", "business", "hynix"])
    parser.add_argument("contract", nargs="?")
    args = parser.parse_args()
    request = {"action": args.action, "route": args.route}
    if args.action == "execute":
        if not args.contract:
            parser.error("execute requires a contract JSON file")
        request["contract"] = json.loads(Path(args.contract).read_text())
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(args.socket))
    client.sendall(json.dumps(request, separators=(",", ":")).encode() + b"\n")
    response = b""
    while not response.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            break
        response += chunk
    value = json.loads(response)
    if not value.get("ok"):
        raise PermissionError(value.get("error", "router request denied"))
    print(json.dumps(value["result"], sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, PermissionError, json.JSONDecodeError) as exc:
        print(f"DENIED: {exc}", file=__import__("sys").stderr)
        raise SystemExit(77)
