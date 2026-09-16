#!/usr/bin/env python3
"""Minimal JSON-line client for the project graph service."""

import argparse
import json
import socket
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("request", type=Path, nargs="?")
    args = parser.parse_args()
    payload = (args.request.read_bytes() if args.request else sys.stdin.buffer.read()).rstrip(b"\n") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(args.socket))
        connection.sendall(payload)
        response = b""
        while not response.endswith(b"\n"):
            chunk = connection.recv(65536)
            if not chunk:
                break
            response += chunk
    value = json.loads(response)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 77


if __name__ == "__main__":
    raise SystemExit(main())
