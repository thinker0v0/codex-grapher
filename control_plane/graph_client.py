#!/usr/bin/env python3
"""Minimal JSON-line client for the project graph service."""

import argparse
import json
import socket
import sys
import time
from pathlib import Path
from typing import Any

if __package__:
    from .graph_transport import (
        CLIENT_TIMEOUT_SECONDS, MAX_REQUEST, MAX_RESPONSE, FrameError, decode_object,
        encode_frame, receive_frame, remaining, timeout_seconds as validate_timeout,
    )
else:
    # The installer places this dependency beside its root-owned script. This
    # also supports running the source file directly without changing sys.path.
    from graph_transport import (
        CLIENT_TIMEOUT_SECONDS, MAX_REQUEST, MAX_RESPONSE, FrameError, decode_object,
        encode_frame, receive_frame, remaining, timeout_seconds as validate_timeout,
    )


def request(socket_path: Path, payload: dict[str, Any], *,
            timeout_seconds: float = CLIENT_TIMEOUT_SECONDS) -> dict[str, Any]:
    """Send once under an absolute deadline; uncertain mutations are never retried."""
    deadline = time.monotonic() + validate_timeout(timeout_seconds)
    frame = encode_frame(payload, MAX_REQUEST)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(remaining(deadline))
        connection.connect(str(socket_path))
        connection.settimeout(remaining(deadline))
        connection.sendall(frame)
        response = receive_frame(connection, deadline, MAX_RESPONSE)
    if type(response.get("ok")) is not bool:
        raise FrameError("response must contain a boolean ok field")
    expected = {"ok", "result"} if response["ok"] else {"ok", "error"}
    if set(response) != expected or (not response["ok"] and type(response["error"]) is not str):
        raise FrameError("invalid graph response envelope")
    return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=CLIENT_TIMEOUT_SECONDS)
    parser.add_argument("request", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        if args.request:
            with args.request.open("rb") as source:
                payload = source.read(MAX_REQUEST + 1)
        else:
            payload = sys.stdin.buffer.read(MAX_REQUEST + 1)
        if not payload.endswith(b"\n"):
            payload += b"\n"
        value = request(args.socket, decode_object(payload, MAX_REQUEST),
                        timeout_seconds=args.timeout_seconds)
    except TimeoutError:
        value = {"ok": False, "error": "graph request timed out; inspect node status before retrying a mutation"}
    except (OSError, ValueError):
        value = {"ok": False, "error": "graph request failed: check socket, one-object JSON framing and size limits"}
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 77


if __name__ == "__main__":
    raise SystemExit(main())
