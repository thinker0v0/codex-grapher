#!/usr/bin/env python3
"""Run one worker command in its own process group under active task limits."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

try:
    from codex_usage import parse_jsonl
    from controller_client import request
except ModuleNotFoundError:
    from control_plane.codex_usage import parse_jsonl
    from control_plane.controller_client import request


def terminate_group(process: subprocess.Popen, grace_seconds: float = 0.2) -> None:
    def group_exists() -> bool:
        return _group_active(process.pid)

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace_seconds
    while group_exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if group_exists():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        kill_deadline = time.monotonic() + grace_seconds
        while group_exists() and time.monotonic() < kill_deadline:
            time.sleep(0.05)
    if group_exists():
        raise RuntimeError("process group did not become quiescent")


def supervise(
    command: list[str],
    event_log: Path,
    timeout_seconds: float,
    max_tokens: int,
    state_reader: Callable[[], str],
    usage_recorder: Callable[[int], None],
    poll_seconds: float = 0.25,
) -> dict:
    started = time.monotonic()
    with event_log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    reason = "exited"
    while process.poll() is None:
        state = state_reader()
        tokens = parse_jsonl(event_log)
        if state != "RUNNING":
            reason = "cancelled" if state == "CANCELLED" else "controller_state_changed"
            terminate_group(process)
            break
        if time.monotonic() - started >= timeout_seconds:
            reason = "timeout"
            terminate_group(process)
            break
        if tokens >= max_tokens:
            reason = "budget"
            terminate_group(process)
            break
        time.sleep(poll_seconds)
    exit_code = process.wait()
    tokens = parse_jsonl(event_log)
    usage_recorder(tokens)
    mapped_exit = {"cancelled": 130, "controller_state_changed": 130, "timeout": 124, "budget": 78}.get(reason, exit_code)
    return {
        "reason": reason,
        "exit_code": mapped_exit,
        "child_exit_code": exit_code,
        "pid": process.pid,
        "process_group": process.pid,
        "tokens": tokens,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "execution_quiesced": reason == "exited" or not _group_exists(process.pid),
    }


def _group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False


def _group_active(process_group: int) -> bool:
    """Return true only for non-zombie members of a Linux process group."""
    proc = Path("/proc")
    if not proc.is_dir():
        return _group_exists(process_group)
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().split()
            state = fields[2]
            group = int(fields[4])
        except (FileNotFoundError, PermissionError, IndexError, ValueError):
            continue
        if group == process_group and state != "Z":
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--event-log", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--max-tokens", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command and args.command[0] == "--" else args.command
    if not command:
        raise ValueError("command is required")

    def state_reader() -> str:
        return request(args.socket, {"action": "get", "task_id": args.task_id})["state"]

    def usage_recorder(tokens: int) -> None:
        request(args.socket, {"action": "usage", "task_id": args.task_id, "cost_usd": 0, "tokens": tokens})

    result = supervise(command, args.event_log, args.timeout_seconds, args.max_tokens, state_reader, usage_recorder)
    print(json.dumps(result, sort_keys=True))
    return int(result["exit_code"])


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, PermissionError, ValueError) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        raise SystemExit(77)
