#!/usr/bin/python3
"""OFFLINE PROTOCOL FIXTURE. No model, subscription or login credential is used.

Emits the supported CLI wire solely to test durable lifecycle interruption. The
version and login strings are deliberate protocol fixtures, not authentication
evidence. The production provider executable must never resolve to this file.
"""
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if args == ["--version"]:
    print("codex-cli 0.155.1")
elif args == ["login", "status"]:
    print("Logged in using ChatGPT (DETERMINISTIC OFFLINE PROTOCOL FIXTURE)")
elif "--help" in args:
    print("--ask-for-approval --ignore-user-config --ephemeral --sandbox workspace-write danger-full-access "
          "--json --model --output-schema --color --cd")
else:
    if "exec" not in args or "--cd" not in args:
        raise SystemExit("unsupported deterministic fixture invocation")
    candidate = Path(args[args.index("--cd") + 1])
    if candidate.resolve() != Path.cwd().resolve():
        raise SystemExit("fixture checkout differs from cwd")
    sys.stdin.read(262145)
    # An explicit allowed, tracked fixture output is the launch witness. The
    # pinned deterministic fixture appends once at actual execution; this is not
    # a hostile-worker tamperproof audit claim or an extra authority/mount.
    with (candidate / "fixture-launches.jsonl").open("a") as stream:
        stream.write('{"fixture":true}\n')
        stream.flush(); os.fsync(stream.fileno())
    expected = candidate / "value.py"
    if expected.read_text() != "VALUE = 0\n":
        raise SystemExit("deterministic fixture requires exact seeded input")
    expected.write_text("VALUE = 42\n")
    events = [
        {"type": "thread.started", "thread_id": "deterministic-guest-fixture", "model": "gpt-5.6-sol"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"id": "guest-fixture-final", "type": "agent_message", "text": json.dumps({
            "schema_version": 1, "status": "completed", "summary": "Deterministic offline guest fixture."})}},
        {"type": "turn.completed", "usage": {"input_tokens": 0, "output_tokens": 0}},
    ]
    for event in events:
        print(json.dumps(event), flush=True)
