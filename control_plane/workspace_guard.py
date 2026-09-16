#!/usr/bin/env python3
"""Hash an isolated task workspace and reject changes outside approved paths."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def inventory(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if relative == ".git" or relative.startswith(".git/"):
            continue
        if path.is_symlink():
            result[relative] = "symlink:" + str(path.readlink())
        elif path.is_file():
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def is_allowed(path: str, allowed: list[str]) -> bool:
    return any(path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/") for prefix in allowed)


def violations(before: dict[str, str], after: dict[str, str], allowed: list[str]) -> list[str]:
    changed = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
    return sorted(path for path in changed if not is_allowed(path, allowed))


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    snapshot = sub.add_parser("snapshot")
    snapshot.add_argument("workspace", type=Path)
    snapshot.add_argument("output", type=Path)
    check = sub.add_parser("check")
    check.add_argument("workspace", type=Path)
    check.add_argument("snapshot", type=Path)
    check.add_argument("contract", type=Path)
    args = parser.parse_args()
    if args.command == "snapshot":
        args.output.write_text(json.dumps(inventory(args.workspace), sort_keys=True) + "\n")
        return 0
    before = json.loads(args.snapshot.read_text())
    contract = json.loads(args.contract.read_text())
    denied = violations(before, inventory(args.workspace), contract["allowed_paths"])
    print(json.dumps({"valid": not denied, "violations": denied}, sort_keys=True))
    return 0 if not denied else 3


if __name__ == "__main__":
    raise SystemExit(main())
