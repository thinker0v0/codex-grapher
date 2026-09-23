#!/usr/bin/env python3
"""Verify a real quiescent workspace backup, or restore on a fresh original root.

This command never deletes a workspace to simulate disaster recovery. Use the
separate disposable guest harness for source-inaccessible recovery evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

# A source checkout can run the same public implementation as an installed wheel.
if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_plane.backup_archive import inspect_archive
from control_plane.workspace_backup import backup_workspace, restore_workspace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--output", type=Path, help="publish a new validated backup")
    modes.add_argument("--restore", type=Path, help="restore a backup to its empty original root")
    parser.add_argument("--profile", type=Path, help="required separately provisioned restore profile")
    args = parser.parse_args()
    if args.restore and args.profile is None:
        parser.error("--restore requires --profile")
    started = time.monotonic()
    try:
        if args.output:
            receipt = backup_workspace(args.workspace, args.output)
            backup = args.output
        else:
            receipt = restore_workspace(args.restore, args.workspace, args.profile)
            backup = args.restore
        manifest = inspect_archive(backup)
        result = {"schema_version": 1, "result": "VERIFIED_OFFLINE_CLOSURE",
                  "elapsed_seconds": round(time.monotonic() - started, 6),
                  "receipt": receipt.to_dict(),
                  "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True,
                      separators=(",", ":")).encode()).hexdigest(),
                  "claim_scope": "local archive/closure verification; guest recovery remains separate"}
    except Exception as error:
        print(json.dumps({"schema_version": 1, "result": "REJECTED", "error": str(error),
                          "classification": getattr(error, "code", "RESTORE_INVALID")}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
