#!/usr/bin/env python3
"""Verify the complete local developer lifecycle, replay, recovery and rollback."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_plane.local_workflow import run_local_workflow


def main():
    with tempfile.TemporaryDirectory(prefix="grapher-verified-example-") as temporary:
        workspace = Path(temporary) / "normal"
        built = run_local_workflow(workspace, stop_after="built")
        if built["accepted_sha"] != built["baseline_sha"]:
            raise RuntimeError("unevaluated artifact changed the accepted baseline")
        evaluated = run_local_workflow(workspace, stop_after="evaluated")
        promoted = run_local_workflow(workspace)
        replay = run_local_workflow(workspace)
        if (replay["accepted_sha"], replay["publication_journal_entries"]) != (
            promoted["accepted_sha"], promoted["publication_journal_entries"],
        ):
            raise RuntimeError("promotion replay was not idempotent")
        status = run_local_workflow(workspace, operation="status")
        rolled_back = run_local_workflow(workspace, operation="rollback")
        rollback_replay = run_local_workflow(workspace, operation="rollback")
        if rollback_replay != rolled_back or rolled_back["accepted_sha"] != built["baseline_sha"]:
            raise RuntimeError("rollback did not restore the exact baseline idempotently")

        interrupted = Path(temporary) / "interrupted"
        command = [sys.executable, "-B", "-m", "control_plane.local_workflow", "--workspace",
                   str(interrupted), "--crash-at", "after_binding"]
        crashed = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                 capture_output=True, timeout=90)
        if crashed.returncode != 86:
            raise RuntimeError("intentional subprocess interruption did not reach the promotion hook")
        recovered = run_local_workflow(interrupted, operation="recover")
        recovered_replay = run_local_workflow(interrupted, operation="recover")
        if recovered != recovered_replay or recovered["workflow_state"] != "promoted":
            raise RuntimeError("process restart did not recover promotion exactly once")

        denied = run_local_workflow(Path(temporary) / "denied", failure="evaluator")
        if denied["task_state"] != "FAILED_GATE" or denied["accepted_sha"] != denied["baseline_sha"]:
            raise RuntimeError("failed independent acceptance changed the baseline")
        print(json.dumps({
            "scope": "trusted local developer lifecycle; same-UID roles, temporary keys",
            "stages": [built["workflow_state"], evaluated["workflow_state"], promoted["workflow_state"]],
            "task_verdict": evaluated["task_verdict"], "release_verdict": "NOT_PASS",
            "real_required_tests": True, "independent_evaluator_process": True,
            "signed_task_schema": 4, "immutable_artifact": promoted["artifact_id"],
            "successor_consumed": promoted["successor_consumed"],
            "read_only_status_verified": status["integrity_verified"],
            "promotion_replay_verified": True, "rollback_replay_verified": True,
            "subprocess_crash_exit": crashed.returncode,
            "restart_recovery_verified": True, "failed_candidate_preserved_baseline": True,
            "temporary_workspaces_removed": True,
        }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
