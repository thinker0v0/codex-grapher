import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from control_plane.artifact_builder import RequiredTestOutputLimitExceeded
from control_plane.evaluation_policy import load_task_policy
from control_plane.local_workflow import (
    ATTEMPT, ROLLBACK, TASK, _coordinator, _evaluate_sample, _write_json,
    produce_worker_artifact, run_local_workflow,
)
from control_plane.project_graph import ProjectGraph


class VerifiedLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="test-grapher-lifecycle-")
        self.root = Path(self.temporary.name) / "workflow"

    def tearDown(self):
        self.temporary.cleanup()

    def open_graph(self):
        policy = load_task_policy(self.root / "task-policy.json")
        return ProjectGraph(self.root / "graph.sqlite", self.root / "evaluator-public.pem",
                            policy.sha256, evaluation_policy=policy)

    def test_actual_pipeline_stages_reopen_replay_successor_and_rollback(self):
        built = run_local_workflow(self.root, stop_after="built")
        self.assertEqual(built["workflow_state"], "built")
        self.assertEqual(built["accepted_sha"], built["baseline_sha"])
        digest = built["artifact_id"].split(":")[1]
        manifest_path = self.root / "evidence/sha256" / digest[:2] / digest / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        output = manifest_path.parent / manifest["required_tests"][0]["output"]["path"]
        self.assertEqual(output.read_text(), "2 required greeting assertions passed\n")
        self.assertEqual(manifest["required_tests"][0]["candidate_sha"], manifest["candidate_sha"])
        self.assertEqual(manifest["producer_identity"], "hermes-oss")
        evaluated = run_local_workflow(self.root, stop_after="evaluated")
        self.assertEqual(evaluated["accepted_sha"], built["baseline_sha"])
        evaluation = json.loads((self.root / "evaluation.json").read_bytes())
        self.assertEqual(evaluation["schema_version"], 4)
        self.assertEqual(set(evaluation["mandatory_gates"]), {"required_tests", "independent_assertions", "write_scope"})
        self.assertNotEqual(json.loads((self.root / "evaluator-checks.json").read_bytes())["process_id"], os.getpid())
        promoted = run_local_workflow(self.root)
        self.assertEqual(promoted["successor_consumed"]["base_sha"], promoted["accepted_sha"])
        self.assertEqual(promoted["successor_consumed"]["output"], "Hello, Ada!")
        replay = run_local_workflow(self.root)
        self.assertEqual(replay, promoted)
        self.assertEqual(promoted["publication_journal_entries"], 1)
        self.assertEqual(promoted["release_verdict"], "NOT_PASS")
        rolled_back = run_local_workflow(self.root, operation="rollback")
        self.assertEqual(rolled_back["accepted_sha"], built["baseline_sha"])
        self.assertEqual(rolled_back["workflow_state"], "rolled_back")
        self.assertEqual(run_local_workflow(self.root, operation="rollback"), rolled_back)
        self.assertTrue((self.root / "publications" / promoted["accepted_sha"] / "src/greeting.py").exists())
        self.assertEqual(stat.S_IMODE((self.root / ".evaluator-private").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / ".evaluator-private/key.pem").stat().st_mode), 0o600)

    def test_status_does_not_modify_any_workspace_file(self):
        run_local_workflow(self.root)

        def snapshot():
            return {
                str(path.relative_to(self.root)): (hashlib.sha256(path.read_bytes()).hexdigest(),
                    path.stat().st_mode, path.stat().st_mtime_ns)
                for path in self.root.rglob("*") if path.is_file()
            }

        before = snapshot()
        result = run_local_workflow(self.root, operation="status")
        self.assertEqual(result["workflow_state"], "promoted")
        self.assertEqual(snapshot(), before)

    def test_status_detects_corrupt_unevaluated_artifact_bytes(self):
        built = run_local_workflow(self.root, stop_after="built")
        digest = built["artifact_id"].split(":")[1]
        output = self.root / "evidence/sha256" / digest[:2] / digest / "required-tests/0000.output"
        output.chmod(0o600)
        output.write_bytes(b"forged evidence\n")
        with self.assertRaises(PermissionError):
            run_local_workflow(self.root, operation="status")

    def test_real_process_crash_recovery_and_replay_after_binding(self):
        child = subprocess.run(
            [sys.executable, "-B", "-m", "control_plane.local_workflow", "--workspace", str(self.root),
             "--crash-at", "after_binding"], capture_output=True, timeout=90,
        )
        self.assertEqual(child.returncode, 86, child.stderr.decode())
        with sqlite3.connect(self.root / "graph.sqlite") as connection:
            self.assertEqual(connection.execute("SELECT status FROM integration_attempts").fetchone()[0], "PREPARED")
            self.assertEqual(connection.execute("SELECT count(*) FROM publication_journal").fetchone()[0], 0)
        recovered = run_local_workflow(self.root, operation="recover")
        self.assertEqual(recovered["workflow_state"], "promoted")
        self.assertEqual(recovered["publication_journal_entries"], 1)
        self.assertEqual(run_local_workflow(self.root, operation="recover"), recovered)

    def test_required_test_failure_never_publishes_manifest_or_changes_baseline(self):
        failed = run_local_workflow(self.root, failure="required-test")
        self.assertEqual(failed["workflow_state"], "failed")
        self.assertIsNone(failed["artifact_id"])
        self.assertEqual(failed["accepted_sha"], failed["baseline_sha"])
        self.assertFalse(list((self.root / "worker-output").rglob("manifest.json")))
        self.assertEqual(failed["publication_journal_entries"], 0)

    def test_interrupted_rollback_status_and_recovery(self):
        promoted = run_local_workflow(self.root)
        graph = self.open_graph()
        try:
            coordinator = _coordinator(self.root, graph, load_task_policy(self.root / "task-policy.json"))

            def interrupt(point):
                if point == "after_rollback_binding":
                    raise RuntimeError("simulated rollback interruption")

            with self.assertRaisesRegex(RuntimeError, "simulated rollback"):
                coordinator.rollback(ROLLBACK, TASK, ATTEMPT, 1, crash_hook=interrupt)
        finally:
            graph.connection.close()
        status = run_local_workflow(self.root, operation="status")
        self.assertEqual(status["workflow_state"], "recovery_required")
        self.assertEqual(status["accepted_sha"], promoted["baseline_sha"])
        recovered = run_local_workflow(self.root, operation="recover")
        self.assertEqual(recovered["workflow_state"], "rolled_back")
        self.assertEqual(recovered["accepted_sha"], promoted["baseline_sha"])
        self.assertEqual(run_local_workflow(self.root, operation="recover"), recovered)
        self.assertEqual(run_local_workflow(self.root, operation="rollback"), recovered)

    def test_independent_assertion_failure_rejects_passing_required_tests(self):
        failed = run_local_workflow(self.root, failure="evaluator")
        self.assertEqual(failed["task_state"], "FAILED_GATE")
        self.assertIsNotNone(failed["artifact_id"])
        self.assertIsNone(failed["outcome_id"])
        self.assertEqual(failed["accepted_sha"], failed["baseline_sha"])
        self.assertFalse((self.root / "evaluation.json").exists())
        self.assertEqual(failed["publication_journal_entries"], 0)

    def test_expired_evaluator_claim_is_reclaimed_after_restart(self):
        run_local_workflow(self.root, stop_after="built")
        graph = self.open_graph()
        try:
            node = graph.get_node(TASK)
            graph.claim_evidence(TASK, node["version"], node["active_artifact_id"], "hermes-evaluator", 10)
            past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
            graph.connection.execute("UPDATE evaluation_claims SET expires_at=?", (past,))
            graph.connection.commit()
        finally:
            graph.connection.close()
        result = run_local_workflow(self.root, operation="recover")
        self.assertEqual(result["workflow_state"], "promoted")
        with sqlite3.connect(self.root / "graph.sqlite") as connection:
            self.assertEqual([row[0] for row in connection.execute("SELECT status FROM evaluation_claims ORDER BY claim_version")], ["EXPIRED", "EVALUATED"])

    def test_saved_signed_response_replays_without_rerunning_evaluator(self):
        run_local_workflow(self.root, stop_after="built")
        graph = self.open_graph()
        try:
            node = graph.get_node(TASK)
            claim = graph.claim_evidence(TASK, node["version"], node["active_artifact_id"], "hermes-evaluator", 600)
            _write_json(self.root / "evaluation-request.json", {
                "artifact_id": node["active_artifact_id"], "claim_id": claim["artifact"]["claim_id"],
                "previous_ledger_hash": None,
            })
        finally:
            graph.connection.close()
        _evaluate_sample(self.root)
        original = (self.root / "evaluation.json").read_bytes()
        with patch("control_plane.local_workflow._run", side_effect=AssertionError("evaluator must not rerun")):
            result = run_local_workflow(self.root, stop_after="evaluated")
        self.assertEqual(result["task_state"], "PASSED")
        self.assertEqual((self.root / "evaluation.json").read_bytes(), original)

    def test_policy_and_contract_substitution_fail_before_promotion(self):
        run_local_workflow(self.root, stop_after="built")
        (self.root / "task-contract.json").write_text("{}\n")
        with self.assertRaises(PermissionError):
            run_local_workflow(self.root)
        self.assertEqual(json.loads((self.root / "binding.json").read_bytes())["base_sha"],
                         json.loads((self.root / "workflow.json").read_bytes())["baseline_sha"])

    def test_tampered_saved_evaluation_is_not_replaced_or_promoted(self):
        run_local_workflow(self.root, stop_after="built")
        graph = self.open_graph()
        try:
            node = graph.get_node(TASK)
            claim = graph.claim_evidence(TASK, node["version"], node["active_artifact_id"], "hermes-evaluator", 600)
            _write_json(self.root / "evaluation-request.json", {
                "artifact_id": node["active_artifact_id"], "claim_id": claim["artifact"]["claim_id"],
                "previous_ledger_hash": None,
            })
        finally:
            graph.connection.close()
        _evaluate_sample(self.root)
        path = self.root / "evaluation.json"
        invalid = json.loads(path.read_bytes())
        invalid["signature"] = "AAAA"
        _write_json(path, invalid)
        original = path.read_bytes()
        with patch("control_plane.local_workflow._run", side_effect=AssertionError("must not re-sign")):
            with self.assertRaises(PermissionError):
                run_local_workflow(self.root, stop_after="evaluated")
        self.assertEqual(path.read_bytes(), original)
        with sqlite3.connect(self.root / "graph.sqlite") as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM evaluation_outcomes").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM integration_attempts").fetchone()[0], 0)

    def generic_workspace(self, timeout=2):
        run_local_workflow(self.root, stop_after="built")
        repo = Path(self.temporary.name) / "custom"
        subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(self.root / "canonical"), str(repo)], check=True)
        contract = json.loads((self.root / "task-contract.json").read_bytes())
        contract["timeout_seconds"] = timeout
        contract_path = Path(self.temporary.name) / "custom-contract.json"
        _write_json(contract_path, contract)
        return repo, contract_path, Path(self.temporary.name) / "custom-output"

    def test_reusable_worker_denies_real_out_of_scope_edit(self):
        repo, contract, output = self.generic_workspace()
        with self.assertRaisesRegex(PermissionError, "outside allowed_paths"):
            produce_worker_artifact(repo, contract, output, 1,
                [sys.executable, "-I", "-B", "-c", "from pathlib import Path; Path('forbidden.txt').write_text('bad')"])
        self.assertFalse(output.exists())

    def test_reusable_worker_requires_budget_idempotency_and_narrow_scope(self):
        repo, contract, output = self.generic_workspace()
        original = json.loads(contract.read_bytes())
        for alteration in ({"budget": {}}, {"idempotency_key": ""}, {"allowed_paths": ["."]}, {"allowed_paths": ["src//"]}):
            with self.subTest(alteration=alteration):
                _write_json(contract, {**original, **alteration})
                with self.assertRaises(ValueError):
                    produce_worker_artifact(repo, contract, output, 1, ["false"])

    def test_reusable_worker_denies_out_of_scope_mode_change(self):
        repo, contract, output = self.generic_workspace()
        code = "from pathlib import Path; p=Path('tests/check_greeting.py'); p.chmod(p.stat().st_mode | 0o111)"
        with self.assertRaisesRegex(PermissionError, "outside allowed_paths"):
            produce_worker_artifact(repo, contract, output, 1, [sys.executable, "-I", "-B", "-c", code])
        self.assertFalse(output.exists())

    def test_worker_output_and_descendant_lifetime_are_bounded(self):
        repo, contract, output = self.generic_workspace(timeout=1)
        pid_file = Path(self.temporary.name) / "child.pid"
        code = ("import os,time; from pathlib import Path; child=os.fork(); "
                + "\nif child == 0:\n os.setsid(); Path(" + repr(str(pid_file)) + ").write_text(str(os.getpid())); time.sleep(60)"
                + "\nelse:\n time.sleep(60)")
        with self.assertRaises(subprocess.TimeoutExpired):
            produce_worker_artifact(repo, contract, output, 1, [sys.executable, "-I", "-B", "-c", code])
        self.assertFalse((Path("/proc") / pid_file.read_text()).exists())
        with self.assertRaises(RequiredTestOutputLimitExceeded):
            produce_worker_artifact(repo, contract, output, 1,
                                   [sys.executable, "-I", "-B", "-c", "print('x' * 300000)"])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
