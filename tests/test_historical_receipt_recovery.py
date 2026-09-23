"""Recovery uses sealed historical checks and the admitted durable bundle."""
import copy
import json
import os
import shutil
import sqlite3
import unittest
from unittest.mock import patch

import test_evaluation_broker as broker_fixture
import test_repository_workflow as workflow_fixture
from control_plane.evaluation_broker import (
    EvaluationBroker, _receipt_request, verify_public_receipt_store,
)
from control_plane.isolated_runner import execute_candidate_tests
from control_plane.sealed_protocol import canonical, digest


class HistoricalReceiptRecoveryTests(unittest.TestCase):
    def _built(self, *, worker_invocations=1):
        initialize = workflow_fixture.RepositoryWorkflowTests.initialize

        def initialize_with_budget(fixture):
            fixture.task["limits"]["worker_invocations"] = worker_invocations
            fixture.task_path.write_text(json.dumps(fixture.task))
            return initialize(fixture)

        if worker_invocations == 1:
            fixture, workflow = broker_fixture.BrokerWorkflowIntegrationTests._fixture(self)
        else:
            with patch.object(workflow_fixture.RepositoryWorkflowTests, "initialize", initialize_with_budget):
                fixture, workflow = broker_fixture.BrokerWorkflowIntegrationTests._fixture(self)
        with patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}), \
             patch("control_plane.worker_provider.launch_worker", side_effect=fixture.fake_worker):
            result = workflow.run_repository_workflow(fixture.root, stop_after="built")
        self.assertEqual(result["task_state"], "EVIDENCE_PENDING")
        self.assertEqual(fixture.launches, 1)
        return fixture, workflow

    def _recover_with_damaged_candidate_object(self, *, delete):
        fixture, workflow = self._built()
        attempt = fixture.root / "attempts/repair-value-attempt-1"
        required = json.loads((attempt / "required-receipt.json").read_bytes())
        candidate = required["candidate_sha"]
        loose = attempt / "checkout/.git/objects" / candidate[:2] / candidate[2:]
        self.assertTrue(loose.is_file(), "fixture must damage the actual candidate commit")
        self.assertGreater(loose.stat().st_size, 0)
        if delete:
            loose.unlink()
        else:
            loose.chmod(0o600)
            loose.write_bytes(b"")
        with patch("control_plane.worker_provider.provider_preflight", side_effect=AssertionError("recovery relaunched provider")), \
             patch("control_plane.worker_provider.launch_worker", side_effect=AssertionError("recovery relaunched worker")), \
             patch("control_plane.isolated_runner.execute_candidate_tests", wraps=execute_candidate_tests) as execute:
            result = workflow.run_repository_workflow(fixture.root, "recover")
        self.assertEqual(result["task_state"], "INTEGRATED")
        self.assertEqual(result["workflow_state"], "promoted")
        self.assertEqual(fixture.launches, 1)
        self.assertEqual([call.args[0]["kind"] for call in execute.call_args_list], ["independent"])
        self.assertEqual(json.loads((attempt / "required-receipt.json").read_bytes()), required)
        public = verify_public_receipt_store(fixture.root, fixture.profile)
        self.assertEqual(len(public["receipt_ids"]), 2)
        self.assertEqual(public["rejection_ids"], [])
        self.assertEqual(workflow._git(fixture.root / "canonical", "rev-parse", "refs/ai-ops/accepted/opensource"), candidate)

    def test_full_recovery_with_zeroed_candidate_commit_object(self):
        self._recover_with_damaged_candidate_object(delete=False)

    def test_full_recovery_with_deleted_candidate_commit_object(self):
        self._recover_with_damaged_candidate_object(delete=True)

    def _capture_evaluation_request(self, fixture, workflow):
        class CapturedEvaluation(RuntimeError):
            pass

        requests = []

        def capture(request, profile):
            requests.append(copy.deepcopy(request))
            raise CapturedEvaluation("evaluation claim persisted")

        with patch("control_plane.evaluation_broker.evaluate_artifact", side_effect=capture):
            with self.assertRaises(CapturedEvaluation):
                workflow.run_repository_workflow(fixture.root, "recover")
        self.assertEqual(len(requests), 1)
        return requests[0]

    def test_broker_evaluation_with_entire_old_checkout_absent(self):
        fixture, workflow = self._built()
        request = self._capture_evaluation_request(fixture, workflow)
        checkout = fixture.root / "attempts/repair-value-attempt-1/checkout"
        shutil.rmtree(checkout)
        broker = EvaluationBroker(fixture.root, fixture.profile)
        self.addCleanup(broker.close)
        with patch("control_plane.worker_provider.launch_worker", side_effect=AssertionError("broker relaunched worker")), \
             patch("control_plane.isolated_runner.execute_candidate_tests", wraps=execute_candidate_tests) as execute:
            result = broker.handle("sign-evaluation", request)
        self.assertEqual(result["verdict"], "PASS")
        self.assertTrue(result["signature"])
        self.assertEqual(fixture.launches, 1)
        self.assertFalse(checkout.exists())
        self.assertEqual([call.args[0]["kind"] for call in execute.call_args_list], ["independent"])
        public = verify_public_receipt_store(fixture.root, fixture.profile)
        self.assertEqual(len(public["receipt_ids"]), 2)
        self.assertEqual(public["rejection_ids"], [])
        # This exercises the broker boundary only. G deliberately still requires
        # reservation checkout directories, independently of historical checks.

    def _seal_altered_required(self, fixture, changes, *, reconstruct_request=False):
        pointer = fixture.root / "attempts/repair-value-attempt-1/required-receipt.json"
        original = json.loads(pointer.read_bytes())
        original_path = fixture.root / ".broker-receipts/receipts" / original["receipt_id"] / "receipt.json"
        original_bytes = original_path.read_bytes()
        altered = copy.deepcopy(original)
        altered.update(changes)
        broker = EvaluationBroker(fixture.root, fixture.profile)
        try:
            if reconstruct_request:
                altered["request_sha256"] = digest(_receipt_request(altered, broker.frozen))
            altered["receipt_id"] = digest({key: value for key, value in altered.items() if key != "receipt_id"})
            self.assertNotEqual(altered["receipt_id"], original["receipt_id"])
            outputs = {result[stream]["relative_path"]: broker.store.output(original["receipt_id"], result[stream]["relative_path"])
                       for result in original["results"] for stream in ("stdout", "stderr")}
            self.assertEqual(broker.store.seal_receipt(altered, outputs), altered)
            self.assertEqual(broker.store.fetch(original["receipt_id"]), original)
        finally:
            broker.close()
        # The graph owns this pointer; the original authority record is immutable.
        pointer.write_bytes(canonical(altered))
        self.assertEqual(original_path.read_bytes(), original_bytes)
        self.addCleanup(lambda: self.assertEqual(original_path.read_bytes(), original_bytes))
        return altered

    def _assert_recovery_denied_before_execution(self, fixture, workflow, *, message=None):
        with patch("control_plane.isolated_runner.execute_candidate_tests", side_effect=AssertionError("invalid history reached test execution")) as execute, \
             patch("control_plane.evaluation_broker.signer_main", side_effect=AssertionError("invalid history reached signing")) as signer, \
             patch("control_plane.isolated_runner.run_signer_process", side_effect=AssertionError("invalid history reached isolated signing")) as isolated_signer, \
             patch("control_plane.worker_provider.launch_worker", side_effect=AssertionError("invalid history relaunched worker")) as worker:
            if message is None:
                with self.assertRaises((PermissionError, ValueError, FileNotFoundError)):
                    workflow.run_repository_workflow(fixture.root, "recover")
            else:
                with self.assertRaisesRegex(PermissionError, message):
                    workflow.run_repository_workflow(fixture.root, "recover")
            execute.assert_not_called()
            signer.assert_not_called()
            isolated_signer.assert_not_called()
            worker.assert_not_called()
        self.assertEqual(fixture.launches, 1)
        connection = sqlite3.connect(fixture.root / "state/graph.sqlite")
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM evaluation_outcomes").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT state FROM nodes WHERE node_id=?", (fixture.task["task_id"],)).fetchone()[0], "EVALUATING")
        finally:
            connection.close()

    def test_sealed_historical_request_hash_mismatch_rejects_before_execution(self):
        fixture, workflow = self._built()
        self._seal_altered_required(fixture, {"request_sha256": "0" * 64})
        self._assert_recovery_denied_before_execution(fixture, workflow, message="request/workspace binding mismatch")

    def test_sealed_other_candidate_rejects_even_with_exact_historical_request_hash(self):
        fixture, workflow = self._built()
        self._seal_altered_required(fixture, {"candidate_sha": fixture.base}, reconstruct_request=True)
        self._assert_recovery_denied_before_execution(fixture, workflow, message="another artifact candidate")

    def test_sealed_other_admissible_attempt_rejects_before_execution(self):
        fixture, workflow = self._built(worker_invocations=3)
        name = "repair-value-attempt-2-required"
        self._seal_altered_required(fixture, {"run_id": name, "request_id": name}, reconstruct_request=True)
        self._assert_recovery_denied_before_execution(fixture, workflow, message="attempt")

    def test_sealed_independent_kind_cannot_stand_in_for_required_history(self):
        fixture, workflow = self._built()
        self._seal_altered_required(fixture, {"kind": "independent"})
        self._assert_recovery_denied_before_execution(fixture, workflow, message="kind|attempt|required")

    def test_sealed_pre_tree_mismatch_rejects_before_independent_execution(self):
        fixture, workflow = self._built()
        self._seal_altered_required(fixture, {"pre_tree_sha256": "0" * 64, "post_tree_sha256": "0" * 64})
        self._assert_recovery_denied_before_execution(fixture, workflow, message="candidate|tree|bytes")

    def test_unsealed_receipt_pointer_rejects_before_execution(self):
        fixture, workflow = self._built()
        pointer = fixture.root / "attempts/repair-value-attempt-1/required-receipt.json"
        value = json.loads(pointer.read_bytes())
        value["request_sha256"] = "0" * 64
        value["receipt_id"] = digest({key: item for key, item in value.items() if key != "receipt_id"})
        pointer.write_bytes(canonical(value))
        self._assert_recovery_denied_before_execution(fixture, workflow)

    def test_tampered_sealed_receipt_bytes_reject_before_execution(self):
        fixture, workflow = self._built()
        pointer = fixture.root / "attempts/repair-value-attempt-1/required-receipt.json"
        elapsed = json.loads(pointer.read_bytes())["elapsed_ms"]
        altered = self._seal_altered_required(fixture, {"elapsed_ms": elapsed + 1})
        sealed = fixture.root / ".broker-receipts/receipts" / altered["receipt_id"] / "receipt.json"
        # Fault injection targets a newly sealed fixture copy, preserving the
        # genuine historical receipt and deliberately invalidating its digest.
        altered["candidate_sha"] = fixture.base
        os.chmod(sealed, 0o600)
        sealed.write_bytes(canonical(altered))
        os.chmod(sealed, 0o444)
        self._assert_recovery_denied_before_execution(fixture, workflow)


if __name__ == "__main__":
    unittest.main()
