import datetime as dt
import tempfile
import unittest
import subprocess
import json
from pathlib import Path

from control_plane.task_controller import (
    TaskController,
    authorization_subject_hash,
    validate_contract,
    verify_authorization_envelope,
)
from control_plane.authorization_issuer import issue


def contract(**overrides):
    now = dt.datetime.now(dt.timezone.utc)
    value = {
        "project_id": "oss", "task_id": "task-001", "requester_identity": "slack:U123",
        "authorization": {"decision": "allow", "policy_version": "slack-rbac-v1",
                          "authorized_at": (now - dt.timedelta(seconds=1)).isoformat(),
                          "expires_at": (now + dt.timedelta(minutes=10)).isoformat(),
                          "subject_sha256": "0" * 64,
                          "evidence_sha256": "b" * 64,
                          "signature_sha256": "c" * 64},
        "idempotency_key": "idem-000000000001", "repo": "codex_opensource", "base_sha": "a" * 40,
        "objective": "verify controller", "acceptance_criteria": ["tests pass"],
        "required_tests": ["python -m unittest"], "allowed_paths": ["control_plane/"],
        "allowed_tools": ["python"], "forbidden_actions": ["external writes"],
        "budget": {"max_cost_usd": 1.0, "max_tokens": 1000},
        "deadline": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat(),
        "timeout_seconds": 60, "max_iterations": 1, "cancellation_token": "cancel-0000000001",
        "builder_identity": "hermes-oss", "evaluator_contract_id": "eval-v1",
    }
    value.update(overrides)
    value["authorization"]["subject_sha256"] = authorization_subject_hash(value)
    return value


def envelope(value):
    authorization = value["authorization"]
    return {
        "decision": "allow",
        "policy_version": authorization["policy_version"],
        "subject_sha256": authorization["subject_sha256"],
        "requester_identity": value["requester_identity"],
        "project_id": value["project_id"],
        "builder_identity": value["builder_identity"],
        "repo": value["repo"],
        "base_sha": value["base_sha"],
        "allowed_paths": value["allowed_paths"],
        "allowed_tools": value["allowed_tools"],
        "budget": value["budget"],
        "authorized_at": authorization["authorized_at"],
        "expires_at": authorization["expires_at"],
    }


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.controller = TaskController(Path(self.temp.name) / "tasks.db")

    def tearDown(self):
        self.temp.cleanup()

    def test_idempotent_duplicate_returns_same_task(self):
        task_contract = contract()
        first = self.controller.submit(task_contract)
        second = self.controller.submit(task_contract)
        self.assertEqual(first["task_id"], second["task_id"])
        self.assertNotIn("contract_json", first)

    def test_database_is_private(self):
        mode = (Path(self.temp.name) / "tasks.db").stat().st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_idempotency_conflict_fails_closed(self):
        self.controller.submit(contract())
        with self.assertRaisesRegex(ValueError, "different input"):
            self.controller.submit(contract(objective="changed"))

    def test_cross_project_builder_identity_denied(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_contract(contract(builder_identity="hermes-business"))

    def test_expired_authorization_denied(self):
        now = dt.datetime.now(dt.timezone.utc)
        authorization = {"decision": "allow", "policy_version": "v1",
                         "authorized_at": (now - dt.timedelta(hours=2)).isoformat(),
                         "expires_at": (now - dt.timedelta(hours=1)).isoformat(),
                         "subject_sha256": "0" * 64,
                         "evidence_sha256": "c" * 64,
                         "signature_sha256": "d" * 64}
        with self.assertRaisesRegex(ValueError, "not currently valid"):
            validate_contract(contract(authorization=authorization))

    def test_authorization_envelope_is_bound_to_full_subject(self):
        value = contract()
        verify_authorization_envelope(value, envelope(value))
        altered = dict(envelope(value))
        altered["repo"] = "codex_business"
        with self.assertRaisesRegex(ValueError, "does not match"):
            verify_authorization_envelope(value, altered)

    def test_authorization_subject_detects_contract_mutation(self):
        value = contract()
        value["objective"] = "mutated after approval"
        with self.assertRaisesRegex(ValueError, "subject hash"):
            validate_contract(value)

    def test_repo_and_path_and_tools_are_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "repo does not match"):
            validate_contract(contract(repo="codex_business"))
        with self.assertRaisesRegex(ValueError, "relative, scoped"):
            validate_contract(contract(allowed_paths=["../escape"]))
        with self.assertRaisesRegex(ValueError, "allowed_tools"):
            validate_contract(contract(allowed_tools=[]))

    def test_root_issuer_signs_exact_bound_envelope(self):
        if __import__("os").geteuid() != 0:
            self.skipTest("root-only issuer")
        root = Path(self.temp.name)
        private_key = root / "private.pem"
        public_key = root / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key], check=True)
        subprocess.run(["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key], check=True)
        value = contract()
        finalized = issue(value, private_key, root / "authorizations", 60)
        evidence_hash = finalized["authorization"]["evidence_sha256"]
        evidence_path = root / "authorizations" / f"{evidence_hash}.json"
        signature_path = root / "authorizations" / f"{evidence_hash}.sig"
        verify_authorization_envelope(finalized, json.loads(evidence_path.read_text()))
        subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", public_key, "-sigfile", signature_path, "-in", evidence_path],
            check=True,
            capture_output=True,
        )

    def test_optimistic_version_and_terminal_mutation(self):
        self.controller.submit(contract())
        authorized = self.controller.transition("task-001", 0, "AUTHORIZED", "rbac pass")
        with self.assertRaisesRegex(ValueError, "version conflict"):
            self.controller.transition("task-001", 0, "NORMALIZED", "stale")
        rejected = self.controller.transition("task-001", authorized["version"], "REJECTED", "policy")
        with self.assertRaisesRegex(ValueError, "forbidden transition"):
            self.controller.transition("task-001", rejected["version"], "AUTHORIZED", "revive")

    def test_budget_exhaustion_fails_before_lease(self):
        self.controller.submit(contract())
        row = self.controller.get("task-001")
        for state in ("AUTHORIZED", "NORMALIZED", "PLANNED", "QUEUED"):
            row = self.controller.transition("task-001", row["version"], state, "ok")
        self.controller.record_usage("task-001", 1.0, 0)
        row = self.controller.transition("task-001", row["version"], "LEASED", "try")
        self.assertEqual(row["state"], "FAILED_BUDGET")

    def test_startup_recovery_terminalizes_orphaned_execution(self):
        self.controller.submit(contract())
        row = self.controller.get("task-001")
        for state in ("AUTHORIZED", "NORMALIZED", "PLANNED", "QUEUED", "LEASED", "RUNNING"):
            row = self.controller.transition("task-001", row["version"], state, "prepare orphan")
        recovered = self.controller.recover_orphaned_executions()
        self.assertEqual(len(recovered), 1)
        self.assertEqual(recovered[0]["state"], "FAILED_PERMANENT")
        self.assertTrue(self.controller.verify_event_chain("task-001"))
        self.assertEqual(self.controller.recover_orphaned_executions(), [])

    def test_iteration_limit_stops_rework(self):
        self.controller.submit(contract())
        row = self.controller.get("task-001")
        for state in ("AUTHORIZED", "NORMALIZED", "PLANNED", "QUEUED", "LEASED", "RUNNING", "EVIDENCE_PENDING", "EVALUATING", "REWORK_REQUESTED", "QUEUED"):
            row = self.controller.transition("task-001", row["version"], state, "test")
        row = self.controller.transition("task-001", row["version"], "LEASED", "retry")
        self.assertEqual(row["state"], "FAILED_STAGNATION")

    def test_cancellation_token_and_terminal_idempotency(self):
        self.controller.submit(contract())
        with self.assertRaisesRegex(ValueError, "invalid"):
            self.controller.cancel("task-001", "wrong")
        cancelled = self.controller.cancel("task-001", "cancel-0000000001")
        again = self.controller.cancel("task-001", "cancel-0000000001")
        self.assertEqual(cancelled["version"], again["version"])
        self.assertTrue(self.controller.verify_event_chain("task-001"))

    def test_event_hash_chain_verifies_and_detects_tamper(self):
        self.controller.submit(contract())
        self.controller.transition("task-001", 0, "AUTHORIZED", "rbac evidence")
        self.assertTrue(self.controller.verify_event_chain("task-001"))
        self.controller.connection.execute("UPDATE task_events SET reason='tampered' WHERE version=1")
        self.assertFalse(self.controller.verify_event_chain("task-001"))
