import datetime as dt
import tempfile
import unittest
from pathlib import Path

from control_plane.controller_service import AUTONOMY_POLICY, MAX_CODEX_POLICY, authorize, dispatch, validate_bounded_authorization_request
from control_plane.task_controller import TaskController, authorization_subject_hash


def contract():
    now = dt.datetime.now(dt.timezone.utc)
    value = {
        "project_id": "oss", "task_id": "service-001", "requester_identity": "slack:U1",
        "authorization": {"decision": "allow", "policy_version": "v1",
                          "authorized_at": (now - dt.timedelta(seconds=1)).isoformat(),
                          "expires_at": (now + dt.timedelta(minutes=5)).isoformat(),
                          "subject_sha256": "0" * 64, "evidence_sha256": "a" * 64,
                          "signature_sha256": "b" * 64},
        "idempotency_key": "service-idempotency-001", "repo": "codex_opensource", "base_sha": "c" * 40,
        "objective": "test", "acceptance_criteria": ["pass"], "required_tests": ["unit"],
        "allowed_paths": ["src/"], "allowed_tools": ["apply_patch"], "forbidden_actions": ["network"],
        "budget": {"max_cost_usd": 1, "max_tokens": 100},
        "deadline": (now + dt.timedelta(hours=1)).isoformat(), "timeout_seconds": 60,
        "max_iterations": 1, "cancellation_token": "cancel-service-001",
        "builder_identity": "hermes-oss", "evaluator_contract_id": "eval-v1",
    }
    value["authorization"]["subject_sha256"] = authorization_subject_hash(value)
    return value


def envelope(value):
    authorization = value["authorization"]
    return {
        "decision": "allow", "policy_version": authorization["policy_version"],
        "subject_sha256": authorization["subject_sha256"],
        "requester_identity": value["requester_identity"], "project_id": value["project_id"],
        "builder_identity": value["builder_identity"], "repo": value["repo"], "base_sha": value["base_sha"],
        "allowed_paths": value["allowed_paths"], "allowed_tools": value["allowed_tools"],
        "budget": value["budget"], "authorized_at": authorization["authorized_at"],
        "expires_at": authorization["expires_at"],
    }


class ControllerServicePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.controller = TaskController(Path(self.temp.name) / "tasks.db")

    def tearDown(self):
        self.temp.cleanup()

    def test_unknown_and_cross_project_callers_are_denied(self):
        with self.assertRaises(PermissionError):
            authorize("oss", "hermes-business", {"action": "get"})
        with self.assertRaises(PermissionError):
            dispatch(self.controller, "oss", "hermes-oss", {"action": "submit", "contract": {**contract(), "project_id": "business"}})

    def test_builder_cannot_self_certify_or_complete(self):
        for target in ("EVALUATING", "PASSED", "COMPLETED", "HUMAN_APPROVAL_PENDING"):
            with self.assertRaises(PermissionError, msg=target):
                authorize("oss", "hermes-oss", {"action": "transition", "target": target})

    def test_evaluator_cannot_submit_use_budget_or_complete(self):
        for action in ("submit", "usage", "cancel"):
            with self.assertRaises(PermissionError, msg=action):
                authorize("oss", "hermes-evaluator", {"action": action})
        with self.assertRaises(PermissionError):
            authorize("oss", "hermes-evaluator", {"action": "transition", "target": "COMPLETED"})

    def test_builder_can_submit_and_only_execute_states(self):
        value = contract()
        result = dispatch(self.controller, "oss", "hermes-oss", {"action": "submit", "contract": value, "envelope": envelope(value)})
        self.assertEqual(result["state"], "RECEIVED")
        self.assertEqual(authorize("oss", "hermes-oss", {"action": "transition", "target": "RUNNING"}), "builder")

    def test_direct_submit_cannot_bypass_authorization_envelope(self):
        value = contract()
        altered = envelope(value)
        altered["objective"] = "extra field"
        with self.assertRaisesRegex(ValueError, "does not match"):
            dispatch(self.controller, "oss", "hermes-oss", {"action": "submit", "contract": value, "envelope": altered})

    def bounded_draft(self):
        value = contract()
        value["authorization"] = {"decision": "allow", "policy_version": AUTONOMY_POLICY}
        value["allowed_paths"] = ["evidence/slack-task.txt"]
        value["allowed_tools"] = ["apply_patch", "shell"]
        value["forbidden_actions"] = ["external writes", "secret access", "merge", "release", "deployment"]
        value["budget"] = {"max_cost_usd": 1.0, "max_tokens": 100000}
        value["timeout_seconds"] = 300
        value["max_iterations"] = 1
        return value

    def test_bounded_slack_authorization_accepts_isolated_task(self):
        value = self.bounded_draft()
        validate_bounded_authorization_request(
            "oss", "hermes-oss", value,
            {"repo": value["repo"], "base_sha": value["base_sha"]},
        )

    def test_bounded_slack_authorization_denies_privilege_expansion(self):
        mutations = [
            ("allowed_paths", ["../etc/passwd"]),
            ("allowed_paths", [".git/config"]),
            ("allowed_tools", ["terminal"]),
            ("budget", {"max_cost_usd": 2, "max_tokens": 100000}),
            ("max_iterations", 2),
            ("forbidden_actions", ["external writes"]),
        ]
        for key, replacement in mutations:
            value = self.bounded_draft()
            value[key] = replacement
            with self.assertRaises(PermissionError, msg=key):
                validate_bounded_authorization_request(
                    "oss", "hermes-oss", value,
                    {"repo": value["repo"], "base_sha": value["base_sha"]},
                )

    def test_max_codex_policy_prefers_results_over_efficiency(self):
        value = self.bounded_draft()
        value["authorization"]["policy_version"] = MAX_CODEX_POLICY
        value["budget"] = {"max_cost_usd": 1_000_000, "max_tokens": 1_000_000_000}
        value["timeout_seconds"] = 21600
        value["max_iterations"] = 5
        value["deadline"] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=23)).isoformat()
        validate_bounded_authorization_request(
            "oss", "hermes-oss", value,
            {"repo": value["repo"], "base_sha": value["base_sha"]},
        )


if __name__ == "__main__":
    unittest.main()
