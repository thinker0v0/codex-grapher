import unittest
import datetime as dt
import inspect

from control_plane import project_router
from control_plane.project_router import ROUTES, dispatch, normalize_contract
from control_plane.controller_service import AUTONOMY_POLICY


def bounded_contract(profile):
    now = dt.datetime.now(dt.timezone.utc)
    value = {
        "project_id": profile, "task_id": "router-001", "requester_identity": "slack:U1",
        "authorization": {"decision": "allow", "policy_version": AUTONOMY_POLICY},
        "idempotency_key": "router-idempotency-001", "repo": f"repo-{profile}", "base_sha": "c" * 40,
        "objective": "test", "acceptance_criteria": ["pass"], "required_tests": ["unit"],
        "allowed_paths": ["evidence/router.txt"], "allowed_tools": ["apply_patch", "shell"],
        "forbidden_actions": ["external writes", "secret access", "merge", "release", "deployment"],
        "budget": {"max_cost_usd": 1, "max_tokens": 1000},
        "deadline": (now + dt.timedelta(minutes=30)).isoformat(), "timeout_seconds": 60,
        "max_iterations": 1, "cancellation_token": "cancel-router-001",
        "builder_identity": f"hermes-{profile}", "evaluator_contract_id": "eval-router-v1",
    }
    return value, {"repo": value["repo"], "base_sha": value["base_sha"]}


class ProjectRouterTests(unittest.TestCase):
    def test_router_runs_four_isolated_routes_concurrently(self):
        source = inspect.getsource(project_router.serve)
        self.assertIn("ThreadPoolExecutor(max_workers=4", source)

    def test_four_public_routes_map_to_isolated_profiles(self):
        self.assertEqual(ROUTES["nomad"], "fin-korea")
        self.assertEqual(ROUTES["opensource"], "oss")
        self.assertEqual(ROUTES["business"], "business")
        self.assertEqual(ROUTES["hynix"], "hynix")

    def test_normalizer_overwrites_privileged_identity_and_binding(self):
        value, binding = bounded_contract("hynix")
        value["project_id"] = "oss"
        value["builder_identity"] = "hermes-oss"
        profile, normalized = normalize_contract("hynix", value, binding)
        self.assertEqual(profile, "hynix")
        self.assertEqual(normalized["builder_identity"], "hermes-hynix")
        self.assertEqual(normalized["repo"], binding["repo"])

    def test_unknown_route_and_non_router_identity_fail_closed(self):
        value, binding = bounded_contract("oss")
        with self.assertRaises(PermissionError):
            normalize_contract("unknown", value, binding)
        with self.assertRaises(PermissionError):
            dispatch("hermes-business", {"action": "status", "route": "business"})


if __name__ == "__main__":
    unittest.main()
