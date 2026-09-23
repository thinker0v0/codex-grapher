import copy
import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from control_plane.evaluation_policy import load_task_policy, validate_task_policy
from control_plane.evidence_ingress import IngressArtifact
from control_plane.graph_bootstrap import apply_database
from control_plane.graph_planner import plan_goal
from control_plane.graph_schema import SchemaError
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_graph import ProjectGraph, digest
from control_plane.project_integrator import ProjectIntegrator, sha256_file, verify_evaluation
from tests.evaluation_helpers import generate_keypair, make_evaluation, resign
from tests import test_project_integrator as integrator_fixtures


def policy_document():
    return {
        "schema_version": 1, "name": "local-task",
        "sections": {
            "correctness": {"minimum": 57, "maximum": 60},
            "scope": {"minimum": 38, "maximum": 40},
        },
        "mandatory_gates": ["required_tests", "authorized_scope"], "threshold": 97,
    }


class EvaluationPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.path = self.root / "task-policy.json"
        self.path.write_text(json.dumps(policy_document()) + "\n")
        self.policy = load_task_policy(self.path)
        self.private, self.public = generate_keypair(self.root)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text('{"tests":"pass"}\n')

    def evaluation(self):
        value = make_evaluation(
            self.private, self.manifest, self.path,
            task_id="task", contract_id="contract", candidate_sha="b" * 40,
        )
        value.update({
            "schema_version": 4, "policy_sha256": self.policy.sha256,
            "section_scores": {"correctness": 60, "scope": 40},
            "mandatory_gates": {gate: "PASS" for gate in self.policy.mandatory_gates},
        })
        return resign(value, self.private)

    def verify(self, value, policy=...):
        verify_evaluation(
            value, self.public, self.manifest, self.policy.sha256,
            expected_task_id="task", expected_contract_id="contract",
            evaluation_policy=self.policy if policy is ... else policy,
        )

    def graph(self):
        database = self.root / "graph.db"
        apply_database(database)
        graph = ProjectGraph(database, self.public, self.policy.sha256,
                             evaluation_policy=self.policy)
        self.addCleanup(graph.connection.close)
        graph.create_goal("goal", "opensource", "local task", "a" * 40)
        graph.add_node("task", "goal", "BUILD", {"evaluator_contract_id": "contract"}, ["src/"])
        return graph

    def claim(self, graph):
        row = graph.lease("task", 0, "hermes-oss", 60)
        row = graph.start("task", row["version"], row["lease_id"], "hermes-oss")
        manifest_hash = sha256_file(self.manifest)
        artifact = IngressArtifact(
            f"sha256:{manifest_hash}", manifest_hash,
            f"sha256/{manifest_hash[:2]}/{manifest_hash}/manifest.json",
            "task", 1, "oss", "a" * 40, "b" * 40, "c" * 64,
        )
        row = graph.record_ingressed_evidence("task", row["version"], artifact)["node"]
        claimed = graph.claim_evidence("task", row["version"], artifact.artifact_id,
                                       "hermes-evaluator", 60)
        value = self.evaluation()
        value["artifact_id"] = artifact.artifact_id
        value["claim_id"] = claimed["artifact"]["claim_id"]
        return artifact, claimed["node"], resign(value, self.private)

    def test_exact_file_bytes_and_immutable_fields(self):
        self.assertEqual(self.policy.sha256, hashlib.sha256(self.path.read_bytes()).hexdigest())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.policy.threshold = 95
        with self.assertRaises(TypeError):
            self.policy.sections[0] = ("correctness", 0, 100)
        before = self.policy.sha256
        self.path.write_text(json.dumps(policy_document(), indent=2))
        self.assertNotEqual(load_task_policy(self.path).sha256, before)
        validate_task_policy(self.policy, before)

    def test_rejects_malformed_and_degenerate_policies(self):
        mutations = [
            ("schema_version", True), ("schema_version", 2), ("name", " "),
            ("sections", {}), ("sections", {"": {"minimum": 95, "maximum": 100}}),
            ("sections", {"x": {"minimum": 95, "maximum": 99}}),
            ("sections", {"x": {"minimum": 101, "maximum": 100}}),
            ("sections", {"x": {"minimum": True, "maximum": 100}}),
            ("sections", {"x": {"minimum": 0, "maximum": 0}}),
            ("sections", {"x": {"minimum": 0, "maximum": float("inf")}}),
            ("sections", {"x": {"minimum": 95, "maximum": 100, "extra": 1}}),
            ("mandatory_gates", []), ("mandatory_gates", ["x", "x"]),
            ("mandatory_gates", [True]), ("mandatory_gates", [""]),
            ("threshold", True), ("threshold", 94), ("threshold", 101),
            ("threshold", float("nan")), ("threshold", 10**1000),
            ("extra", "not allowed"),
        ]
        for field, invalid in mutations:
            with self.subTest(field=field, invalid=repr(invalid)[:80]):
                value = policy_document()
                value[field] = invalid
                self.path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_task_policy(self.path)
        for raw in ('{"schema_version":1,"schema_version":1}', '[]', '{bad'):
            self.path.write_text(raw)
            with self.assertRaises(ValueError):
                load_task_policy(self.path)

    def test_duplicate_nested_keys_and_symlinks_rejected(self):
        raw = json.dumps(policy_document()).replace('"minimum": 57', '"minimum": 57, "minimum": 0')
        self.path.write_text(raw)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            load_task_policy(self.path)
        link = self.root / "link.json"
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            load_task_policy(link)

    def test_v4_verifies_only_in_explicit_task_mode(self):
        value = self.evaluation()
        self.verify(value)
        with self.assertRaises(PermissionError):
            self.verify(value, None)
        legacy = make_evaluation(self.private, self.manifest, self.path,
                                 task_id="task", contract_id="contract", candidate_sha="b" * 40)
        self.verify(legacy, None)
        with self.assertRaises(PermissionError):
            self.verify(legacy)

    def test_signed_task_result_rejects_wrong_schema_policy_scores_and_gates(self):
        mutations = [
            ("schema_version", True), ("schema_version", 3), ("schema_version", 4.0),
            ("policy_sha256", "f" * 64), ("policy_sha256", "malformed"),
            ("rubric_sha256", "f" * 64), ("mandatory_gates", {"HG1": "PASS"}),
            ("mandatory_gates", {gate: "UNPROVEN" for gate in self.policy.mandatory_gates}),
            ("section_scores", {"correctness": 59, "wrong": 40}),
            ("section_scores", {"correctness": 61, "scope": 39}),
            ("section_scores", {"correctness": 56, "scope": 40}),
            ("section_scores", {"correctness": True, "scope": 40}),
            ("section_scores", {"correctness": float("nan"), "scope": 40}),
            ("section_scores", {"correctness": 10**1000, "scope": 40}),
            ("total_score", 10**1000), ("verdict", "NOT_PASS"),
            ("evaluator_identity", "hermes-oss"), ("policy", policy_document()),
        ]
        for field, invalid in mutations:
            with self.subTest(field=field, invalid=repr(invalid)[:80]):
                value = self.evaluation()
                value[field] = invalid
                if field == "section_scores":
                    value["total_score"] = sum(invalid.values())
                with self.assertRaises(PermissionError):
                    self.verify(resign(value, self.private))

    def test_task_threshold_and_signature_are_enforced(self):
        value = self.evaluation()
        value["section_scores"] = {"correctness": 58, "scope": 38}
        value["total_score"] = 96
        with self.assertRaisesRegex(PermissionError, "threshold"):
            self.verify(resign(value, self.private))
        value = self.evaluation()
        value["evaluation_id"] = "unsigned mutation"
        with self.assertRaises(PermissionError):
            self.verify(value)

    def test_policy_object_field_tampering_cannot_change_verifier(self):
        policy = copy.copy(self.policy)
        object.__setattr__(policy, "threshold", 0)
        with self.assertRaises(PermissionError):
            self.verify(self.evaluation(), policy)

    def test_graph_pins_policy_before_lease_and_reopen_rejects_substitution(self):
        graph = self.graph()
        row = graph.get_node("task")
        self.assertEqual(json.loads(row["spec_json"])["evaluation_policy_sha256"], self.policy.sha256)
        self.assertEqual(digest(json.loads(row["spec_json"])), row["spec_hash"])
        graph.connection.close()
        before = (self.root / "graph.db").read_bytes()
        with self.assertRaises(SchemaError):
            ProjectGraph(self.root / "graph.db", self.public, self.policy.sha256)
        value = policy_document()
        value["name"] = "different-policy"
        self.path.write_text(json.dumps(value))
        other = load_task_policy(self.path)
        with self.assertRaises(SchemaError):
            ProjectGraph(self.root / "graph.db", self.public, other.sha256, evaluation_policy=other)
        self.assertEqual(before, (self.root / "graph.db").read_bytes())
        reopened = ProjectGraph(self.root / "graph.db", self.public, self.policy.sha256,
                                evaluation_policy=self.policy)
        reopened.connection.close()

    def test_explicit_conflicting_spec_and_rubric_are_rejected(self):
        graph = self.graph()
        with self.assertRaises(PermissionError):
            graph.add_node("other", "goal", "BUILD", {
                "evaluator_contract_id": "other", "evaluation_policy_sha256": "f" * 64,
            }, ["src/"])
        with self.assertRaises(PermissionError):
            ProjectGraph(self.root / "graph.db", self.public, "f" * 64,
                         evaluation_policy=self.policy)
        self.assertIsNone(graph.connection.execute("SELECT node_id FROM nodes WHERE node_id='other'").fetchone())

    def test_planner_task_policy_replay_is_exact(self):
        graph = self.graph()
        templates = {"opensource": [{"kind": "BUILD", "acceptance": ["tests"], "write_set": ["src/"]}]}
        first = plan_goal(graph, templates, "planned", "opensource", "planned task", "a" * 40)
        self.assertEqual(plan_goal(graph, templates, "planned", "opensource", "planned task", "a" * 40), first)

    def test_graph_signed_v4_record_reverify_and_replay(self):
        graph = self.graph()
        artifact, row, value = self.claim(graph)
        result = graph.record_evaluation("task", row["version"], artifact.artifact_id, value, self.manifest)
        outcome = result["outcome"]["outcome_id"]
        self.assertEqual(graph.verify_recorded_outcome("task", outcome, artifact.artifact_id, self.manifest)[1], value)
        self.assertEqual(graph.record_evaluation("task", row["version"], artifact.artifact_id, value, self.manifest)["outcome"]["outcome_id"], outcome)
        graph.evaluation_policy = None
        with self.assertRaises((PermissionError, RuntimeError)):
            graph.verify_recorded_outcome("task", outcome, artifact.artifact_id, self.manifest)

    def test_wrong_mode_evaluation_never_changes_node_or_ledger(self):
        graph = self.graph()
        artifact, row, value = self.claim(graph)
        value.pop("schema_version")
        value.pop("policy_sha256")
        with self.assertRaises(PermissionError):
            graph.record_evaluation("task", row["version"], artifact.artifact_id,
                                    resign(value, self.private), self.manifest)
        self.assertEqual(graph.get_node("task"), row)
        self.assertEqual(graph.connection.execute("SELECT COUNT(*) FROM evaluation_ledger").fetchone()[0], 0)

    def test_coordinator_rejects_configuration_mismatch_before_any_effects(self):
        graph = self.graph()
        integrator = ProjectIntegrator(self.root, self.root / "binding.json", self.public,
                                       self.path, "refs/ai-ops/accepted/opensource",
                                       evaluation_policy=self.policy)
        coordinator = ProjectCoordinator(graph, integrator)
        before = graph.get_node("task")
        for field, invalid in (("evaluation_policy", None), ("rubric_sha256", "f" * 64)):
            original = getattr(integrator, field)
            setattr(integrator, field, invalid)
            try:
                with self.subTest(field=field), self.assertRaises(PermissionError):
                    ProjectCoordinator(graph, integrator)
                with self.assertRaises(PermissionError):
                    coordinator.reconcile("task", "b" * 40)
            finally:
                setattr(integrator, field, original)
        other_root = self.root / "other-key"
        other_root.mkdir()
        _, other_key = generate_keypair(other_root)
        integrator.evaluator_public_key = other_key
        with self.assertRaisesRegex(PermissionError, "public key"):
            ProjectCoordinator(graph, integrator)
        self.assertEqual(graph.get_node("task"), before)
        self.assertFalse((self.root / "binding.json").exists())


class DirectTaskPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integrator_fixtures.ProjectIntegratorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        f = self.fixture
        f.rubric.write_text(json.dumps(policy_document()))
        self.policy = load_task_policy(f.rubric)
        f.integrator = ProjectIntegrator(f.repo, f.binding, f.public_key, f.rubric,
                                         f.accepted_ref, evaluation_policy=self.policy)

    def evaluation(self):
        f = self.fixture
        value = f.evaluation()
        value.update(schema_version=4, policy_sha256=self.policy.sha256,
                     section_scores={"correctness": 60, "scope": 40},
                     mandatory_gates={gate: "PASS" for gate in self.policy.mandatory_gates})
        return resign(value, f.private_key)

    def test_direct_task_promotion_and_exact_replay(self):
        f = self.fixture
        value = self.evaluation()
        first = f.promote(evaluation=value)
        self.assertEqual(first["base_sha"], f.candidate)
        self.assertEqual(f.promote(evaluation=value)["base_sha"], f.candidate)
        self.assertEqual(f.integrator.rollback(f.candidate)["base_sha"], f.base)

    def test_direct_promotion_denies_wrong_mode_and_changed_policy_bytes(self):
        f = self.fixture
        before = f.binding.read_bytes()
        with self.assertRaises(PermissionError):
            f.promote(evaluation=f.evaluation())
        value = self.evaluation()
        f.rubric.write_text(f.rubric.read_text() + "\n")
        with self.assertRaisesRegex(PermissionError, "rubric bytes changed"):
            f.promote(evaluation=value)
        self.assertEqual(f.binding.read_bytes(), before)
        self.assertIsNone(f.integrator._ref_sha(f.accepted_ref))

    def effect_state(self):
        f = self.fixture
        publications = f.integrator.publications.root
        return (
            f.binding.read_bytes(), f.binding.stat().st_mtime_ns,
            f.integrator._ref_sha(f.accepted_ref),
            f.integrator._ref_sha(f.integrator._rollback_ref(f.candidate)),
            tuple(sorted(
                (str(path.relative_to(publications)), path.stat().st_mode,
                 sha256_file(path) if path.is_file() else None)
                for path in publications.rglob("*")
            )),
        )

    def assert_configuration_drift_denied(self, operation):
        f = self.fixture
        before = self.effect_state()
        for field, path in (("policy", f.rubric), ("public_key", f.public_key)):
            original = path.read_bytes()
            for change in ("changed", "missing"):
                with self.subTest(field=field, change=change):
                    if change == "changed":
                        path.write_bytes(original + b"\n")
                    else:
                        path.unlink()
                    try:
                        with patch.object(
                            f.integrator, "_binding_lock",
                            side_effect=AssertionError("configuration denial must precede locking"),
                        ), self.assertRaises(PermissionError):
                            operation()
                        self.assertEqual(self.effect_state(), before)
                    finally:
                        path.write_bytes(original)

    def test_direct_promotion_recovery_rechecks_policy_and_key_before_effects(self):
        f = self.fixture

        def crash(phase):
            if phase == "after_ref":
                raise RuntimeError("simulated interruption after promotion ref")

        with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
            f.integrator.promote(
                f.candidate, f.base, ["src/"], self.evaluation(), f.evidence,
                expected_task_id="node-1", expected_contract_id="eval-node-1-v1",
                fault_hook=crash,
            )
        self.assertEqual(json.loads(f.binding.read_text())["base_sha"], f.base)
        self.assertEqual(f.integrator._ref_sha(f.accepted_ref), f.candidate)
        self.assert_configuration_drift_denied(
            lambda: f.integrator.reconcile_promotion(f.base, f.candidate),
        )
        self.assertEqual(f.integrator.reconcile_promotion(f.base, f.candidate), f.candidate)
        self.assertEqual(json.loads(f.binding.read_text())["base_sha"], f.candidate)
        recovered = self.effect_state()
        self.assertEqual(f.integrator.reconcile_promotion(f.base, f.candidate), f.candidate)
        self.assertEqual(self.effect_state(), recovered)

    def test_direct_rollback_and_recovery_recheck_policy_and_key_before_effects(self):
        f = self.fixture
        f.promote(evaluation=self.evaluation())
        for method in ("rollback", "reconcile_rollback"):
            with self.subTest(method=method):
                self.assert_configuration_drift_denied(
                    lambda: getattr(f.integrator, method)(f.candidate),
                )

        def crash(phase):
            if phase == "after_rollback_ref":
                raise RuntimeError("simulated interruption after rollback ref")

        with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
            f.integrator.rollback(f.candidate, fault_hook=crash)
        self.assertEqual(json.loads(f.binding.read_text())["base_sha"], f.candidate)
        self.assertEqual(f.integrator._ref_sha(f.accepted_ref), f.base)
        self.assert_configuration_drift_denied(lambda: f.integrator.reconcile_rollback(
            f.candidate, expected_previous_sha=f.base, require_started=True,
        ))
        result = f.integrator.reconcile_rollback(
            f.candidate, expected_previous_sha=f.base, require_started=True,
        )
        self.assertEqual(result["base_sha"], f.base)
        recovered = self.effect_state()
        self.assertEqual(f.integrator.reconcile_rollback(f.candidate)["base_sha"], f.base)
        self.assertEqual(self.effect_state(), recovered)


if __name__ == "__main__":
    unittest.main()
