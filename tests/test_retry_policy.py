import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from control_plane.graph_bootstrap import apply_database
from control_plane.graph_schema import SchemaError
from control_plane.project_graph import ProjectGraph, canonical, digest
from control_plane.retry_policy import RETRY_EVENT_PREFIX, RetryPolicy, parse_retry_event


class RetryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "graph.db"
        apply_database(self.database)
        self.graph = ProjectGraph(self.database)
        self.addCleanup(lambda: self.graph.connection.close())
        self.clock = dt.datetime.now(dt.timezone.utc)
        self.clock_patch = patch("control_plane.project_graph.utc_now", side_effect=lambda: self.clock)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)
        self.graph.create_goal("goal", "opensource", "bounded retry", "a" * 40)

    def node(self, **spec):
        self.graph.add_node("node", "goal", "BUILD", {
            "evaluator_contract_id": "node-evaluation", **spec,
        }, ["src/"])

    def lease(self, start=True):
        current = self.graph.get_node("node")
        leased = self.graph.lease("node", current["version"], "worker", 60)
        return self.graph.start("node", leased["version"], leased["lease_id"], "worker") if start else leased

    def fail(self, returncode=1, state="RUNNING", prose=None):
        current = self.graph.get_node("node")
        return self.graph.reconcile_worker("node", current["version"], returncode, state, prose)

    def advance(self):
        self.clock = dt.datetime.fromisoformat(self.graph.retry_status("node")["next_eligible_at"])

    def reopen(self):
        self.graph.connection.close()
        self.graph = ProjectGraph(self.database)

    def test_deadline_persists_across_reopen_and_exact_deadline_admits(self):
        self.node()
        self.lease()
        self.assertEqual(self.fail(0, None)["state"], "READY")
        status = self.graph.retry_status("node")
        self.assertEqual(status["failure_class"], "UNKNOWN")
        self.assertEqual(dt.datetime.fromisoformat(status["next_eligible_at"]), self.clock + dt.timedelta(seconds=5))
        self.reopen()
        self.assertEqual(self.graph.retry_status("node"), status)
        with self.assertRaisesRegex(RuntimeError, "backoff"):
            self.lease()
        self.advance()
        self.assertEqual(self.lease()["attempt"], 2)

    def test_identical_failures_ignore_changed_prose_and_prevent_third_launch(self):
        self.node(retry_policy={"max_attempts": 100})
        for prose in ({"reason": "first"}, {"reason": "entirely different"}):
            self.lease()
            self.fail(prose=prose)
            self.advance()
        current = self.graph.get_node("node")
        self.assertEqual((current["state"], current["attempt"]), ("NEEDS_HUMAN", 2))
        self.assertEqual(self.graph.retry_status("node")["identical_failures"], 2)
        # A generic reopen cannot erase the durable failure history.
        self.graph.transition("node", current["version"], "READY", "operator retries")
        with self.assertRaisesRegex(PermissionError, "identical"):
            self.lease()
        self.assertEqual(self.graph.get_node("node")["attempt"], 2)

    def test_distinct_failures_stop_at_total_attempt_limit_with_bounded_backoff(self):
        self.node(retry_policy={"initial_delay_seconds": 3, "max_delay_seconds": 4})
        for code, delay in ((1, 3), (2, 4), (3, 4)):
            self.lease()
            before = self.clock
            self.fail(code)
            self.advance()
            self.assertEqual(self.clock - before, dt.timedelta(seconds=delay))
        self.reopen()
        self.assertEqual(self.graph.get_node("node")["state"], "NEEDS_HUMAN")
        row = self.graph.get_node("node")
        self.graph.transition("node", row["version"], "READY", "reopen")
        with self.assertRaisesRegex(PermissionError, "attempt limit"):
            self.lease()

    def test_safety_permanent_budget_and_cancellation_never_retry(self):
        for state in ("FAILED_GATE", "FAILED_PERMANENT", "FAILED_BUDGET", "CANCELLED"):
            with self.subTest(state=state):
                graph = self.graph
                node_id = state.lower()
                graph.add_node(node_id, "goal", "BUILD", {"evaluator_contract_id": "e"}, [node_id])
                leased = graph.lease(node_id, 0, "worker", 60)
                running = graph.start(node_id, leased["version"], leased["lease_id"], "worker")
                failed = graph.reconcile_worker(node_id, running["version"], 0, state, None)
                self.assertEqual(failed["state"], "CANCELLED" if state == "CANCELLED" else "FAILED_GATE")
                self.assertIsNone(graph.retry_status(node_id)["next_eligible_at"])
                with self.assertRaises(ValueError):
                    graph.transition(node_id, failed["version"], "READY", "retry")

    def test_permanent_failure_while_leased_uses_valid_terminal_history(self):
        self.node()
        self.lease(start=False)
        self.assertEqual(self.fail(1, "FAILED_PERMANENT")["state"], "FAILED_GATE")
        self.graph.assert_static_integrity()

    def test_timeout_is_retryable_but_successful_transport_never_admits_prose_evidence(self):
        self.node()
        self.lease()
        self.fail(124, "FAILED_TIMEOUT")
        self.assertEqual(self.graph.retry_status("node")["failure_class"], "TIMEOUT")
        self.advance()
        self.lease()
        self.assertEqual(self.fail(0, "EVIDENCE_PENDING", {"PASS": True})["state"], "READY")
        self.assertIsNone(self.graph.get_node("node")["active_artifact_id"])

    def test_lost_leases_consume_attempts_and_recovery_does_not_reset_delay(self):
        self.node()
        for index in range(2):
            self.lease(start=False)
            self.clock += dt.timedelta(seconds=61)
            self.assertEqual(self.graph.recover_leases(), 1)
            self.assertEqual(self.graph.recover_leases(force_startup=True), 0)
            self.assertEqual(self.graph.retry_status("node")["failure_class"], "LOST_LEASE")
            self.reopen()
            if index == 0:
                with self.assertRaisesRegex(RuntimeError, "backoff"):
                    self.lease()
                self.advance()
        self.assertEqual(self.graph.get_node("node")["state"], "NEEDS_HUMAN")
        self.assertEqual(self.graph.get_node("node")["attempt"], 2)

    def test_expired_worker_cannot_fabricate_reconciliation(self):
        self.node()
        self.lease()
        self.clock += dt.timedelta(seconds=61)
        with self.assertRaisesRegex(PermissionError, "recovery"):
            self.fail()
        self.graph.recover_leases()
        self.assertEqual(self.graph.retry_status("node")["failure_class"], "LOST_LEASE")

    def test_generic_transitions_cannot_admit_or_retry_workers(self):
        self.node()
        with self.assertRaisesRegex(ValueError, "admission"):
            self.graph.transition("node", 0, "LEASED", "raw lease")
        leased = self.lease(start=False)
        for target in ("RUNNING", "READY"):
            with self.assertRaises(ValueError):
                self.graph.transition("node", leased["version"], target, "bypass")
        self.graph.start("node", leased["version"], leased["lease_id"], "worker")
        with self.assertRaises(ValueError):
            self.graph.transition("node", self.graph.get_node("node")["version"], "READY", "bypass")

    def test_human_gate_denies_lease_start_reopen_and_forced_recovery(self):
        self.node(human_gate=True)
        with self.assertRaisesRegex(PermissionError, "pending human gate"):
            self.lease()
        row = self.graph.get_node("node")
        self.assertEqual((row["state"], row["attempt"]), ("NEEDS_HUMAN", 0))
        with self.assertRaises(PermissionError):
            self.graph.start("node", row["version"], "invented", "worker")
        with self.assertRaises(PermissionError):
            self.graph.transition("node", row["version"], "READY", "approved=true")
        self.assertEqual(self.graph.recover_leases(force_startup=True), 0)
        self.assertEqual(self.graph.portfolio_status()[0]["blocked_reason"], "pending human gate: signed approval capability is not implemented")

    def test_malformed_human_gate_and_retry_policy_reject_before_creation(self):
        specs = [{"human_gate": value} for value in (0, 1, "false", None, [])]
        specs += [{"retry_policy": value} for value in (
            None, [], {"max_attempts": True}, {"max_attempts": 101},
            {"max_attempts": 0}, {"max_identical_failures": 3},
            {"initial_delay_seconds": 0}, {"max_delay_seconds": 3601},
            {"backoff_multiplier": float("nan")}, {"backoff_multiplier": True},
            {"backoff_multiplier": float("inf")}, {"backoff_multiplier": 10 ** 309}, {"extra": 1},
        )]
        for spec in specs:
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                self.node(**spec)
        self.assertEqual(self.graph.connection.execute("SELECT COUNT(*) FROM nodes").fetchone()[0], 0)

    def test_preexisting_human_gated_lease_cannot_start_heartbeat_or_escape_recovery(self):
        self.node(human_gate=True)
        # Reproduce a schema-v5 lease admitted by the older implementation.
        self.graph.connection.execute(
            "UPDATE nodes SET state='LEASED',version=1,attempt=1,lease_id='old',"
            "lease_owner='worker',lease_expires_at=? WHERE node_id='node'",
            ((self.clock + dt.timedelta(seconds=60)).isoformat(),),
        )
        self.graph._event("node", 1, "READY", "LEASED", "leased to worker", digest({"lease_id": "old"}))
        self.graph.connection.commit()
        with self.assertRaisesRegex(PermissionError, "human gate"):
            self.graph.start("node", 1, "old", "worker")
        with self.assertRaisesRegex(PermissionError, "human gate"):
            self.graph.heartbeat("node", "old", "worker")
        self.assertEqual(self.graph.recover_leases(force_startup=True), 1)
        self.assertEqual(self.graph.get_node("node")["state"], "NEEDS_HUMAN")
        self.graph.assert_static_integrity()

    def test_types_are_exact_and_fail_without_state_changes(self):
        self.node()
        for version, ttl in ((False, 60), (0, True), (0, "60"), (0, 60.0)):
            with self.assertRaises(ValueError):
                self.graph.lease("node", version, "worker", ttl)
        row = self.lease()
        for code, state in ((True, None), ("0", None), (1.0, None), (1, "garbage"), (1, [])):
            with self.assertRaises(ValueError):
                self.fail(code, state)
        self.assertEqual(self.graph.get_node("node"), row)

    def test_spec_rewrite_fails_even_when_attacker_recomputes_stored_hash(self):
        self.node(retry_policy={"max_attempts": 1})
        spec = {"evaluator_contract_id": "node-evaluation", "retry_policy": {"max_attempts": 100}}
        self.graph.connection.execute("UPDATE nodes SET spec_json=?,spec_hash=?", (canonical(spec), digest(spec)))
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "genesis"):
            self.graph.lease("node", 0, "worker")
        self.graph.connection.close()
        with self.assertRaisesRegex(SchemaError, "genesis"):
            ProjectGraph(self.database)

    def test_spec_bytes_and_attempt_counter_tamper_are_detected(self):
        self.node()
        self.lease()
        self.graph.connection.execute("UPDATE nodes SET attempt=0")
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "attempt counter"):
            self.graph.recover_leases(force_startup=True)
        self.graph.connection.execute("UPDATE nodes SET attempt=1,spec_json='{}'")
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "specification hash"):
            self.graph.assert_static_integrity()

    def test_status_exposes_exact_resume_state_without_lease_capability(self):
        self.node()
        running = self.lease()
        status = self.graph.portfolio_status()[0]
        self.assertEqual(status["version"], running["version"])
        self.assertEqual(status["base_sha"], running["base_sha"])
        self.assertNotIn("lease_id", status)
        self.assertNotIn("lease_owner", status)

    def test_defaults_and_maximum_backoff_are_finite(self):
        policy = RetryPolicy.from_spec({})
        self.assertEqual((policy.max_attempts, policy.max_identical_failures), (3, 2))
        self.assertEqual([policy.delay(i) for i in (1, 2, 100)], [5, 10, 300])

    def test_legacy_migrated_histories_preserve_consumed_attempts_on_lease_and_recovery(self):
        # Reuse the exact recognized predecessor fixtures, including their
        # synthetic genesis payloads and historically unpopulated attempt field.
        from tests.test_graph_schema import GraphSchemaTests
        fixture = GraphSchemaTests()
        for predecessor in ("v0", "v1", "v2", "v3", "v4"):
            for state in ("READY", "LEASED"):
                with self.subTest(predecessor=predecessor, state=state):
                    database = Path(self.temp.name) / f"legacy-{predecessor}-{state}.db"
                    history = [(0, None, "READY"), (1, "READY", "LEASED")]
                    if state == "READY":
                        history.extend([(2, "LEASED", "RUNNING"), (3, "RUNNING", "READY")])
                    fixture.legacy_with_history(database, predecessor, history, state, len(history) - 1)
                    apply_database(database)
                    graph = ProjectGraph(database)
                    try:
                        self.assertEqual(graph.get_node("node")["attempt"], 0)
                        self.assertEqual(graph.retry_status("node")["attempts_consumed"], 1)
                        if state == "READY":
                            leased = graph.lease("node", len(history) - 1, "worker", 60)
                            self.assertEqual(leased["attempt"], 2)
                            running = graph.start("node", leased["version"], leased["lease_id"], "worker")
                            graph.reconcile_worker("node", running["version"], 1, "RUNNING", None)
                        else:
                            self.assertEqual(graph.recover_leases(force_startup=True), 1)
                            self.assertEqual(graph.get_node("node")["attempt"], 1)
                        graph.assert_static_integrity()
                    finally:
                        graph.connection.close()
                    reopened = ProjectGraph(database)
                    reopened.connection.close()

    def test_rehashed_retry_event_cannot_change_immutable_policy_deadline(self):
        self.node()
        self.lease()
        self.fail()
        previous = None
        for raw in self.graph.connection.execute("SELECT * FROM events ORDER BY version").fetchall():
            event = dict(raw)
            record = parse_retry_event(event["reason"])
            if record:
                record["next_eligible_at"] = record["recorded_at"]
                event["reason"] = RETRY_EVENT_PREFIX + canonical(record)
                event["payload_hash"] = digest(record)
            event_hash = digest({
                "node": "node", "version": event["version"], "old": event["old_state"],
                "new": event["new_state"], "reason": event["reason"],
                "payload": event["payload_hash"], "previous": previous,
            })
            self.graph.connection.execute(
                "UPDATE events SET reason=?,payload_hash=?,previous_hash=?,event_hash=? WHERE event_id=?",
                (event["reason"], event["payload_hash"], previous, event_hash, event["event_id"]),
            )
            previous = event_hash
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "retry deadline"):
            self.graph.lease("node", self.graph.get_node("node")["version"], "worker")

    def test_planner_does_not_coerce_malformed_human_gate_to_false(self):
        from control_plane.graph_planner import load_templates, plan_goal
        templates = {project: [{
            "kind": "BUILD", "write_set": ["src/"], "acceptance": ["tests"], "human_gate": 0,
        }] for project in ("nomad", "opensource", "business", "hynix")}
        path = Path(self.temp.name) / "templates.json"
        path.write_text(json.dumps(templates))
        with self.assertRaisesRegex(ValueError, "human_gate"):
            load_templates(path)
        with self.assertRaisesRegex(ValueError, "human_gate"):
            plan_goal(self.graph, templates, "new-goal", "opensource", "must reject", "a" * 40)
        self.assertEqual(self.graph.connection.execute("SELECT COUNT(*) FROM nodes").fetchone()[0], 0)


class HumanGateUpgradeTests(unittest.TestCase):
    def legacy_snapshot(self, state):
        """Produce valid old-style history by disabling only the new gate guards."""
        from tests.test_project_graph import ProjectGraphTests
        fixture = ProjectGraphTests()
        fixture.spec = lambda contract: {
            "acceptance": ["tests pass"], "evaluator_contract_id": contract, "human_gate": True,
        }
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        self.addCleanup(lambda: fixture.graph.connection.close())
        with patch.object(ProjectGraph, "_assert_no_human_gate"), patch.object(ProjectGraph, "_retry_blocker", return_value=None):
            row = fixture.running()
            artifact = fixture.artifact()
            fixture.graph.record_ingressed_evidence("n1", row["version"], artifact)
            if state in {"EVALUATING", "PASSED"}:
                row = fixture.graph.get_node("n1")
                fixture.graph.claim_evidence("n1", row["version"], artifact.artifact_id, "hermes-evaluator", 60)
            if state == "PASSED":
                row = fixture.graph.get_node("n1")
                claim = fixture.graph.connection.execute("SELECT claim_id FROM evaluation_claims").fetchone()[0]
                evaluation = fixture.evaluation(artifact_id=artifact.artifact_id, claim_id=claim)
                fixture.graph.record_evaluation("n1", row["version"], artifact.artifact_id, evaluation, fixture.evidence)
        fixture.graph.connection.close()
        fixture.graph = ProjectGraph(fixture.root / "graph.db", fixture.public_key, fixture.rubric_hash)
        self.assertEqual(fixture.graph.get_node("n1")["state"], state)
        return fixture, artifact

    @staticmethod
    def snapshot(graph):
        return {table: [tuple(row) for row in graph.connection.execute(f"SELECT * FROM {table}")]
                for table in ("nodes", "events", "evidence_artifacts", "evaluation_claims", "evaluation_outcomes", "evaluation_ledger")}

    def test_historical_pending_human_evidence_cannot_be_claimed_after_reopen(self):
        fixture, artifact = self.legacy_snapshot("EVIDENCE_PENDING")
        graph = fixture.graph
        before = self.snapshot(graph)
        with self.assertRaisesRegex(PermissionError, "pending human gate"):
            graph.claim_evidence("n1", graph.get_node("n1")["version"], artifact.artifact_id, "hermes-evaluator")
        self.assertEqual(self.snapshot(graph), before)

    def test_historical_human_evaluation_cannot_heartbeat_reclaim_or_pass(self):
        fixture, artifact = self.legacy_snapshot("EVALUATING")
        graph = fixture.graph
        row = graph.get_node("n1")
        claim = graph.connection.execute("SELECT claim_id FROM evaluation_claims").fetchone()[0]
        evaluation = fixture.evaluation(artifact_id=artifact.artifact_id, claim_id=claim)
        before = self.snapshot(graph)
        calls = (
            lambda: graph.claim_evidence("n1", row["version"] - 1, artifact.artifact_id, "hermes-evaluator"),
            lambda: graph.heartbeat_evidence_claim("n1", row["version"], artifact.artifact_id, claim, "hermes-evaluator"),
            lambda: graph.record_evaluation("n1", row["version"], artifact.artifact_id, evaluation, fixture.evidence),
        )
        for call in calls:
            with self.assertRaisesRegex(PermissionError, "pending human gate"):
                call()
            self.assertEqual(self.snapshot(graph), before)

    def test_historical_human_pass_is_inspectable_but_cannot_authorize_promotion(self):
        fixture, artifact = self.legacy_snapshot("PASSED")
        graph = fixture.graph
        row = graph.get_node("n1")
        outcome = graph.connection.execute("SELECT outcome_id FROM evaluation_outcomes").fetchone()[0]
        before = self.snapshot(graph)
        verified_row, evaluation = graph.verify_recorded_outcome("n1", outcome, artifact.artifact_id, fixture.evidence)
        self.assertEqual(verified_row["state"], "PASSED")
        status = graph.portfolio_status()[0]
        self.assertTrue(status["human_gate"])
        self.assertIn("pending human gate", status["blocked_reason"])
        calls = (
            lambda: graph.validate_recorded_outcome("n1", outcome, artifact.artifact_id, fixture.evidence),
            lambda: graph.record_evaluation("n1", row["version"] - 1, artifact.artifact_id, evaluation, fixture.evidence),
            lambda: graph.transition("n1", row["version"], "INTEGRATING", "promote old pass"),
            lambda: graph._record_integration_locked(row, row["version"], row["result_sha"]),
        )
        for call in calls:
            with self.assertRaisesRegex(PermissionError, "pending human gate"):
                call()
            self.assertEqual(self.snapshot(graph), before)


if __name__ == "__main__":
    unittest.main()
