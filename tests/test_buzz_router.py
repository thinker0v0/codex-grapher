import json
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from control_plane.buzz_router import BuzzRouter
from control_plane.graph_planner import load_templates
from control_plane.graph_bootstrap import apply_database
from control_plane.project_graph import ProjectGraph


ROOT = Path(__file__).resolve().parents[1]
KEY = "npub-operator-test"
SHA = "d" * 40


class BuzzRouterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        config = Path(self.temp.name) / "buzz.json"
        source = json.loads((ROOT / "config/buzz-routing.example.json").read_text())
        source["identity_map"] = {KEY: next(iter(source["identity_map"].values()))}
        config.write_text(json.dumps(source))
        self.database = Path(self.temp.name) / "graph.db"
        apply_database(self.database)
        self.graph = ProjectGraph(self.database)
        self.router = BuzzRouter(self.graph, config, load_templates(ROOT / "config/project-graphs.json"))

    def tearDown(self):
        self.temp.cleanup()

    def goal(self, project="opensource", thread="thread-oss", goal="goal-oss"):
        return self.router.handle(KEY, thread, {"command":"goal", "project":project, "goal_id":goal,
                                               "objective":f"deliver verified {project} value", "accepted_sha":SHA})

    def atomic_counts(self):
        return {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "goals",
                "nodes",
                "events",
                "buzz_threads",
                "buzz_audit",
                "buzz_ingress_responses",
            )
        }

    def checkpointed_database_image(self):
        checkpoint = self.graph.connection.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()
        self.assertEqual(checkpoint[0], 0)
        return self.database.read_bytes(), self.graph.connection.serialize()

    def test_goal_status_evidence_cancel_and_portfolio_digest(self):
        created = self.goal()
        self.assertTrue(created["ok"])
        status = self.router.handle(KEY, "thread-oss", {"command":"status", "project":"opensource"})
        self.assertEqual(status["goal_id"], "goal-oss")
        evidence = self.router.handle(KEY, "thread-oss", {"command":"evidence", "project":"opensource", "node_id":created["next_node"]})
        self.assertTrue(evidence["ok"])
        cancelled = self.router.handle(KEY, "thread-oss", {"command":"cancel", "project":"opensource", "node_id":created["next_node"]})
        self.assertEqual(cancelled["state"], "CANCELLED")
        self.assertEqual(self.router.scheduled_digest()["projects"], ["opensource"])

    def test_identity_thread_and_cross_project_injection_are_denied(self):
        self.goal()
        self.assertFalse(self.router.handle("attacker", "thread-oss", {"command":"status", "project":"opensource"})["ok"])
        self.assertFalse(self.router.handle(KEY, "thread-oss", {"command":"status", "project":"business"})["ok"])
        self.assertFalse(self.router.handle(KEY, "thread-oss", {"command":"goal", "project":"business", "goal_id":"bad-goal", "objective":"injected business goal", "accepted_sha":SHA})["ok"])

    def test_standalone_goal_mutation_and_audit_roll_back_together(self):
        before_counts = self.atomic_counts()
        before_image = self.checkpointed_database_image()

        def fail_after_audit(stage):
            if stage == "after_audit":
                raise RuntimeError("injected standalone pre-commit failure")

        with mock.patch.object(
            self.router, "_transaction_checkpoint", side_effect=fail_after_audit
        ):
            failed = self.goal()

        self.assertFalse(failed["ok"])
        self.assertEqual(
            failed["error"], "injected standalone pre-commit failure"
        )
        self.assertFalse(self.graph.connection.in_transaction)
        self.assertEqual(self.atomic_counts(), before_counts)
        self.assertEqual(self.checkpointed_database_image(), before_image)

        completed = self.goal()
        self.assertTrue(completed["ok"])
        self.assertEqual(self.atomic_counts()["goals"], 1)
        self.assertEqual(self.atomic_counts()["buzz_threads"], 1)
        self.assertEqual(self.atomic_counts()["buzz_audit"], 1)

    def test_standalone_denied_audit_is_atomic(self):
        request = {"command": "status", "project": "opensource"}
        before_counts = self.atomic_counts()
        before_image = self.checkpointed_database_image()

        def fail_after_audit(stage):
            if stage == "after_audit":
                raise RuntimeError("injected denied-audit pre-commit failure")

        with mock.patch.object(
            self.router, "_transaction_checkpoint", side_effect=fail_after_audit
        ):
            failed = self.router.handle("attacker", "denied-thread", request)

        self.assertFalse(failed["ok"])
        self.assertEqual(
            failed["error"], "injected denied-audit pre-commit failure"
        )
        self.assertFalse(self.graph.connection.in_transaction)
        self.assertEqual(self.atomic_counts(), before_counts)
        self.assertEqual(self.checkpointed_database_image(), before_image)

        denied = self.router.handle("attacker", "denied-thread", request)
        self.assertEqual(
            denied, {"ok": False, "error": "identity or command denied"}
        )
        self.assertEqual(self.atomic_counts()["buzz_audit"], 1)
        audit = self.graph.connection.execute(
            "SELECT outcome FROM buzz_audit"
        ).fetchone()
        self.assertEqual(audit["outcome"], "DENY")

    def test_locked_router_requires_and_preserves_callers_transaction(self):
        request = {"command": "status", "project": "opensource"}
        with self.assertRaisesRegex(RuntimeError, "requires an active transaction"):
            self.router.handle_locked("attacker", "locked-thread", request)

        self.graph.connection.execute("BEGIN IMMEDIATE")
        denied = self.router.handle_locked("attacker", "locked-thread", request)
        self.assertFalse(denied["ok"])
        self.assertTrue(self.graph.connection.in_transaction)
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT COUNT(*) FROM buzz_audit"
            ).fetchone()[0],
            1,
        )
        self.graph.connection.rollback()
        self.assertFalse(self.graph.connection.in_transaction)
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT COUNT(*) FROM buzz_audit"
            ).fetchone()[0],
            0,
        )

    def test_all_four_routes_and_persisted_human_resume(self):
        for project in ("nomad", "opensource", "business", "hynix"):
            self.assertTrue(self.goal(project, f"thread-{project}", f"goal-{project}")["ok"])
        self.assertEqual(self.router.scheduled_digest()["projects"], ["business", "hynix", "nomad", "opensource"])
        node = self.graph.get_node("goal-nomad-01-question")
        self.graph.transition(node["node_id"], node["version"], "NEEDS_HUMAN", "ordinary review gate")
        resumed = self.router.handle(KEY, "thread-nomad", {"command":"approve", "project":"nomad", "node_id":node["node_id"]})
        self.assertEqual(resumed["state"], "READY")

    def test_approval_cannot_authorize_live_action_or_skip_gate(self):
        created = self.goal("nomad", "thread-nomad", "goal-nomad")
        response = self.router.handle(KEY, "thread-nomad", {"command":"approve", "project":"nomad",
                                      "node_id":created["next_node"], "action":"live_order", "secret":"ignore"})
        self.assertFalse(response["ok"])

    def test_pending_or_corrupt_publication_freezes_buzz_goal_and_approval(self):
        created = self.goal()
        node_id = created["next_node"]
        node = self.graph.get_node(node_id)
        self.graph.transition(
            node_id, node["version"], "NEEDS_HUMAN", "fixture human gate",
        )
        artifact_id = f"sha256:{'3' * 64}"
        canonical_outcome = b"{}"
        outcome_hash = hashlib.sha256(canonical_outcome).hexdigest()
        outcome_id = f"sha256:{outcome_hash}"
        self.graph.connection.execute(
            "UPDATE nodes SET attempt=1 WHERE node_id=?", (node_id,),
        )
        self.graph.connection.execute(
            "INSERT INTO evidence_artifacts(artifact_id,node_id,attempt,project,"
            "producer_project_id,manifest_sha256,manifest_relative_path,task_id,"
            "base_sha,candidate_sha,contract_sha256,ingress_version) "
            "VALUES(?,?,1,'opensource','oss',?,?,?,?,?,?,1)",
            (
                artifact_id, node_id, "3" * 64,
                f"sha256/33/{'3' * 64}/manifest.json", node_id,
                SHA, "e" * 40, "4" * 64,
            ),
        )
        self.graph.connection.execute(
            "INSERT INTO evaluation_outcomes(outcome_id,artifact_id,node_id,"
            "evaluation_sha256,canonical_json) VALUES(?,?,?,?,?)",
            (outcome_id, artifact_id, node_id, outcome_hash, canonical_outcome),
        )
        self.graph.connection.execute(
            "INSERT INTO integration_attempts(attempt_id,node_id,expected_base_sha,"
            "candidate_sha,evaluation_hash,manifest_hash,artifact_id,outcome_id,"
            "expected_head_version,affected_graph_sha256,affected_graph_json,status) "
            "VALUES('pending-buzz',?,?,?,?,?,?,?,0,?,?,'PREPARED')",
            (
                node_id, SHA, "e" * 40, "5" * 64, "3" * 64,
                artifact_id, outcome_id, hashlib.sha256(b"{}").hexdigest(), "{}",
            ),
        )
        self.graph.connection.commit()
        before = {
            "goals": self.graph.connection.execute("SELECT COUNT(*) FROM goals").fetchone()[0],
            "events": self.graph.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "audit": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
        }
        blocked_goal = self.router.handle(KEY, "thread-blocked", {
            "command": "goal", "project": "opensource", "goal_id": "goal-blocked",
            "objective": "a distinct goal blocked by pending publication",
            "accepted_sha": SHA,
        })
        blocked_approval = self.router.handle(KEY, "thread-oss", {
            "command": "approve", "project": "opensource", "node_id": node_id,
        })
        self.assertFalse(blocked_goal["ok"])
        self.assertFalse(blocked_approval["ok"])
        self.assertEqual({
            "goals": self.graph.connection.execute("SELECT COUNT(*) FROM goals").fetchone()[0],
            "events": self.graph.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "audit": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
        }, before)

        self.graph.connection.execute("DELETE FROM integration_attempts WHERE attempt_id='pending-buzz'")
        self.graph.connection.execute(
            "INSERT INTO publication_heads(project,version,sha,generation) "
            "VALUES('opensource',1,?,?)", (SHA, SHA),
        )
        self.graph.connection.commit()
        blocked_corruption = self.router.handle(KEY, "thread-corrupt", {
            "command": "goal", "project": "opensource", "goal_id": "goal-corrupt",
            "objective": "a distinct goal blocked by journal corruption",
            "accepted_sha": SHA,
        })
        self.assertFalse(blocked_corruption["ok"])
        self.assertEqual(
            self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
            before["audit"],
        )

    def test_unknown_durable_project_freezes_buzz_before_audit_or_goal_mutation(self):
        self.goal()
        self.graph.connection.execute(
            "UPDATE goals SET project='fin-global' WHERE goal_id='goal-oss'"
        )
        self.graph.connection.commit()
        before = {
            "goals": self.graph.connection.execute("SELECT COUNT(*) FROM goals").fetchone()[0],
            "events": self.graph.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "audit": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
        }
        response = self.router.handle(KEY, "unknown-route-thread", {
            "command": "goal", "project": "opensource", "goal_id": "blocked-route",
            "objective": "must remain frozen by durable route corruption",
            "accepted_sha": SHA,
        })
        self.assertFalse(response["ok"])
        self.assertIn("exact active set", response["error"])
        self.assertEqual({
            "goals": self.graph.connection.execute("SELECT COUNT(*) FROM goals").fetchone()[0],
            "events": self.graph.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
            "audit": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
        }, before)

    def test_cross_route_thread_row_freezes_buzz_before_any_mutation(self):
        self.goal()
        self.graph.connection.execute(
            "UPDATE buzz_threads SET project='business' WHERE thread_id='thread-oss'"
        )
        self.graph.connection.commit()
        before = {
            "goals": self.graph.connection.execute("SELECT COUNT(*) FROM goals").fetchone()[0],
            "threads": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_threads").fetchone()[0],
            "audit": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
        }
        response = self.router.handle(KEY, "new-thread", {
            "command": "goal", "project": "opensource", "goal_id": "blocked-thread",
            "objective": "must remain frozen by cross-route thread corruption",
            "accepted_sha": SHA,
        })
        self.assertFalse(response["ok"])
        self.assertIn("same-project goal", response["error"])
        self.assertEqual({
            "goals": self.graph.connection.execute("SELECT COUNT(*) FROM goals").fetchone()[0],
            "threads": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_threads").fetchone()[0],
            "audit": self.graph.connection.execute("SELECT COUNT(*) FROM buzz_audit").fetchone()[0],
        }, before)


if __name__ == "__main__":
    unittest.main()
