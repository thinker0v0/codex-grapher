import tempfile
import unittest
import hashlib
import concurrent.futures
import datetime as dt
import json
import sqlite3
from pathlib import Path

from control_plane.evidence_ingress import IngressArtifact
from control_plane.evidence_store import deterministic_claim_id
from control_plane.graph_bootstrap import apply_database
from control_plane.graph_schema import SchemaError
from control_plane.project_graph import ProjectGraph, digest
from tests.evaluation_helpers import generate_keypair, make_evaluation, resign


SHA = "a" * 40
CANDIDATE = "b" * 40
class ProjectGraphTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private_key, self.public_key = generate_keypair(self.root)
        self.rubric = self.root / "RUBRIC.md"
        self.rubric.write_text("frozen rubric")
        self.rubric_hash = hashlib.sha256(self.rubric.read_bytes()).hexdigest()
        database = self.root / "graph.db"
        apply_database(database)
        self.graph = ProjectGraph(database, self.public_key, self.rubric_hash)
        self.evidence = self.root / "evidence.json"
        self.evidence.write_text('{"tests":"pass"}\n')
        self.graph.create_goal("g1", "opensource", "ship verified value", SHA)
        self.graph.add_node("n1", "g1", "BUILD", self.spec("eval-n1"), ["control_plane/"])

    def tearDown(self):
        self.temp.cleanup()

    def spec(self, contract_id):
        return {"acceptance": ["tests pass"], "evaluator_contract_id": contract_id}

    def evidence_for(self, task_id="n1", attempt=1):
        if task_id == "n1" and attempt == 1:
            return self.evidence
        path = self.root / f"{task_id}-attempt-{attempt}.json"
        if not path.exists():
            path.write_text(f'{{"attempt":{attempt},"task":"{task_id}","tests":"pass"}}\n')
        return path

    def evaluation(
        self, task_id="n1", contract_id="eval-n1", previous=None,
        *, evidence=None, artifact_id=None, claim_id=None, candidate=CANDIDATE,
    ):
        return make_evaluation(
            self.private_key, evidence or self.evidence_for(task_id), self.rubric,
            task_id=task_id, contract_id=contract_id, candidate_sha=candidate,
            artifact_id=artifact_id or f"sha256:{'a' * 64}",
            claim_id=claim_id or f"claim:{'b' * 64}",
            previous_ledger_hash=previous,
        )

    def artifact(self, task_id="n1", attempt=1, candidate=CANDIDATE):
        manifest_hash = hashlib.sha256(
            self.evidence_for(task_id, attempt).read_bytes()
        ).hexdigest()
        return IngressArtifact(
            artifact_id=f"sha256:{manifest_hash}",
            manifest_sha256=manifest_hash,
            manifest_relative_path=f"sha256/{manifest_hash[:2]}/{manifest_hash}/manifest.json",
            task_id=task_id,
            attempt=attempt,
            project_id="oss",
            base_sha=SHA,
            candidate_sha=candidate,
            contract_sha256="d" * 64,
        )

    def running(self, node_id="n1"):
        ready = self.graph.get_node(node_id)
        leased = self.graph.lease(node_id, ready["version"], "fixture-worker", 60)
        return self.graph.start(
            node_id, leased["version"], leased["lease_id"], "fixture-worker",
        )

    def claimed(self, node_id="n1"):
        running = self.running(node_id)
        artifact = self.artifact(node_id, running["attempt"])
        recorded = self.graph.record_ingressed_evidence(
            node_id, running["version"], artifact,
        )
        claimed = self.graph.claim_evidence(
            node_id, recorded["node"]["version"], artifact.artifact_id,
            "hermes-evaluator", 60,
        )
        return artifact, self.evidence_for(node_id, running["attempt"]), recorded, claimed

    def disposed_claim(self, disposition="RETRY", reason_sha256="9" * 64):
        artifact, _, _, claimed = self.claimed()
        result = self.graph.reject_evidence(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            disposition, reason_sha256, "hermes-evaluator",
        )
        return artifact, result["claim"]

    def expired_claim(self):
        artifact, _, _, claimed = self.claimed()
        now = dt.datetime.now(dt.timezone.utc)
        self.graph.connection.execute(
            "UPDATE evaluation_claims SET expires_at=? WHERE claim_id=?",
            ((now - dt.timedelta(seconds=1)).isoformat(), claimed["artifact"]["claim_id"]),
        )
        self.graph.connection.commit()
        self.assertEqual(self.graph.recover_evaluator_claims(now=now), 1)
        claim = dict(self.graph.connection.execute(
            "SELECT * FROM evaluation_claims WHERE claim_id=?",
            (claimed["artifact"]["claim_id"],),
        ).fetchone())
        return artifact, claim

    def passed_claim(self):
        artifact, evidence, _, claimed = self.claimed()
        evaluation = self.evaluation(
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"], evidence=evidence,
        )
        passed = self.graph.record_evaluation(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            evaluation, evidence,
        )
        claim = dict(self.graph.connection.execute(
            "SELECT * FROM evaluation_claims WHERE claim_id=?",
            (evaluation["claim_id"],),
        ).fetchone())
        return artifact, evaluation, passed, claim

    def rehash_events(self, node_id="n1"):
        previous = None
        for raw in self.graph.connection.execute(
            "SELECT * FROM events WHERE node_id=? ORDER BY version", (node_id,),
        ).fetchall():
            row = dict(raw)
            event_hash = digest({
                "node": node_id, "version": row["version"],
                "old": row["old_state"], "new": row["new_state"],
                "reason": row["reason"], "payload": row["payload_hash"],
                "previous": previous,
            })
            self.graph.connection.execute(
                "UPDATE events SET previous_hash=?,event_hash=? WHERE event_id=?",
                (previous, event_hash, row["event_id"]),
            )
            previous = event_hash

    def raw_update_ignoring_checks(self, statement, parameters=()):
        self.graph.connection.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self.graph.connection.execute(statement, parameters)
            self.graph.connection.commit()
        finally:
            self.graph.connection.execute("PRAGMA ignore_check_constraints=OFF")

    def assert_graph_mutation_frozen(self, message_pattern):
        tables = (
            "goals", "nodes", "events", "evidence_artifacts",
            "evaluation_claims", "evaluation_outcomes", "evaluation_ledger",
            "buzz_threads", "buzz_audit", "buzz_ingress_responses",
        )
        before = {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in tables
        }
        with self.assertRaisesRegex(RuntimeError, message_pattern):
            self.graph.create_goal(
                "blocked-claim-corruption", "business", "must not persist", SHA,
            )
        self.assertEqual({
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in tables
        }, before)

    def test_rc_zero_unknown_state_is_safe_retry_not_failure_or_success(self):
        row = self.running()
        row = self.graph.reconcile_worker("n1", row["version"], 0, None, None)
        self.assertEqual(row["state"], "READY")

    def test_legacy_reconcile_cannot_admit_evidence_or_self_pass(self):
        row = self.running()
        row = self.graph.reconcile_worker("n1", row["version"], 0, "EVIDENCE_PENDING", {"sha": SHA})
        self.assertEqual(row["state"], "READY")
        with self.assertRaises(ValueError):
            self.graph.transition(
                "n1", row["version"], "EVIDENCE_PENDING", "legacy evidence",
            )

    def test_ingressed_artifact_and_evaluator_claim_are_durable_idempotent_transitions(self):
        row = self.running()
        artifact = self.artifact()
        recorded = self.graph.record_ingressed_evidence("n1", row["version"], artifact)
        self.assertEqual(recorded["node"]["state"], "EVIDENCE_PENDING")
        self.assertEqual(recorded["artifact"]["artifact_id"], artifact.artifact_id)
        replay = self.graph.record_ingressed_evidence("n1", row["version"], artifact)
        self.assertEqual(replay["node"]["version"], recorded["node"]["version"])
        claimed = self.graph.claim_evidence(
            "n1", recorded["node"]["version"], artifact.artifact_id, "hermes-evaluator",
        )
        self.assertEqual(claimed["node"]["state"], "EVALUATING")
        self.assertEqual(claimed["artifact"]["claimed_by"], "hermes-evaluator")
        claim_replay = self.graph.claim_evidence(
            "n1", recorded["node"]["version"], artifact.artifact_id, "hermes-evaluator",
        )
        self.assertEqual(claim_replay["artifact"]["claim_id"], claimed["artifact"]["claim_id"])
        self.assertEqual(claim_replay["node"]["version"], claimed["node"]["version"])

    def test_claimed_artifact_reopens_and_evaluator_can_dispose_retry_without_pass(self):
        artifact, _, _, claimed = self.claimed()
        first_claim_id = claimed["artifact"]["claim_id"]
        database = self.graph.database
        self.graph.connection.close()
        self.graph = ProjectGraph(database, self.public_key, self.rubric_hash)

        reason_sha256 = "9" * 64
        disposed = self.graph.reject_evidence(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            "RETRY", reason_sha256, "hermes-evaluator",
        )
        self.assertEqual(disposed["node"]["state"], "READY")
        self.assertEqual(disposed["claim"]["status"], "DISPOSED")
        self.assertEqual(disposed["claim"]["reason_sha256"], reason_sha256)
        self.assertIsNone(self.graph.connection.execute(
            "SELECT claim_id FROM evidence_artifacts WHERE artifact_id=?",
            (artifact.artifact_id,),
        ).fetchone()[0])
        replay = self.graph.reject_evidence(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            "RETRY", reason_sha256, "hermes-evaluator",
        )
        self.assertEqual(replay["claim"]["claim_id"], first_claim_id)
        with self.assertRaises(ValueError):
            self.graph.claim_evidence(
                "n1", disposed["node"]["version"], artifact.artifact_id,
                "hermes-evaluator",
            )
        running = self.running()
        second_artifact = self.artifact("n1", running["attempt"], "c" * 40)
        second = self.graph.record_ingressed_evidence(
            "n1", running["version"], second_artifact,
        )
        reclaimed = self.graph.claim_evidence(
            "n1", second["node"]["version"], second_artifact.artifact_id,
            "hermes-evaluator",
        )
        self.assertNotEqual(reclaimed["artifact"]["claim_id"], first_claim_id)
        self.assertEqual(reclaimed["node"]["state"], "EVALUATING")
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM evidence_artifacts WHERE node_id='n1'",
        ).fetchone()[0], 2)
        self.assertEqual(
            self.graph.get_node("n1")["active_artifact_id"],
            second_artifact.artifact_id,
        )
        self.assertTrue(self.graph.verify_event_chain("n1"))

    def test_artifact_tamper_wrong_role_and_wrong_claim_id_do_not_mutate_state(self):
        row = self.running()
        artifact = self.artifact()
        recorded = self.graph.record_ingressed_evidence("n1", row["version"], artifact)
        before = self.graph.get_node("n1")
        tampered = IngressArtifact(**{**artifact.as_record(), "candidate_sha": "e" * 40})
        with self.assertRaises(ValueError):
            self.graph.record_ingressed_evidence("n1", row["version"], tampered)
        with self.assertRaises(PermissionError):
            self.graph.claim_evidence(
                "n1", recorded["node"]["version"], artifact.artifact_id, "hermes-oss",
            )
        with self.assertRaises(KeyError):
            self.graph.claim_evidence(
                "n1", recorded["node"]["version"], f"sha256:{'f' * 64}", "hermes-evaluator",
            )
        self.assertEqual(self.graph.get_node("n1"), before)

    def test_claim_heartbeat_is_exact_and_extends_durable_expiry(self):
        artifact, _, _, claimed = self.claimed()
        claim_id = claimed["artifact"]["claim_id"]
        before = self.graph.connection.execute(
            "SELECT heartbeat_at,expires_at FROM evaluation_claims WHERE claim_id=?",
            (claim_id,),
        ).fetchone()
        renewed = self.graph.heartbeat_evidence_claim(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            claim_id, "hermes-evaluator", 120,
        )
        self.assertGreater(renewed["claim"]["expires_at"], before["expires_at"])
        self.assertGreaterEqual(renewed["claim"]["heartbeat_at"], before["heartbeat_at"])
        for wrong in (
            {"claim_id": f"claim:{'f' * 64}"},
            {"artifact_id": f"sha256:{'f' * 64}"},
            {"expected_version": claimed["node"]["version"] + 1},
            {"claimant": "hermes-oss"},
        ):
            values = {
                "expected_version": claimed["node"]["version"],
                "artifact_id": artifact.artifact_id,
                "claim_id": claim_id,
                "claimant": "hermes-evaluator",
            }
            values.update(wrong)
            with self.subTest(wrong=wrong), self.assertRaises(
                (KeyError, PermissionError, ValueError)
            ):
                self.graph.heartbeat_evidence_claim("n1", **values)

    def test_expired_claim_is_evented_reclaimed_and_stale_signed_result_is_rejected(self):
        artifact, evidence, _, claimed = self.claimed()
        old_claim_id = claimed["artifact"]["claim_id"]
        stale = self.evaluation(
            artifact_id=artifact.artifact_id, claim_id=old_claim_id, evidence=evidence,
        )
        expired_at = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
        self.graph.connection.execute(
            "UPDATE evaluation_claims SET expires_at=? WHERE claim_id=?",
            (expired_at, old_claim_id),
        )
        self.graph.connection.commit()

        reclaimed = self.graph.claim_evidence(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            "hermes-evaluator", 60,
        )
        new_claim_id = reclaimed["artifact"]["claim_id"]
        self.assertNotEqual(new_claim_id, old_claim_id)
        self.assertEqual(reclaimed["node"]["state"], "EVALUATING")
        self.graph.assert_static_integrity()
        self.assertEqual(self.graph.connection.execute(
            "SELECT status FROM evaluation_claims WHERE claim_id=?", (old_claim_id,),
        ).fetchone()[0], "EXPIRED")
        replay = self.graph.claim_evidence(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            "hermes-evaluator", 60,
        )
        self.assertEqual(replay["artifact"]["claim_id"], new_claim_id)
        self.assertEqual(replay["node"]["version"], reclaimed["node"]["version"])
        with self.assertRaises(PermissionError):
            self.graph.record_evaluation(
                "n1", reclaimed["node"]["version"], artifact.artifact_id,
                stale, evidence,
            )
        current = self.evaluation(
            artifact_id=artifact.artifact_id, claim_id=new_claim_id, evidence=evidence,
        )
        passed = self.graph.record_evaluation(
            "n1", reclaimed["node"]["version"], artifact.artifact_id,
            current, evidence,
        )
        self.assertEqual(passed["node"]["state"], "PASSED")
        self.graph.assert_static_integrity()
        self.assertEqual([
            tuple(row) for row in self.graph.connection.execute(
                "SELECT status,disposition FROM evaluation_claims "
                "WHERE artifact_id=? ORDER BY claim_version",
                (artifact.artifact_id,),
            ).fetchall()
        ], [("EXPIRED", "EXPIRED"), ("EVALUATED", None)])
        self.assertEqual(tuple(self.graph.connection.execute(
            "SELECT claim_id,claimed_by,claim_version,claimed_at "
            "FROM evidence_artifacts WHERE artifact_id=?",
            (artifact.artifact_id,),
        ).fetchone()), (None, None, None, None))
        self.assertTrue(any(
            row[0] == "expired evaluator claim recovered"
            for row in self.graph.connection.execute(
                "SELECT reason FROM events WHERE node_id='n1' ORDER BY version"
            )
        ))

    def test_unknown_claim_status_freezes_mutation_and_runtime_open(self):
        self.disposed_claim()
        self.raw_update_ignoring_checks(
            "UPDATE evaluation_claims SET status='UNKNOWN'"
        )
        self.assert_graph_mutation_frozen("claim status")
        database = self.graph.database
        self.graph.connection.close()
        with self.assertRaisesRegex(SchemaError, "claim status|quick_check"):
            ProjectGraph(database, self.public_key, self.rubric_hash)

    def test_terminal_stale_or_partial_artifact_pointer_freezes_mutation(self):
        for index, defect in enumerate(("stale", "partial")):
            with self.subTest(defect=defect):
                if index:
                    self.tearDown()
                    self.setUp()
                artifact, claim = self.disposed_claim()
                if defect == "stale":
                    self.graph.connection.execute(
                        "UPDATE evidence_artifacts SET claim_id=?,claimed_by=?,"
                        "claim_version=?,claimed_at=? WHERE artifact_id=?",
                        (
                            claim["claim_id"], claim["claimed_by"],
                            claim["claim_version"], claim["claimed_at"],
                            artifact.artifact_id,
                        ),
                    )
                    self.graph.connection.commit()
                else:
                    self.raw_update_ignoring_checks(
                        "UPDATE evidence_artifacts SET claimed_by='hermes-evaluator' "
                        "WHERE artifact_id=?", (artifact.artifact_id,),
                    )
                self.assert_graph_mutation_frozen("artifact pointer")

    def test_missing_terminal_claim_event_freezes_mutation(self):
        _, claim = self.disposed_claim()
        terminal_version = claim["claim_version"] + 2
        self.graph.connection.execute(
            "DELETE FROM events WHERE node_id='n1' AND version=?",
            (terminal_version,),
        )
        self.graph.connection.execute(
            "UPDATE nodes SET state='EVALUATING',version=? WHERE node_id='n1'",
            (claim["claim_version"] + 1,),
        )
        self.graph.connection.commit()
        self.assertTrue(self.graph.verify_event_chain("n1"))
        self.assert_graph_mutation_frozen("disposed.*resolution event")

    def test_disposed_claim_requires_exact_disposition_target_reason_and_payload(self):
        for index, defect in enumerate(("disposition", "target", "reason", "payload")):
            with self.subTest(defect=defect):
                if index:
                    self.tearDown()
                    self.setUp()
                _, claim = self.disposed_claim()
                version = claim["claim_version"] + 2
                if defect == "disposition":
                    self.graph.connection.execute(
                        "UPDATE evaluation_claims SET disposition='FAILED_GATE' "
                        "WHERE claim_id=?", (claim["claim_id"],),
                    )
                elif defect == "target":
                    self.graph.connection.execute(
                        "UPDATE events SET new_state='FAILED_GATE' "
                        "WHERE node_id='n1' AND version=?", (version,),
                    )
                    self.graph.connection.execute(
                        "UPDATE nodes SET state='FAILED_GATE' WHERE node_id='n1'"
                    )
                elif defect == "reason":
                    self.graph.connection.execute(
                        "UPDATE events SET reason='forged evaluator disposition' "
                        "WHERE node_id='n1' AND version=?", (version,),
                    )
                else:
                    self.graph.connection.execute(
                        "UPDATE events SET payload_hash=? "
                        "WHERE node_id='n1' AND version=?", ("8" * 64, version),
                    )
                if defect != "disposition":
                    self.rehash_events()
                self.graph.connection.commit()
                self.assertTrue(self.graph.verify_event_chain("n1"))
                self.assert_graph_mutation_frozen("disposed.*resolution event")

    def test_expired_claim_resolution_event_is_exact_and_proof_bound(self):
        defects = ("target", "reason", "payload", "resolution_hash", "disposition")
        for index, defect in enumerate(defects):
            with self.subTest(defect=defect):
                if index:
                    self.tearDown()
                    self.setUp()
                _, claim = self.expired_claim()
                version = claim["claim_version"] + 2
                if defect == "target":
                    self.graph.connection.execute(
                        "UPDATE events SET new_state='READY' "
                        "WHERE node_id='n1' AND version=?", (version,),
                    )
                    self.graph.connection.execute(
                        "UPDATE nodes SET state='READY' WHERE node_id='n1'"
                    )
                elif defect == "reason":
                    self.graph.connection.execute(
                        "UPDATE events SET reason='forged expiry recovery' "
                        "WHERE node_id='n1' AND version=?", (version,),
                    )
                elif defect == "payload":
                    self.graph.connection.execute(
                        "UPDATE events SET payload_hash=? "
                        "WHERE node_id='n1' AND version=?", ("8" * 64, version),
                    )
                elif defect == "resolution_hash":
                    self.graph.connection.execute(
                        "UPDATE evaluation_claims SET reason_sha256=? WHERE claim_id=?",
                        ("8" * 64, claim["claim_id"]),
                    )
                else:
                    self.raw_update_ignoring_checks(
                        "UPDATE evaluation_claims SET disposition='RETRY' WHERE claim_id=?",
                        (claim["claim_id"],),
                    )
                if defect in {"target", "reason", "payload"}:
                    self.rehash_events()
                self.graph.connection.commit()
                if defect == "target":
                    self.assertTrue(self.graph.verify_event_chain("n1"))
                self.assert_graph_mutation_frozen("event chain|expired.*resolution")

    def test_evaluated_claim_requires_exact_pass_event(self):
        for index, defect in enumerate(("target", "reason", "payload")):
            with self.subTest(defect=defect):
                if index:
                    self.tearDown()
                    self.setUp()
                _, _, _, claim = self.passed_claim()
                if defect == "target":
                    self.graph.connection.execute(
                        "UPDATE events SET new_state='FAILED_GATE' "
                        "WHERE node_id='n1' AND version=?",
                        (claim["claim_version"] + 2,),
                    )
                    self.graph.connection.execute(
                        "UPDATE nodes SET state='FAILED_GATE' WHERE node_id='n1'"
                    )
                elif defect == "reason":
                    self.graph.connection.execute(
                        "UPDATE events SET reason='forged independent evaluation' "
                        "WHERE node_id='n1' AND version=?",
                        (claim["claim_version"] + 2,),
                    )
                else:
                    self.graph.connection.execute(
                        "UPDATE events SET payload_hash=? "
                        "WHERE node_id='n1' AND version=?",
                        ("8" * 64, claim["claim_version"] + 2),
                    )
                self.rehash_events()
                self.graph.connection.commit()
                self.assertTrue(self.graph.verify_event_chain("n1"))
                self.assert_graph_mutation_frozen("evaluated.*resolution event")

    def test_claim_resolution_metadata_and_timestamps_are_closed(self):
        cases = (
            ("reason", "UPDATE evaluation_claims SET reason_sha256='not-a-hash'"),
            ("resolved", "UPDATE evaluation_claims SET resolved_at='not-a-time'"),
            ("resolved-null", "UPDATE evaluation_claims SET resolved_at=NULL"),
            ("disposition", "UPDATE evaluation_claims SET disposition=NULL"),
        )
        for index, (defect, statement) in enumerate(cases):
            with self.subTest(defect=defect):
                if index:
                    self.tearDown()
                    self.setUp()
                self.disposed_claim()
                self.raw_update_ignoring_checks(statement)
                self.assert_graph_mutation_frozen("claim|disposed")

        self.tearDown()
        self.setUp()
        self.claimed()
        self.raw_update_ignoring_checks(
            "UPDATE evaluation_claims SET reason_sha256=?", ("8" * 64,),
        )
        self.assert_graph_mutation_frozen("active evaluator claim")

        self.tearDown()
        self.setUp()
        self.claimed()
        self.graph.connection.execute(
            "UPDATE evaluation_claims SET expires_at='2099-01-01T00:00:00'"
        )
        self.graph.connection.commit()
        self.assert_graph_mutation_frozen("expires_at.*timezone")

    def test_active_claim_must_be_at_the_exact_current_evaluating_version(self):
        self.claimed()
        events = (
            ("EVALUATING", "READY", "raw retry"),
            ("READY", "LEASED", "raw lease"),
            ("LEASED", "RUNNING", "raw start"),
            ("RUNNING", "EVIDENCE_PENDING", "raw evidence"),
            ("EVIDENCE_PENDING", "EVALUATING", "raw reclaim"),
        )
        version = self.graph.get_node("n1")["version"]
        for old_state, new_state, reason in events:
            version += 1
            self.graph._event(
                "n1", version, old_state, new_state, reason, digest({"version": version}),
            )
        self.graph.connection.execute(
            "UPDATE nodes SET state='EVALUATING',version=? WHERE node_id='n1'",
            (version,),
        )
        self.graph.connection.commit()
        self.assertTrue(self.graph.verify_event_chain("n1"))
        self.assert_graph_mutation_frozen("active evaluator claim pointer")

    def test_evaluation_ledger_sequence_gap_freezes_mutation(self):
        self.passed_claim()
        self.graph.connection.execute(
            "UPDATE evaluation_ledger SET sequence=7 WHERE sequence=1"
        )
        self.graph.connection.commit()
        self.assert_graph_mutation_frozen("ledger sequence adjacency")

    def test_internal_exception_reasons_require_their_durable_proof(self):
        with self.assertRaisesRegex(ValueError, "contiguous and authorized"):
            self.graph._event(
                "n1", 1, "READY", "READY",
                "project-global promotion baseline rebind", "f" * 64,
            )
        artifact, _, _, claimed = self.claimed()
        with self.assertRaisesRegex(ValueError, "contiguous and authorized"):
            self.graph._event(
                "n1", claimed["node"]["version"] + 1,
                "EVALUATING", "EVIDENCE_PENDING",
                "expired evaluator claim recovered", "e" * 64,
            )
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT status FROM evaluation_claims WHERE artifact_id=?",
                (artifact.artifact_id,),
            ).fetchone()[0],
            "ACTIVE",
        )

    def test_pass_outcome_is_content_addressed_and_sql_immutable(self):
        artifact, evidence, _, claimed = self.claimed()
        evaluation = self.evaluation(
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"], evidence=evidence,
        )
        passed = self.graph.record_evaluation(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            evaluation, evidence,
        )
        outcome = passed["outcome"]
        self.assertEqual(outcome["outcome_id"], f"sha256:{outcome['evaluation_sha256']}")
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.connection.execute(
                "UPDATE evaluation_outcomes SET evaluation_sha256=? WHERE outcome_id=?",
                ("f" * 64, outcome["outcome_id"]),
            )
        self.graph.connection.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.connection.execute(
                "DELETE FROM evaluation_outcomes WHERE outcome_id=?",
                (outcome["outcome_id"],),
            )
        self.graph.connection.rollback()
        with self.assertRaises(sqlite3.IntegrityError):
            self.graph.connection.execute(
                "INSERT OR REPLACE INTO evaluation_outcomes("
                "outcome_id,artifact_id,node_id,evaluation_sha256,canonical_json) "
                "VALUES(?,?,?,?,?)",
                (
                    outcome["outcome_id"], artifact.artifact_id, "n1",
                    outcome["evaluation_sha256"], b"{}",
                ),
            )
        self.graph.connection.rollback()
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT canonical_json FROM evaluation_outcomes WHERE outcome_id=?",
                (outcome["outcome_id"],),
            ).fetchone()[0],
            json.dumps(evaluation, sort_keys=True, separators=(",", ":")).encode(),
        )

    def test_expired_worker_lease_denies_start_and_ingress(self):
        leased = self.graph.lease("n1", 0, "fixture-worker", 60)
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
        self.graph.connection.execute(
            "UPDATE nodes SET lease_expires_at=? WHERE node_id='n1'", (past,),
        )
        self.graph.connection.commit()
        with self.assertRaises(PermissionError):
            self.graph.start(
                "n1", leased["version"], leased["lease_id"], "fixture-worker",
            )
        self.graph.recover_leases()
        running = self.running()
        self.graph.connection.execute(
            "UPDATE nodes SET lease_expires_at=? WHERE node_id='n1'", (past,),
        )
        self.graph.connection.commit()
        with self.assertRaises(PermissionError):
            self.graph.record_ingressed_evidence(
                "n1", running["version"], self.artifact("n1", running["attempt"]),
            )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM evidence_artifacts"
        ).fetchone()[0], 0)

    def test_restart_recovers_work_without_terminalizing_it(self):
        row = self.graph.transition("n1", 0, "LEASED", "lease")
        self.graph.transition("n1", row["version"], "RUNNING", "started")
        self.assertEqual(self.graph.recover_leases(force_startup=True), 1)
        self.assertEqual(self.graph.get_node("n1")["state"], "READY")

    def test_dependencies_do_not_release_and_direct_integration_cannot_bypass_attempt(self):
        self.graph.add_node("n2", "g1", "TEST", self.spec("eval-n2"), ["tests/"], ["n1"])
        self.assertEqual(self.graph.release_dependencies("g1"), [])
        artifact, evidence, _, claimed = self.claimed()
        evaluation = self.evaluation(
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"], evidence=evidence,
        )
        passed = self.graph.record_evaluation(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            evaluation, evidence,
        )
        row = self.graph.transition(
            "n1", passed["node"]["version"], "INTEGRATING", "integrate",
        )
        before = self.graph.get_node("n1")
        event_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM events WHERE node_id='n1'"
        ).fetchone()[0]
        with self.assertRaisesRegex(RuntimeError, "completed integration attempt"):
            self.graph.record_integration("n1", row["version"], SHA)
        self.assertEqual(self.graph.get_node("n1"), before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM events WHERE node_id='n1'"
        ).fetchone()[0], event_count)
        self.assertEqual(self.graph.release_dependencies("g1"), [])
        self.assertEqual(self.graph.get_node("n2")["state"], "BLOCKED")

    def test_cross_goal_dependency_is_denied(self):
        self.graph.create_goal("g2", "business", "validate a business hypothesis", SHA)
        with self.assertRaises(ValueError):
            self.graph.add_node("foreign", "g2", "BUILD", self.spec("eval-foreign"), ["docs/"], ["n1"])

    def test_overlapping_write_sets_cannot_run_concurrently(self):
        self.graph.add_node("parallel", "g1", "BUILD", self.spec("eval-parallel"), ["control_plane/x.py"])
        self.graph.lease("n1", 0, "worker-one")
        with self.assertRaises(RuntimeError):
            self.graph.lease("parallel", 0, "worker-two")

    def test_overlapping_write_sets_conflict_across_same_project_goals_only(self):
        self.graph.create_goal("g-same", "opensource", "another open-source goal", SHA)
        self.graph.add_node(
            "same-project", "g-same", "BUILD", self.spec("eval-same"),
            ["control_plane/x.py"],
        )
        self.graph.create_goal("g-other", "business", "a business goal", SHA)
        self.graph.add_node(
            "other-project", "g-other", "BUILD", self.spec("eval-other"),
            ["control_plane/x.py"],
        )
        self.graph.lease("n1", 0, "worker-one")
        with self.assertRaises(RuntimeError):
            self.graph.lease("same-project", 0, "worker-two")
        self.assertEqual(
            self.graph.lease("other-project", 0, "worker-three")["state"], "LEASED"
        )

    def test_unsigned_or_tampered_evaluation_cannot_pass(self):
        artifact, evidence, _, claimed = self.claimed()
        evaluation = self.evaluation(
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"], evidence=evidence,
        )
        evaluation["evaluation_id"] = "tampered-after-signing"
        with self.assertRaises(PermissionError):
            self.graph.record_evaluation(
                "n1", claimed["node"]["version"], artifact.artifact_id,
                evaluation, evidence,
            )
        self.assertEqual(self.graph.get_node("n1")["state"], "EVALUATING")

    def test_section_minimum_task_contract_and_ledger_chain_are_enforced(self):
        artifact, evidence, _, claimed = self.claimed()
        binding = {
            "artifact_id": artifact.artifact_id,
            "claim_id": claimed["artifact"]["claim_id"],
            "evidence": evidence,
        }
        low = self.evaluation(**binding)
        low["section_scores"]["problem_and_evidence"] = 7
        low["total_score"] = sum(low["section_scores"].values())
        low = resign(low, self.private_key)
        with self.assertRaises(PermissionError):
            self.graph.record_evaluation(
                "n1", claimed["node"]["version"], artifact.artifact_id, low, evidence,
            )
        wrong_task = self.evaluation(task_id="another-node", **binding)
        with self.assertRaises(PermissionError):
            self.graph.record_evaluation(
                "n1", claimed["node"]["version"], artifact.artifact_id,
                wrong_task, evidence,
            )
        first = self.evaluation(**binding)
        self.graph.record_evaluation(
            "n1", claimed["node"]["version"], artifact.artifact_id, first, evidence,
        )

        self.graph.add_node("ledger-node", "g1", "TEST", self.spec("eval-ledger"), ["ledger/"])
        second_artifact, second_evidence, _, second = self.claimed("ledger-node")
        second_binding = {
            "task_id": "ledger-node", "contract_id": "eval-ledger",
            "artifact_id": second_artifact.artifact_id,
            "claim_id": second["artifact"]["claim_id"], "evidence": second_evidence,
        }
        broken_chain = self.evaluation(previous=None, **second_binding)
        with self.assertRaises(PermissionError):
            self.graph.record_evaluation(
                "ledger-node", second["node"]["version"],
                second_artifact.artifact_id, broken_chain, second_evidence,
            )
        chained = self.evaluation(previous=first["ledger_hash"], **second_binding)
        self.assertEqual(
            self.graph.record_evaluation(
                "ledger-node", second["node"]["version"],
                second_artifact.artifact_id, chained, second_evidence,
            )["node"]["state"],
            "PASSED",
        )

    def test_deleted_unpublished_ledger_predecessor_freezes_mutation_and_restart(self):
        artifact, evidence, _, claimed = self.claimed()
        first = self.evaluation(
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"], evidence=evidence,
        )
        self.graph.record_evaluation(
            "n1", claimed["node"]["version"], artifact.artifact_id, first, evidence,
        )
        self.graph.add_node(
            "ledger-successor", "g1", "TEST", self.spec("eval-ledger-successor"),
            ["ledger-successor/"],
        )
        second_artifact, second_evidence, _, second_claim = self.claimed(
            "ledger-successor"
        )
        second = self.evaluation(
            task_id="ledger-successor", contract_id="eval-ledger-successor",
            previous=first["ledger_hash"], artifact_id=second_artifact.artifact_id,
            claim_id=second_claim["artifact"]["claim_id"], evidence=second_evidence,
        )
        self.graph.record_evaluation(
            "ledger-successor", second_claim["node"]["version"],
            second_artifact.artifact_id, second, second_evidence,
        )
        self.graph.connection.execute(
            "DELETE FROM evaluation_ledger WHERE node_id='n1'"
        )
        self.graph.connection.commit()
        goal_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0]
        with self.assertRaisesRegex(RuntimeError, "predecessor adjacency"):
            self.graph.create_goal("blocked-ledger", "business", "must freeze", SHA)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0], goal_count)
        database = self.graph.database
        self.graph.connection.close()
        with self.assertRaisesRegex(SchemaError, "predecessor adjacency"):
            ProjectGraph(database, self.public_key, self.rubric_hash)

    def test_forged_active_claim_pointer_on_evaluated_artifact_freezes_mutation(self):
        artifact, evidence, _, claimed = self.claimed()
        evaluation = self.evaluation(
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"], evidence=evidence,
        )
        passed = self.graph.record_evaluation(
            "n1", claimed["node"]["version"], artifact.artifact_id,
            evaluation, evidence,
        )
        claim_version = passed["node"]["version"]
        forged_id = deterministic_claim_id(
            artifact.artifact_id, "n1", claim_version, "hermes-evaluator",
        )
        claimed_at = "2026-08-30T00:00:00+00:00"
        self.graph.connection.execute(
            "INSERT INTO evaluation_claims(claim_id,artifact_id,node_id,claim_version,"
            "claimed_by,status,claimed_at,heartbeat_at,expires_at) "
            "VALUES(?,?,?,?,'hermes-evaluator','ACTIVE',?,?,?)",
            (
                forged_id, artifact.artifact_id, "n1", claim_version,
                claimed_at, claimed_at, "2099-01-01T00:00:00+00:00",
            ),
        )
        self.graph.connection.execute(
            "UPDATE evidence_artifacts SET claim_id=?,claimed_by='hermes-evaluator',"
            "claim_version=?,claimed_at=? WHERE artifact_id=?",
            (forged_id, claim_version, claimed_at, artifact.artifact_id),
        )
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "exact graph event|claim closure"):
            self.graph.create_goal("blocked-claim", "business", "must freeze", SHA)
        self.assertEqual(self.graph.get_node("n1")["state"], "PASSED")

    def test_current_unknown_project_freezes_mutation_and_runtime_open(self):
        self.graph.connection.execute(
            "UPDATE goals SET project='fin-global' WHERE goal_id='g1'"
        )
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "exact active set"):
            self.graph.create_goal("blocked-route", "business", "must freeze", SHA)
        database = self.graph.database
        self.graph.connection.close()
        with self.assertRaisesRegex(SchemaError, "exact active set"):
            ProjectGraph(database, self.public_key, self.rubric_hash)

    def test_terminal_event_deletion_and_head_mismatch_freeze_mutation_and_restart(self):
        for defect in ("delete-terminal", "head-version"):
            with self.subTest(defect=defect):
                if defect != "delete-terminal":
                    self.tearDown()
                    self.setUp()
                node = self.graph.get_node("n1")
                terminal = self.graph.transition(
                    "n1", node["version"], "CANCELLED", "fixture terminal",
                )
                if defect == "delete-terminal":
                    self.graph.connection.execute(
                        "DELETE FROM events WHERE node_id='n1' AND version=?",
                        (terminal["version"],),
                    )
                else:
                    self.graph.connection.execute(
                        "UPDATE nodes SET version=version+1 WHERE node_id='n1'"
                    )
                self.graph.connection.commit()
                with self.assertRaisesRegex(RuntimeError, "event chain"):
                    self.graph.create_goal(
                        f"blocked-{defect}", "business", "must freeze", SHA,
                    )
                database = self.graph.database
                self.graph.connection.close()
                with self.assertRaisesRegex(SchemaError, "event chain"):
                    ProjectGraph(database, self.public_key, self.rubric_hash)

    def test_goal_submission_is_idempotent_but_conflicts_fail(self):
        existing = self.graph.create_goal("different-id", "opensource", "ship verified value", SHA, "g1")
        self.assertEqual(existing["goal_id"], "g1")
        with self.assertRaises(ValueError):
            self.graph.create_goal("bad", "business", "different objective", SHA, "g1")

    def test_pre_head_project_rejects_a_second_active_baseline(self):
        before = self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals WHERE project='opensource'"
        ).fetchone()[0]
        with self.assertRaisesRegex(RuntimeError, "existing project graph"):
            self.graph.create_goal(
                "g-other", "opensource", "divergent baseline", "c" * 40,
            )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals WHERE project='opensource'"
        ).fetchone()[0], before)

    def test_lease_heartbeat_requires_exact_identity_and_chain_verifies(self):
        row = self.graph.lease("n1", 0, "worker-one", 60)
        renewed = self.graph.heartbeat("n1", row["lease_id"], "worker-one", 120)
        self.assertGreater(renewed["lease_expires_at"], row["lease_expires_at"])
        with self.assertRaises(PermissionError):
            self.graph.heartbeat("n1", row["lease_id"], "worker-two")
        self.assertTrue(self.graph.verify_event_chain("n1"))

    def test_live_lease_is_not_recovered_before_expiry(self):
        self.graph.lease("n1", 0, "worker-one", 60)
        self.assertEqual(self.graph.recover_leases(), 0)
        self.assertEqual(self.graph.get_node("n1")["state"], "LEASED")

    def test_two_connections_cannot_race_overlapping_write_sets(self):
        self.graph.add_node("racer", "g1", "BUILD", self.spec("eval-racer"), ["control_plane/x.py"])
        database = Path(self.temp.name) / "graph.db"
        def attempt(node, owner):
            separate = ProjectGraph(database, self.public_key, self.rubric_hash)
            try:
                separate.lease(node, 0, owner, 60)
                return "leased"
            except (RuntimeError, ValueError):
                return "denied"
            finally:
                separate.connection.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: attempt(*args), [("n1", "one"), ("racer", "two")]))
        self.assertEqual(sorted(results), ["denied", "leased"])

    def test_two_goals_in_one_project_cannot_race_overlapping_write_sets(self):
        self.graph.create_goal("g-race", "opensource", "race another goal", SHA)
        self.graph.add_node(
            "cross-goal-racer", "g-race", "BUILD", self.spec("eval-cross-racer"),
            ["control_plane/x.py"],
        )
        database = Path(self.temp.name) / "graph.db"

        def attempt(node, owner):
            separate = ProjectGraph(database, self.public_key, self.rubric_hash)
            try:
                separate.lease(node, 0, owner, 60)
                return "leased"
            except (RuntimeError, ValueError):
                return "denied"
            finally:
                separate.connection.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda args: attempt(*args),
                [("n1", "one"), ("cross-goal-racer", "two")],
            ))
        self.assertEqual(sorted(results), ["denied", "leased"])


if __name__ == "__main__":
    unittest.main()
