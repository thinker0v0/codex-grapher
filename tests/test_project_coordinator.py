import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from control_plane.buzz_native_adapter import BuzzNativeAdapter, canonical_event_id
from control_plane.buzz_router import BuzzRouter
from control_plane.evidence_ingress import IngressArtifact
from control_plane.evidence_store import deterministic_claim_id
from control_plane.graph_planner import load_templates
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_graph import ProjectGraph, digest
from control_plane.graph_bootstrap import apply_database
from control_plane.graph_schema import inspect_schema
from control_plane.project_integrator import ProjectIntegrator, sha256_file
from tests.evaluation_helpers import generate_keypair, make_evaluation


ROOT = Path(__file__).resolve().parents[1]
BUZZ_NOW = 1_800_000_000


class SimulatedCrash(RuntimeError):
    pass


class ProjectCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "-C", self.repo, "init", "-q"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.name", "Coordinator Test"], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src/base.txt").write_text("base\n")
        self.commit("base")
        self.base = self.rev()
        (self.repo / "src/value.txt").write_text("candidate bytes\n")
        self.commit("candidate")
        self.candidate = self.rev()

        self.evidence_root = self.root / "evidence"
        self.evidence_root.mkdir()
        self.bundle = self.evidence_root / "node-1.bundle"
        subprocess.run(
            ["git", "-C", self.repo, "bundle", "create", self.bundle, "HEAD", f"^{self.base}"],
            check=True, capture_output=True,
        )
        self.manifest = self.evidence_root / "node-1.manifest.json"
        required_output = self.evidence_root / "required-tests" / "0000.output"
        required_output.parent.mkdir()
        required_output.write_bytes(b"fixture required test output\n")
        path_check = self.evidence_root / "path-check.json"
        path_check.write_text('{"valid":true,"violations":[]}\n')
        self.manifest.write_text(json.dumps({
            "schema_version": 4,
            "task_id": "node-1", "attempt": 1,
            "project_id": "oss", "base_sha": self.base,
            "candidate_sha": self.candidate, "producer_identity": "hermes-oss",
            "created_at": "2026-08-30T00:00:00+00:00",
            "contract_sha256": "a" * 64,
            "path_check": {
                "path": path_check.name,
                "sha256": sha256_file(path_check),
                "byte_length": path_check.stat().st_size,
            },
            "bundle": {"path": self.bundle.name, "sha256": sha256_file(self.bundle),
                       "byte_length": self.bundle.stat().st_size},
            "required_tests": [{
                "sequence": 0, "command": "fixture-required-test",
                "candidate_sha": self.candidate, "exit_code": 0,
                "output": {
                    "path": "required-tests/0000.output",
                    "sha256": sha256_file(required_output),
                    "byte_length": required_output.stat().st_size,
                },
            }],
        }, sort_keys=True, separators=(",", ":")) + "\n")
        self.manifest = self.materialize_manifest(self.manifest)
        subprocess.run(["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
                       check=True, capture_output=True)

        self.binding = self.root / "binding.json"
        self.binding.write_text(json.dumps({"repo": "test", "base_sha": self.base}) + "\n")
        os.chmod(self.binding, 0o440)
        self.binding_metadata = self.binding.stat()
        self.rubric = self.root / "RUBRIC.md"
        self.rubric.write_text("frozen rubric\n")
        self.private_key, self.public_key = generate_keypair(self.root)
        self.rubric_hash = hashlib.sha256(self.rubric.read_bytes()).hexdigest()
        database = self.root / "graph.db"
        apply_database(database)
        self.graph = ProjectGraph(database, self.public_key, self.rubric_hash)
        self.graph.create_goal("goal-1", "opensource", "deliver a verified cumulative change", self.base)
        self.graph.add_node(
            "node-1", "goal-1", "BUILD",
            {"acceptance": ["pass"], "evaluator_contract_id": "eval-node-1-v1"}, ["src/"],
        )
        self.graph.add_node(
            "node-2", "goal-1", "TEST",
            {"acceptance": ["visible"], "evaluator_contract_id": "eval-node-2-v1"},
            ["tests/"], ["node-1"],
        )
        leased = self.graph.lease("node-1", 0, "hermes-oss", 60)
        row = self.graph.start(
            "node-1", leased["version"], leased["lease_id"], "hermes-oss",
        )
        manifest_hash = sha256_file(self.manifest)
        artifact = IngressArtifact(
            artifact_id=f"sha256:{manifest_hash}", manifest_sha256=manifest_hash,
            manifest_relative_path=(
                f"sha256/{manifest_hash[:2]}/{manifest_hash}/manifest.json"
            ),
            task_id="node-1", attempt=1, project_id="oss", base_sha=self.base,
            candidate_sha=self.candidate, contract_sha256="a" * 64,
        )
        ingressed = self.graph.record_ingressed_evidence(
            "node-1", row["version"], artifact,
        )
        claimed = self.graph.claim_evidence(
            "node-1", ingressed["node"]["version"], artifact.artifact_id,
            "hermes-evaluator", 60,
        )
        self.artifact_id = artifact.artifact_id
        self.evaluation = make_evaluation(
            self.private_key, self.manifest, self.rubric, task_id="node-1",
            contract_id="eval-node-1-v1", candidate_sha=self.candidate,
            artifact_id=self.artifact_id, claim_id=claimed["artifact"]["claim_id"],
        )
        passed = self.graph.record_evaluation(
            "node-1", claimed["node"]["version"], self.artifact_id,
            self.evaluation, self.manifest,
        )
        self.outcome_id = passed["outcome"]["outcome_id"]
        self.accepted_ref = "refs/ai-ops/accepted/opensource"
        integrator = ProjectIntegrator(
            self.repo, self.binding, self.public_key, self.rubric, self.accepted_ref
        )
        self.coordinator = ProjectCoordinator(
            self.graph, integrator, self.evidence_root, "oss",
        )

    def tearDown(self):
        self.temp.cleanup()

    def commit(self, message):
        subprocess.run(["git", "-C", self.repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-qm", message], check=True)

    def rev(self):
        return subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    def materialize_manifest(self, source_manifest):
        """Build the same content-addressed tree produced by immutable ingress."""
        manifest_hash = sha256_file(source_manifest)
        destination = (
            self.evidence_root / "sha256" / manifest_hash[:2]
            / manifest_hash / "manifest.json"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        value = json.loads(source_manifest.read_text())
        relative_paths = [
            value["bundle"]["path"], value["path_check"]["path"],
            *(item["output"]["path"] for item in value["required_tests"]),
        ]
        for relative in relative_paths:
            target = destination.parent / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_manifest.parent / relative, target)
        shutil.copy2(source_manifest, destination)
        return destination

    def accepted_sha(self):
        return subprocess.run(
            ["git", "-C", self.repo, "rev-parse", self.accepted_ref], check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    def rehash_publication_journal(self):
        """Rebuild hashes after an intentional corruption-fixture rewrite."""
        previous = None
        last_sequence = None
        for raw in self.graph.connection.execute(
            "SELECT * FROM publication_journal ORDER BY sequence"
        ).fetchall():
            row = dict(raw)
            entry_hash = digest(
                ProjectCoordinator._journal_hash_subject(row, previous)
            )
            self.graph.connection.execute(
                "UPDATE publication_journal SET previous_hash=?,entry_hash=? "
                "WHERE sequence=?",
                (previous, entry_hash, row["sequence"]),
            )
            previous = entry_hash
            last_sequence = row["sequence"]
        self.graph.connection.execute(
            "UPDATE publication_journal_tail SET last_sequence=?,last_hash=? "
            "WHERE singleton=1",
            (last_sequence, previous),
        )
        return previous

    def rehash_event_chain(self, node_id):
        """Rebuild a raw-tamper fixture while preserving event hash adjacency."""
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

    def integrity_snapshot(self):
        """Capture every durable row plus refs and the worker-readable binding."""
        tables = [
            row[0] for row in self.graph.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
        ]
        rows = {
            table: [tuple(row) for row in self.graph.connection.execute(
                f"SELECT * FROM {table} ORDER BY rowid"
            ).fetchall()]
            for table in tables
        }
        refs = subprocess.run(
            [
                "git", "-C", str(self.repo), "for-each-ref",
                "--format=%(refname):%(objectname)", "refs/ai-ops/",
            ],
            check=True, capture_output=True, text=True,
        ).stdout
        publication_root = self.coordinator.integrator.publications.root
        publications = []
        if publication_root.exists():
            for item in sorted(publication_root.rglob("*")):
                metadata = item.lstat()
                publications.append((
                    str(item.relative_to(publication_root)),
                    stat.S_IFMT(metadata.st_mode),
                    stat.S_IMODE(metadata.st_mode),
                    hashlib.sha256(item.read_bytes()).hexdigest()
                    if item.is_file() and not item.is_symlink() else None,
                ))
        return {
            "rows": rows,
            "refs": refs,
            "binding": self.binding.read_bytes(),
            "binding_mode": stat.S_IMODE(self.binding.stat().st_mode),
            "publications": publications,
        }

    @staticmethod
    def corrupt_file_same_length(path):
        original = path.read_bytes()
        if not original:
            raise AssertionError("corruption fixture must be nonempty")
        changed = bytearray(original)
        index = len(changed) // 2
        changed[index] = (changed[index] + 1) % 256
        path.write_bytes(changed)
        if len(path.read_bytes()) != len(original):
            raise AssertionError("corruption fixture changed byte length")

    def corrupt_durable_evidence(self, corruption):
        manifest = json.loads(self.manifest.read_text())
        if corruption == "manifest":
            self.corrupt_file_same_length(self.manifest)
        elif corruption == "bundle":
            self.corrupt_file_same_length(
                self.manifest.parent / manifest["bundle"]["path"]
            )
        elif corruption == "required-output":
            self.corrupt_file_same_length(
                self.manifest.parent
                / manifest["required_tests"][0]["output"]["path"]
            )
        elif corruption == "signed-outcome":
            trigger = self.graph.connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='trigger' "
                "AND name='evaluation_outcomes_no_update'"
            ).fetchone()[0]
            canonical_bytes = bytes(self.graph.connection.execute(
                "SELECT canonical_json FROM evaluation_outcomes WHERE outcome_id=?",
                (self.outcome_id,),
            ).fetchone()[0])
            evaluation = json.loads(canonical_bytes)
            signature = evaluation["signature"]
            evaluation["signature"] = (
                ("A" if signature[0] != "A" else "B") + signature[1:]
            )
            changed = json.dumps(
                evaluation, sort_keys=True, separators=(",", ":"),
            ).encode()
            self.assertEqual(len(changed), len(canonical_bytes))
            old_outcome_id = self.outcome_id
            evaluation_hash = digest(evaluation)
            self.outcome_id = f"sha256:{evaluation_hash}"

            # Preserve every DB-static content/hash/event binding so the two
            # public surfaces must reach Ed25519 verification. Foreign keys are
            # disabled only for this raw corruption fixture while the parent
            # outcome identity and its attempt child are rewritten together.
            self.graph.connection.commit()
            self.graph.connection.execute("PRAGMA foreign_keys=OFF")
            self.assertEqual(self.graph.connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0], 0)
            self.graph.connection.execute(
                "DROP TRIGGER evaluation_outcomes_no_update"
            )
            self.graph.connection.execute(
                "UPDATE evaluation_outcomes SET outcome_id=?,evaluation_sha256=?,"
                "canonical_json=? WHERE outcome_id=?",
                (self.outcome_id, evaluation_hash, changed, old_outcome_id),
            )
            self.graph.connection.execute(
                "UPDATE integration_attempts SET outcome_id=?,evaluation_hash=? "
                "WHERE outcome_id=?",
                (self.outcome_id, evaluation_hash, old_outcome_id),
            )
            self.graph.connection.execute(
                "UPDATE nodes SET evaluation_hash=? WHERE node_id='node-1'",
                (evaluation_hash,),
            )
            self.graph.connection.execute(
                "UPDATE evaluation_ledger SET evaluation_hash=? WHERE node_id='node-1'",
                (evaluation_hash,),
            )
            self.graph.connection.execute(
                "UPDATE evaluation_claims SET reason_sha256=? WHERE claim_id=?",
                (evaluation_hash, evaluation["claim_id"]),
            )
            self.graph.connection.execute(
                "UPDATE events SET payload_hash=? WHERE node_id='node-1' "
                "AND reason='verified independent evaluation'",
                (evaluation_hash,),
            )
            self.rehash_event_chain("node-1")
            self.graph.connection.execute(trigger)
            self.graph.connection.commit()
            self.graph.connection.execute("PRAGMA foreign_keys=ON")
            self.assertEqual(self.graph.connection.execute(
                "PRAGMA foreign_keys"
            ).fetchone()[0], 1)
            self.assertIsNone(self.graph.connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchone())
            self.assertEqual(inspect_schema(self.graph.connection).status, "current")
            self.graph.assert_static_integrity()
            ProjectCoordinator.assert_graph_publication_integrity(self.graph)
        else:
            raise AssertionError(corruption)

    def integrate(self, attempt_id="attempt-1", crash_hook=None):
        return self.coordinator.integrate(
            attempt_id, "node-1", self.outcome_id, self.artifact_id, self.manifest,
            "oss", self.evidence_root, crash_hook,
        )

    def reintegrate_same_candidate(self):
        manifest = self.evidence_root / "node-3.manifest.json"
        value = json.loads(self.manifest.read_text())
        value["task_id"] = "node-3"
        manifest.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        manifest = self.materialize_manifest(manifest)
        self.graph.add_node(
            "node-3", "goal-1", "BUILD",
            {"acceptance": ["pass again"], "evaluator_contract_id": "eval-node-3-v1"},
            ["src/"],
        )
        leased = self.graph.lease("node-3", 0, "hermes-oss", 60)
        row = self.graph.start(
            "node-3", leased["version"], leased["lease_id"], "hermes-oss",
        )
        manifest_hash = sha256_file(manifest)
        artifact = IngressArtifact(
            artifact_id=f"sha256:{manifest_hash}", manifest_sha256=manifest_hash,
            manifest_relative_path=(
                f"sha256/{manifest_hash[:2]}/{manifest_hash}/manifest.json"
            ),
            task_id="node-3", attempt=1, project_id="oss", base_sha=self.base,
            candidate_sha=self.candidate, contract_sha256="a" * 64,
        )
        ingressed = self.graph.record_ingressed_evidence(
            "node-3", row["version"], artifact,
        )
        claimed = self.graph.claim_evidence(
            "node-3", ingressed["node"]["version"], artifact.artifact_id,
            "hermes-evaluator", 60,
        )
        evaluation = make_evaluation(
            self.private_key, manifest, self.rubric, task_id="node-3",
            contract_id="eval-node-3-v1", candidate_sha=self.candidate,
            artifact_id=artifact.artifact_id,
            claim_id=claimed["artifact"]["claim_id"],
            previous_ledger_hash=self.evaluation["ledger_hash"],
        )
        passed = self.graph.record_evaluation(
            "node-3", claimed["node"]["version"], artifact.artifact_id,
            evaluation, manifest,
        )
        return self.coordinator.integrate(
            "attempt-2", "node-3", passed["outcome"]["outcome_id"],
            artifact.artifact_id, manifest, "oss", self.evidence_root,
        )

    @staticmethod
    def crash_at(wanted):
        def hook(point):
            if point == wanted:
                raise SimulatedCrash(point)
        return hook

    def test_integration_publishes_candidate_and_preserves_worker_binding_contract(self):
        result = self.integrate()
        self.assertEqual(result["status"], "COMPLETED")
        binding = json.loads(self.binding.read_text())
        self.assertEqual(binding, {"repo": "test", "base_sha": self.candidate})
        metadata = self.binding.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o440)
        self.assertEqual((metadata.st_uid, metadata.st_gid),
                         (self.binding_metadata.st_uid, self.binding_metadata.st_gid))
        accepted = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", self.accepted_ref], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        visible = subprocess.run(
            ["git", "-C", self.repo, "show", f"{accepted}:src/value.txt"], check=True,
            capture_output=True, text=True,
        ).stdout
        self.assertEqual(accepted, self.candidate)
        self.assertEqual(visible, "candidate bytes\n")
        publication = self.root / "publications" / self.candidate
        self.assertEqual((publication / "src/value.txt").read_text(), "candidate bytes\n")
        self.assertFalse((self.repo / "src/value.txt").exists())
        self.assertEqual(self.rev(), self.base)
        self.assertEqual(self.graph.get_node("node-2")["base_sha"], self.candidate)
        self.assertEqual(self.graph.get_node("node-2")["state"], "READY")

    def test_pre_binding_failure_is_retryable_with_the_same_idempotency_key(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("before_ref"))
        self.assertEqual(self.graph.get_node("node-1")["state"], "PASSED")
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)
        self.assertEqual(
            subprocess.run(
                ["git", "-C", self.repo, "rev-parse", "--verify", self.accepted_ref],
                check=False, capture_output=True,
            ).returncode,
            128,
        )
        self.assertEqual(self.integrate()["status"], "COMPLETED")

    def test_crash_after_ref_reconciles_materialization_binding_and_graph_exactly_once(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("after_ref"))
        result = self.coordinator.reconcile("node-1", self.candidate)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.candidate)
        self.assertEqual(self.graph.get_node("node-1")["integration_sha"], self.candidate)
        self.assertEqual(self.coordinator.reconcile("node-1", self.candidate)["status"], "COMPLETED")

    def test_reconcile_revalidates_durable_manifest_and_signed_outcome_before_progress(self):
        for corruption in ("manifest-missing", "outcome-bytes"):
            with self.subTest(corruption=corruption):
                if corruption != "manifest-missing":
                    self.tearDown()
                    self.setUp()
                with self.assertRaises(SimulatedCrash):
                    self.integrate(crash_hook=self.crash_at("after_ref"))
                if corruption == "manifest-missing":
                    self.manifest.unlink()
                else:
                    self.graph.connection.execute(
                        "DROP TRIGGER evaluation_outcomes_no_update"
                    )
                    self.graph.connection.execute(
                        "UPDATE evaluation_outcomes SET canonical_json=X'7B7D' "
                        "WHERE outcome_id=?", (self.outcome_id,),
                    )
                    self.graph.connection.commit()
                binding_before = self.binding.read_bytes()
                ref_before = self.accepted_sha()
                with self.assertRaises((OSError, PermissionError, RuntimeError)):
                    self.coordinator.reconcile("node-1", self.candidate)
                self.assertEqual(self.binding.read_bytes(), binding_before)
                self.assertEqual(self.accepted_sha(), ref_before)
                self.assertEqual(self.graph.get_node("node-1")["state"], "PASSED")
                self.assertEqual(self.graph.connection.execute(
                    "SELECT status FROM integration_attempts WHERE attempt_id='attempt-1'"
                ).fetchone()[0], "PREPARED")

    def test_passed_evaluation_replay_reverifies_manifest_and_signature(self):
        passed = self.graph.get_node("node-1")
        replay = self.graph.record_evaluation(
            "node-1", passed["version"] - 1, self.artifact_id,
            self.evaluation, self.manifest,
        )
        self.assertEqual(replay["outcome"]["outcome_id"], self.outcome_id)
        self.corrupt_file_same_length(self.manifest)
        with self.assertRaises(PermissionError):
            self.graph.record_evaluation(
                "node-1", passed["version"] - 1, self.artifact_id,
                self.evaluation, self.manifest,
            )

    def test_state_independent_outcome_verifier_binds_node_and_artifact_base(self):
        self.graph.connection.execute(
            "UPDATE nodes SET base_sha=? WHERE node_id='node-1'", ("c" * 40,),
        )
        self.graph.connection.commit()
        with self.assertRaisesRegex(PermissionError, "outcome/artifact/node"):
            self.graph.verify_recorded_outcome(
                "node-1", self.outcome_id, self.artifact_id, self.manifest,
            )

    def test_startup_rejects_deleted_completed_attempt_before_any_effect(self):
        from control_plane.graph_service import reconcile_startup

        self.integrate()
        binding_before = self.binding.read_bytes()
        ref_before = self.accepted_sha()
        head_before = dict(self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project='opensource'"
        ).fetchone())
        tail_before = tuple(self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone())
        event_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]
        self.graph.connection.execute(
            "DELETE FROM integration_attempts WHERE attempt_id='attempt-1'"
        )
        self.graph.connection.commit()

        with self.assertRaisesRegex(
            RuntimeError, "lost its integration attempt|completed integration attempt",
        ):
            reconcile_startup(self.graph, {"opensource": self.coordinator})

        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), ref_before)
        self.assertEqual(dict(self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project='opensource'"
        ).fetchone()), head_before)
        self.assertEqual(tuple(self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone()), tail_before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0], event_count)

    def test_dispatch_rejects_tampered_completed_manifest_path_even_with_same_bytes(self):
        from control_plane.graph_service import dispatch

        self.integrate()
        alternate = self.evidence_root / "alternate-copy"
        shutil.copytree(self.manifest.parent, alternate)
        self.graph.connection.execute(
            "UPDATE evidence_artifacts SET manifest_relative_path=? WHERE artifact_id=?",
            ("alternate-copy/manifest.json", self.artifact_id),
        )
        self.graph.connection.commit()
        binding_before = self.binding.read_bytes()
        ref_before = self.accepted_sha()
        event_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        with self.assertRaisesRegex(RuntimeError, "artifact.*binding"):
            dispatch(
                self.graph, {}, "root", {"action": "status"},
                coordinators={"opensource": self.coordinator},
            )

        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), ref_before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0], event_count)

    def test_crash_after_publication_keeps_old_selector_and_replays_generation(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("after_publication"))
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)
        self.assertEqual(self.graph.get_node("node-1")["state"], "PASSED")
        self.assertTrue((self.root / "publications" / self.candidate).is_dir())
        self.assertEqual(self.integrate()["status"], "COMPLETED")

    def test_generic_lease_recovery_preserves_journaled_integrating_work(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("after_ref"))
        self.assertEqual(self.graph.get_node("node-1")["state"], "PASSED")
        self.assertEqual(self.graph.recover_leases(force_startup=True), 0)
        self.assertEqual(self.graph.get_node("node-1")["state"], "PASSED")
        self.assertEqual(
            self.coordinator.reconcile("node-1", self.candidate)["status"], "COMPLETED"
        )

    def test_crash_after_binding_reconciles_the_unwritten_journal(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("after_binding"))
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.candidate)
        attempt = self.graph.connection.execute(
            "SELECT status,integration_sha FROM integration_attempts WHERE attempt_id='attempt-1'"
        ).fetchone()
        self.assertEqual((attempt["status"], attempt["integration_sha"]), ("PREPARED", None))
        self.assertEqual(self.coordinator.reconcile("node-1", self.candidate)["status"], "COMPLETED")

    def test_crash_after_graph_record_reconciles_without_duplicate_promotion(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("after_graph"))
        accepted = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", self.accepted_ref], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        result = self.coordinator.reconcile("node-1", self.candidate)
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(
            subprocess.run(
                ["git", "-C", self.repo, "rev-parse", self.accepted_ref], check=True,
                capture_output=True, text=True,
            ).stdout.strip(),
            accepted,
        )

    def test_completion_and_dependency_release_commit_together_after_fault(self):
        with self.assertRaises(SimulatedCrash):
            self.integrate(crash_hook=self.crash_at("before_completion_commit"))
        self.assertEqual(self.graph.get_node("node-1")["state"], "PASSED")
        self.assertEqual(self.graph.get_node("node-2")["state"], "BLOCKED")
        self.assertEqual(self.integrate()["status"], "COMPLETED")
        self.assertEqual(self.graph.get_node("node-2")["state"], "READY")
        self.assertEqual(self.graph.get_node("node-2")["base_sha"], self.candidate)

    def test_graph_bound_rollback_is_hash_chained_idempotent_and_retains_history(self):
        self.integrate()
        head = self.coordinator.publication_head()
        self.assertEqual((head["version"], head["sha"]), (1, self.candidate))

        result = self.coordinator.rollback(
            "rollback-1", "node-1", "attempt-1", head["version"]
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["head_version"], 2)
        self.assertEqual(json.loads(self.binding.read_text()),
                         {"repo": "test", "base_sha": self.base})
        self.assertEqual(self.coordinator.publication_head()["sha"], self.base)
        goal = self.graph.connection.execute(
            "SELECT accepted_sha FROM goals WHERE goal_id='goal-1'"
        ).fetchone()
        self.assertEqual(goal["accepted_sha"], self.base)
        self.assertEqual(self.graph.get_node("node-1")["state"], "INTEGRATED")
        self.assertEqual(self.graph.get_node("node-1")["integration_sha"], self.candidate)
        self.assertEqual(self.graph.get_node("node-2")["base_sha"], self.base)
        self.assertTrue(self.coordinator.verify_publication_journal())
        self.assertEqual(
            self.coordinator.rollback("rollback-1", "node-1", "attempt-1", 1),
            result,
        )
        with self.assertRaises(sqlite3.DatabaseError):
            with self.graph.connection:
                self.graph.connection.execute(
                    "UPDATE publication_journal SET phase='FORGED' WHERE operation_id='rollback-1'"
                )

    def test_two_goal_promotion_and_rollback_rebind_project_globally_with_events(self):
        self.graph.create_goal(
            "goal-peer", "opensource", "keep a peer graph on the global baseline", self.base,
        )
        self.graph.add_node(
            "node-peer", "goal-peer", "BUILD",
            {"acceptance": ["peer"], "evaluator_contract_id": "eval-peer-v1"},
            ["peer/"],
        )
        self.integrate()
        self.assertEqual(self.graph.connection.execute(
            "SELECT accepted_sha FROM goals WHERE goal_id='goal-peer'"
        ).fetchone()[0], self.candidate)
        peer = self.graph.get_node("node-peer")
        self.assertEqual((peer["base_sha"], peer["version"]), (self.candidate, 1))
        self.assertEqual(self.graph.connection.execute(
            "SELECT reason FROM events WHERE node_id='node-peer' AND version=1"
        ).fetchone()[0], "project-global promotion baseline rebind")
        affected = json.loads(self.graph.connection.execute(
            "SELECT affected_graph_json FROM publication_journal "
            "WHERE operation_id='attempt-1' AND phase='COMPLETED'"
        ).fetchone()[0])
        self.assertEqual(
            {goal["goal_id"] for goal in affected["goals"]},
            {"goal-1", "goal-peer"},
        )

        self.coordinator.rollback("rollback-peer", "node-1", "attempt-1", 1)
        self.assertEqual(self.graph.connection.execute(
            "SELECT accepted_sha FROM goals WHERE goal_id='goal-peer'"
        ).fetchone()[0], self.base)
        peer = self.graph.get_node("node-peer")
        self.assertEqual((peer["base_sha"], peer["version"]), (self.base, 2))
        self.assertEqual(self.graph.connection.execute(
            "SELECT reason FROM events WHERE node_id='node-peer' AND version=2"
        ).fetchone()[0], "project-global publication rollback baseline rebind")
        self.assertEqual(self.graph.get_node("node-1")["state"], "INTEGRATED")

    def test_new_goal_must_match_the_monotonic_project_publication_head(self):
        self.integrate()
        with self.assertRaisesRegex(RuntimeError, "publication head"):
            self.graph.create_goal(
                "goal-stale", "opensource", "stale baseline", self.base,
            )
        created = self.graph.create_goal(
            "goal-current", "opensource", "current baseline", self.candidate,
        )
        self.assertEqual(created["accepted_sha"], self.candidate)

    def test_prehead_and_completed_physical_projection_drift_fail_closed(self):
        os.chmod(self.binding, 0o640)
        self.binding.write_text(
            json.dumps({"repo": "test", "base_sha": self.candidate}) + "\n"
        )
        os.chmod(self.binding, 0o440)
        with self.assertRaisesRegex(RuntimeError, "pre-head binding"):
            self.coordinator.assert_publication_integrity()
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM publication_heads"
        ).fetchone()[0], 0)

        self.tearDown()
        self.setUp()
        self.integrate()
        head_before = self.coordinator.publication_head()
        subprocess.run(
            ["git", "-C", self.repo, "update-ref", self.accepted_ref,
             self.base, self.candidate],
            check=True,
        )
        with self.assertRaisesRegex(RuntimeError, "accepted ref/binding"):
            self.coordinator.assert_publication_integrity()
        self.assertEqual(
            dict(self.graph.connection.execute(
                "SELECT * FROM publication_heads WHERE project='opensource'"
            ).fetchone()),
            head_before,
        )

    def test_completed_head_graph_drift_blocks_live_dispatch_lease(self):
        from control_plane.graph_service import dispatch
        from control_plane.buzz_router import BuzzRouter

        self.integrate()
        ready = self.graph.get_node("node-2")
        self.graph.connection.execute(
            "UPDATE nodes SET base_sha=? WHERE node_id='node-2'", (self.base,),
        )
        self.graph.connection.commit()
        journal_before = self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone()
        head_before = dict(self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project='opensource'"
        ).fetchone())
        binding_before = self.binding.read_bytes()
        ref_before = self.accepted_sha()
        for action in ("lease", "start", "ingest_evidence"):
            with self.subTest(action=action):
                with self.assertRaisesRegex(RuntimeError, "publication baseline"):
                    dispatch(
                        self.graph, {}, "hermes-oss",
                        {"action": action, "node_id": "node-2", "version": ready["version"]},
                        coordinators={"opensource": self.coordinator},
                    )

        routing = self.root / "buzz-routing.json"
        routing.write_text(json.dumps({
            "identity_map": {
                "operator-key": {
                    "role": "operator", "projects": ["opensource"],
                    "commands": ["goal"],
                },
            },
        }))
        response = BuzzRouter(self.graph, routing, {}).handle(
            "operator-key", "stale-graph-thread", {
                "command": "goal", "project": "opensource",
                "goal_id": "must-not-persist", "objective": "blocked by drift",
                "accepted_sha": self.candidate,
            },
        )
        self.assertFalse(response["ok"])
        current = self.graph.get_node("node-2")
        self.assertEqual(
            (current["state"], current["version"], current["base_sha"]),
            ("READY", ready["version"], self.base),
        )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals WHERE goal_id='must-not-persist'"
        ).fetchone()[0], 0)
        self.assertEqual(tuple(self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone()), tuple(journal_before))
        self.assertEqual(dict(self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project='opensource'"
        ).fetchone()), head_before)
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), ref_before)

    def test_paired_completed_origin_base_tamper_freezes_reopen_mutation_dispatch_and_startup(self):
        from control_plane.graph_service import dispatch, reconcile_startup
        from control_plane.graph_schema import SchemaError

        self.integrate()
        self.graph.connection.execute(
            "UPDATE nodes SET base_sha=? WHERE node_id='node-1'", ("c" * 40,),
        )
        self.graph.connection.execute(
            "UPDATE integration_attempts SET expected_base_sha=? "
            "WHERE attempt_id='attempt-1'", ("c" * 40,),
        )
        self.graph.connection.commit()
        before = {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("goals", "nodes", "events", "publication_journal")
        }
        binding_before = self.binding.read_bytes()
        ref_before = self.accepted_sha()

        with self.assertRaisesRegex(RuntimeError, "origin base"):
            self.graph.create_goal(
                "base-tamper-goal", "opensource", "must not persist", self.candidate,
            )
        with self.assertRaisesRegex(RuntimeError, "origin base"):
            dispatch(
                self.graph, {}, "root", {"action": "status"},
                coordinators={"opensource": self.coordinator},
            )
        with self.assertRaisesRegex(RuntimeError, "origin base"):
            reconcile_startup(self.graph, {"opensource": self.coordinator})
        with self.assertRaisesRegex(SchemaError, "origin base"):
            ProjectGraph(
                self.graph.database, self.public_key, self.rubric_hash,
            )

        self.assertEqual({
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("goals", "nodes", "events", "publication_journal")
        }, before)
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), ref_before)

    def test_all_durable_outcome_bytes_freeze_startup_and_status_before_any_effect(self):
        from control_plane.graph_service import dispatch, reconcile_startup

        first = True
        for published in (False, True):
            for corruption in (
                "manifest", "bundle", "required-output", "signed-outcome",
            ):
                for surface in ("startup", "status"):
                    with self.subTest(
                        published=published, corruption=corruption, surface=surface,
                    ):
                        if first:
                            first = False
                        else:
                            self.tearDown()
                            self.setUp()
                        if published:
                            self.integrate()
                        self.corrupt_durable_evidence(corruption)
                        before = self.integrity_snapshot()

                        def exercise_surface():
                            if surface == "startup":
                                reconcile_startup(
                                    self.graph, {"opensource": self.coordinator},
                                )
                            else:
                                dispatch(
                                    self.graph, {}, "root", {"action": "status"},
                                    coordinators={"opensource": self.coordinator},
                                )
                        if corruption == "signed-outcome":
                            with self.assertRaisesRegex(
                                PermissionError, "invalid evaluator signature",
                            ):
                                exercise_surface()
                        else:
                            with self.assertRaises(
                                (
                                    KeyError, OSError, PermissionError, RuntimeError,
                                    TypeError, ValueError, json.JSONDecodeError,
                                    subprocess.CalledProcessError,
                                )
                            ):
                                exercise_surface()
                        self.assertEqual(self.integrity_snapshot(), before)

    def test_intact_unpublished_and_completed_evidence_allow_startup_status_and_mutation(self):
        from control_plane.graph_service import dispatch, reconcile_startup

        for published in (False, True):
            with self.subTest(published=published):
                if published:
                    self.integrate()
                coordinators = {"opensource": self.coordinator}
                reconcile_startup(self.graph, coordinators)
                status = dispatch(
                    self.graph, {}, "root", {"action": "status"},
                    coordinators=coordinators,
                )
                self.assertTrue(status)
                accepted_sha = self.candidate if published else self.base
                nodes = dispatch(
                    self.graph,
                    load_templates(ROOT / "config/project-graphs.json"),
                    "hermes-oss",
                    {
                        "action": "create_goal",
                        "goal_id": f"intact-{'completed' if published else 'passed'}",
                        "project": "opensource",
                        "objective": "prove unrelated authorized mutation remains enabled",
                        "accepted_sha": accepted_sha,
                    },
                    coordinators=coordinators,
                )
                self.assertTrue(nodes)
                if not published:
                    self.tearDown()
                    self.setUp()

    def test_rehashed_terminal_event_tamper_freezes_graph_service_and_buzz(self):
        from control_plane.graph_service import dispatch

        defects = (
            "passed-reason", "passed-payload",
            "integrated-reason", "integrated-payload",
        )
        for index, defect in enumerate(defects):
            with self.subTest(defect=defect):
                if index:
                    self.tearDown()
                    self.setUp()
                self.integrate()
                integrated = self.graph.get_node("node-1")
                claim = self.graph.connection.execute(
                    "SELECT claim_version FROM evaluation_claims "
                    "WHERE node_id='node-1' AND status='EVALUATED'"
                ).fetchone()
                is_passed = defect.startswith("passed-")
                version = (
                    claim["claim_version"] + 2
                    if is_passed else integrated["version"]
                )
                if defect.endswith("-reason"):
                    self.graph.connection.execute(
                        "UPDATE events SET reason=? "
                        "WHERE node_id='node-1' AND version=?",
                        (
                            "forged independent evaluation"
                            if is_passed else "forged atomic integration",
                            version,
                        ),
                    )
                else:
                    self.graph.connection.execute(
                        "UPDATE events SET payload_hash=? "
                        "WHERE node_id='node-1' AND version=?",
                        (("f" * 64) if is_passed else ("f" * 40), version),
                    )
                self.rehash_event_chain("node-1")
                self.graph.connection.commit()
                self.assertTrue(self.graph.verify_event_chain("node-1"))

                pubkey = "1" * 64
                routing = self.root / "buzz-event-closure-routing.json"
                routing.write_text(json.dumps({
                    "identity_map": {
                        pubkey: {
                            "role": "operator", "projects": ["opensource"],
                            "commands": ["status"],
                        },
                    },
                }))
                router = BuzzRouter(
                    self.graph, routing, {}, {"opensource": self.coordinator},
                )
                adapter_config = json.loads(
                    (ROOT / "config/buzz-native-fixture.example.json").read_text()
                )
                channel = next(
                    channel for channel, route in adapter_config["channel_routes"].items()
                    if route == "opensource"
                )
                event = {
                    "pubkey": pubkey, "created_at": BUZZ_NOW, "kind": 42,
                    "tags": [
                        ["e", channel, "", "root"],
                        ["e", "3" * 64, "", "reply"],
                    ],
                    "content": json.dumps(
                        {"command": "status"}, sort_keys=True, separators=(",", ":"),
                    ),
                }
                event["id"] = canonical_event_id(event)
                event["sig"] = "2" * 128
                adapter = BuzzNativeAdapter(
                    router, ROOT / "config/buzz-native-fixture.example.json",
                    lambda _pubkey, _event_id, _signature: True,
                    clock=lambda: BUZZ_NOW,
                )
                tables = (
                    "goals", "nodes", "events", "buzz_audit",
                    "buzz_ingress_responses", "publication_journal",
                )
                before = {
                    table: self.graph.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in tables
                }
                binding_before = self.binding.read_bytes()
                ref_before = self.accepted_sha()

                expected_error = (
                    "evaluated.*resolution event" if is_passed else "integrat.*event"
                )
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    self.graph.create_goal(
                        "blocked-event-goal", "business", "must not persist", self.base,
                    )
                with self.assertRaisesRegex(RuntimeError, expected_error):
                    dispatch(self.graph, {}, "root", {"action": "status"})
                direct = router.handle(
                    pubkey, "3" * 64,
                    {"command": "status", "project": "opensource"},
                )
                self.assertFalse(direct["ok"])
                self.assertIn(
                    "evaluated" if is_passed else "integrat", direct["error"],
                )
                native = adapter.handle_event(event)
                self.assertFalse(native["ok"])
                self.assertEqual(native["error"], "durable graph integrity denied")

                self.assertEqual({
                    table: self.graph.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in tables
                }, before)
                self.assertEqual(self.binding.read_bytes(), binding_before)
                self.assertEqual(self.accepted_sha(), ref_before)

    def test_committed_binding_updated_attempt_is_not_a_public_integrity_transient(self):
        self.integrate()
        self.graph.connection.execute(
            "UPDATE integration_attempts SET status='BINDING_UPDATED' "
            "WHERE attempt_id='attempt-1'"
        )
        self.graph.connection.commit()
        before = self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0]
        with self.assertRaisesRegex(RuntimeError, "completed integration attempt"):
            self.graph.create_goal(
                "blocked-transient", "business", "must not persist", self.base,
            )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0], before)

    def test_buzz_completed_mutations_require_full_exact_durable_inventory(self):
        cases = (
            "missing-full-verifier",
            "missing-manifest",
            "tampered-manifest",
            "extra-unbound-file",
        )
        for index, corruption in enumerate(cases):
            with self.subTest(corruption=corruption):
                if index:
                    self.tearDown()
                    self.setUp()
                self.integrate()
                if corruption == "missing-manifest":
                    self.manifest.unlink()
                elif corruption == "tampered-manifest":
                    self.manifest.write_bytes(self.manifest.read_bytes() + b" ")
                elif corruption == "extra-unbound-file":
                    (self.manifest.parent / "unbound-extra.txt").write_text(
                        "not named by the canonical manifest\n"
                    )

                pubkey = "1" * 64
                routing = self.root / "buzz-durable-routing.json"
                routing.write_text(json.dumps({
                    "identity_map": {
                        pubkey: {
                            "role": "operator", "projects": ["opensource"],
                            "commands": ["status"],
                        },
                    },
                }))
                verifiers = (
                    {} if corruption == "missing-full-verifier"
                    else {"opensource": self.coordinator}
                )
                router = BuzzRouter(self.graph, routing, {}, verifiers)
                adapter_config = json.loads(
                    (ROOT / "config/buzz-native-fixture.example.json").read_text()
                )
                channel = next(
                    channel for channel, route in adapter_config["channel_routes"].items()
                    if route == "opensource"
                )
                event = {
                    "pubkey": pubkey,
                    "created_at": BUZZ_NOW,
                    "kind": 42,
                    "tags": [
                        ["e", channel, "", "root"],
                        ["e", "3" * 64, "", "reply"],
                    ],
                    "content": json.dumps(
                        {"command": "status"}, sort_keys=True, separators=(",", ":"),
                    ),
                }
                event["id"] = canonical_event_id(event)
                event["sig"] = "2" * 128
                adapter = BuzzNativeAdapter(
                    router, ROOT / "config/buzz-native-fixture.example.json",
                    lambda _pubkey, _event_id, _signature: True,
                    clock=lambda: BUZZ_NOW,
                )
                before = {
                    table: self.graph.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "goals", "nodes", "events", "buzz_audit",
                        "buzz_ingress_responses",
                    )
                }

                direct = router.handle(
                    pubkey, "3" * 64,
                    {"command": "status", "project": "opensource"},
                )
                self.assertFalse(direct["ok"])
                native = adapter.handle_event(event)
                self.assertFalse(native["ok"])
                self.assertEqual(native["error"], "durable graph integrity denied")
                self.assertEqual({
                    table: self.graph.connection.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "goals", "nodes", "events", "buzz_audit",
                        "buzz_ingress_responses",
                    )
                }, before)

    def test_buzz_unpublished_pass_requires_and_reuses_exact_durable_coordinator(self):
        pubkey = "1" * 64
        routing = self.root / "buzz-unpublished-routing.json"
        routing.write_text(json.dumps({
            "identity_map": {
                pubkey: {
                    "role": "operator", "projects": ["opensource"],
                    "commands": ["status"],
                },
            },
        }))
        before = self.graph.connection.execute(
            "SELECT COUNT(*) FROM buzz_audit"
        ).fetchone()[0]
        missing = BuzzRouter(self.graph, routing, {}, {}).handle(
            pubkey, "unpublished-thread", {"command": "status"},
        )
        self.assertFalse(missing["ok"])
        self.assertIn("coordinators", missing["error"])
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM buzz_audit"
        ).fetchone()[0], before)

        router = BuzzRouter(
            self.graph, routing, {}, {"opensource": self.coordinator},
        )
        intact = router.handle(
            pubkey, "unpublished-thread", {"command": "status"},
        )
        self.assertTrue(intact["ok"])
        self.assertTrue(intact["portfolio"])
        after_intact = self.graph.connection.execute(
            "SELECT COUNT(*) FROM buzz_audit"
        ).fetchone()[0]
        self.assertEqual(after_intact, before + 1)

        manifest = json.loads(self.manifest.read_text())
        output = (
            self.manifest.parent
            / manifest["required_tests"][0]["output"]["path"]
        )
        self.corrupt_file_same_length(output)
        denied = router.handle(
            pubkey, "another-unpublished-thread", {"command": "status"},
        )
        self.assertFalse(denied["ok"])
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM buzz_audit"
        ).fetchone()[0], after_intact)

    def test_buzz_completed_publication_intact_coordinator_allows_goal_and_status(self):
        self.integrate()
        pubkey = "1" * 64
        thread_id = "4" * 64
        routing = self.root / "buzz-intact-routing.json"
        routing.write_text(json.dumps({
            "identity_map": {
                pubkey: {
                    "role": "operator",
                    "projects": ["opensource"],
                    "commands": ["goal", "status"],
                },
            },
        }))
        router = BuzzRouter(
            self.graph,
            routing,
            load_templates(ROOT / "config/project-graphs.json"),
            {"opensource": self.coordinator},
        )
        adapter_config = json.loads(
            (ROOT / "config/buzz-native-fixture.example.json").read_text()
        )
        channel = next(
            channel
            for channel, route in adapter_config["channel_routes"].items()
            if route == "opensource"
        )
        adapter = BuzzNativeAdapter(
            router,
            ROOT / "config/buzz-native-fixture.example.json",
            lambda _pubkey, _event_id, _signature: True,
            clock=lambda: BUZZ_NOW,
        )

        def event(payload):
            value = {
                "pubkey": pubkey,
                "created_at": BUZZ_NOW,
                "kind": 42,
                "tags": [
                    ["e", channel, "", "root"],
                    ["e", thread_id, "", "reply"],
                ],
                "content": json.dumps(
                    payload, sort_keys=True, separators=(",", ":")
                ),
            }
            value["id"] = canonical_event_id(value)
            value["sig"] = "2" * 128
            return value

        goal_event = event({
            "command": "goal",
            "goal_id": "goal-completed-buzz",
            "objective": "prove intact completed publication Buzz mutation",
            "accepted_sha": self.candidate,
        })
        before = {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "goals", "nodes", "events", "buzz_threads", "buzz_audit",
                "buzz_ingress_responses",
            )
        }

        created = adapter.handle_event(goal_event)
        self.assertTrue(created["ok"])
        self.assertEqual(created["goal_id"], "goal-completed-buzz")
        status_event = event({"command": "status"})
        status = adapter.handle_event(status_event)
        self.assertTrue(status["ok"])
        self.assertEqual(status["goal_id"], "goal-completed-buzz")
        self.assertTrue(status["nodes"])
        self.assertTrue(self.coordinator.verify_publication_journal())

        after = {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in before
        }
        self.assertEqual(after["goals"], before["goals"] + 1)
        self.assertEqual(after["buzz_threads"], before["buzz_threads"] + 1)
        self.assertEqual(after["buzz_audit"], before["buzz_audit"] + 2)
        self.assertEqual(
            after["buzz_ingress_responses"],
            before["buzz_ingress_responses"] + 2,
        )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM buzz_ingress_responses WHERE state!='COMPLETE'"
        ).fetchone()[0], 0)

        self.assertEqual(adapter.handle_event(goal_event), created)
        self.assertEqual(adapter.handle_event(status_event), status)
        self.assertEqual({
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in after
        }, after)

    def test_buzz_full_integrity_mapping_cannot_be_a_noop_or_cross_bound(self):
        routing = self.root / "buzz-verifier-binding.json"
        routing.write_text(json.dumps({"identity_map": {}}))
        with self.assertRaisesRegex(TypeError, "actual ProjectCoordinator"):
            BuzzRouter(
                self.graph, routing, {},
                {"opensource": lambda: None},  # type: ignore[dict-item]
            )
        with self.assertRaisesRegex(ValueError, "another project"):
            BuzzRouter(
                self.graph, routing, {}, {"business": self.coordinator},
            )

        other_database = self.root / "other-graph.db"
        apply_database(other_database)
        other_graph = ProjectGraph(
            other_database, self.public_key, self.rubric_hash,
        )
        try:
            cross_graph = ProjectCoordinator(
                other_graph, self.coordinator.integrator,
                self.evidence_root, "oss",
            )
            with self.assertRaisesRegex(ValueError, "another graph"):
                BuzzRouter(
                    self.graph, routing, {}, {"opensource": cross_graph},
                )
        finally:
            other_graph.connection.close()

    def test_sensitive_projects_reject_none_empty_partial_and_nonexact_integrity_maps(self):
        for mapping in (None, {}):
            with self.subTest(mapping=mapping), self.assertRaisesRegex(
                RuntimeError, "lack exact coordinators",
            ):
                ProjectCoordinator.require_external_integrity(self.graph, mapping)

        business_integrator = ProjectIntegrator(
            self.repo, self.binding, self.public_key, self.rubric,
            "refs/ai-ops/accepted/business",
        )
        business_coordinator = ProjectCoordinator(
            self.graph, business_integrator, self.evidence_root, "business",
        )
        with self.assertRaisesRegex(RuntimeError, "lack exact coordinators"):
            ProjectCoordinator.require_external_integrity(
                self.graph, {"business": business_coordinator},
            )

        with self.assertRaisesRegex(TypeError, "actual ProjectCoordinator"):
            ProjectCoordinator.require_external_integrity(
                self.graph, {"opensource": object()},  # type: ignore[dict-item]
            )
        with self.assertRaisesRegex(TypeError, "actual ProjectIntegrator"):
            ProjectCoordinator.require_external_integrity(
                self.graph,
                {"opensource": ProjectCoordinator(
                    self.graph, object(), self.evidence_root, "oss",  # type: ignore[arg-type]
                )},
            )
        normalized = ProjectCoordinator.require_external_integrity(
            self.graph, {"opensource": self.coordinator},
        )
        self.assertIs(normalized["opensource"], self.coordinator)

    def test_outcome_project_remains_required_after_failed_gate_and_instance_shadow_cannot_bypass(self):
        failed = self.graph.transition(
            "node-1", self.graph.get_node("node-1")["version"],
            "FAILED_GATE", "fixture post-pass safety failure",
        )
        self.assertEqual(failed["state"], "FAILED_GATE")
        with self.assertRaisesRegex(RuntimeError, "lack exact coordinators"):
            ProjectCoordinator.require_external_integrity(self.graph, None)
        ProjectCoordinator.require_external_integrity(
            self.graph, {"opensource": self.coordinator},
        )

        self.corrupt_file_same_length(self.manifest)
        self.coordinator.assert_publication_integrity = lambda: None
        self.coordinator._assert_durable_evidence_integrity = lambda: None
        with self.assertRaises((PermissionError, RuntimeError)):
            ProjectCoordinator.require_external_integrity(
                self.graph, {"opensource": self.coordinator},
            )

    def test_internally_coherent_third_baseline_is_denied_before_promotion(self):
        third = "c" * 40
        self.graph.create_goal(
            "goal-third", "opensource", "forged internally coherent baseline", self.base,
        )
        self.graph.add_node(
            "node-third", "goal-third", "BUILD",
            {"acceptance": ["third"], "evaluator_contract_id": "eval-third-v1"},
            ["third/"],
        )
        self.graph.connection.execute(
            "UPDATE goals SET accepted_sha=? WHERE goal_id='goal-third'", (third,),
        )
        self.graph.connection.execute(
            "UPDATE nodes SET base_sha=? WHERE node_id='node-third'", (third,),
        )
        self.graph.connection.commit()
        binding_before = self.binding.read_bytes()
        with self.assertRaisesRegex(
            RuntimeError, "multiple active baselines|outside the publication baseline",
        ):
            self.integrate()
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM integration_attempts"
        ).fetchone()[0], 0)

    def test_artifact_bearing_human_peer_is_not_quiescent_for_promotion(self):
        self.graph.create_goal(
            "goal-human", "opensource", "human disposition peer", self.base,
        )
        self.graph.add_node(
            "node-human", "goal-human", "BUILD",
            {"acceptance": ["human"], "evaluator_contract_id": "eval-human-v1"},
            ["human/"],
        )
        artifact_id = f"sha256:{'6' * 64}"
        self.graph.connection.execute(
            "INSERT INTO evidence_artifacts(artifact_id,node_id,attempt,project,"
            "producer_project_id,manifest_sha256,manifest_relative_path,task_id,"
            "base_sha,candidate_sha,contract_sha256,ingress_version) "
            "VALUES(?, 'node-human',1,'opensource','oss',?,?, 'node-human',?,?,?,1)",
            (
                artifact_id, "6" * 64,
                f"sha256/66/{'6' * 64}/manifest.json",
                self.base, "d" * 40, "7" * 64,
            ),
        )
        self.graph.connection.execute(
            "UPDATE nodes SET state='NEEDS_HUMAN',version=1,attempt=1,"
            "active_artifact_id=?,evidence_hash=? WHERE node_id='node-human'",
            (artifact_id, "6" * 64),
        )
        self.graph._event(
            "node-human", 1, "READY", "NEEDS_HUMAN",
            "fixture human disposition", digest({"artifact_id": artifact_id}),
        )
        self.graph.connection.commit()
        binding_before = self.binding.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "not quiescent"):
            self.integrate()
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM integration_attempts"
        ).fetchone()[0], 0)

    def test_promotion_denies_cross_goal_active_node_before_physical_mutation(self):
        self.graph.create_goal(
            "goal-peer", "opensource", "active peer", self.base,
        )
        self.graph.add_node(
            "node-peer", "goal-peer", "BUILD",
            {"acceptance": ["peer"], "evaluator_contract_id": "eval-peer-v1"},
            ["peer/"],
        )
        self.graph.lease("node-peer", 0, "peer-worker", 60)
        binding_before = self.binding.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "not quiescent"):
            self.integrate()
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "--verify", self.accepted_ref],
            check=False, capture_output=True,
        ).returncode, 128)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM integration_attempts"
        ).fetchone()[0], 0)

    def test_rollback_denies_residual_active_lease_before_physical_mutation(self):
        self.integrate()
        self.graph.connection.execute(
            "UPDATE nodes SET lease_id='residual',lease_owner='worker',"
            "lease_expires_at='2099-01-01T00:00:00+00:00',"
            "heartbeat_at='2026-08-30T00:00:00+00:00' WHERE node_id='node-2'"
        )
        self.graph.connection.commit()
        binding_before = self.binding.read_bytes()
        with self.assertRaisesRegex(RuntimeError, "not quiescent"):
            self.coordinator.rollback(
                "rollback-active-lease", "node-1", "attempt-1", 1,
            )
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), self.candidate)
        self.assertEqual(self.coordinator.publication_head()["version"], 1)

    def test_publication_append_truncation_and_head_corruption_fail_before_side_effects(self):
        for corruption in ("append", "truncate", "head"):
            with self.subTest(corruption=corruption):
                if corruption != "append":
                    self.tearDown()
                    self.setUp()
                self.integrate()
                binding_before = self.binding.read_bytes()
                ref_before = self.accepted_sha()
                head_before = dict(self.graph.connection.execute(
                    "SELECT * FROM publication_heads WHERE project='opensource'"
                ).fetchone())
                if corruption == "append":
                    affected = json.dumps({}, sort_keys=True, separators=(",", ":"))
                    self.graph.connection.execute(
                        "INSERT INTO publication_journal(operation_id,operation_kind,phase,"
                        "project,goal_id,node_id,integration_attempt_id,version_before,"
                        "version_after,from_sha,to_sha,from_generation,to_generation,"
                        "affected_graph_sha256,affected_graph_json,previous_hash,entry_hash) "
                        "VALUES('forged','PROMOTION','COMPLETED','opensource','goal-1',"
                        "'node-1','attempt-1',1,2,?,?,?,?,?,?,?,?)",
                        (
                            self.candidate, self.base, self.candidate, self.base,
                            hashlib.sha256(affected.encode()).hexdigest(), affected,
                            head_before["last_journal_hash"], "f" * 64,
                        ),
                    )
                elif corruption == "truncate":
                    self.graph.connection.execute(
                        "DROP TRIGGER publication_journal_no_delete"
                    )
                    self.graph.connection.execute(
                        "DELETE FROM publication_journal WHERE operation_id='attempt-1'"
                    )
                else:
                    self.graph.connection.execute(
                        "UPDATE publication_heads SET version=99 WHERE project='opensource'"
                    )
                self.graph.connection.commit()
                with self.assertRaises(RuntimeError):
                    self.coordinator.rollback(
                        f"blocked-{corruption}", "node-1", "attempt-1", 1,
                    )
                self.assertEqual(self.binding.read_bytes(), binding_before)
                self.assertEqual(self.accepted_sha(), ref_before)
                if corruption != "head":
                    self.assertEqual(dict(self.graph.connection.execute(
                        "SELECT * FROM publication_heads WHERE project='opensource'"
                    ).fetchone()), head_before)

    def test_truncated_pending_rollback_tail_and_prepared_mutations_fail_closed(self):
        self.integrate()
        with self.assertRaises(SimulatedCrash):
            self.coordinator.rollback(
                "rollback-prepared", "node-1", "attempt-1", 1,
                self.crash_at("after_rollback_prepare"),
            )
        integrated = self.graph.get_node("node-1")
        with self.assertRaisesRegex(RuntimeError, "prepared publication rollback"):
            self.graph.record_integration(
                "node-1", integrated["version"], self.candidate,
            )
        peer = self.graph.get_node("node-2")
        artifact_id = f"sha256:{'9' * 64}"
        claim_version = peer["version"] + 3
        claim_id = deterministic_claim_id(
            artifact_id, "node-2", claim_version, "hermes-evaluator",
        )
        claimed_at = "2000-01-01T00:00:00+00:00"
        self.graph.connection.execute(
            "INSERT INTO evidence_artifacts(artifact_id,node_id,attempt,project,"
            "producer_project_id,manifest_sha256,manifest_relative_path,task_id,"
            "base_sha,candidate_sha,contract_sha256,ingress_version,claim_id,"
            "claimed_by,claim_version,claimed_at) VALUES(?,?,1,'opensource','oss',"
            "?,?,?,?,?,?,?,?,'hermes-evaluator',?,'2000-01-01T00:00:00+00:00')",
            (
                artifact_id, "node-2", "9" * 64,
                f"sha256/99/{'9' * 64}/manifest.json", "node-2",
                self.candidate, "d" * 40, "7" * 64, peer["version"] + 2,
                claim_id, claim_version,
            ),
        )
        self.graph.connection.execute(
            "INSERT INTO evaluation_claims(claim_id,artifact_id,node_id,claim_version,"
            "claimed_by,status,claimed_at,heartbeat_at,expires_at) "
            "VALUES(?,?,?,?,'hermes-evaluator','ACTIVE',?,?,?)",
            (
                claim_id, artifact_id, "node-2", claim_version,
                claimed_at, claimed_at,
                "2000-01-01T00:00:01+00:00",
            ),
        )
        self.graph._event(
            "node-2", peer["version"] + 1, "READY", "LEASED",
            "fixture lease", digest({"lease_id": "fixture-lease"}),
        )
        self.graph._event(
            "node-2", peer["version"] + 2, "LEASED", "RUNNING",
            "fixture start", digest({}),
        )
        self.graph._event(
            "node-2", peer["version"] + 3, "RUNNING", "EVIDENCE_PENDING",
            "immutable evaluator artifact ingressed", "9" * 64,
        )
        self.graph._event(
            "node-2", peer["version"] + 4, "EVIDENCE_PENDING", "EVALUATING",
            "independent evaluator claimed immutable artifact",
            digest({"artifact_id": artifact_id, "claim_id": claim_id}),
        )
        self.graph.connection.execute(
            "UPDATE nodes SET state='EVALUATING',version=?,attempt=1,"
            "active_artifact_id=?,evidence_hash=?,lease_id=NULL,lease_owner=NULL,"
            "lease_expires_at=NULL,heartbeat_at=NULL WHERE node_id='node-2'",
            (peer["version"] + 4, artifact_id, "9" * 64),
        )
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "prepared publication rollback"):
            self.graph.recover_evaluator_claims()
        self.assertEqual(self.graph.connection.execute(
            "SELECT status FROM evaluation_claims WHERE claim_id=?", (claim_id,),
        ).fetchone()[0], "ACTIVE")
        self.graph.connection.execute("DROP TRIGGER publication_journal_no_delete")
        self.graph.connection.execute(
            "DELETE FROM publication_journal WHERE operation_id='rollback-prepared'"
        )
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "tail anchor"):
            self.coordinator.assert_publication_integrity()

    def test_rollback_crash_points_reconcile_physical_and_graph_state(self):
        for point in ("after_rollback_ref", "after_rollback_binding",
                      "before_rollback_completion_commit"):
            with self.subTest(point=point):
                self.tearDown()
                self.setUp()
                self.integrate()
                with self.assertRaises(SimulatedCrash):
                    self.coordinator.rollback(
                        "rollback-crash", "node-1", "attempt-1", 1,
                        self.crash_at(point),
                    )
                result = self.coordinator.reconcile_rollback("rollback-crash")
                self.assertEqual(result["status"], "COMPLETED")
                self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)
                self.assertEqual(self.coordinator.publication_head()["version"], 2)
                self.assertEqual(
                    self.graph.connection.execute(
                        "SELECT accepted_sha FROM goals WHERE goal_id='goal-1'"
                    ).fetchone()[0],
                    self.base,
                )

    def test_rollback_writer_lock_excludes_journal_race_until_published(self):
        self.integrate()
        with self.assertRaises(SimulatedCrash):
            self.coordinator.rollback(
                "rollback-writer-lock", "node-1", "attempt-1", 1,
                self.crash_at("after_rollback_prepare"),
            )
        blocked = []

        def contend(point):
            if point != "after_rollback_binding":
                return
            contender = sqlite3.connect(self.graph.database, timeout=0)
            try:
                contender.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as exc:
                blocked.append(str(exc))
            else:
                contender.rollback()
                self.fail("a concurrent journal writer entered during physical rollback")
            finally:
                contender.close()

        result = self.coordinator.reconcile_rollback(
            "rollback-writer-lock", contend,
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(len(blocked), 1)
        self.assertIn("locked", blocked[0])
        self.assertEqual([
            row[0] for row in self.graph.connection.execute(
                "SELECT phase FROM publication_journal "
                "WHERE operation_id='rollback-writer-lock' ORDER BY sequence"
            ).fetchall()
        ], ["PREPARED", "PUBLISHED", "COMPLETED"])

    def test_prepared_snapshot_tamper_fails_before_rollback_physical_mutation(self):
        self.integrate()
        with self.assertRaises(SimulatedCrash):
            self.coordinator.rollback(
                "rollback-snapshot", "node-1", "attempt-1", 1,
                self.crash_at("after_rollback_prepare"),
            )
        row = dict(self.graph.connection.execute(
            "SELECT * FROM publication_journal "
            "WHERE operation_id='rollback-snapshot' AND phase='PREPARED'"
        ).fetchone())
        affected = json.loads(row["affected_graph_json"])
        affected["nodes"][-1]["version"] += 1
        affected_json = json.dumps(affected, sort_keys=True, separators=(",", ":"))
        self.graph.connection.execute("DROP TRIGGER publication_journal_no_update")
        self.graph.connection.execute(
            "UPDATE publication_journal SET affected_graph_json=?,"
            "affected_graph_sha256=? WHERE sequence=?",
            (affected_json, digest(affected), row["sequence"]),
        )
        self.rehash_publication_journal()
        self.graph.connection.commit()
        binding_before = self.binding.read_bytes()
        ref_before = self.accepted_sha()
        with self.assertRaisesRegex(RuntimeError, "affected graph changed"):
            self.coordinator.reconcile_rollback("rollback-snapshot")
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), ref_before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT phase FROM publication_journal ORDER BY sequence DESC LIMIT 1"
        ).fetchone()[0], "PREPARED")

    def test_pending_rollback_single_operation_admission_and_exact_replay(self):
        self.integrate()
        with self.assertRaises(SimulatedCrash):
            self.coordinator.rollback(
                "rollback-only", "node-1", "attempt-1", 1,
                self.crash_at("after_rollback_prepare"),
            )
        before = self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone()
        with self.assertRaises(SimulatedCrash):
            self.coordinator.rollback(
                "rollback-only", "node-1", "attempt-1", 1,
                self.crash_at("before_rollback_ref"),
            )
        self.assertEqual(
            tuple(self.graph.connection.execute(
                "SELECT last_sequence,last_hash FROM publication_journal_tail"
            ).fetchone()), tuple(before),
        )
        with self.assertRaisesRegex(RuntimeError, "prepared publication rollback"):
            self.coordinator.rollback(
                "rollback-conflict", "node-1", "attempt-1", 1,
            )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM publication_journal "
            "WHERE operation_id='rollback-conflict'"
        ).fetchone()[0], 0)
        self.assertEqual(self.accepted_sha(), self.candidate)
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.candidate)

    def test_semantically_discontinuous_rehashed_journal_is_rejected(self):
        self.integrate()
        self.coordinator.rollback(
            "rollback-semantic", "node-1", "attempt-1", 1,
        )
        forged = "b" * 40
        self.graph.connection.execute("DROP TRIGGER publication_journal_no_update")
        rows = self.graph.connection.execute(
            "SELECT sequence,affected_graph_json FROM publication_journal "
            "WHERE operation_id='rollback-semantic' ORDER BY sequence"
        ).fetchall()
        for row in rows:
            affected = json.loads(row["affected_graph_json"])
            affected["from_sha"] = forged
            affected["head"]["sha"] = forged
            affected["head"]["generation"] = forged
            for goal in affected["goals"]:
                goal["accepted_sha"] = forged
            for node in affected["nodes"]:
                node["base_sha"] = forged
            affected_json = json.dumps(
                affected, sort_keys=True, separators=(",", ":"),
            )
            self.graph.connection.execute(
                "UPDATE publication_journal SET from_sha=?,from_generation=?,"
                "affected_graph_json=?,affected_graph_sha256=? WHERE sequence=?",
                (forged, forged, affected_json, digest(affected), row["sequence"]),
            )
        final_hash = self.rehash_publication_journal()
        self.graph.connection.execute(
            "UPDATE publication_heads SET last_journal_hash=? "
            "WHERE project='opensource'", (final_hash,),
        )
        self.graph.connection.commit()
        with self.assertRaisesRegex(RuntimeError, "discontinuous|node event chain"):
            self.coordinator.assert_publication_integrity()

    def test_missing_pending_rollback_ref_blocks_startup_before_mutation(self):
        from control_plane.graph_service import reconcile_startup

        self.integrate()
        with self.assertRaises(SimulatedCrash):
            self.coordinator.rollback(
                "rollback-missing-ref", "node-1", "attempt-1", 1,
                self.crash_at("after_rollback_prepare"),
            )
        rollback_ref = (
            f"refs/ai-ops/rollback/opensource/{self.candidate}"
        )
        subprocess.run(
            ["git", "-C", self.repo, "update-ref", "-d", rollback_ref], check=True,
        )
        binding_before = self.binding.read_bytes()
        ref_before = self.accepted_sha()
        head_before = dict(self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project='opensource'"
        ).fetchone())
        tail_before = tuple(self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone())
        with self.assertRaisesRegex(RuntimeError, "predecessor ref"):
            reconcile_startup(self.graph, {"opensource": self.coordinator})
        self.assertEqual(self.binding.read_bytes(), binding_before)
        self.assertEqual(self.accepted_sha(), ref_before)
        self.assertEqual(dict(self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project='opensource'"
        ).fetchone()), head_before)
        self.assertEqual(tuple(self.graph.connection.execute(
            "SELECT last_sequence,last_hash FROM publication_journal_tail"
        ).fetchone()), tail_before)

    def test_stale_generation_and_cross_project_rollback_are_denied(self):
        self.integrate()
        with self.assertRaises(RuntimeError):
            self.coordinator.rollback("rollback-stale", "node-1", "attempt-1", 0)
        foreign = ProjectCoordinator(
            self.graph,
            ProjectIntegrator(
                self.repo, self.binding, self.public_key, self.rubric,
                "refs/ai-ops/accepted/business",
            ),
        )
        with self.assertRaises(PermissionError):
            foreign.rollback("rollback-foreign", "node-1", "attempt-1", 1)

    def test_monotonic_head_version_defeats_sha_aba(self):
        self.integrate()
        first = self.coordinator.rollback(
            "rollback-first", "node-1", "attempt-1", 1,
        )
        self.reintegrate_same_candidate()
        head = self.coordinator.publication_head()
        self.assertEqual((head["version"], head["sha"]), (3, self.candidate))
        self.assertEqual(
            self.coordinator.rollback(
                "rollback-first", "node-1", "attempt-1", 1,
            ),
            first,
        )
        with self.assertRaises(RuntimeError):
            self.coordinator.rollback(
                "rollback-stale-after-aba", "node-1", "attempt-1", 3
            )
        current = self.coordinator.rollback(
            "rollback-current-after-aba", "node-3", "attempt-2", 3
        )
        self.assertEqual(current["head_version"], 4)

    def test_idempotency_conflict_cannot_replace_attempt(self):
        self.integrate("attempt-original")
        with self.assertRaises(ValueError):
            self.integrate("attempt-different")

    def test_manifest_mismatch_is_denied_before_fetch_or_binding_mutation(self):
        bad_manifest = self.evidence_root / "wrong.manifest.json"
        value = json.loads(self.manifest.read_text())
        value["task_id"] = "wrong-node"
        bad_manifest.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        before = self.binding.read_bytes()
        with self.assertRaises(PermissionError):
            self.coordinator.integrate(
                "attempt-bad", "node-1", self.outcome_id, self.artifact_id,
                bad_manifest,
                "oss", self.evidence_root,
            )
        self.assertEqual(self.binding.read_bytes(), before)
        refs = subprocess.run(
            ["git", "-C", self.repo, "for-each-ref", "--format=%(refname)", "refs/ai-ops/candidates/"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertEqual(refs, "")

    def test_unpassed_node_is_denied_before_manifest_or_fetch_processing(self):
        self.graph.add_node(
            "node-unpassed", "goal-1", "BUILD",
            {"acceptance": ["not yet"], "evaluator_contract_id": "eval-unpassed-v1"},
            ["other/"],
        )
        with self.assertRaises(PermissionError):
            self.coordinator.integrate(
                "attempt-unpassed", "node-unpassed", self.outcome_id,
                self.artifact_id, self.manifest,
                "oss", self.evidence_root,
            )
        refs = subprocess.run(
            ["git", "-C", self.repo, "for-each-ref", "--format=%(refname)", "refs/ai-ops/candidates/"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertEqual(refs, "")


if __name__ == "__main__":
    unittest.main()
