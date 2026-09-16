import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from control_plane.evidence_ingress import EvidenceIngress, resolve_manifest


BASE = "a" * 40
CANDIDATE = "b" * 40


class EvidenceIngressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "worker-evidence"
        self.target = self.root / "evaluator-artifacts"
        self.source.mkdir()
        self.target.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def file_record(path: str, data: bytes) -> dict:
        return {
            "path": path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "byte_length": len(data),
        }

    def fixture(self, task_id: str = "node-1", attempt: int = 1) -> tuple[str, dict]:
        artifact_root = self.source / task_id / f"attempt-{attempt}"
        outputs = artifact_root / "required-tests"
        outputs.mkdir(parents=True)
        bundle = b"fixture bundle bytes\n"
        first = b"fixture one\n"
        second = b"fixture two\n"
        path_check = b'{"valid":true,"violations":[]}\n'
        (artifact_root / "candidate.bundle").write_bytes(bundle)
        (artifact_root / "path-check.json").write_bytes(path_check)
        (outputs / "0000.output").write_bytes(first)
        (outputs / "0001.output").write_bytes(second)
        manifest = {
            "schema_version": 4,
            "task_id": task_id,
            "attempt": attempt,
            "project_id": "oss",
            "base_sha": BASE,
            "candidate_sha": CANDIDATE,
            "producer_identity": "hermes-oss",
            "created_at": "2026-08-30T00:00:00+00:00",
            "contract_sha256": "c" * 64,
            "path_check": self.file_record("path-check.json", path_check),
            "bundle": self.file_record("candidate.bundle", bundle),
            "required_tests": [
                {
                    "sequence": 0,
                    "command": "fixture-command-one",
                    "candidate_sha": CANDIDATE,
                    "exit_code": 0,
                    "output": self.file_record("required-tests/0000.output", first),
                },
                {
                    "sequence": 1,
                    "command": "fixture-command-two",
                    "candidate_sha": CANDIDATE,
                    "exit_code": 0,
                    "output": self.file_record("required-tests/0001.output", second),
                },
            ],
        }
        relative = f"{task_id}/attempt-{attempt}/manifest.json"
        (self.source / relative).write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        return relative, manifest

    def ingest(
        self, task_id: str = "node-1", contract_sha256: str = "c" * 64,
        attempt: int = 1,
    ):
        return EvidenceIngress(self.source, self.target).ingest(
            expected_task_id=task_id,
            expected_attempt=attempt,
            expected_project_id="oss",
            expected_base_sha=BASE,
            expected_contract_sha256=contract_sha256,
            expected_required_tests=["fixture-command-one", "fixture-command-two"],
        )

    def test_ingress_copies_new_inodes_and_exact_replay_is_idempotent(self):
        relative, manifest = self.fixture()
        first = self.ingest()
        second = self.ingest()
        self.assertEqual(first, second)
        self.assertEqual(first.artifact_id, f"sha256:{first.manifest_sha256}")
        stored_manifest = self.target / first.manifest_relative_path
        self.assertEqual(stored_manifest.read_bytes(), (self.source / relative).read_bytes())
        source_root = self.source / "node-1" / "attempt-1"
        source_bundle = source_root / manifest["bundle"]["path"]
        stored_bundle = stored_manifest.parent / manifest["bundle"]["path"]
        source_path_check = source_root / manifest["path_check"]["path"]
        stored_path_check = stored_manifest.parent / manifest["path_check"]["path"]
        self.assertNotEqual(source_bundle.stat().st_ino, stored_bundle.stat().st_ino)
        self.assertEqual(stored_bundle.stat().st_nlink, 1)
        self.assertNotEqual(source_path_check.stat().st_ino, stored_path_check.stat().st_ino)
        self.assertEqual(stored_path_check.stat().st_nlink, 1)

    def test_attempt_namespace_and_manifest_binding_are_exact(self):
        first_relative, _ = self.fixture(attempt=1)
        second_relative, _ = self.fixture(attempt=2)
        first = self.ingest(attempt=1)
        second = self.ingest(attempt=2)
        self.assertNotEqual(first.artifact_id, second.artifact_id)
        self.assertEqual(first.attempt, 1)
        self.assertEqual(second.attempt, 2)
        self.assertTrue(first_relative.endswith("node-1/attempt-1/manifest.json"))
        self.assertTrue(second_relative.endswith("node-1/attempt-2/manifest.json"))

        value = json.loads((self.source / first_relative).read_text())
        value["attempt"] = 2
        (self.source / first_relative).write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        )
        with self.assertRaises(PermissionError):
            self.ingest(attempt=1)

    def test_existing_content_address_is_never_overwritten(self):
        relative, _ = self.fixture()
        manifest_bytes = (self.source / relative).read_bytes()
        manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
        occupied = self.target / "sha256" / manifest_hash[:2] / manifest_hash
        occupied.mkdir(parents=True)
        marker = occupied / "do-not-overwrite"
        marker.write_text("existing\n")
        with self.assertRaises((PermissionError, FileNotFoundError)):
            self.ingest()
        self.assertEqual(marker.read_text(), "existing\n")

    def test_source_symlink_hardlink_and_traversal_are_rejected(self):
        relative, _ = self.fixture()
        source_root = self.source / "node-1" / "attempt-1"
        bundle = source_root / "candidate.bundle"
        os.link(bundle, source_root / "second-link.bundle")
        with self.assertRaises(PermissionError):
            self.ingest()
        (source_root / "second-link.bundle").unlink()
        real_manifest = self.source / relative
        saved_manifest = self.source / "saved.manifest.json"
        real_manifest.rename(saved_manifest)
        real_manifest.symlink_to(saved_manifest)
        with self.assertRaises(OSError):
            self.ingest()
        with self.assertRaises(PermissionError):
            EvidenceIngress(self.source, self.target).ingest(
                expected_task_id="../outside", expected_project_id="oss",
                expected_attempt=1,
                expected_base_sha=BASE, expected_contract_sha256="c" * 64,
                expected_required_tests=["fixture-command-one", "fixture-command-two"],
            )

    def test_test_result_order_exit_candidate_and_output_tampering_are_rejected(self):
        mutations = [
            lambda value: value["required_tests"][0].update(sequence=1),
            lambda value: value["required_tests"][0].update(exit_code=True),
            lambda value: value["required_tests"][0].update(exit_code=9),
            lambda value: value["required_tests"][0].update(candidate_sha="e" * 40),
            lambda value: value["required_tests"][0]["output"].update(sha256="f" * 64),
            lambda value: value["required_tests"][0]["output"].update(byte_length=999),
            lambda value: value["required_tests"][0]["output"].update(path="../escape"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                task_id = f"node-{index + 10}"
                relative, manifest = self.fixture(task_id)
                mutate(manifest)
                (self.source / relative).write_text(
                    json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
                )
                with self.assertRaises(PermissionError):
                    self.ingest(task_id)

    def test_tampered_published_bytes_make_replay_fail_closed(self):
        relative, manifest = self.fixture()
        artifact = self.ingest()
        stored_manifest = self.target / artifact.manifest_relative_path
        stored_output = stored_manifest.parent / manifest["required_tests"][0]["output"]["path"]
        os.chmod(stored_output, 0o600)
        stored_output.write_bytes(b"tampered\n")
        with self.assertRaises(PermissionError):
            self.ingest()

    def test_completed_recovery_rejects_an_extra_unbound_file(self):
        self.fixture()
        artifact = self.ingest()
        stored_manifest = self.target / artifact.manifest_relative_path
        os.chmod(stored_manifest.parent, 0o750)
        extra = stored_manifest.parent / "unbound-extra.txt"
        extra.write_text("not named by the canonical manifest\n")
        with self.assertRaisesRegex(PermissionError, "unexpected files"):
            resolve_manifest(
                self.target, artifact.manifest_relative_path,
                artifact.manifest_sha256,
            )

    def test_completed_recovery_rejects_an_extra_empty_directory(self):
        self.fixture()
        artifact = self.ingest()
        stored_manifest = self.target / artifact.manifest_relative_path
        os.chmod(stored_manifest.parent, 0o750)
        (stored_manifest.parent / "unbound-empty-directory").mkdir()
        with self.assertRaisesRegex(PermissionError, "unexpected files or directories"):
            resolve_manifest(
                self.target, artifact.manifest_relative_path,
                artifact.manifest_sha256,
            )

    def test_contract_hash_command_and_path_check_bindings_fail_closed(self):
        relative, manifest = self.fixture()
        with self.assertRaises(PermissionError):
            self.ingest(contract_sha256="e" * 64)

        manifest["required_tests"][0]["command"] = "worker-selected-command"
        (self.source / relative).write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        with self.assertRaises(PermissionError):
            self.ingest()

        manifest["required_tests"][0]["command"] = "fixture-command-one"
        path_check = self.source / "node-1" / "attempt-1" / "path-check.json"
        path_check.write_text('{"valid":false,"violations":["forbidden"]}\n')
        manifest["path_check"] = self.file_record("path-check.json", path_check.read_bytes())
        (self.source / relative).write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        with self.assertRaises(PermissionError):
            self.ingest()


if __name__ == "__main__":
    unittest.main()
