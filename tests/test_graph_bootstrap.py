import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from control_plane.graph_bootstrap import (
    apply_database,
    synthetic_bootstrap_verification,
    verify_bootstrap,
    verify_project,
)
from control_plane.publication_store import MARKER, PublicationStore


class GraphBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "fixture-repo"
        self.repo.mkdir()
        subprocess.run(["git", "-C", self.repo, "init", "-q"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.name", "Fixture"], check=True)
        (self.repo / "value.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", self.repo, "add", "value.txt"], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-qm", "fixture"], check=True)
        self.sha = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        self.accepted_ref = "refs/ai-ops/accepted/opensource"
        subprocess.run(["git", "-C", self.repo, "update-ref", self.accepted_ref, self.sha], check=True)
        self.binding = self.root / "binding.json"
        self.binding.write_text(
            json.dumps({"repo": self.repo.name, "base_sha": self.sha}) + "\n", encoding="utf-8",
        )
        os.chmod(self.binding, 0o440)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        (self.evidence / "manifest.json").write_text(
            json.dumps({"accepted_sha": self.sha}) + "\n", encoding="utf-8",
        )
        self.database = self.root / "graph.sqlite"
        apply_database(self.database)
        self.publication = self.root / "publication"
        self.publication.mkdir()
        PublicationStore(self.publication).ensure(
            self.repo, self.repo.name, self.sha, self.binding.stat(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_canonical_synthetic_verifier_is_local_complete_and_idempotent(self):
        result = synthetic_bootstrap_verification()
        self.assertTrue(result["pass"])
        self.assertTrue(result["database_created_only_by_apply"])
        self.assertFalse(result["second_apply_changed"])
        self.assertEqual(result["publication_status"], "verified")

    def test_project_verification_requires_the_versioned_publication(self):
        with self.assertRaises(PermissionError):
            verify_project(
                self.repo, self.binding, self.accepted_ref, None, self.evidence,
            )

    def test_sha_named_immutable_publication_is_accepted_and_tampering_is_denied(self):
        result = verify_project(
            self.repo, self.binding, self.accepted_ref, self.publication, self.evidence,
        )
        self.assertEqual(result["publication"]["status"], "verified")
        self.assertEqual(result["publication"]["generation"], self.sha)

        marker = self.publication / self.sha / ".git" / MARKER
        marker.chmod(0o600)
        value = json.loads(marker.read_text())
        value["generation"] = "f" * 40
        marker.write_text(json.dumps(value) + "\n")
        with self.assertRaises(PermissionError):
            verify_project(
                self.repo, self.binding, self.accepted_ref, self.publication, self.evidence,
            )

    def test_bootstrap_verifier_binds_database_ref_workspace_and_binding(self):
        project = {
            "repo": self.repo,
            "binding": self.binding,
            "accepted_ref": self.accepted_ref,
            "publication_root": self.publication,
            "evidence_root": self.evidence,
        }
        self.assertTrue(verify_bootstrap(self.database, [project])["pass"])
        self.binding.chmod(0o640)
        with self.assertRaises(PermissionError):
            verify_bootstrap(self.database, [project])

    def test_evidence_symlink_and_dirty_canonical_workspace_are_denied(self):
        outside = self.root / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        (self.evidence / "link").symlink_to(outside)
        with self.assertRaises(PermissionError):
            verify_project(
                self.repo, self.binding, self.accepted_ref, self.publication, self.evidence,
            )
        (self.evidence / "link").unlink()

        (self.repo / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(PermissionError):
            verify_project(
                self.repo, self.binding, self.accepted_ref, self.publication, self.evidence,
            )

    def test_clean_source_head_may_advance_while_ref_binding_and_publication_stay_pinned(self):
        (self.repo / "later.txt").write_text("later source head\n")
        subprocess.run(["git", "-C", self.repo, "add", "later.txt"], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-qm", "later"], check=True)
        self.assertNotEqual(
            subprocess.run(
                ["git", "-C", self.repo, "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip(),
            self.sha,
        )
        result = verify_project(
            self.repo, self.binding, self.accepted_ref, self.publication, self.evidence,
        )
        self.assertEqual(result["accepted_sha"], self.sha)


if __name__ == "__main__":
    unittest.main()
