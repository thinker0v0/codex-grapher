"""Signer public snapshots preserve source bytes and exclude runtime authority."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane._signer_view import SignerViewError, signer_view
from control_plane.graph_bootstrap import apply_database


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.geteuid() == 0, "signer view creation requires bootstrap root")
class SignerViewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir(mode=0o755)
        for name in ("state", "frozen", "canonical", "evidence", "publications",
                     "attempts", "worker-output", ".broker-receipts/receipts",
                     ".broker-receipts/rejections", ".broker-receipts/.private"):
            (self.root / name).mkdir(parents=True, mode=0o700)
        apply_database(self.root / "state/graph.sqlite")
        (self.root / "state/binding.json").write_text('{"base_sha":"' + "a" * 40 + '"}\n')
        (self.root / "canonical/script.sh").write_text("#!/bin/sh\nexit 0\n")
        (self.root / "canonical/script.sh").chmod(0o755)
        (self.root / "evidence/public-output").write_bytes(b"sealed output\n")
        (self.root / "publications/retained").write_bytes(b"retained generation\n")
        for name in ("attempts/private-prompt", "worker-output/unadmitted",
                     ".broker-receipts/.private/reservation", ".broker-receipts/.lock",
                     "state/.workflow.lock", "state/graph.sqlite.owner.lock"):
            (self.root / name).write_bytes(b"excluded private runtime bytes\n")
        self.profile = SimpleNamespace(
            roles={"graph": SimpleNamespace(uid=20003, gid=20003),
                   "signer": SimpleNamespace(uid=20002, gid=20002)},
            paths={"signer_private_key": str(Path(self.temporary.name) / "external-key")},
            auth_home=Path(self.temporary.name) / "account",
        )
        frozen = {"task.json": b"{}\n", "profile.json": b'{"fixture":"root-validated"}\n',
                  "checks.json": b"{}\n", "producer-contract.json": b"{}\n",
                  "public-key.pem": b"public fixture\n",
                  "policy.json": (ROOT / "examples/repository-workflow/policy.json").read_bytes()}
        self.profile.sha256 = hashlib.sha256(frozen["profile.json"]).hexdigest()
        files = {}
        for name, data in frozen.items():
            (self.root / "frozen" / name).write_bytes(data)
            files["frozen/" + name] = hashlib.sha256(data).hexdigest()
        record = {"workspace": str(self.root), "files": files,
                  "profile_sha256": self.profile.sha256,
                  "policy_sha256": files["frozen/policy.json"]}
        (self.root / "workflow.json").write_text(json.dumps(record, indent=2) + "\n")

    def source_inventory(self):
        return {str(path.relative_to(self.root)): (path.read_bytes(), stat.S_IMODE(path.stat().st_mode),
                                                    path.stat().st_uid, path.stat().st_gid)
                for path in self.root.rglob("*") if path.is_file()}

    def test_public_snapshot_permissions_closure_manifest_and_cleanup(self):
        before = self.source_inventory()
        with signer_view(self.root, self.profile) as view:
            self.assertNotEqual(view, self.root)
            self.assertEqual((view / "workflow.json").read_bytes(), (self.root / "workflow.json").read_bytes())
            self.assertEqual((view / "evidence/public-output").read_bytes(), b"sealed output\n")
            self.assertEqual((view / "publications/retained").read_bytes(), b"retained generation\n")
            self.assertEqual(stat.S_IMODE((view / "canonical/script.sh").stat().st_mode), 0o555)
            binding = (view / "state/binding.json").stat()
            self.assertEqual((binding.st_uid, binding.st_gid, stat.S_IMODE(binding.st_mode)), (20003, 20002, 0o440))
            self.assertEqual(stat.S_IMODE((view / "state/graph.sqlite").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE((view / "state").stat().st_mode), 0o755)
            for name in ("attempts", "worker-output", ".broker-receipts/.private",
                         ".broker-receipts/.lock", "state/.workflow.lock", "state/graph.sqlite.owner.lock"):
                self.assertFalse((view / name).exists())
            manifest_path = view.parent / "view-manifest.json"
            manifest = json.loads(manifest_path.read_bytes())
            self.assertEqual(manifest["workspace"], str(self.root))
            self.assertEqual(manifest["profile_sha256"], self.profile.sha256)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o400)
            self.assertFalse((view / "view-manifest.json").exists())
        self.assertFalse(view.exists())
        self.assertEqual(self.source_inventory(), before)

    def test_socket_and_git_metadata_lock_are_not_copied(self):
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(endpoint.close)
        endpoint.bind(str(self.root / "canonical/runtime.sock"))
        metadata = self.root / "canonical/.git"
        metadata.mkdir()
        (metadata / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = false\n")
        (metadata / "index.lock").write_bytes(b"transient")
        with signer_view(self.root, self.profile) as view:
            self.assertFalse((view / "canonical/runtime.sock").exists())
            self.assertFalse((view / "canonical/.git/index.lock").exists())

    def test_tracked_lockfiles_and_private_names_survive_canonical_and_publication_copy(self):
        repository = self.root / "canonical"
        tracked = {
            "Cargo.lock": b"frozen Rust dependency graph\n",
            "uv.lock": b"frozen Python dependency graph\n",
            ".lock": b"ordinary tracked dotfile\n",
            "index.lock": b"ordinary tracked worktree lockfile\n",
            ".private/tracked.txt": b"ordinary tracked source directory\n",
            ".git-data/index.lock": b"ordinary tracked Git-like directory\n",
            "src/index.lock": b"ordinary tracked nested lockfile\n",
        }
        for relative, data in tracked.items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)

        def git(root, *arguments):
            return subprocess.run(
                ["git", "-C", str(root), *arguments], check=True, capture_output=True,
                env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                     "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
            ).stdout

        git(repository, "init", "-q")
        git(repository, "config", "user.name", "Signer view fixture")
        git(repository, "config", "user.email", "signer@example.invalid")
        git(repository, "config", "core.hooksPath", os.devnull)
        git(repository, "add", ".")
        git(repository, "commit", "-qm", "tracked lockfile fixture")
        candidate = git(repository, "rev-parse", "HEAD").decode().strip()
        generation = self.root / "publications" / candidate
        shutil.copytree(repository, generation)
        for root in (repository, generation):
            (root / ".git/index.lock").write_bytes(b"transient Git index lock\n")
            (root / ".git/refs/heads/pending.lock").write_bytes(b"transient Git ref lock\n")
            self.assertEqual(git(root, "status", "--porcelain=v1"), b"")
        (self.root / "evidence/output.lock").write_bytes(b"immutable evidence bytes\n")
        before = self.source_inventory()
        with signer_view(self.root, self.profile) as view:
            for root in (view / "canonical", view / "publications" / candidate):
                for relative, expected in tracked.items():
                    self.assertEqual((root / relative).read_bytes(), expected)
                self.assertEqual(git(root, "status", "--porcelain=v1"), b"")
                self.assertEqual(git(root, "rev-parse", "HEAD").decode().strip(), candidate)
                self.assertFalse((root / ".git/index.lock").exists())
                self.assertFalse((root / ".git/refs/heads/pending.lock").exists())
            self.assertEqual((view / "evidence/output.lock").read_bytes(), b"immutable evidence bytes\n")
            for excluded in ("state/.workflow.lock", "state/graph.sqlite.owner.lock",
                             ".broker-receipts/.lock", ".broker-receipts/.private"):
                self.assertFalse((view / excluded).exists())
        self.assertEqual(self.source_inventory(), before)

    def test_symlink_hardlink_and_fifo_inputs_reject(self):
        entry = self.root / "evidence/unsafe"
        entry.symlink_to(self.root / "workflow.json")
        with self.assertRaises(SignerViewError):
            with signer_view(self.root, self.profile):
                self.fail("unsafe input admitted")
        entry.unlink()
        os.link(self.root / "evidence/public-output", entry)
        with self.assertRaises(SignerViewError):
            with signer_view(self.root, self.profile):
                self.fail("hardlink admitted")
        entry.unlink()
        os.mkfifo(entry)
        with self.assertRaises(SignerViewError):
            with signer_view(self.root, self.profile):
                self.fail("fifo admitted")

    def test_database_sidecars_and_invalid_graph_are_rejected(self):
        sidecar = self.root / "state/graph.sqlite-wal"
        sidecar.write_bytes(b"uncheckpointed WAL")
        with self.assertRaises(SignerViewError):
            with signer_view(self.root, self.profile):
                self.fail("WAL omission admitted")
        sidecar.unlink()
        (self.root / "state/graph.sqlite").write_bytes(b"not sqlite")
        with self.assertRaises(SignerViewError):
            with signer_view(self.root, self.profile):
                self.fail("corrupt graph admitted")

    def test_frozen_bytes_profile_and_original_path_are_bound(self):
        for field in ("workspace", "profile_sha256"):
            raw = (self.root / "workflow.json").read_bytes()
            record = json.loads(raw)
            record[field] = "/other" if field == "workspace" else "0" * 64
            (self.root / "workflow.json").write_text(json.dumps(record))
            with self.subTest(field=field), self.assertRaises(SignerViewError):
                with signer_view(self.root, self.profile):
                    self.fail("authority mismatch admitted")
            (self.root / "workflow.json").write_bytes(raw)
        (self.root / "frozen/checks.json").write_text('{"changed":true}')
        with self.assertRaises(SignerViewError):
            with signer_view(self.root, self.profile):
                self.fail("changed frozen input admitted")

    def test_source_mutation_between_copy_and_verification_rejects(self):
        import control_plane._signer_view as module
        original = module._verify_snapshot

        def mutate(*arguments):
            original(*arguments)
            (self.root / "evidence/public-output").write_bytes(b"changed source\n")

        with patch.object(module, "_verify_snapshot", side_effect=mutate):
            with self.assertRaises(SignerViewError):
                with signer_view(self.root, self.profile):
                    self.fail("changed source admitted")

    def test_configured_private_key_inside_selected_inputs_rejects(self):
        for relative in ("secret", "Cargo.lock", ".private/key"):
            secret = self.root / "canonical" / relative
            secret.parent.mkdir(parents=True, exist_ok=True)
            secret.write_bytes(b"private fixture")
            self.profile.paths["signer_private_key"] = str(secret)
            with self.subTest(relative=relative), self.assertRaises(SignerViewError):
                with signer_view(self.root, self.profile):
                    self.fail("configured private path copied")
            secret.unlink()

    def test_copy_limits_and_nonroot_fail_closed(self):
        with patch("control_plane._signer_view.MAX_FILE_BYTES", 10):
            with self.assertRaises(SignerViewError):
                with signer_view(self.root, self.profile):
                    self.fail("oversized input admitted")
        with patch("control_plane._signer_view.os.geteuid", return_value=20002):
            with self.assertRaises(SignerViewError):
                with signer_view(self.root, self.profile):
                    self.fail("nonroot created snapshot")

    def test_git_filter_configuration_is_rejected_without_execution(self):
        metadata = self.root / "canonical/.git"
        metadata.mkdir()
        config = metadata / "config"
        config.write_text("[core]\nrepositoryformatversion = 0\nbare = false\nhooksPath = /dev/null\n")
        with patch("subprocess.Popen", side_effect=AssertionError("Git must not execute during config parsing")):
            with signer_view(self.root, self.profile):
                pass
            config.write_text("[filter \"attack\"]\nclean = touch /must-not-exist\n")
            with self.assertRaises(SignerViewError):
                with signer_view(self.root, self.profile):
                    self.fail("executable Git config admitted")


if __name__ == "__main__":
    unittest.main()
