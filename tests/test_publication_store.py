import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import control_plane.publication_store as publication_store
from control_plane.publication_store import PublicationStore


class PublicationStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "-C", self.repo, "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", self.repo, "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", self.repo, "config", "user.name", "Publication Test"],
            check=True,
        )
        (self.repo / "value.txt").write_text("old\n")
        self.commit("old")
        self.old = self.rev()
        (self.repo / "value.txt").write_text("new\n")
        self.commit("new")
        self.new = self.rev()
        self.binding = self.root / "binding.json"
        self.binding.write_text(json.dumps({"repo": "test", "base_sha": self.old}) + "\n")
        os.chmod(self.binding, 0o440)
        self.store = PublicationStore(self.root / "publications")

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

    def replace_binding(self, sha):
        temporary = self.root / "binding.next"
        temporary.write_text(json.dumps({"repo": "test", "base_sha": sha}) + "\n")
        os.chmod(temporary, 0o440)
        os.replace(temporary, self.binding)

    def test_old_and_new_readers_pin_distinct_complete_generations(self):
        metadata = self.binding.stat()
        self.store.ensure(self.repo, "test", self.old, metadata)
        self.store.ensure(self.repo, "test", self.new, metadata)
        old_reader = self.store.pin_binding(
            self.binding, expected_repo="test", expected_base_sha=self.old
        )
        self.replace_binding(self.new)
        new_reader = self.store.pin_binding(
            self.binding, expected_repo="test", expected_base_sha=self.new
        )

        self.assertNotEqual(old_reader.path, new_reader.path)
        self.assertEqual((old_reader.path / "value.txt").read_text(), "old\n")
        self.assertEqual((new_reader.path / "value.txt").read_text(), "new\n")
        self.assertEqual(
            subprocess.run(
                ["git", "-C", old_reader.path, "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip(),
            self.old,
        )
        self.assertEqual(self.rev(), self.new)

    def test_stale_generation_cross_repository_and_marker_tamper_are_denied(self):
        self.store.ensure(self.repo, "test", self.old, self.binding.stat())
        with self.assertRaises(PermissionError):
            self.store.pin_binding(self.binding, expected_base_sha=self.new)
        with self.assertRaises(PermissionError):
            self.store.pin_binding(self.binding, expected_repo="another-project")

        marker = self.root / "publications" / self.old / ".git/ai-ops-publication.json"
        value = json.loads(marker.read_text())
        value["repo"] = "another-project"
        marker.write_text(json.dumps(value))
        with self.assertRaises(PermissionError):
            self.store.pin_binding(self.binding, expected_repo="test")

    def test_generation_is_self_contained_and_idempotent(self):
        first = self.store.ensure(self.repo, "test", self.old, self.binding.stat())
        second = self.store.ensure(self.repo, "test", self.old, self.binding.stat())
        self.assertEqual(first, second)
        self.assertFalse((first.path / ".git/objects/info/alternates").exists())
        subprocess.run(
            ["git", "-C", self.repo, "repack", "-ad"], check=True,
            capture_output=True,
        )
        self.assertEqual(
            subprocess.run(
                ["git", "-C", first.path, "fsck", "--no-dangling"], check=True,
                capture_output=True, text=True,
            ).returncode,
            0,
        )

    def test_raced_empty_destination_is_never_replaced(self):
        destination = self.root / "publications" / self.old
        raced_marker = destination / "raced-owner"
        atomic_rename = publication_store._rename_noreplace

        def race(source, target):
            self.assertEqual(target, destination)
            target.mkdir()
            raced_marker.write_text("must survive\n")
            atomic_rename(source, target)

        with mock.patch.object(publication_store, "_rename_noreplace", side_effect=race):
            with self.assertRaises((PermissionError, FileNotFoundError)):
                self.store.ensure(self.repo, "test", self.old, self.binding.stat())
        self.assertEqual(raced_marker.read_text(), "must survive\n")
        self.assertFalse((destination / ".git").exists())

    def test_safe_relative_file_symlink_is_verified(self):
        (self.repo / "target.txt").write_text("inside\n")
        (self.repo / "safe-link").symlink_to("target.txt")
        self.commit("safe in-tree file symlink")
        sha = self.rev()
        pin = self.store.ensure(self.repo, "test", sha, self.binding.stat())
        self.assertEqual((pin.path / "safe-link").read_text(), "inside\n")
        self.assertEqual(os.readlink(pin.path / "safe-link"), "target.txt")

    def test_unsafe_symlink_classes_are_rejected_before_publication(self):
        external = self.root / "external.txt"
        external.write_text("outside\n")
        cases = {
            "absolute-link": str(external),
            "escape-link": "../external.txt",
            "broken-link": "missing-target",
            "cyclic-link": "cyclic-link",
            "git-link": ".git/config",
            "directory-link": ".",
        }
        for index, (name, target) in enumerate(cases.items()):
            with self.subTest(name=name):
                link = self.repo / name
                link.symlink_to(target)
                self.commit(f"unsafe symlink {index}")
                sha = self.rev()
                with self.assertRaises(PermissionError):
                    self.store.ensure(self.repo, "test", sha, self.binding.stat())
                self.assertFalse((self.root / "publications" / sha).exists())
                link.unlink()
                self.commit(f"remove unsafe symlink {index}")


if __name__ == "__main__":
    unittest.main()
