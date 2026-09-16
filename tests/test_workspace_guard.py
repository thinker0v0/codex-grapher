import tempfile
import unittest
from pathlib import Path

from control_plane.workspace_guard import inventory, violations


class WorkspaceGuardTests(unittest.TestCase):
    def test_denies_changes_outside_allowed_prefix(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "allowed").mkdir()
            (root / "allowed/a.txt").write_text("before")
            (root / "policy.txt").write_text("fixed")
            before = inventory(root)
            (root / "allowed/a.txt").write_text("after")
            (root / "policy.txt").write_text("tampered")
            self.assertEqual(violations(before, inventory(root), ["allowed/"]), ["policy.txt"])

    def test_detects_delete_and_symlink_outside_scope(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "fixed.txt").write_text("fixed")
            before = inventory(root)
            (root / "fixed.txt").unlink()
            (root / "escape").symlink_to("/etc/passwd")
            self.assertEqual(violations(before, inventory(root), ["src/"]), ["escape", "fixed.txt"])


if __name__ == "__main__":
    unittest.main()
