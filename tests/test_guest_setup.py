"""Public guest setup permissions, checked without launching a guest."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts/verify-guest-recovery.py"


class GuestSetupPermissionTests(unittest.TestCase):
    def test_public_setup_under_private_umask_preserves_existing_paths(self):
        spec = importlib.util.spec_from_file_location("guest_recovery_harness", HARNESS)
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        previous = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix="grapher-install-modes-") as temporary:
                fixture = Path(temporary)
                tree = fixture / "public-code"
                nested = tree / "control_plane"
                nested.mkdir(parents=True)
                data = nested / "module.py"
                data.write_text("# inert public fixture\n")
                executable = tree / "fixture-provider"
                executable.write_text("#!/bin/sh\nexit 0\n")
                executable.chmod(0o700)
                before = {str(path.relative_to(fixture)): stat.S_IMODE(path.stat().st_mode)
                          for path in (tree, nested, data, executable)}
                self.assertEqual(before["public-code"], 0o700)
                self.assertEqual(before["public-code/control_plane"], 0o700)
                argv = [sys.executable, "-I", "-c", harness.PUBLIC_TREE_MODE_PROGRAM, str(tree)]
                subprocess.run(argv, capture_output=True, timeout=10, check=True)
                after = {str(path.relative_to(fixture)): stat.S_IMODE(path.stat().st_mode)
                         for path in (tree, nested, data, executable)}
                self.assertEqual(after, {"public-code": 0o555, "public-code/control_plane": 0o555,
                    "public-code/control_plane/module.py": 0o444, "public-code/fixture-provider": 0o555})
                cache = fixture / "new-public-parent/cache"
                harness.make_public_directory(cache)
                self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(cache.parent.stat().st_mode), 0o755)
                existing = fixture / "existing-private"
                existing.mkdir(mode=0o700)
                harness.make_public_directory(existing)
                self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(fixture.stat().st_mode), 0o700)
                # Permit ordinary non-root test runners to remove this fixture.
                for directory in (tree, nested):
                    directory.chmod(0o700)
        finally:
            os.umask(previous)


if __name__ == "__main__":
    unittest.main()
