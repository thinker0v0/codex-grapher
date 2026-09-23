"""Public guest setup permissions, checked without launching a guest."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts/verify-guest-recovery.py"


class GuestSetupPermissionTests(unittest.TestCase):
    @unittest.skipUnless(Path("/usr/sbin/groupadd").is_file() and Path("/usr/sbin/useradd").is_file(),
                         "requires Debian-compatible identity tools for harmless --help probes")
    def test_guest_account_commands_resolve_with_restricted_path(self):
        source = ROOT / "examples/guest-recovery/guest_driver.py"
        spec = importlib.util.spec_from_file_location("guest_recovery_driver", source)
        driver = importlib.util.module_from_spec(spec)
        previous_bytecode = sys.dont_write_bytecode
        try:
            spec.loader.exec_module(driver)
        finally:
            sys.dont_write_bytecode = previous_bytecode
        self.assertEqual(driver.ENV["PATH"], "/usr/bin:/bin")
        identities = {"grapher-" + role.replace("_", "-"): uid for role, uid in driver.ROLES.items()}
        created = set()
        checked = set()

        def lookup(name):
            if name not in created:
                raise KeyError(name)
            return SimpleNamespace(pw_uid=identities[name], pw_gid=identities[name])

        def harmless_probe(argv):
            executable = str(argv[0])
            self.assertIn(executable, {"/usr/sbin/groupadd", "/usr/sbin/useradd"})
            if executable not in checked:
                # Execute only fixed --help probes under the real restricted
                # environment. Never forward account-creation arguments.
                subprocess.run([executable, "--help"], env=driver.ENV, check=True,
                               capture_output=True, timeout=5)
                checked.add(executable)
            if executable == "/usr/sbin/useradd":
                created.add(argv[-1])

        with patch.object(driver.pwd, "getpwnam", side_effect=lookup), \
             patch.object(driver.pwd, "getpwuid", side_effect=KeyError), \
             patch.object(driver, "command", side_effect=harmless_probe):
            driver.accounts()
        self.assertEqual(created, set(identities))
        self.assertEqual(checked, {"/usr/sbin/groupadd", "/usr/sbin/useradd"})

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
