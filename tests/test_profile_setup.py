import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from control_plane.execution_profile import ExecutionProfileError, load_execution_profile
from control_plane.profile_setup import create_execution_profile


class ProfileSetupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.code = self.root / "installed-code"
        self.code.mkdir()
        (self.code / "module.py").write_text("VALUE = 1\n")
        self.tool = self.root / "tool"
        self.marker = self.root / "unexpected-execution"
        self.tool.write_text(f"#!/bin/sh\ntouch '{self.marker}'\nprintf 'fixture 1\\n'\n")
        self.tool.chmod(0o755)
        self.private = self.root / "private.pem"
        self.private.write_text("SECRET-KEY-FIXTURE-NEVER-PROFILE-CONTENT\n")
        self.private.chmod(0o600)
        self.public = self.root / "public.pem"
        self.public.write_text("PUBLIC-FIXTURE\n")
        self.output = self.root / "profile.json"
        account = pwd.getpwuid(os.getuid())
        self.arguments = {
            "mode": "trusted-local", "worker_account": account.pw_name,
            "model": "explicit-model", "reasoning_effort": "medium", "service_tier": "default",
            "python_path": self.tool, "git_path": self.tool,
            "provider_path": self.tool, "openssl_path": self.tool,
            "trusted_code_root": self.code, "signer_public_key": self.public,
            "signer_private_key": self.private,
            "roles": {name: {"uid": account.pw_uid, "gid": account.pw_gid}
                      for name in ("worker", "test_runner", "signer", "graph")},
            "observed_versions": {name: "fixture 1" for name in ("python", "git", "provider", "openssl")},
        }

    def create(self, **updates):
        return create_execution_profile(self.output, **(self.arguments | updates))

    def assert_no_output(self):
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".profile-*")), [])
        self.assertFalse(self.marker.exists())

    def test_hashes_explicit_files_and_does_not_execute_or_copy_secrets(self):
        with patch.object(subprocess, "Popen", side_effect=AssertionError("must not execute")), \
                patch.dict(os.environ, {"OPENAI_API_KEY": "AMBIENT-SECRET-NOT-CONFIG"}):
            profile = self.create()
            loaded = load_execution_profile(self.output, require_private_key=True)
        raw = self.output.read_bytes()
        value = json.loads(raw)
        self.assertEqual(profile.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(loaded.sha256, profile.sha256)
        self.assertEqual(value["tools"]["provider"]["sha256"], hashlib.sha256(self.tool.read_bytes()).hexdigest())
        self.assertEqual(value["tools"]["provider"]["version"], "fixture 1")
        self.assertEqual(value["provider"]["model"], "explicit-model")
        self.assertIsNone(value["tools"]["bwrap"])
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(b"SECRET-KEY-FIXTURE", raw)
        self.assertNotIn(b"AMBIENT-SECRET", raw)
        self.assertFalse(self.marker.exists())

    def test_versions_require_exact_enabled_tool_names_before_writing(self):
        for versions in ({}, self.arguments["observed_versions"] | {"unrecognized": "v1"}):
            with self.subTest(versions=versions), self.assertRaises(ExecutionProfileError):
                self.create(observed_versions=versions)
            self.assert_no_output()

    def test_invalid_role_configuration_is_rejected_without_output(self):
        roles = self.arguments["roles"] | {"worker": {"uid": True, "gid": os.getgid()}}
        with self.assertRaises(ExecutionProfileError):
            self.create(roles=roles)
        self.assert_no_output()

    def test_existing_output_is_preserved(self):
        original = b"previous operator profile\n"
        self.output.write_bytes(original)
        with self.assertRaises(ExecutionProfileError):
            self.create()
        self.assertEqual(self.output.read_bytes(), original)
        self.assertEqual(list(self.root.glob(".profile-*")), [])

    def test_concurrent_output_is_preserved_and_temporary_file_removed(self):
        real_link = os.link

        def competing_writer(source, destination, **kwargs):
            self.output.write_bytes(b"concurrent operator profile")
            return real_link(source, destination, **kwargs)

        with patch("control_plane.profile_setup.os.link", side_effect=competing_writer), \
                self.assertRaises(ExecutionProfileError):
            self.create()
        self.assertEqual(self.output.read_bytes(), b"concurrent operator profile")
        self.assertEqual(list(self.root.glob(".profile-*")), [])

    def test_symlink_tool_is_rejected_without_resolving_away_evidence(self):
        link = self.root / "provider-link"
        link.symlink_to(self.tool)
        with self.assertRaises(ExecutionProfileError):
            self.create(provider_path=link)
        self.assert_no_output()

    def test_symlink_output_parent_is_rejected(self):
        alias = self.root / "parent-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ExecutionProfileError):
            create_execution_profile(alias / self.output.name, **self.arguments)
        self.assert_no_output()

    def test_output_cannot_change_the_code_tree_it_pins(self):
        with self.assertRaises(ExecutionProfileError):
            create_execution_profile(self.code / "profile.json", **self.arguments)
        self.assertFalse((self.code / "profile.json").exists())
        self.assert_no_output()

    def test_missing_private_key_requires_explicit_verify_only_intent(self):
        self.private.unlink()
        with self.assertRaises(ExecutionProfileError):
            self.create()
        self.assert_no_output()
        self.create(require_private_key=False)
        with self.assertRaises(ExecutionProfileError):
            load_execution_profile(self.output, require_private_key=True)
        self.assertFalse(self.private.exists())

    def test_tool_change_between_hash_and_admission_is_rejected(self):
        from control_plane import profile_setup
        real_digest = profile_setup.executable_digest
        calls = 0

        def replaced_digest(path):
            nonlocal calls
            result = real_digest(path)
            calls += 1
            if calls == 4:
                self.tool.write_text("#!/bin/sh\nexit 0\n")
            return result

        with patch.object(profile_setup, "executable_digest", side_effect=replaced_digest), \
                self.assertRaises(ExecutionProfileError):
            self.create()
        self.assert_no_output()

    def test_isolated_mode_cannot_use_root_worker_or_implicit_fallback(self):
        roles = self.arguments["roles"] | {"worker": {"uid": 0, "gid": 0}}
        with self.assertRaises(ExecutionProfileError):
            self.create(mode="isolated-linux", roles=roles)
        self.assert_no_output()


if __name__ == "__main__":
    unittest.main()
