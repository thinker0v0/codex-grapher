import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import venv

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

    @unittest.skipUnless(os.geteuid() == 0, "requires dropping credentials for a disposable copied venv")
    def test_trusted_local_venv_create_and_load_as_actual_nonroot_user(self):
        try:
            account = pwd.getpwuid(1000)
        except KeyError:
            self.skipTest("requires an existing UID 1000 account; never creates host accounts")
        self.root.chmod(0o755)
        fixture = self.root / "user-owned"
        fixture.mkdir()
        prefix = fixture / "venv"
        venv.EnvBuilder(with_pip=False, symlinks=False).create(prefix)
        minor = f"{sys.version_info.major}.{sys.version_info.minor}"
        code = prefix / "lib" / f"python{minor}" / "site-packages"
        package = code / "control_plane"
        package.mkdir()
        source = Path(__file__).resolve().parents[1] / "control_plane"
        for name in ("__init__.py", "execution_profile.py", "profile_setup.py"):
            shutil.copyfile(source / name, package / name)
        tool = fixture / "tool"
        marker = fixture / "unexpected-tool-execution"
        tool.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 87\n")
        tool.chmod(0o755)
        (fixture / "public.pem").write_text("PUBLIC-FIXTURE\n")
        private = fixture / "private.pem"
        private.write_text("SECRET-KEY-FIXTURE-NEVER-PROFILE-CONTENT\n")
        private.chmod(0o600)
        for directory, directories, files in os.walk(fixture, followlinks=False):
            for path in [Path(directory), *(Path(directory) / name for name in directories + files)]:
                os.chown(path, account.pw_uid, account.pw_gid, follow_symlinks=False)
        python = prefix / "bin" / f"python{minor}"
        self.assertFalse(python.is_symlink())
        cfg = prefix / "pyvenv.cfg"
        initial_cfg = cfg.read_bytes(), cfg.stat().st_mode
        driver = textwrap.dedent("""
            import hashlib, json, os, pathlib, pwd, subprocess, sys
            from unittest.mock import patch
            from control_plane import execution_profile, profile_setup

            fixture = pathlib.Path(sys.argv[1])
            prefix = fixture / "venv"
            code = prefix / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
            account = pwd.getpwuid(os.getuid())
            tool = fixture / "tool"
            versions = {name: "fixture 1" for name in ("git", "provider", "openssl")}
            versions["python"] = "Python " + ".".join(str(part) for part in sys.version_info[:3])
            output = fixture / "profile.json"
            with patch.object(subprocess, "Popen", side_effect=AssertionError("profile tools must never execute")):
                created = profile_setup.create_execution_profile(
                    output, mode="trusted-local", worker_account=account.pw_name,
                    model="explicit-model", reasoning_effort="medium", service_tier="default",
                    python_path=pathlib.Path(sys.executable), git_path=tool,
                    provider_path=tool, openssl_path=tool, trusted_code_root=code,
                    signer_public_key=fixture / "public.pem", signer_private_key=fixture / "private.pem",
                    roles={name: {"uid": os.getuid(), "gid": os.getgid()}
                           for name in ("worker", "test_runner", "signer", "graph")},
                    observed_versions=versions)
                loaded = execution_profile.load_execution_profile(output, require_private_key=True)
            print(json.dumps({
                "uid": os.getuid(), "gid": os.getgid(), "mode": loaded.mode,
                "prefix": sys.prefix, "module": execution_profile.__file__,
                "cfg_uid": (prefix / "pyvenv.cfg").stat().st_uid,
                "profile_uid": output.stat().st_uid,
                "loaded_hash_matches": loaded.sha256 == created.sha256 == hashlib.sha256(output.read_bytes()).hexdigest(),
                "code_hash_matches": loaded.paths["trusted_code_sha256"] == execution_profile.trusted_code_digest(code, isolated=False),
            }))
        """)
        result = subprocess.run(
            [str(python), "-I", "-B", "-c", driver, str(fixture)],
            cwd=fixture, user=account.pw_uid, group=account.pw_gid, extra_groups=[],
            env={"HOME": account.pw_dir, "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                 "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(observed, {
            "uid": 1000, "gid": account.pw_gid, "mode": "trusted-local",
            "prefix": str(prefix), "module": str(package / "execution_profile.py"),
            "cfg_uid": 1000, "profile_uid": 1000,
            "loaded_hash_matches": True, "code_hash_matches": True,
        })
        self.assertEqual((cfg.read_bytes(), cfg.stat().st_mode), initial_cfg)
        self.assertFalse(marker.exists())
        self.assertNotIn(b"SECRET-KEY-FIXTURE", (fixture / "profile.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
