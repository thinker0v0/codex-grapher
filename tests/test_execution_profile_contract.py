"""Focused admission tests; no provider process or host account mutation."""

import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import pwd
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jsonschema

from control_plane.execution_profile import (
    ExecutionProfileError,
    executable_digest,
    load_execution_profile,
    trusted_code_digest,
    validate_execution_profile,
    venv_runtime_metadata,
)


ROOT = Path(__file__).resolve().parents[1]


class ExecutionProfileContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.code = self.root / "installed"
        self.code.mkdir()
        (self.code / "entry.py").write_text("# immutable fixture; never imported\n")
        self.tool = self.root / "tool"
        self.tool.write_text("#!/bin/sh\necho NEVER_EXECUTE_PROFILE_TOOLS\nexit 87\n")
        self.tool.chmod(0o755)
        self.public = self.root / "public.pem"
        self.public.write_text("public fixture, not a cryptographic key\n")
        self.private = self.root / "private.pem"
        account = pwd.getpwuid(os.getuid())
        self.value = {
            "schema_version": 1,
            "mode": "trusted-local",
            "tools": {
                name: ({"path": str(self.tool), "sha256": executable_digest(self.tool),
                        "version": "declared fixture 1"}
                       if name not in {"bwrap", "setpriv"} else None)
                for name in ("python", "git", "provider", "openssl", "bwrap", "setpriv")
            },
            "provider": {"backend": "codex", "model": "gpt-5.6-sol",
                         "reasoning_effort": "medium", "service_tier": "default"},
            "roles": {name: {"uid": account.pw_uid, "gid": account.pw_gid}
                      for name in ("worker", "test_runner", "signer", "graph")},
            "auth": {"kind": "existing-cli-login", "account": account.pw_name},
            "paths": {"trusted_code_root": str(self.code),
                      "trusted_code_sha256": trusted_code_digest(self.code),
                      "signer_private_key": str(self.private),
                      "signer_public_key": str(self.public)},
            "sqlite": {"profile": "delete-extra", "attestation": None},
        }

    def write_profile(self, value=None):
        path = self.root / "profile.json"
        path.write_text(json.dumps(self.value if value is None else value, indent=2) + "\n")
        return path

    def isolated(self):
        value = copy.deepcopy(self.value)
        value["mode"] = "isolated-linux"
        value["tools"]["bwrap"] = copy.deepcopy(value["tools"]["python"])
        value["tools"]["setpriv"] = copy.deepcopy(value["tools"]["python"])
        for index, name in enumerate(value["roles"]):
            value["roles"][name] = {"uid": 20001 + index, "gid": 20001 + index}
        home = self.root / "account-home"
        home.mkdir(exist_ok=True)
        os.chown(home, 20001, 20001)
        value["auth"]["account"] = "fixture-worker"
        account = SimpleNamespace(pw_name="fixture-worker", pw_uid=20001,
                                  pw_gid=20001, pw_dir=str(home))
        return value, account

    def test_load_binds_exact_bytes_and_never_executes_tools(self):
        path = self.write_profile()
        with patch("subprocess.Popen", side_effect=AssertionError("no execution")):
            profile = load_execution_profile(path)
        self.assertEqual(profile.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(profile.tools["provider"].version, "declared fixture 1")
        self.assertEqual(profile.auth_home, Path(pwd.getpwuid(os.getuid()).pw_dir))
        self.assertEqual(profile.to_dict(), self.value)
        with self.assertRaises(FrozenInstanceError):
            profile.mode = "isolated-linux"
        with self.assertRaises(TypeError):
            profile.provider["model"] = "another"
        changed = profile.raw
        changed["tools"]["python"]["path"] = "/bad"
        self.assertEqual(profile.to_dict(), self.value)

    def test_semantically_equal_bytes_have_distinct_profile_hashes(self):
        compact = json.dumps(self.value).encode()
        pretty = json.dumps(self.value, indent=2).encode()
        left = validate_execution_profile(self.value, raw_bytes=compact)
        right = validate_execution_profile(self.value, raw_bytes=pretty)
        self.assertNotEqual(left.sha256, right.sha256)
        self.assertEqual(left.to_dict(), right.to_dict())

    def test_raw_bytes_must_match_validated_dictionary(self):
        other = copy.deepcopy(self.value)
        other["provider"]["model"] = "different"
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value, raw_bytes=json.dumps(other).encode())

    def test_profile_size_encoding_and_special_file_fail_before_loading(self):
        path = self.write_profile()
        for data in (b" " * (65536 + 1), b"\xff", b"\xef\xbb\xbf{}", b"[]"):
            path.write_bytes(data)
            with self.subTest(data=data[:4]), self.assertRaises(ExecutionProfileError):
                load_execution_profile(path)
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(ExecutionProfileError):
            load_execution_profile(path)

    def test_duplicate_json_keys_including_nested_and_nonfinite_reject(self):
        path = self.write_profile()
        raw = path.read_text()
        cases = [raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                 raw.replace('"backend": "codex"', '"backend": "codex", "backend": "codex"'),
                 raw.replace('"schema_version": 1', '"schema_version": NaN'),
                 raw.replace('"schema_version": 1', '"schema_version": Infinity')]
        for case in cases:
            with self.subTest(case=case[:40]):
                path.write_text(case)
                with self.assertRaises(ExecutionProfileError):
                    load_execution_profile(path)

    def test_strict_types_unknown_fields_hashes_and_bounds_reject(self):
        changes = [
            (("schema_version",), True), (("schema_version",), 1.0),
            (("roles", "worker", "uid"), True), (("roles", "worker", "gid"), -1),
            (("roles", "graph", "uid"), 4294967295),
            (("roles", "graph", "uid"), 1.0),
            (("auth", "home"), "/tmp"), (("environment",), {}),
            (("tools", "python", "sha256"), "A" * 64),
            (("tools", "python", "version"), ""),
            (("tools", "provider"), None), (("provider", "model"), " "),
            (("provider", "backend"), "other"),
            (("tools", "python", "extra"), "arbitrary"),
            (("sqlite", "attestation"), str(self.public)),
        ]
        for parts, replacement in changes:
            value = copy.deepcopy(self.value)
            target = value
            for key in parts[:-1]:
                target = target[key]
            target[parts[-1]] = replacement
            with self.subTest(parts=parts, replacement=replacement):
                with self.assertRaises(ExecutionProfileError):
                    validate_execution_profile(value)

    def test_account_uid_gid_and_home_are_bound_to_actual_database(self):
        actual = pwd.getpwuid(os.getuid())
        for field in ("pw_uid", "pw_gid", "pw_name", "pw_dir"):
            account = SimpleNamespace(pw_name=actual.pw_name, pw_uid=actual.pw_uid,
                                      pw_gid=actual.pw_gid, pw_dir=actual.pw_dir)
            setattr(account, field, "/missing-auth-home" if field == "pw_dir" else
                    "wrong-name" if field == "pw_name" else getattr(account, field) + 1)
            with self.subTest(field=field), patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
                with self.assertRaises(ExecutionProfileError):
                    validate_execution_profile(self.value)
        with patch("control_plane.execution_profile.pwd.getpwnam", side_effect=KeyError):
            with self.assertRaises(ExecutionProfileError):
                validate_execution_profile(self.value)

    def test_missing_private_key_is_verify_only_and_permissions_checked(self):
        validate_execution_profile(self.value, require_private_key=False)
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value, require_private_key=True)
        self.private.write_text("private fixture; never printed\n")
        self.private.chmod(0o600)
        validate_execution_profile(self.value, require_private_key=True)
        for mode in (0o644, 0o620, 0o604):
            self.private.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ExecutionProfileError):
                validate_execution_profile(self.value, require_private_key=True)

    def test_profile_tool_and_ancestor_symlinks_reject(self):
        source = self.write_profile()
        link = self.root / "linked-profile"
        link.symlink_to(source)
        with self.assertRaises(ExecutionProfileError):
            load_execution_profile(link)
        directory_link = self.root / "linked-root"
        directory_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ExecutionProfileError):
            load_execution_profile(directory_link / "profile.json")
        value = copy.deepcopy(self.value)
        value["tools"]["python"]["path"] = str(directory_link / "tool")
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(value)

    def test_tool_pin_mode_and_canonical_path_are_enforced(self):
        original = self.tool.read_bytes()
        self.tool.write_bytes(original + b"# drift\n")
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value)
        validate_execution_profile(self.value, verify_tools=False)
        self.tool.write_bytes(original)
        for mode in (0o644, 0o4755, 0o2755):
            self.tool.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ExecutionProfileError):
                validate_execution_profile(self.value, verify_tools=False)
        self.tool.chmod(0o755)
        for path in ("tool", str(self.root) + "/./tool", str(self.root) + "//tool",
                     str(self.root) + "/else/../tool"):
            value = copy.deepcopy(self.value)
            value["tools"]["python"]["path"] = path
            with self.subTest(path=path), self.assertRaises(ExecutionProfileError):
                validate_execution_profile(value)

    def test_tree_digest_is_order_and_timestamp_independent_but_complete(self):
        left, right = self.root / "left", self.root / "right"
        left.mkdir()
        right.mkdir()
        for name in ("z", "a", "unicode-\u2603", "line\nbreak"):
            (left / name).write_text(name)
        for name in ("line\nbreak", "unicode-\u2603", "a", "z"):
            (right / name).write_text(name)
            os.utime(right / name, (1, 1))
        self.assertEqual(trusted_code_digest(left), trusted_code_digest(right))
        initial = trusted_code_digest(left)
        (left / "z").chmod(0o755)
        self.assertNotEqual(initial, trusted_code_digest(left))
        (right / ".hidden").write_text("all entries are bound")
        self.assertNotEqual(initial, trusted_code_digest(right))

    def test_tree_links_special_files_and_changed_code_fail(self):
        entry = self.code / "entry.py"
        entry.write_text("# changed\n")
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value, verify_tools=False)
        link = self.code / "link.py"
        link.symlink_to(entry)
        with self.assertRaises(ExecutionProfileError):
            trusted_code_digest(self.code)
        link.unlink()
        os.link(entry, link)
        with self.assertRaises(ExecutionProfileError):
            trusted_code_digest(self.code)
        link.unlink()
        fifo = self.code / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ExecutionProfileError):
            trusted_code_digest(self.code)

    def test_tree_mutation_during_inventory_rejects(self):
        import control_plane.execution_profile as module
        original = module._read_regular

        def mutate_after_read(path, label, **kwargs):
            result = original(path, label, **kwargs)
            (self.code / "new-module.py").write_text("# late addition\n")
            return result

        with patch.object(module, "_read_regular", side_effect=mutate_after_read):
            with self.assertRaises(ExecutionProfileError):
                trusted_code_digest(self.code)

    def test_signing_keys_cannot_be_importable_trusted_code(self):
        key = self.code / "public.pem"
        key.write_text("fixture")
        self.value["paths"]["trusted_code_sha256"] = trusted_code_digest(self.code)
        self.value["paths"]["signer_public_key"] = str(key)
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value)

    @unittest.skipUnless(os.geteuid() == 0, "requires ownership of disposable fixture files")
    def test_isolated_profile_accepts_distinct_numeric_roles_without_account_creation(self):
        value, account = self.isolated()
        with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
            result = validate_execution_profile(value)
        self.assertEqual(len({role.uid for role in result.roles.values()}), 4)

    @unittest.skipUnless(os.geteuid() == 0, "requires ownership of disposable fixture files")
    def test_isolated_root_duplicate_uid_or_missing_tools_reject(self):
        value, account = self.isolated()
        cases = []
        for uid in (0, value["roles"]["worker"]["uid"]):
            changed = copy.deepcopy(value)
            changed["roles"]["signer"]["uid"] = uid
            cases.append(changed)
        for tool in ("bwrap", "setpriv"):
            changed = copy.deepcopy(value)
            changed["tools"][tool] = None
            cases.append(changed)
        with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
            for changed in cases:
                with self.assertRaises(ExecutionProfileError):
                    validate_execution_profile(changed)

    @unittest.skipUnless(os.geteuid() == 0, "requires ownership of disposable fixture files")
    def test_isolated_profile_and_ancestors_must_be_protected(self):
        value, account = self.isolated()
        path = self.write_profile(value)
        with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
            load_execution_profile(path)
            path.chmod(0o666)
            with self.assertRaises(ExecutionProfileError):
                load_execution_profile(path)
            path.chmod(0o600)
            self.root.chmod(0o777)
            with self.assertRaises(ExecutionProfileError):
                load_execution_profile(path)
            self.root.chmod(0o700)
            os.chown(self.code / "entry.py", 20001, 20001)
            with self.assertRaises(ExecutionProfileError):
                load_execution_profile(path)

    @unittest.skipUnless(os.geteuid() == 0, "requires ownership of disposable fixture files")
    def test_isolated_key_group_cannot_be_shared_with_graph(self):
        value, account = self.isolated()
        self.private.write_text("private fixture")
        self.private.chmod(0o440)
        os.chown(self.private, 0, value["roles"]["signer"]["gid"])
        with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
            validate_execution_profile(value, require_private_key=True)
            value["roles"]["graph"]["gid"] = value["roles"]["signer"]["gid"]
            with self.assertRaises(ExecutionProfileError):
                validate_execution_profile(value, require_private_key=True)

    @unittest.skipUnless(os.geteuid() == 0, "requires ownership of disposable fixture files")
    def test_isolated_kernel_root_mapping_and_acl_reject(self):
        value, account = self.isolated()
        original = Path.read_text

        def mapped_root(path, *args, **kwargs):
            if str(path) == "/proc/self/uid_map":
                return "20001 0 4\n"
            return original(path, *args, **kwargs)

        with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
            with patch.object(Path, "read_text", new=mapped_root):
                with self.assertRaises(ExecutionProfileError):
                    validate_execution_profile(value)
            with patch("control_plane.execution_profile.os.listxattr", return_value=["system.posix_acl_access"]):
                with self.assertRaises(ExecutionProfileError):
                    validate_execution_profile(value)

    def test_wal_profile_requires_actual_loaded_runtime_attestation(self):
        attestation = self.root / "attestation.json"
        attestation.write_text('{"patched": true}\n')
        self.value["sqlite"] = {"profile": "wal-full", "attestation": str(attestation)}
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value)

    def test_schema_agrees_on_shape_and_conditional_tools(self):
        schema = json.loads((ROOT / "schemas/execution-profile.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.validate(self.value, schema)
        changes = [(("schema_version",), True), (("auth", "home"), "/tmp"),
                   (("roles", "worker", "uid"), True), (("tools", "python"), None),
                   (("mode",), "isolated-linux"),
                   (("sqlite", "profile"), "wal-full")]
        for parts, replacement in changes:
            changed = copy.deepcopy(self.value)
            target = changed
            for key in parts[:-1]:
                target = target[key]
            target[parts[-1]] = replacement
            with self.subTest(parts=parts), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(changed, schema)


@unittest.skipUnless(os.geteuid() == 0, "copied-venv metadata must have protected root ownership")
class VenvMetadataTests(unittest.TestCase):
    # Reuse only the fixture, rather than rerunning the unchanged base cases.
    def setUp(self):
        ExecutionProfileContractTests.setUp(self)
        self.prefix = self.root / "venv"
        self.venv_code = self.prefix / "lib/python3.12/site-packages"
        self.venv_code.mkdir(parents=True)
        (self.venv_code / "trusted.py").write_text("# trusted fixture\n")
        (self.prefix / "bin").mkdir()
        self.venv_python = self.prefix / "bin/python3.12"
        self.venv_python.write_bytes(self.tool.read_bytes())
        self.venv_python.chmod(0o755)
        self.cfg = self.prefix / "pyvenv.cfg"
        self.cfg.write_text("home = /usr/bin\ninclude-system-site-packages = false\n"
                            "version = 3.12.3\ncommand = /usr/bin/python3.12 -m venv --copies fixture\n")

    def test_venv_metadata_is_explicit_and_hashed_without_execution(self):
        with patch("subprocess.Popen", side_effect=AssertionError("no tool execution")):
            self.assertEqual(venv_runtime_metadata(self.venv_python, self.venv_code), (self.cfg,))
            before = trusted_code_digest(self.venv_code)
            self.cfg.write_text(self.cfg.read_text().replace("--copies fixture", "--copies changed"))
            self.assertNotEqual(before, trusted_code_digest(self.venv_code))
        self.assertEqual(venv_runtime_metadata(self.tool, self.code), ())

    def test_venv_mismatched_prefix_and_version_are_denied(self):
        with self.assertRaises(ExecutionProfileError):
            venv_runtime_metadata(self.tool, self.venv_code)
        with self.assertRaises(ExecutionProfileError):
            venv_runtime_metadata(self.venv_python, self.code)
        self.cfg.write_text(self.cfg.read_text().replace("3.12.3", "3.11.3"))
        with self.assertRaises(ExecutionProfileError):
            trusted_code_digest(self.venv_code)

    def test_venv_unsafe_metadata_and_system_imports_are_denied(self):
        original = self.cfg.read_bytes()
        self.cfg.chmod(0o666)
        with self.assertRaises(ExecutionProfileError):
            venv_runtime_metadata(self.venv_python, self.venv_code)
        self.cfg.chmod(0o644)
        for bad in (original.replace(b"= false", b"= true"),
                    original + b"home = /usr/bin\n", original + b"unsupported = value\n",
                    original.replace(b"/usr/bin\n", b"/tmp\n", 1),
                    original.replace(b"version =", b"\x0bversion =")):
            self.cfg.write_bytes(bad)
            with self.subTest(bad=bad[-30:]), self.assertRaises(ExecutionProfileError):
                venv_runtime_metadata(self.venv_python, self.venv_code)
        self.cfg.unlink()
        original_path = self.root / "original.cfg"
        original_path.write_bytes(original)
        self.cfg.symlink_to(original_path)
        with self.assertRaises(ExecutionProfileError):
            trusted_code_digest(self.venv_code)

    def test_venv_profile_binds_metadata_and_declared_python_version(self):
        self.value["tools"]["python"] = {"path": str(self.venv_python),
            "sha256": executable_digest(self.venv_python), "version": "Python 3.12.3"}
        self.value["paths"]["trusted_code_root"] = str(self.venv_code)
        self.value["paths"]["trusted_code_sha256"] = trusted_code_digest(self.venv_code)
        validate_execution_profile(self.value)
        self.value["tools"]["python"]["version"] = "Python 3.12.4"
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value)
        self.value["tools"]["python"]["version"] = "Python 3.12.3"
        self.cfg.write_text(self.cfg.read_text().replace("--copies fixture", "--copies changed"))
        with self.assertRaises(ExecutionProfileError):
            validate_execution_profile(self.value)

    def test_trusted_local_venv_preserves_metadata_digest_bytes_and_modes(self):
        original = self.cfg.read_bytes()
        previous = None
        for contents, mode in ((original, 0o644), (original + b"\n", 0o644),
                               (original + b"\n", 0o640)):
            self.cfg.write_bytes(contents)
            self.cfg.chmod(mode)
            with self.subTest(contents=len(contents), mode=mode):
                strict = trusted_code_digest(self.venv_code)
                self.assertEqual(strict, trusted_code_digest(self.venv_code, isolated=True))
                self.assertEqual(strict, trusted_code_digest(self.venv_code, isolated=False))
                self.assertEqual(venv_runtime_metadata(self.venv_python, self.venv_code), (self.cfg,))
                self.assertEqual(venv_runtime_metadata(self.venv_python, self.venv_code, isolated=False),
                                 (self.cfg,))
                if previous is not None:
                    self.assertNotEqual(strict, previous)
                previous = strict

    def test_trusted_local_venv_nonroot_metadata_and_ancestor_remain_isolated_denials(self):
        self.value["tools"]["python"] = {
            "path": str(self.venv_python), "sha256": executable_digest(self.venv_python),
            "version": "Python 3.12.3"}
        self.value["paths"]["trusted_code_root"] = str(self.venv_code)
        self.value["paths"]["trusted_code_sha256"] = trusted_code_digest(self.venv_code)
        isolated_value, account = ExecutionProfileContractTests.isolated(self)
        isolated_path = self.root / "isolated-profile.json"
        isolated_path.write_text(json.dumps(isolated_value))
        with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
            # Establish this fixture is otherwise valid before testing ownership.
            load_execution_profile(isolated_path, verify_tools=False)
        for target in (self.cfg, self.prefix):
            original_uid, original_gid = target.stat().st_uid, target.stat().st_gid
            os.chown(target, 20001, 20001)
            try:
                with self.subTest(target=target.name):
                    self.assertEqual(venv_runtime_metadata(self.venv_python, self.venv_code, isolated=False),
                                     (self.cfg,))
                    self.assertEqual(trusted_code_digest(self.venv_code, isolated=False),
                                     self.value["paths"]["trusted_code_sha256"])
                    validate_execution_profile(self.value, verify_tools=False)
                    for kwargs in ({}, {"isolated": True}):
                        with self.assertRaises(ExecutionProfileError):
                            trusted_code_digest(self.venv_code, **kwargs)
                        with self.assertRaises(ExecutionProfileError):
                            venv_runtime_metadata(self.venv_python, self.venv_code, **kwargs)
                    with patch("control_plane.execution_profile.pwd.getpwnam", return_value=account):
                        for verify_tools in (False, True):
                            with self.subTest(verify_tools=verify_tools), self.assertRaises(ExecutionProfileError):
                                load_execution_profile(isolated_path, verify_tools=verify_tools)
            finally:
                os.chown(target, original_uid, original_gid)

    def test_trusted_local_venv_frozen_hash_rejects_metadata_mutation(self):
        os.chown(self.prefix, 20001, 20001)
        os.chown(self.cfg, 20001, 20001)
        self.value["tools"]["python"] = {
            "path": str(self.venv_python), "sha256": executable_digest(self.venv_python),
            "version": "Python 3.12.3"}
        self.value["paths"]["trusted_code_root"] = str(self.venv_code)
        self.value["paths"]["trusted_code_sha256"] = trusted_code_digest(self.venv_code, isolated=False)
        path = self.root / "local-profile.json"
        path.write_text(json.dumps(self.value))
        load_execution_profile(path, verify_tools=False)
        self.cfg.write_text(self.cfg.read_text().replace("--copies fixture", "--copies changed"))
        for verify_tools in (False, True):
            with self.subTest(verify_tools=verify_tools), self.assertRaisesRegex(ExecutionProfileError, "hash mismatch"):
                load_execution_profile(path, verify_tools=verify_tools)

    def test_trusted_local_venv_isolation_switches_require_actual_booleans(self):
        from control_plane.execution_profile import _read_venv_config, _trusted_inventory

        for invalid in ("false", "true", "trusted-local", 0, 1, None):
            for code in (self.code, self.venv_code):
                with self.subTest(invalid=invalid, code=code.name):
                    with self.assertRaises(ExecutionProfileError):
                        trusted_code_digest(code, isolated=invalid)
                    with self.assertRaises(ExecutionProfileError):
                        venv_runtime_metadata(self.venv_python, code, isolated=invalid)
                    with self.assertRaises(ExecutionProfileError):
                        _trusted_inventory(code, venv_isolated=invalid)
                    with self.assertRaises(ExecutionProfileError):
                        _trusted_inventory(code, protected=invalid)
            with self.subTest(invalid=invalid), self.assertRaises(ExecutionProfileError):
                _read_venv_config(self.cfg, "3.12", isolated=invalid)
        with self.assertRaises(ExecutionProfileError):
            _trusted_inventory(self.venv_code, protected=True, venv_isolated=False)


if __name__ == "__main__":
    unittest.main()
