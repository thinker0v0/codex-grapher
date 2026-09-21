"""Provider guard unit tests; no candidate, model or guest is executed.

Scope mechanics use a real validated profile and BrokerStore, with only the
installed-code profile check mocked. Separate profile-check cases read actual
module-tree and executable hashes without mocking that security check.
"""

from contextlib import contextmanager
import copy
import dataclasses
import hashlib
import os
from pathlib import Path
import pwd
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane import _provider_admission as admission
from control_plane import isolated_runner as runner
from control_plane.evaluation_broker import BrokerStore, EvaluationBroker
from control_plane.execution_profile import executable_digest, trusted_code_digest, validate_execution_profile
from control_plane.worker_provider import build_codex_argv, execute_provider_preflight


@unittest.skipUnless(os.geteuid() == 0, "private admission fixtures require root-owned temporary files")
class ProviderAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.code = self.root / "trusted-code"
        self.code.mkdir()
        (self.code / "entry.py").write_text("# immutable fixture, never imported\n")
        (self.code / "schemas").mkdir()
        schema = Path(__file__).resolve().parents[1] / "schemas/worker-result.schema.json"
        (self.code / "schemas/worker-result.schema.json").write_bytes(schema.read_bytes())
        self.tool = self.root / "pinned-tool"
        self.tool.write_bytes(b"#!/bin/sh\nexit 99\n")
        self.tool.chmod(0o755)
        self.public = self.root / "public.pem"
        self.public.write_bytes(b"public fixture\n")
        accounts = [account for account in pwd.getpwall() if account.pw_uid > 0
                    and Path(account.pw_dir).is_dir()
                    and Path(account.pw_dir).stat().st_uid == account.pw_uid
                    and not Path(account.pw_dir).is_symlink()]
        if not accounts:
            self.skipTest("no existing nonroot account with its owned home")
        account = next((account for account in accounts if account.pw_uid == 1000), accounts[0])
        role_ids = iter(uid for uid in range(20001, 20006) if uid != account.pw_uid)
        raw = {
            "schema_version": 1, "mode": "isolated-linux",
            "tools": {name: {"path": str(self.tool), "sha256": executable_digest(self.tool),
                             "version": "codex-cli 0.155.1" if name == "provider" else "unit-fixture 1"}
                      for name in ("python", "git", "provider", "openssl", "bwrap", "setpriv")},
            "provider": {"backend": "codex", "model": "gpt-5.6-sol",
                         "reasoning_effort": "medium", "service_tier": "default"},
            "roles": {"worker": {"uid": account.pw_uid, "gid": account.pw_gid},
                      **{name: {"uid": uid, "gid": uid} for name in ("test_runner", "signer", "graph")
                         for uid in [next(role_ids)]}},
            "auth": {"kind": "existing-cli-login", "account": account.pw_name},
            "paths": {"trusted_code_root": str(self.code), "trusted_code_sha256": trusted_code_digest(self.code),
                      "signer_private_key": str(self.root / "not-provisioned.pem"), "signer_public_key": str(self.public)},
            "sqlite": {"profile": "delete-extra", "attestation": None},
        }
        self.profile = validate_execution_profile(raw)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o755)
        self.store = BrokerStore(self.workspace)
        self.addCleanup(self.store.close)
        # Actual broker type and actual private storage; avoid unrelated graph
        # lifecycle setup because this suite tests only the admission contract.
        self.broker = object.__new__(EvaluationBroker)
        self.broker.profile, self.broker.store = self.profile, self.store
        self.broker.frozen = SimpleNamespace(root=self.workspace, record={"profile_sha256": self.profile.sha256})
        for name in ("_ACTIVE_BOOTSTRAP", "_ACTIVE_DISPATCH"):
            context = patch.object(admission, name, None)
            context.start()
            self.addCleanup(context.stop)
        for name in ("_PRODUCTION_FUNCTIONS", "_PRODUCTION_HELPERS"):
            registry = patch.object(admission, name, None)
            registry.start()
            self.addCleanup(registry.stop)
        admission.freeze_runner_functions()
        self.request = {
            "schema_version": 1, "project_id": "fixture", "task_id": "task", "idempotency_key": "once",
            "attempt_id": "task-attempt-1", "attempt_number": 1, "base_sha": "a" * 40,
            "checkout": str(self.root / "checkout"), "task_sha256": "b" * 64,
            "profile_sha256": self.profile.sha256, "prompt": "Frozen task prompt.",
            "prompt_sha256": hashlib.sha256(b"Frozen task prompt.").hexdigest(),
            "limits": {"worker_invocations": 1, "worker_timeout_seconds": 30, "max_output_bytes": 4096},
        }
        self.exec_spy = patch("os.execve", side_effect=AssertionError("guard tests must not exec"))
        self.exec_mock = self.exec_spy.start()
        self.addCleanup(self.exec_spy.stop)
        self.process_spy = patch("subprocess.Popen", side_effect=AssertionError("guard tests must not spawn"))
        self.process_mock = self.process_spy.start()
        self.addCleanup(self.process_spy.stop)
        self.addCleanup(self.exec_mock.assert_not_called)
        self.addCleanup(self.process_mock.assert_not_called)

    @contextmanager
    def scope(self):
        with patch.object(admission, "_check_profile"):
            with admission.bootstrap_admission(self.broker, self.profile) as authority:
                yield authority

    def register(self, request=None, *, altered_hash=False):
        request = self.request if request is None else request
        key = "request-" + hashlib.sha256(admission._canonical(request["attempt_id"])).hexdigest()
        self.store.reserve(key, {
            "request_sha256": "0" * 64 if altered_hash else hashlib.sha256(admission._canonical(request)).hexdigest(),
            "request": request,
        })

    def git_argv(self):
        return [self.profile.tools["git"].path, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                "-C", self.request["checkout"], "rev-parse", "--verify", "HEAD^{commit}"]

    def test_absent_boundary_and_provider_preflight_reject_before_execution(self):
        with self.assertRaises(runner.IsolationError):
            admission.assert_active_provider_boundary(None, self.profile)
        with self.assertRaises(PermissionError):
            execute_provider_preflight(self.profile)
        with self.assertRaises(runner.IsolationError):
            runner.run_provider_process(None, self.profile, [self.tool.as_posix(), "--version"], b"")

    def test_dispatch_requires_actual_active_broker_and_private_registration(self):
        with self.assertRaises(runner.IsolationError):
            with admission.provider_dispatch(self.broker, None):
                self.fail("absent bootstrap admitted")
        with self.scope():
            with self.assertRaises(runner.IsolationError):
                with admission.provider_dispatch(self.broker, self.request):
                    self.fail("unregistered request admitted")
            other = object.__new__(EvaluationBroker)
            with self.assertRaises(runner.IsolationError):
                with admission.provider_dispatch(other, None):
                    self.fail("another broker admitted")
            self.register(altered_hash=True)
            with self.assertRaises(runner.IsolationError):
                with admission.provider_dispatch(self.broker, self.request):
                    self.fail("forged private hash admitted")

    def test_registered_payload_cannot_be_changed_under_the_same_attempt(self):
        self.register()
        changed = copy.deepcopy(self.request)
        changed["prompt"] += " modified"
        with self.scope():
            with self.assertRaises(runner.IsolationError):
                with admission.provider_dispatch(self.broker, changed):
                    self.fail("changed registration admitted")

    def test_stale_pid_uid_deadline_request_and_context_flags_reject(self):
        self.register()
        with self.scope() as authority:
            with admission.provider_dispatch(self.broker, self.request):
                current = admission._ACTIVE_DISPATCH
                admission.assert_active_provider_boundary(self.request, self.profile)
                cases = [(authority, "active", False), (current, "active", False),
                         (authority, "pid", os.getpid() + 1), (current, "deadline", 0),
                         (authority, "workspace", str(self.root / "other"))]
                for target, name, bad in cases:
                    with self.subTest(name=name), patch.object(target, name, bad):
                        with self.assertRaises(runner.IsolationError):
                            admission.assert_active_provider_boundary(self.request, self.profile)
                with patch.object(admission.os, "geteuid", return_value=1000):
                    with self.assertRaises(runner.IsolationError):
                        admission.assert_active_provider_boundary(self.request, self.profile)
                changed = copy.deepcopy(self.request)
                changed["checkout"] += "-other"
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(changed, self.profile)
            self.assertFalse(current.active)
            with self.assertRaises(runner.IsolationError):
                admission.assert_active_provider_boundary(self.request, self.profile)
        self.assertFalse(authority.active)

    def test_replaced_private_store_descriptor_rejects(self):
        replacement = self.root / "different-store"
        replacement.mkdir()
        descriptor = os.open(replacement, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        with self.scope(), admission.provider_dispatch(self.broker, None):
            with patch.object(self.store, "fd", descriptor):
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(None, self.profile)

    def test_nested_authority_and_nested_dispatch_are_rejected(self):
        with self.scope():
            with self.assertRaises(runner.IsolationError):
                with admission.bootstrap_admission(self.broker, self.profile):
                    self.fail("nested bootstrap admitted")
            with admission.provider_dispatch(self.broker, None):
                with self.assertRaises(runner.IsolationError):
                    with admission.provider_dispatch(self.broker, None):
                        self.fail("nested dispatch admitted")

    def test_production_function_replacement_and_in_place_code_mutation_reject(self):
        with self.scope(), admission.provider_dispatch(self.broker, None):
            with patch.object(runner, "run_role_process", lambda *args, **kwargs: None):
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(None, self.profile)
            function = runner._sandbox
            original = function.__code__
            replacement = lambda *args, **kwargs: None
            try:
                function.__code__ = replacement.__code__
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(None, self.profile)
            finally:
                function.__code__ = original
            with patch.object(admission, "_PRODUCTION_FUNCTIONS", None):
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(None, self.profile)
            with patch.object(admission, "_PRODUCTION_HELPERS", None):
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(None, self.profile)

    def test_provider_builder_helper_replacement_rejects(self):
        from control_plane import worker_provider
        with self.scope(), admission.provider_dispatch(self.broker, None):
            with patch.object(worker_provider, "build_codex_argv", lambda *args, **kwargs: []):
                with self.assertRaises(runner.IsolationError):
                    admission.assert_active_provider_boundary(None, self.profile)

    def test_preflight_argv_phases_are_finite_and_ordered(self):
        executable = self.profile.tools["provider"].path
        allowed = [[executable, "--version"], [executable, "--help"],
                   [executable, "exec", "--help"], [executable, "login", "status"]]
        with self.scope(), admission.provider_dispatch(self.broker, None):
            with self.assertRaises(runner.IsolationError):
                admission.admit_provider_command(None, self.profile, allowed[1], b"")
            with self.assertRaises(runner.IsolationError):
                admission.admit_provider_command(None, self.profile, allowed[0], b"unexpected stdin")
            self.assertEqual(admission._ACTIVE_DISPATCH.stage, 0)
            for command in allowed:
                admission.admit_provider_command(None, self.profile, command, b"")
            with self.assertRaises(runner.IsolationError):
                admission.admit_provider_command(None, self.profile, allowed[0], b"")

    def test_worker_argv_prompt_and_three_phase_limit_are_bound(self):
        self.register()
        with self.scope(), admission.provider_dispatch(self.broker, self.request):
            git = self.git_argv()
            bad_git = list(git)
            bad_git[-1] = "other-ref"
            with self.assertRaises(runner.IsolationError):
                admission.admit_provider_command(self.request, self.profile, bad_git, b"")
            admission.admit_provider_command(self.request, self.profile, git, b"")
            argv = build_codex_argv(self.profile, self.request["checkout"],
                                    self.code / "schemas/worker-result.schema.json", request=self.request)
            self.assertEqual(argv[argv.index("--sandbox") + 1], "danger-full-access")
            changed = list(argv)
            changed[changed.index("--sandbox") + 1] = "workspace-write"
            for command, prompt in ((changed, self.request["prompt"].encode()), (argv, b"changed prompt")):
                with self.assertRaises(runner.IsolationError):
                    admission.admit_provider_command(self.request, self.profile, command, prompt)
            admission.admit_provider_command(self.request, self.profile, argv, self.request["prompt"].encode())
            admission.admit_provider_command(self.request, self.profile, git, b"")
            with self.assertRaises(runner.IsolationError):
                admission.admit_provider_command(self.request, self.profile, git, b"")

    def test_installed_resources_schema_is_admitted_without_source_schema_layout(self):
        destination = self.code / "control_plane/resources"
        destination.mkdir(parents=True)
        (self.code / "schemas/worker-result.schema.json").rename(destination / "worker-result.schema.json")
        # Scope mechanics mock _check_profile; the real profile-hash tests below
        # independently cover immutable install integrity.
        self.register()
        with self.scope(), admission.provider_dispatch(self.broker, self.request):
            admission.admit_provider_command(self.request, self.profile, self.git_argv(), b"")
            argv = build_codex_argv(self.profile, self.request["checkout"],
                                    destination / "worker-result.schema.json", request=self.request)
            admission.admit_provider_command(self.request, self.profile, argv, self.request["prompt"].encode())

    def test_recorded_boundary_binds_command_phase_and_observation(self):
        with self.scope() as authority, admission.provider_dispatch(self.broker, None):
            command = [self.profile.tools["provider"].path, "--version"]
            admission.admit_provider_command(None, self.profile, command, b"")
            with self.assertRaises(runner.IsolationError):
                admission.record_boundary(SimpleNamespace(boundary=None, observation={}))
            self.assertEqual(authority.observations, [])
            # This test verifies record binding only; these fixture dictionaries
            # are explicitly not evidence of an actual child OS boundary.
            boundary = {"fixture": "boundary"}
            observation = {"fixture": "observation"}
            admission.record_boundary(SimpleNamespace(boundary=boundary, observation=observation))
            self.assertEqual(authority.observations, [{
                "action": "provider-preflight", "request_sha256": None,
                "command_phase": 0, "argv_sha256": hashlib.sha256(admission._canonical(command)).hexdigest(),
                "observation": observation, "boundary": boundary,
            }])

    def _real_profile_authority(self):
        root = Path(admission.__file__).resolve().parent
        raw = self.profile.raw
        raw["paths"]["trusted_code_root"] = str(root)
        raw["paths"]["trusted_code_sha256"] = trusted_code_digest(root)
        data = admission._canonical(raw)
        profile = dataclasses.replace(self.profile, paths=MappingProxyType(dict(raw["paths"])),
                                      _json=data, sha256=hashlib.sha256(data).hexdigest())
        broker = SimpleNamespace(frozen=SimpleNamespace(record={"profile_sha256": profile.sha256}))
        authority = SimpleNamespace(profile=profile, profile_bytes=data, broker=broker,
                                    code_sha256=profile.paths["trusted_code_sha256"])
        return profile, authority

    def test_real_profile_guard_rejects_identity_raw_hash_and_origin_spoofing(self):
        authority = SimpleNamespace(profile=self.profile, profile_bytes=admission._canonical(self.profile.raw),
            broker=self.broker, code_sha256=self.profile.paths["trusted_code_sha256"])
        with self.assertRaisesRegex(runner.IsolationError, "outside the trusted install"):
            admission._check_profile(self.profile, authority)
        copied = dataclasses.replace(self.profile)
        with self.assertRaisesRegex(runner.IsolationError, "not the admitted frozen profile"):
            admission._check_profile(copied, authority)
        with patch.object(authority, "profile_bytes", b"{}"):
            with self.assertRaisesRegex(runner.IsolationError, "not the admitted frozen profile"):
                admission._check_profile(self.profile, authority)
        self.broker.frozen.record["profile_sha256"] = "0" * 64
        with self.assertRaisesRegex(runner.IsolationError, "hash differs"):
            admission._check_profile(self.profile, authority)

    def test_real_profile_guard_checks_current_code_and_executable_hashes(self):
        profile, authority = self._real_profile_authority()
        admission._check_profile(profile, authority)
        with patch.object(authority, "code_sha256", "0" * 64):
            with self.assertRaisesRegex(runner.IsolationError, "trusted code changed"):
                admission._check_profile(profile, authority)
        self.tool.write_bytes(self.tool.read_bytes() + b"# changed tool\n")
        with self.assertRaisesRegex(runner.IsolationError, "pinned tool changed"):
            admission._check_profile(profile, authority)


if __name__ == "__main__":
    unittest.main()
