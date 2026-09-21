"""Generic lifecycle fixtures; these do not claim provider or OS-isolation proof."""
from contextlib import nullcontext
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane import repository_workflow as workflow
from control_plane.artifact_builder import produce_required_test_results
from control_plane.project_integrator import canonical, evaluation_ledger_hash


class RepositoryWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="grapher-repository-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "source"
        self.source.mkdir()
        workflow._git(self.source, "init", "--quiet")
        workflow._git(self.source, "config", "user.name", "Fixture")
        workflow._git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / "value.py").write_text("VALUE = 0\n")
        workflow._git(self.source, "add", ".")
        workflow._git(self.source, "commit", "--quiet", "-m", "Disclosed fixture regression")
        self.base = workflow._git(self.source, "rev-parse", "HEAD")
        self.root = self.directory / "state"
        self.private = self.directory / "signer.pem"
        self.public = self.directory / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)], check=True, capture_output=True)
        self.profile_path = self.directory / "profile.json"
        self.profile_path.write_text('{"mode":"trusted-local"}')
        profile_hash = hashlib.sha256(self.profile_path.read_bytes()).hexdigest()
        self.profile = SimpleNamespace(mode="trusted-local", sha256=profile_hash,
            tools={"python": SimpleNamespace(path=sys.executable), "git": SimpleNamespace(path="/usr/bin/git"), "provider": SimpleNamespace(sha256="c" * 64)},
            roles={"test_runner": SimpleNamespace(uid=os.geteuid()), "graph": SimpleNamespace(uid=os.geteuid())},
            paths={"signer_public_key": str(self.public)}, raw={"sqlite": {"profile": "delete-extra", "attestation": None}})
        self.profile_patch = patch.object(workflow, "_profile", return_value=self.profile)
        self.profile_patch.start()
        self.addCleanup(self.profile_patch.stop)
        self.policy = {"schema_version": 1, "name": "repository-fixture", "sections": {"correctness": {"minimum": 95, "maximum": 100}},
            "mandatory_gates": ["required_tests", "independent_assertions", "write_scope"], "threshold": 95}
        (self.directory / "policy.json").write_text(json.dumps(self.policy))
        self.check_code = "import value; assert value.VALUE == 1; print('accepted')"
        (self.directory / "checks.json").write_text(json.dumps({"schema_version": 1, "checks": [{"id": "value-behavior", "argv": [sys.executable, "-B", "-c", self.check_code]}]}))
        self.task = {"schema_version": 1, "project_id": "user-project", "task_id": "repair-value", "idempotency_key": "repair-value-v1",
            "base_sha": self.base, "objective": "Set the value to one", "acceptance_criteria": ["VALUE is one"], "allowed_paths": ["value.py"],
            "required_tests": [subprocess.list2cmdline([sys.executable, "-B", "-c", self.check_code])], "worker": {"backend": "codex"},
            "evaluation": {"policy": "policy.json", "checks": "checks.json"}, "limits": {"worker_timeout_seconds": 30, "required_test_timeout_seconds": 30,
            "evaluation_timeout_seconds": 30, "max_output_bytes": 65536}}
        # POSIX shell command encoding is frozen with the producer contract.
        import shlex
        self.task["required_tests"] = [shlex.join([sys.executable, "-B", "-c", self.check_code])]
        self.task_path = self.directory / "task.json"
        self.task_path.write_text(json.dumps(self.task))
        self.launches = 0
        self.outputs = {}

    def initialize(self):
        return workflow.initialize_repository_workflow(self.source, self.task_path, self.root, self.profile_path)

    def fake_worker(self, request, profile):
        self.launches += 1
        (Path(request["checkout"]) / "value.py").write_text("VALUE = 1\n")
        return {"schema_version": 1, "attempt_id": request["attempt_id"], "request_sha256": workflow._hash(workflow.canonical(request)),
            "task_sha256": request["task_sha256"], "profile_sha256": request["profile_sha256"], "prompt_sha256": request["prompt_sha256"],
            "completion": "COMPLETED", "exit_code": 0, "signal": None, "descendants_reaped": True,
            "provider": "codex", "cli_version": "codex-cli 0.155.1", "executable_sha256": "c" * 64,
            "model": None, "session_id": "fixture-session", "usage_observed": None, "elapsed_seconds": 0.1,
            "stdout_sha256": workflow._hash(b"fixture"), "stderr_sha256": workflow._hash(b""), "stdout_bytes": 7, "stderr_bytes": 0}

    def fake_tests(self, request, profile):
        results = []
        for sequence, command in enumerate(request["commands"]):
            process = subprocess.run(command, shell=True, cwd=request["candidate_root"], capture_output=True, timeout=30)
            outputs = {}
            for stream, data in (("stdout", process.stdout), ("stderr", process.stderr)):
                path = f"outputs/{sequence:04d}.{stream}"
                self.outputs[path] = data
                outputs[stream] = {"sha256": workflow._hash(data), "bytes": len(data), "relative_path": path}
            results.append({"sequence": sequence, "id": f"required-{sequence:04d}", "command_sha256": workflow._hash(workflow.canonical(command)),
                "exit_code": process.returncode, **outputs})
        record = workflow._record(self.root / "workflow.json")
        receipt = {"schema_version": 1, "request_sha256": workflow._hash(workflow.canonical(request)), "run_id": request["run_id"],
            "kind": "required", "workspace_id": record["workspace_id"], "task_sha256": request["task_sha256"], "profile_sha256": request["profile_sha256"],
            "candidate_sha": request["candidate_sha"], "commands_sha256": request["commands_sha256"], "replayed": False,
            "pre_tree_sha256": "a" * 64, "post_tree_sha256": "a" * 64, "actual_uid": os.geteuid(), "descendants": {"reaped": True, "survivors": 0}, "results": results}
        receipt["receipt_id"] = workflow._hash(workflow.canonical(receipt))
        return receipt

    def fake_evaluate(self, request, profile):
        manifest = workflow._record(self.root / "evidence" / "sha256" / request["manifest_sha256"][:2] / request["manifest_sha256"] / "manifest.json")
        candidate = Path(workflow._record(self.root / "attempts/repair-value-attempt-1/reservation.json")["request"]["checkout"])
        subprocess.run([sys.executable, "-B", "-c", self.check_code], cwd=candidate, check=True, capture_output=True)
        value = {"schema_version": 4, "policy_sha256": request["policy_sha256"], "evaluation_id": request["evaluation_id"], "task_id": self.task["task_id"],
            "contract_id": request["evaluator_contract_id"], "artifact_id": request["artifact_id"], "claim_id": request["claim_id"],
            "evaluated_git_sha": manifest["candidate_sha"], "evidence_manifest_sha256": request["manifest_sha256"], "rubric_sha256": request["policy_sha256"],
            "section_scores": {"correctness": 100}, "mandatory_gates": {name: "PASS" for name in self.policy["mandatory_gates"]},
            "total_score": 100, "verdict": "PASS", "evaluator_identity": "hermes-evaluator", "previous_ledger_hash": request["previous_ledger_hash"]}
        value["ledger_hash"] = evaluation_ledger_hash(value)
        message, signature = self.directory / "message", self.directory / "signature"
        message.write_bytes(canonical(value))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private), "-in", str(message), "-out", str(signature)], check=True, capture_output=True)
        value["signature"] = base64.b64encode(signature.read_bytes()).decode()
        return value

    def adapters(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}))
        stack.enter_context(patch("control_plane.worker_provider.launch_worker", side_effect=self.fake_worker))
        stack.enter_context(patch("control_plane.evaluation_broker.broker_workspace", side_effect=lambda *a, **kw: nullcontext(), create=True))
        stack.enter_context(patch("control_plane.evaluation_broker.run_candidate_tests", side_effect=self.fake_tests, create=True))
        stack.enter_context(patch("control_plane.evaluation_broker.fetch_receipt_output", side_effect=lambda receipt, path, profile: self.outputs[path], create=True))
        stack.enter_context(patch("control_plane.evaluation_broker.evaluate_artifact", side_effect=self.fake_evaluate, create=True))
        return stack

    def test_initialize_preserves_source_and_status_is_read_only(self):
        # This source-config hook must never execute, including privileged init.
        marker = self.directory / "fsmonitor-ran"
        workflow._git(self.source, "config", "core.fsmonitor", "touch " + str(marker))
        before = workflow._tree_inventory(self.source)
        result = self.initialize()
        self.assertEqual(result["workflow_state"], "ready")
        self.assertEqual(before, workflow._tree_inventory(self.source))
        self.assertFalse(marker.exists())
        state = workflow._tree_inventory(self.root)
        workflow.run_repository_workflow(self.root, "status")
        self.assertEqual(state, workflow._tree_inventory(self.root))
        self.assertEqual(workflow._git(self.root / "canonical", "remote"), "")
        self.assertFalse((self.root / "canonical/.git/hooks").exists())

    def socket_length_root(self, *, multibyte=False):
        remaining = 81 - len(os.fsencode(self.directory)) - 1
        self.assertGreater(remaining, 3)
        if multibyte:
            width = len(os.fsencode("한"))
            self.assertGreater(width, 1)
            name = "한" * (remaining // width) + "x" * (remaining % width)
        else:
            name = "x" * remaining
        root = self.directory / name
        self.assertEqual(len(os.fsencode(root)), 81)
        self.assertEqual(len(os.fsencode(root / "state/.worker-control.sock")), 108)
        if multibyte:
            self.assertLess(len(str(root)), 81)
        return root

    def assert_socket_length_rejected_before_effects(self, root):
        from control_plane.isolated_runner import IsolationError

        self.root = root
        # The generic profile seam supplies mode only; the real socket-path
        # admission must run before any repository or database operation.
        self.profile.mode = "isolated-linux"
        before = workflow._tree_inventory(self.directory)
        with patch.object(workflow, "_git", side_effect=AssertionError("Git ran before path admission")) as git, \
                patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess ran before path admission")) as process, \
                patch.object(Path, "mkdir", side_effect=AssertionError("directory created before path admission")) as mkdir, \
                patch.object(workflow, "apply_database", side_effect=AssertionError("database opened before path admission")) as database:
            with self.assertRaisesRegex(IsolationError, "80 encoded-byte Unix socket limit"):
                self.initialize()
        git.assert_not_called()
        process.assert_not_called()
        mkdir.assert_not_called()
        database.assert_not_called()
        self.assertFalse(self.root.exists())
        self.assertEqual(before, workflow._tree_inventory(self.directory))

    def test_isolated_socket_length_rejects_ascii_before_initialization_effects(self):
        self.assert_socket_length_rejected_before_effects(self.socket_length_root())

    def test_isolated_socket_length_rejects_utf8_bytes_before_initialization_effects(self):
        self.assert_socket_length_rejected_before_effects(self.socket_length_root(multibyte=True))

    def test_trusted_local_initialization_does_not_apply_socket_length_limit(self):
        source_before = workflow._tree_inventory(self.source)
        for multibyte in (False, True):
            with self.subTest(multibyte=multibyte):
                self.root = self.socket_length_root(multibyte=multibyte)
                result = self.initialize()
                self.assertEqual(result["workflow_state"], "ready")
                self.assertTrue((self.root / "state/graph.sqlite").is_file())
                self.assertFalse((self.root / ".launcher.sock").exists())
                self.assertFalse((self.root / "state/.worker-control.sock").exists())
        self.assertEqual(source_before, workflow._tree_inventory(self.source))

    def test_source_clean_filter_cannot_execute(self):
        marker = self.directory / "filter-ran"
        (self.source / ".gitattributes").write_text("value.py filter=hostile\n")
        workflow._git(self.source, "add", ".gitattributes")
        workflow._git(self.source, "commit", "--quiet", "-m", "Filter declaration without executable")
        self.task["base_sha"] = workflow._git(self.source, "rev-parse", "HEAD")
        self.task_path.write_text(json.dumps(self.task))
        workflow._git(self.source, "config", "filter.hostile.clean", "touch " + str(marker) + "; cat")
        workflow._git(self.source, "config", "filter.hostile.smudge", "touch " + str(marker) + "; cat")
        before = workflow._tree_inventory(self.source)
        self.initialize()
        self.assertFalse(marker.exists())
        self.assertEqual(before, workflow._tree_inventory(self.source))

    def test_dirty_source_rejected_without_workspace(self):
        (self.source / "untracked").write_text("preserve")
        before = workflow._tree_inventory(self.source)
        with self.assertRaisesRegex(ValueError, "clean"):
            self.initialize()
        self.assertFalse(self.root.exists())
        self.assertEqual(before, workflow._tree_inventory(self.source))

    def test_source_index_flags_cannot_hide_dirty_worktree(self):
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                workflow._git(self.source, "update-index", "--no-assume-unchanged", "--no-skip-worktree", "value.py")
                (self.source / "value.py").write_text("VALUE = 0\n")
                workflow._git(self.source, "update-index", flag, "value.py")
                (self.source / "value.py").write_text("VALUE = 2\n")
                before = workflow._tree_inventory(self.source)
                with self.assertRaisesRegex(ValueError, "clean"):
                    self.initialize()
                self.assertFalse(self.root.exists())
                self.assertEqual(before, workflow._tree_inventory(self.source))

    def test_external_object_directory_rejected_without_effects(self):
        objects = self.source / ".git/objects"
        external = self.directory / "external-objects"
        objects.rename(external)
        objects.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "external object"):
            self.initialize()
        self.assertFalse(self.root.exists())

    def test_changed_frozen_checks_reject_before_database_effects(self):
        self.initialize()
        before = (self.root / "state/graph.sqlite").read_bytes()
        (self.root / "frozen/checks.json").write_text("{}")
        with self.assertRaisesRegex(workflow.RepositoryWorkflowError, "CONFIG_CHANGED"):
            workflow.run_repository_workflow(self.root)
        self.assertEqual(before, (self.root / "state/graph.sqlite").read_bytes())

    def test_lifecycle_consumer_replay_and_rollback(self):
        before = workflow._tree_inventory(self.source)
        self.initialize()
        with self.adapters():
            built = workflow.run_repository_workflow(self.root, stop_after="built")
            self.assertEqual(built["workflow_state"], "built")
            promoted = workflow.run_repository_workflow(self.root, "recover")
            self.assertEqual(promoted["workflow_state"], "promoted")
            consumer = subprocess.run([sys.executable, "-B", "-c", self.check_code], cwd=promoted["accepted_generation"], check=True, capture_output=True, text=True)
            self.assertEqual(consumer.stdout, "accepted\n")
            replay = workflow.run_repository_workflow(self.root, "recover")
            self.assertEqual(replay["publication_journal_entries"], promoted["publication_journal_entries"])
            self.assertEqual(self.launches, 1)
            rollback = workflow.run_repository_workflow(self.root, "rollback")
            self.assertEqual(rollback["workflow_state"], "rolled_back")
            self.assertEqual(rollback["accepted_sha"], self.base)
            self.assertEqual(workflow.run_repository_workflow(self.root, "recover")["publication_journal_entries"], rollback["publication_journal_entries"])
        self.assertEqual(before, workflow._tree_inventory(self.source))

    def test_unsealed_reservation_never_relaunches(self):
        self.initialize()
        class Interrupted(BaseException): pass
        def barrier(point):
            if point == "after_reservation":
                raise Interrupted()
        with self.adapters():
            with self.assertRaises(Interrupted):
                workflow.run_repository_workflow(self.root, barrier=barrier)
            result = workflow.run_repository_workflow(self.root, "recover")
            self.assertEqual(result["classification"], "WORKER_INTERRUPTED_UNSEALED")
            self.assertEqual(result["attempts"], 1)
            self.assertEqual(self.launches, 0)
            self.assertEqual(result["accepted_sha"], self.base)

    def test_worker_git_authority_tamper_rejected(self):
        self.initialize()
        original = self.fake_worker
        def malicious(request, profile):
            value = original(request, profile)
            (Path(request["checkout"]) / ".git/config").write_text("[core]\n hooksPath = /tmp/unsafe\n")
            return value
        self.fake_worker = malicious
        with self.adapters():
            with self.assertRaisesRegex(workflow.RepositoryWorkflowError, "Git metadata"):
                workflow.run_repository_workflow(self.root)
        state = workflow.run_repository_workflow(self.root, "status")
        self.assertEqual(state["accepted_sha"], self.base)
        self.assertEqual(state["workflow_state"], "failed")

    def test_required_test_seam_checks_output_binding(self):
        target = self.directory / "artifact"
        target.mkdir()
        def fabricated(*args):
            return [{"sequence": 0, "command": "true", "candidate_sha": self.base, "exit_code": 0,
                "output": {"path": "missing", "sha256": "a" * 64, "byte_length": 0}}]
        with self.assertRaises((PermissionError, FileNotFoundError)):
            produce_required_test_results(self.source, ["true"], self.base, target, test_runner=fabricated)

    def test_admitted_and_promotion_boundaries_resume_without_relaunch(self):
        # Each scenario starts from an independent workspace and durable graph.
        for boundary in ("after_artifact_admission", "after_evaluation", "after_binding"):
            with self.subTest(boundary=boundary):
                self.root = self.directory / boundary
                self.initialize()
                class Interrupted(BaseException): pass
                def barrier(point):
                    if point == boundary:
                        raise Interrupted()
                before = self.launches
                with self.adapters():
                    with self.assertRaises(Interrupted):
                        workflow.run_repository_workflow(self.root, barrier=barrier)
                    recovered = workflow.run_repository_workflow(self.root, "recover")
                    self.assertEqual(recovered["workflow_state"], "promoted")
                    self.assertEqual(self.launches, before + 1)
                    self.assertEqual(recovered["publication_operations"], 1)

    def test_pending_rollback_recovers_same_operation(self):
        self.initialize()
        class Interrupted(BaseException): pass
        def barrier(point):
            if point == "rollback_after_binding":
                raise Interrupted()
        with self.adapters():
            workflow.run_repository_workflow(self.root)
            with self.assertRaises(Interrupted):
                workflow.run_repository_workflow(self.root, "rollback", barrier=barrier)
            recovered = workflow.run_repository_workflow(self.root, "recover")
            self.assertEqual(recovered["workflow_state"], "rolled_back")
            self.assertEqual(recovered["accepted_sha"], self.base)
            self.assertEqual(recovered["publication_operations"], 2)
            self.assertEqual(self.launches, 1)

    def test_unsigned_evaluation_never_advances_accepted_binding(self):
        self.initialize()
        original = self.fake_evaluate
        def tampered(request, profile):
            response = original(request, profile)
            response["signature"] = base64.b64encode(b"not a signature").decode()
            return response
        self.fake_evaluate = tampered
        with self.adapters():
            with self.assertRaises((PermissionError, ValueError)):
                workflow.run_repository_workflow(self.root)
        result = workflow.run_repository_workflow(self.root, "status")
        self.assertEqual(result["accepted_sha"], self.base)
        self.assertIsNone(result["outcome_id"])
        self.assertEqual(result["publication_operations"], 0)

    def test_changed_reservation_with_recomputed_hash_is_not_authority(self):
        self.initialize()
        with self.adapters():
            workflow.run_repository_workflow(self.root, stop_after="built")
        reservation = self.root / "attempts/repair-value-attempt-1/reservation.json"
        value = workflow._record(reservation)
        value["request"]["base_sha"] = "a" * 40
        value["request_sha256"] = workflow._hash(workflow.canonical(value["request"]))
        workflow._write_json(reservation, value)
        before = (self.root / "state/graph.sqlite").read_bytes()
        with self.assertRaisesRegex(workflow.RepositoryWorkflowError, "frozen authority"):
            workflow.run_repository_workflow(self.root, "status")
        with self.assertRaisesRegex(workflow.RepositoryWorkflowError, "frozen authority"):
            workflow.run_repository_workflow(self.root, "recover")
        self.assertEqual(before, (self.root / "state/graph.sqlite").read_bytes())


if __name__ == "__main__":
    unittest.main()
