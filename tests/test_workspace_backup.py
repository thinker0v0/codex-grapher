"""Whole-state tests use real Git, graph, ingress and publication implementations."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from control_plane.local_workflow import run_local_workflow
from control_plane.publication_store import PublicationStore
from control_plane.workspace_backup import (
    WorkspaceBackupError, _closed_database, _metadata, _self_contained_git,
    verify_complete_inventory,
)


class CompleteWorkspaceInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="grapher-backup-test-")
        self.root = Path(self.temporary.name) / "workflow"

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, **kwargs):
        value = run_local_workflow(self.root, **kwargs)
        # The generic initializer always materializes the initial generation;
        # the legacy test producer does so only at promotion.
        binding = json.loads((self.root / "binding.json").read_bytes())
        PublicationStore(self.root / "publications").ensure(
            self.root / "canonical", binding["repo"], binding["base_sha"],
            (self.root / "binding.json").stat(),
        )
        return value

    def test_unevaluated_inventory_and_custom_refs_have_complete_closure(self):
        state = self.build(stop_after="built")
        baseline = state["baseline_sha"]
        subprocess.run(["git", "-C", str(self.root / "canonical"), "update-ref",
                        "refs/ai-ops/rollback/retained", baseline], check=True)
        before = (self.root / "graph.sqlite").read_bytes()
        closure = verify_complete_inventory(self.root)
        self.assertEqual([item["artifact_id"] for item in closure["artifacts"]], [state["artifact_id"]])
        self.assertIn("refs/ai-ops/rollback/retained " + baseline, closure["refs"])
        self.assertEqual(before, (self.root / "graph.sqlite").read_bytes())
        self.assertFalse((self.root / "graph.sqlite-wal").exists())

    def test_corrupt_unassessed_artifact_rejects(self):
        state = self.build(stop_after="built")
        digest = state["artifact_id"].split(":")[1]
        output = self.root / "evidence/sha256" / digest[:2] / digest / "required-tests/0000.output"
        output.chmod(0o600)
        output.write_text("changed\n")
        with self.assertRaises((WorkspaceBackupError, PermissionError)):
            verify_complete_inventory(self.root)

    def test_all_retained_generations_checked_after_rollback(self):
        promoted = self.build()
        self.build(operation="rollback")
        generation = self.root / "publications" / promoted["accepted_sha"] / "src/greeting.py"
        generation.chmod(0o640)
        generation.write_text("corrupt historical generation\n")
        with self.assertRaises((WorkspaceBackupError, PermissionError)):
            verify_complete_inventory(self.root)

    def test_every_database_sidecar_is_preserved_and_rejected(self):
        self.build(stop_after="built")
        before = (self.root / "graph.sqlite").read_bytes()
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(suffix=suffix):
                sidecar = Path(str(self.root / "graph.sqlite") + suffix)
                sidecar.write_bytes(b"do not delete")
                with self.assertRaisesRegex(WorkspaceBackupError, "BACKUP_NOT_QUIESCENT"):
                    verify_complete_inventory(self.root)
                self.assertEqual(sidecar.read_bytes(), b"do not delete")
                sidecar.unlink()
        self.assertEqual(before, (self.root / "graph.sqlite").read_bytes())

    def test_recorded_worker_and_evaluator_claims_reject_even_expired(self):
        self.build(stop_after="built")
        # This targets the closure admission guard directly. Graph static
        # validation is separately mandatory in the public wrapper.
        with sqlite3.connect(self.root / "graph.sqlite") as connection:
            connection.execute("UPDATE nodes SET lease_id='still-recorded' WHERE attempt=1")
        with self.assertRaisesRegex(WorkspaceBackupError, "worker lease"):
            verify_complete_inventory(self.root)

    def test_external_git_object_store_rejects_without_following_it(self):
        self.build(stop_after="built")
        path = self.root / "canonical/.git/objects/info/alternates"
        path.write_text("/private/other-project/objects\n")
        with self.assertRaisesRegex(WorkspaceBackupError, "external object"):
            verify_complete_inventory(self.root)

    def test_linked_worktree_and_missing_object_reject(self):
        self.build(stop_after="built")
        (self.root / "canonical/.git/commondir").write_text("/other/.git")
        with self.assertRaisesRegex(WorkspaceBackupError, "external object"):
            verify_complete_inventory(self.root)

    def test_database_mutation_during_inspection_rejects(self):
        self.build(stop_after="built")
        with self.assertRaisesRegex(WorkspaceBackupError, "changed"):
            with _closed_database(self.root):
                with sqlite3.connect(self.root / "graph.sqlite") as connection:
                    connection.execute("UPDATE goals SET objective='changed'")

    def test_actual_active_claim_rejects_and_disposed_artifact_still_closes(self):
        from control_plane.evaluation_policy import load_task_policy
        from control_plane.project_graph import ProjectGraph
        from control_plane.local_workflow import TASK
        state = self.build(stop_after="built")
        policy = load_task_policy(self.root / "task-policy.json")
        graph = ProjectGraph(self.root / "graph.sqlite", self.root / "evaluator-public.pem",
                             policy.sha256, evaluation_policy=policy)
        try:
            node = graph.get_node(TASK)
            graph.claim_evidence(TASK, node["version"], state["artifact_id"], "hermes-evaluator")
        finally:
            graph.connection.close()
        with self.assertRaisesRegex(WorkspaceBackupError, "claim is active"):
            verify_complete_inventory(self.root)
        graph = ProjectGraph(self.root / "graph.sqlite", self.root / "evaluator-public.pem",
                             policy.sha256, evaluation_policy=policy)
        try:
            node = graph.get_node(TASK)
            graph.reject_evidence(TASK, node["version"], state["artifact_id"], "FAILED_GATE",
                                  "a" * 64, "hermes-evaluator")
        finally:
            graph.connection.close()
        closure = verify_complete_inventory(self.root)
        self.assertEqual(closure["artifacts"][0]["artifact_id"], state["artifact_id"])
        digest = state["artifact_id"].split(":")[1]
        manifest = self.root / "evidence/sha256" / digest[:2] / digest / "manifest.json"
        manifest.chmod(0o600)
        manifest.write_bytes(b"{}")
        with self.assertRaises((WorkspaceBackupError, PermissionError)):
            verify_complete_inventory(self.root)

    def test_interrupted_promotion_is_not_quiescent(self):
        import sys
        result = subprocess.run([sys.executable, "-B", "-m", "control_plane.local_workflow",
                                 "--workspace", str(self.root), "--crash-at", "after_binding"],
                                capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 86, result.stderr.decode())
        with self.assertRaisesRegex(WorkspaceBackupError, "promotion is unfinished"):
            verify_complete_inventory(self.root)

    def test_pending_rollback_is_not_quiescent(self):
        from control_plane.evaluation_policy import load_task_policy
        from control_plane.project_graph import ProjectGraph
        from control_plane.local_workflow import TASK, ATTEMPT, _coordinator
        self.build()
        policy = load_task_policy(self.root / "task-policy.json")
        graph = ProjectGraph(self.root / "graph.sqlite", self.root / "evaluator-public.pem",
                             policy.sha256, evaluation_policy=policy)
        try:
            coordinator = _coordinator(self.root, graph, policy)
            def interrupt(point):
                if point == "after_rollback_prepare":
                    raise RuntimeError("frozen pending rollback fixture")
            with self.assertRaisesRegex(RuntimeError, "frozen pending rollback"):
                coordinator.rollback("backup-rollback", TASK, ATTEMPT, 1, interrupt)
        finally:
            graph.connection.close()
        with self.assertRaisesRegex(WorkspaceBackupError, "rollback is unfinished"):
            verify_complete_inventory(self.root)


class WorkspaceBackupRoundTripTests(unittest.TestCase):
    def setUp(self):
        import pwd
        import sys
        from control_plane.execution_profile import trusted_code_digest, executable_digest
        from control_plane.repository_workflow import initialize_repository_workflow
        self.temporary = tempfile.TemporaryDirectory(prefix="grapher-backup-roundtrip-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "workspace"
        self.archive = self.base / "backup.tar"
        source = self.base / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / "value.txt").write_text("baseline\n")
        subprocess.run(["git", "-C", str(source), "add", "."], check=True)
        subprocess.run(["git", "-C", str(source), "-c", "user.name=Backup Test", "-c",
                        "user.email=backup@example.invalid", "commit", "-qm", "baseline"], check=True)
        baseline = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
        code = self.base / "trusted"
        code.mkdir()
        (code / "trusted.py").write_text("# fixed trusted code fixture\n")
        self.key = self.base / "private.pem"
        public = self.base / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        self.key.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(public)],
                       check=True, capture_output=True)
        tools = {}
        for name, executable in {"python": sys.executable, "git": shutil.which("git"),
                                 "openssl": shutil.which("openssl"), "provider": shutil.which("true")}.items():
            path = str(Path(executable).resolve())
            tools[name] = {"path": path, "sha256": executable_digest(path), "version": "backup-unit-fixture"}
        tools.update(bwrap=None, setpriv=None)
        profile = {"schema_version": 1, "mode": "trusted-local", "tools": tools,
                   "provider": {"backend": "codex", "model": "test", "reasoning_effort": "medium", "service_tier": "default"},
                   "roles": {role: {"uid": os.geteuid(), "gid": os.getegid()} for role in ("graph", "worker", "test_runner", "signer")},
                   "auth": {"kind": "existing-cli-login", "account": pwd.getpwuid(os.geteuid()).pw_name},
                   "paths": {"trusted_code_root": str(code), "trusted_code_sha256": trusted_code_digest(code),
                             "signer_private_key": str(self.key), "signer_public_key": str(public)},
                   "sqlite": {"profile": getattr(self, "sqlite_profile", "delete-extra"),
                              "attestation": getattr(self, "sqlite_attestation", None)}}
        self.profile = self.base / "profile.json"
        self.profile.write_text(json.dumps(profile, sort_keys=True))
        policy = {"schema_version": 1, "name": "backup-fixture", "threshold": 100,
                  "sections": {"acceptance": {"minimum": 100, "maximum": 100}},
                  "mandatory_gates": ["required_tests", "independent_checks", "write_scope"]}
        (self.base / "policy.json").write_text(json.dumps(policy))
        (self.base / "checks.json").write_text(json.dumps({"schema_version": 1, "checks": [
            {"id": "value", "argv": [tools["python"]["path"], "-I", "-c", "assert True"]}]}))
        task = {"schema_version": 1, "project_id": "backup-fixture", "task_id": "backup-task",
                "idempotency_key": "backup-task.once", "base_sha": baseline,
                "objective": "Maintain a complete offline workspace", "acceptance_criteria": ["value is intact"],
                "allowed_paths": ["value.txt"], "required_tests": ["true"], "worker": {"backend": "codex"},
                "evaluation": {"policy": "policy.json", "checks": "checks.json"}}
        task_path = self.base / "task.json"
        task_path.write_text(json.dumps(task))
        initialize_repository_workflow(source, task_path, self.root, self.profile)

    def tearDown(self):
        self.temporary.cleanup()

    def test_real_generic_offline_backup_and_original_root_restore(self):
        from control_plane.workspace_backup import backup_workspace, restore_workspace
        from control_plane.backup_archive import inspect_archive
        before = {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                  for p in self.root.rglob("*") if p.is_file()}
        receipt = backup_workspace(self.root, self.archive)
        self.assertTrue(receipt.usable)
        after = {str(p.relative_to(self.root)): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        manifest = inspect_archive(self.archive)
        self.assertNotIn("state/.workflow.lock", {entry["path"] for entry in manifest["entries"]})
        self.assertNotIn(self.key.read_bytes(), self.archive.read_bytes())
        old = self.base / "offline-original"
        self.root.rename(old)
        restored = restore_workspace(self.archive, self.root, self.profile)
        self.assertFalse(restored.verify_only)
        self.assertEqual(restored.closure, manifest["metadata"]["closure"])
        self.assertEqual((self.root / "state/binding.json").read_bytes(), (old / "state/binding.json").read_bytes())
        self.assertTrue((self.root / "state/.workflow.lock").is_file())

    def test_missing_private_key_restore_remains_verify_only(self):
        from control_plane.workspace_backup import backup_workspace, restore_workspace
        backup_workspace(self.root, self.archive)
        self.root.rename(self.base / "offline-original")
        self.key.unlink()
        receipt = restore_workspace(self.archive, self.root, self.profile)
        self.assertTrue(receipt.verify_only)
        self.assertFalse(self.key.exists())

    def test_relocation_and_profile_change_reject_before_publication(self):
        from control_plane.workspace_backup import backup_workspace, restore_workspace
        backup_workspace(self.root, self.archive)
        with self.assertRaisesRegex(WorkspaceBackupError, "relocation"):
            restore_workspace(self.archive, self.base / "relocated", self.profile)
        self.root.rename(self.base / "offline-original")
        value = json.loads(self.profile.read_bytes())
        value["provider"]["model"] = "changed"
        self.profile.write_text(json.dumps(value))
        with self.assertRaisesRegex(WorkspaceBackupError, "profile differs"):
            restore_workspace(self.archive, self.root, self.profile)
        self.assertFalse(self.root.exists())

    def test_mismatched_private_key_rejects_without_replacing_it(self):
        from control_plane.workspace_backup import backup_workspace, restore_workspace
        backup_workspace(self.root, self.archive)
        self.root.rename(self.base / "offline-original")
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        before = self.key.read_bytes()
        with self.assertRaisesRegex(WorkspaceBackupError, "does not match"):
            restore_workspace(self.archive, self.root, self.profile)
        self.assertFalse(self.root.exists())
        self.assertEqual(self.key.read_bytes(), before)

    def test_held_shared_admission_barrier_blocks_backup(self):
        from control_plane.repository_workflow import workspace_lock
        from control_plane.workspace_backup import backup_workspace
        with workspace_lock(self.root):
            with self.assertRaisesRegex(Exception, "BACKUP_NOT_QUIESCENT"):
                backup_workspace(self.root, self.archive)
        self.assertFalse(self.archive.exists())

    def test_open_database_writer_blocks_even_without_workflow_lock(self):
        from control_plane.project_graph import ProjectGraph
        from control_plane.evaluation_policy import load_task_policy
        from control_plane.workspace_backup import backup_workspace
        policy = load_task_policy(self.root / "frozen/policy.json")
        graph = ProjectGraph(self.root / "state/graph.sqlite", self.root / "frozen/public-key.pem",
                             policy.sha256, evaluation_policy=policy)
        try:
            with self.assertRaisesRegex(WorkspaceBackupError, "database writer"):
                backup_workspace(self.root, self.archive)
        finally:
            graph.connection.close()
        self.assertFalse(self.archive.exists())

    @unittest.skipUnless(os.geteuid() == 0, "bootstrap lock belongs to root")
    def test_bootstrap_barrier_and_runtime_control_paths(self):
        import fcntl
        import socket
        from control_plane.workspace_backup import backup_workspace
        from control_plane.backup_archive import inspect_archive
        lock = self.root / ".bootstrap.lock"
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(WorkspaceBackupError, "bootstrap launcher is still active"):
                backup_workspace(self.root, self.archive)
        finally:
            os.close(descriptor)
        control = self.root / "state/task-attempt-1.control.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(control))
        backup_workspace(self.root, self.archive)
        names = {entry["path"] for entry in inspect_archive(self.archive)["entries"]}
        self.assertNotIn(".bootstrap.lock", names)
        self.assertNotIn("state/task-attempt-1.control.sock", names)
        self.assertTrue(control.exists())

    def test_public_verification_script_uses_the_real_backup_api(self):
        import sys
        script = Path(__file__).resolve().parents[1] / "scripts/verify-workspace-backup.py"
        result = subprocess.run([sys.executable, str(script), "--workspace", str(self.root),
                                 "--output", str(self.archive)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["result"], "VERIFIED_OFFLINE_CLOSURE")
        self.assertTrue(report["receipt"]["usable"])

    def test_private_material_or_link_cannot_enter_backup(self):
        from control_plane.workspace_backup import backup_workspace
        payload = self.root / "leaked.pem"
        payload.write_bytes(self.key.read_bytes())
        with self.assertRaisesRegex(WorkspaceBackupError, "private signing material"):
            backup_workspace(self.root, self.archive)
        payload.unlink()
        payload.symlink_to(self.key)
        with self.assertRaisesRegex(WorkspaceBackupError, "links and special"):
            backup_workspace(self.root, self.archive)
        self.assertFalse(self.archive.exists())

    def test_git_executable_configuration_is_rejected_before_verification(self):
        import shlex
        from control_plane.workspace_backup import backup_workspace
        marker = self.base / "executed"
        command = self.base / "unsafe-fsmonitor"
        command.write_text("#!/bin/sh\nprintf executed > " + shlex.quote(str(marker)) + "\n")
        command.chmod(0o755)
        generation = next((self.root / "publications").iterdir())
        subprocess.run(["git", "-C", str(generation), "config", "core.fsmonitor", str(command)], check=True)
        with self.assertRaisesRegex(WorkspaceBackupError, "Git core configuration"):
            backup_workspace(self.root, self.archive)
        self.assertFalse(marker.exists())
        self.assertFalse(self.archive.exists())

    def test_admitted_generic_attempt_receipts_survive_private_registry_exclusion(self):
        from control_plane.repository_workflow import run_repository_workflow
        from control_plane.worker_provider import CLI_VERSION, request_sha256
        from control_plane.workspace_backup import backup_workspace, restore_workspace
        from control_plane.backup_archive import inspect_archive

        def fixture_worker(request, profile):
            (Path(request["checkout"]) / "value.txt").write_text("candidate\n")
            return {"schema_version": 1, "attempt_id": request["attempt_id"],
                    "request_sha256": request_sha256(request), "task_sha256": request["task_sha256"],
                    "profile_sha256": request["profile_sha256"], "prompt_sha256": request["prompt_sha256"],
                    "provider": "codex", "cli_version": CLI_VERSION,
                    "executable_sha256": profile.tools["provider"].sha256,
                    "model": None, "session_id": "fixture-session", "completion": "COMPLETED",
                    "usage_observed": None, "exit_code": 0, "signal": None, "elapsed_seconds": 0.1,
                    "stdout_sha256": hashlib.sha256(b"fixture").hexdigest(),
                    "stderr_sha256": hashlib.sha256(b"").hexdigest(), "stdout_bytes": 7,
                    "stderr_bytes": 0, "descendants_reaped": True}

        with patch("control_plane.worker_provider.launch_worker", side_effect=fixture_worker), \
                patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}):
            result = run_repository_workflow(self.root, stop_after="built")
        self.assertEqual(result["workflow_state"], "built")
        backup_workspace(self.root, self.archive)
        manifest = inspect_archive(self.archive)
        self.assertEqual(len(manifest["metadata"]["closure"]["attempt_provenance"]), 1)
        self.assertFalse(any(entry["path"].startswith(".broker-receipts/.private") for entry in manifest["entries"]))
        self.root.rename(self.base / "offline-original")
        receipt = restore_workspace(self.archive, self.root, self.profile)
        self.assertEqual(len(receipt.closure["attempt_provenance"]), 1)


@unittest.skipUnless(os.geteuid() == 0, "semantic non-root ownership restoration needs root")
class SemanticOwnershipTests(unittest.TestCase):
    def test_restore_applies_trusted_roles_and_preserves_bootstrap_protection(self):
        from types import SimpleNamespace
        from control_plane.backup_archive import create_archive, extract_archive
        from control_plane.workspace_backup import _role_names, _apply_ownership, _check_tree
        with tempfile.TemporaryDirectory(prefix="grapher-backup-roles-") as temporary:
            directory = Path(temporary)
            source = directory / "source"
            source.mkdir(mode=0o700)
            (source / "state").mkdir(mode=0o700)
            (source / "state").chmod(0o2700)
            (source / "publications").mkdir(mode=0o750)
            (source / "publications").chmod(0o2750)
            (source / "state/binding.json").write_text("{}")
            (source / "state/binding.json").chmod(0o440)
            (source / "frozen").mkdir(mode=0o755)
            (source / "frozen/task.json").write_text("{}")
            (source / "frozen/task.json").chmod(0o444)
            checkout = source / "attempts/task-attempt-1/checkout"
            (checkout / ".git").mkdir(parents=True)
            checkout.chmod(0o755)
            (checkout / "value.txt").write_text("candidate\n")
            (checkout / ".git/HEAD").write_text("detached\n")
            archive = directory / "backup.tar"
            manifest = create_archive(source, archive, metadata={"root_mode": 0o755}, role_for_path=_role_names)
            restored = directory / "restored"
            restored.mkdir(mode=0o700)
            extract_archive(archive, restored)
            profile = SimpleNamespace(mode="isolated-linux", auth_home=Path("/root"), paths={}, roles={
                "graph": SimpleNamespace(uid=40011, gid=40021),
                "worker": SimpleNamespace(uid=40012, gid=40022),
                "test_runner": SimpleNamespace(uid=40013, gid=40023),
                "signer": SimpleNamespace(uid=40014, gid=40024),
            })
            _apply_ownership(restored, manifest, profile)
            binding = (restored / "state/binding.json").stat()
            self.assertEqual((binding.st_uid, binding.st_gid), (40011, 40022))
            self.assertEqual((restored / "state").stat().st_uid, 40011)
            self.assertEqual((restored / "state").stat().st_gid, 40022)
            self.assertEqual((restored / "state").stat().st_mode & 0o7777, 0o2700)
            self.assertEqual((restored / "publications").stat().st_gid, 40022)
            self.assertEqual((restored / "publications").stat().st_mode & 0o7777, 0o2750)
            self.assertEqual((restored / "frozen/task.json").stat().st_uid, 0)
            self.assertEqual((restored / "attempts/task-attempt-1/checkout/value.txt").stat().st_uid, 40011)
            self.assertEqual((restored / "attempts/task-attempt-1/checkout/.git/HEAD").stat().st_uid, 40011)
            self.assertEqual(restored.stat().st_mode & 0o777, 0o700)
            _check_tree(restored, profile)
            (restored / "frozen/task.json").chmod(0o666)
            with self.assertRaisesRegex(WorkspaceBackupError, "bootstrap-owned"):
                _check_tree(restored, profile)


@unittest.skipUnless(os.environ.get("CODEX_GRAPHER_SQLITE_ATTESTATION"),
                     "requires explicitly provisioned fixed SQLite runtime and attestation")
class FixedWalWorkspaceBackupTests(unittest.TestCase):
    def test_complete_artifact_workspace_cold_restore_under_actual_fixed_wal(self):
        import sqlite3
        from control_plane.sqlite_runtime import runtime_status
        attestation = os.environ["CODEX_GRAPHER_SQLITE_ATTESTATION"]
        facts = runtime_status(attestation)
        self.assertEqual(facts["patch_status"], "FIXED")
        self.assertEqual(sqlite3.sqlite_version, "3.53.4")
        fixture = WorkspaceBackupRoundTripTests("test_admitted_generic_attempt_receipts_survive_private_registry_exclusion")
        fixture.sqlite_profile = "wal-full"
        fixture.sqlite_attestation = attestation
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.test_admitted_generic_attempt_receipts_survive_private_registry_exclusion()
        original = fixture.base / "offline-original/state/graph.sqlite"
        restored = fixture.root / "state/graph.sqlite"
        self.assertEqual(original.read_bytes(), restored.read_bytes())
        self.assertEqual(restored.read_bytes()[18:20], b"\x02\x02")
        original_receipt = Path(str(original) + ".sqlite-runtime.json")
        restored_receipt = Path(str(restored) + ".sqlite-runtime.json")
        self.assertEqual(original_receipt.read_bytes(), restored_receipt.read_bytes())
        self.assertFalse(any(Path(str(restored) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")))
        print(json.dumps({"scope": "whole-workspace fixed-WAL cold restore; provider fixture",
                          "sqlite_version": sqlite3.sqlite_version,
                          "runtime_patch_status": facts["patch_status"],
                          "original_database_sha256": hashlib.sha256(original.read_bytes()).hexdigest(),
                          "restored_database_sha256": hashlib.sha256(restored.read_bytes()).hexdigest(),
                          "runtime_receipt_sha256": hashlib.sha256(restored_receipt.read_bytes()).hexdigest(),
                          "original_expected_path_unavailable_during_restore": True}, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
