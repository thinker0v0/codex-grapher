"""Real strict-profile snapshot subprocess and cross-UID backup/restore closure.

The worker, test-role observations and evaluator are disclosed deterministic
fixtures. No model, account creation, namespace launch or provider credentials
are used. Actual filesystem ownership, profile admission, receipt sealing, Git,
signed v4 graph promotion and the protected verification subprocess are real.
"""

from contextlib import ExitStack, nullcontext
import os
from pathlib import Path
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from control_plane import repository_workflow as workflow
from control_plane._verification_snapshot import verification_snapshot, verify_backup_snapshot
from control_plane.backup_archive import inspect_archive
from control_plane.evaluation_broker import BrokerStore
from control_plane.execution_profile import executable_digest, load_execution_profile, trusted_code_digest
from control_plane.project_graph import ProjectGraph
from control_plane.workspace_backup import (
    _check_tree, _role_names, _runtime_excludes, backup_workspace, restore_workspace,
)
from tests import test_repository_workflow as lifecycle_fixtures


@unittest.skipUnless(os.geteuid() == 0, "real root-owned verification projection requires root")
class StrictSnapshotSubprocessTests(unittest.TestCase):
    def setUp(self):
        try:
            account = pwd.getpwnam("codex")
        except KeyError:
            self.skipTest("existing codex account required; this test never creates accounts")
        if account.pw_uid != 1000:
            self.skipTest("fixture requires the existing codex UID 1000")
        names = {"python": sys.executable, "git": shutil.which("git"),
                 "openssl": shutil.which("openssl"), "provider": shutil.which("true"),
                 "bwrap": shutil.which("bwrap"), "setpriv": shutil.which("setpriv")}
        if any(value is None for value in names.values()):
            self.skipTest("pinned executable prerequisites are unavailable")

        temporary = tempfile.TemporaryDirectory(prefix="grapher-real-snapshot-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "workspace"
        self.source = self.directory / "source"
        self.source.mkdir()
        workflow._git(self.source, "init", "--quiet")
        workflow._git(self.source, "config", "user.name", "Snapshot Fixture")
        workflow._git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / "value.py").write_text("VALUE = 0\n")
        workflow._git(self.source, "add", ".")
        workflow._git(self.source, "commit", "--quiet", "-m", "Disclosed snapshot fixture regression")
        self.base = workflow._git(self.source, "rev-parse", "HEAD")

        self.trusted = self.directory / "trusted-code"
        self.trusted.mkdir(mode=0o755)
        repository = Path(__file__).resolve().parents[1]
        for name in ("control_plane", "schemas"):
            shutil.copytree(repository / name, self.trusted / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        # Frozen trusted code is readable but not writable by any configured role.
        for path in (self.trusted, *self.trusted.rglob("*")):
            path.chmod(0o755 if path.is_dir() else 0o644)

        self.private, self.public = self.directory / "private.pem", self.directory / "public.pem"
        subprocess.run([names["openssl"], "genpkey", "-algorithm", "ED25519", "-out", str(self.private)],
                       check=True, capture_output=True, timeout=15)
        self.private.chmod(0o600)
        subprocess.run([names["openssl"], "pkey", "-in", str(self.private), "-pubout", "-out", str(self.public)],
                       check=True, capture_output=True, timeout=15)
        self.public.chmod(0o644)
        tools = {}
        for name, executable in names.items():
            path = str(Path(executable).resolve(strict=True))
            tools[name] = {"path": path, "sha256": executable_digest(path),
                           "version": "deterministic-snapshot-fixture"}
        raw_profile = {
            "schema_version": 1, "mode": "isolated-linux", "tools": tools,
            "provider": {"backend": "codex", "model": "fixture", "reasoning_effort": "medium", "service_tier": "default"},
            "roles": {"worker": {"uid": account.pw_uid, "gid": account.pw_gid},
                      "test_runner": {"uid": 61111, "gid": 61111},
                      "graph": {"uid": 61112, "gid": 61112},
                      "signer": {"uid": 61113, "gid": 61113}},
            "auth": {"kind": "existing-cli-login", "account": account.pw_name},
            "paths": {"trusted_code_root": str(self.trusted), "trusted_code_sha256": trusted_code_digest(self.trusted),
                      "signer_private_key": str(self.private), "signer_public_key": str(self.public)},
            "sqlite": {"profile": "delete-extra", "attestation": None},
        }
        self.profile_path = self.directory / "profile.json"
        self.profile_path.write_bytes(workflow.canonical(raw_profile))
        self.profile_path.chmod(0o600)
        # This real loader remains unpatched in the parent and every child.
        self.profile = load_execution_profile(self.profile_path, require_private_key=True)
        self.policy = {
            "schema_version": 1, "name": "strict-snapshot-fixture",
            "sections": {"correctness": {"minimum": 100, "maximum": 100}},
            "mandatory_gates": ["required_tests", "independent_assertions", "write_scope"], "threshold": 100,
        }
        (self.directory / "policy.json").write_bytes(workflow.canonical(self.policy))
        self.check_code = "import value; assert value.VALUE == 1; print('accepted')"
        python = self.profile.tools["python"].path
        (self.directory / "checks.json").write_bytes(workflow.canonical({
            "schema_version": 1, "checks": [{"id": "value-behavior", "argv": [python, "-B", "-c", self.check_code]}],
        }))
        self.task = {
            "schema_version": 1, "project_id": "snapshot-fixture", "task_id": "repair-value",
            "idempotency_key": "strict-snapshot.once", "base_sha": self.base,
            "objective": "Set the value to one", "acceptance_criteria": ["VALUE is one"],
            "allowed_paths": ["value.py"], "required_tests": [shlex.join([python, "-B", "-c", self.check_code])],
            "worker": {"backend": "codex"}, "evaluation": {"policy": "policy.json", "checks": "checks.json"},
            "limits": {"worker_timeout_seconds": 30, "required_test_timeout_seconds": 30,
                       "evaluation_timeout_seconds": 30, "max_output_bytes": 65536},
        }
        task_path = self.directory / "task.json"
        task_path.write_bytes(workflow.canonical(self.task))
        self.launches, self.outputs = 0, {}
        initialized = workflow.initialize_repository_workflow(self.source, task_path, self.root, self.profile_path)
        self.assertEqual(initialized["workflow_state"], "ready")
        self.frozen = {path.name: path.read_bytes() for path in (self.root / "frozen").iterdir()}
        self.workflow_bytes = (self.root / "workflow.json").read_bytes()
        self._promote_fixture()
        self._assign_semantic_owners()
        _check_tree(self.root, self.profile)

    def _worker(self, request, profile):
        receipt = lifecycle_fixtures.RepositoryWorkflowTests.fake_worker(self, request, profile)
        receipt["executable_sha256"] = profile.tools["provider"].sha256
        return receipt

    def _tests(self, request, profile):
        receipt = lifecycle_fixtures.RepositoryWorkflowTests.fake_tests(self, request, profile)
        receipt.pop("receipt_id")
        # Deliberately simulated observations: these test archive/provenance
        # plumbing and must not be reported as actual sandbox isolation proof.
        receipt.update({"request_id": request["run_id"], "actual_uid": profile.roles["test_runner"].uid,
                        "actual_gid": profile.roles["test_runner"].gid,
                        "namespaces": {name: 1 for name in ("user", "mount", "pid", "ipc", "net")},
                        "capabilities": {name: "0" for name in ("inheritable", "permitted", "effective", "bounding", "ambient")},
                        "no_new_privs": True, "elapsed_ms": 1,
                        "limits": {"timeout_seconds": request["timeout_seconds"], "max_output_bytes": request["max_output_bytes"]}})
        receipt["receipt_id"] = workflow._hash(workflow.canonical(receipt))
        store = BrokerStore(self.root)
        try:
            return store.seal_receipt(receipt, self.outputs)
        finally:
            store.close()

    def _output(self, receipt_id, path, profile):
        store = BrokerStore(self.root, create=False)
        try:
            return store.output(receipt_id, path)
        finally:
            store.close()

    def _evaluate(self, request, profile):
        return lifecycle_fixtures.RepositoryWorkflowTests.fake_evaluate(self, request, profile)

    def _promote_fixture(self):
        # Assemble real graph/artifact/signature state under root; only effect
        # adapters are simulated. Public isolated dispatch is not exercised.
        with ExitStack() as adapters:
            adapters.enter_context(patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}))
            adapters.enter_context(patch("control_plane.worker_provider.launch_worker", side_effect=self._worker))
            adapters.enter_context(patch("control_plane.evaluation_broker.broker_workspace", side_effect=lambda *a, **kw: nullcontext()))
            adapters.enter_context(patch("control_plane.evaluation_broker.run_candidate_tests", side_effect=self._tests))
            adapters.enter_context(patch("control_plane.evaluation_broker.fetch_receipt_output", side_effect=self._output))
            adapters.enter_context(patch("control_plane.evaluation_broker.evaluate_artifact", side_effect=self._evaluate))
            adapters.enter_context(patch.object(workflow, "_worker_control", side_effect=lambda *a, **kw: nullcontext()))
            record, task, _checks, profile, policy = workflow._configuration(self.root)
            graph = ProjectGraph(self.root / "state/graph.sqlite", self.root / "frozen/public-key.pem",
                                 policy.sha256, evaluation_policy=policy, **workflow._sqlite_options(profile))
            try:
                coordinator = workflow._coordinator(self.root, graph, record, policy)
                workflow._build(self.root, graph, record, task, profile, lambda _: None)
                workflow._evaluate(self.root, graph, record, task, profile)
                artifact, manifest = workflow._artifact(self.root, graph, record, task)
                outcome = graph.connection.execute("SELECT outcome_id FROM evaluation_outcomes WHERE node_id=?", (task["task_id"],)).fetchone()[0]
                coordinator.integrate(task["task_id"] + "-promotion-v1", task["task_id"], outcome, artifact["artifact_id"],
                                      manifest, "oss", self.root / "evidence")
                self.promoted = workflow._summary(self.root, graph, coordinator, record, task)
                self.assertEqual(self.promoted["workflow_state"], "promoted")
            finally:
                graph.connection.close()

    def _assign_semantic_owners(self):
        self.root.chmod(0o755)
        for path in self.root.rglob("*"):
            owner, group = _role_names(path.relative_to(self.root).as_posix())
            uid = 0 if owner == "bootstrap" else self.profile.roles[owner].uid
            gid = 0 if group == "bootstrap" else self.profile.roles[group].gid
            mode = stat.S_IMODE(path.stat().st_mode)
            os.chown(path, uid, gid)
            path.chmod(mode)
        (self.root / "state").chmod(0o2700)
        (self.root / "publications").chmod(0o2750)

    def _snapshot(self):
        return verification_snapshot(self.root, self.profile, original_root=self.root,
                                     excludes=_runtime_excludes(self.root), role_for_path=_role_names)

    def test_real_subprocess_and_promoted_cross_uid_backup_restore(self):
        source_before = workflow._tree_inventory(self.source)
        state_before = workflow._tree_inventory(self.root)
        self.assertEqual((self.root / "state/binding.json").stat().st_uid, 61112)
        with self._snapshot() as snapshot:
            # This invokes pinned Python -I -B against the protected copied
            # verifier, including real strict profile admission in that process.
            closure = verify_backup_snapshot(snapshot)
        self.assertEqual(closure["binding"]["base_sha"], self.promoted["accepted_sha"])
        self.assertEqual(len(closure["artifacts"]), 1)
        self.assertEqual(len(closure["attempt_provenance"]), 1)
        receipt_id = closure["attempt_provenance"][0]["required_receipt_id"]
        self.assertIn(receipt_id, closure["broker_receipts"]["receipt_ids"])
        self.assertEqual(state_before, workflow._tree_inventory(self.root))

        archive = self.directory / "backup.tar"
        backup = backup_workspace(self.root, archive)
        self.assertTrue(backup.usable)
        manifest = inspect_archive(archive)
        self.assertEqual(manifest["metadata"]["closure"], closure)
        self.assertEqual(manifest["metadata"]["profile_sha256"], self.profile.sha256)
        paths = {entry["path"] for entry in manifest["entries"]}
        self.assertNotIn(".broker-receipts/.private", paths)
        self.assertNotIn("state/.workflow.lock", paths)
        self.assertEqual(state_before, workflow._tree_inventory(self.root))
        # Remove the original completely, so restoring cannot read hidden
        # evidence, Git objects or publication generations from that runtime.
        shutil.rmtree(self.root)
        restored = restore_workspace(archive, self.root, self.profile_path)
        self.assertFalse(restored.verify_only)
        self.assertEqual(restored.closure, closure)
        self.assertEqual((self.root / "state/binding.json").stat().st_uid, 61112)
        self.assertEqual(stat.S_IMODE((self.root / "state").stat().st_mode), 0o2700)
        self.assertEqual(stat.S_IMODE((self.root / "publications").stat().st_mode), 0o2750)
        _check_tree(self.root, self.profile)
        with self._snapshot() as snapshot:
            self.assertEqual(verify_backup_snapshot(snapshot), closure)
        self.assertEqual(self.frozen, {path.name: path.read_bytes() for path in (self.root / "frozen").iterdir()})
        self.assertEqual((self.root / "workflow.json").read_bytes(), self.workflow_bytes)
        self.assertEqual(source_before, workflow._tree_inventory(self.source))
        self.assertEqual(self.launches, 1)


if __name__ == "__main__":
    unittest.main()
