"""Root-only readonly ownership projection; deterministic lifecycle fixtures."""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane import repository_workflow as workflow
from control_plane._verification_snapshot import (
    VerificationSnapshot, verification_snapshot, snapshot_owner_uid, verify_backup_snapshot, _run_verifier,
)
from control_plane.workspace_backup import _role_names, _runtime_excludes, verify_complete_inventory
from tests import test_repository_workflow as workflow_fixtures


@unittest.skipUnless(os.geteuid() == 0, "ownership projection requires root")
class VerificationSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.fixture = workflow_fixtures.RepositoryWorkflowTests("test_lifecycle_consumer_replay_and_rollback")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.profile.roles["graph"] = SimpleNamespace(uid=61112, gid=61112)
        self.fixture.profile.roles["worker"] = SimpleNamespace(uid=61110, gid=61110)
        self.fixture.profile.roles["test_runner"] = SimpleNamespace(uid=0, gid=0)
        self.fixture.profile.roles["signer"] = SimpleNamespace(uid=0, gid=0)
        self.fixture.profile.tools["openssl"] = SimpleNamespace(path="/usr/bin/openssl")
        self.fixture.initialize()
        with self.fixture.adapters():
            workflow.run_repository_workflow(self.fixture.root)
        self.fixture.profile.mode = "isolated-linux"
        for item in self.fixture.root.iterdir():
            if item.name in {"frozen", "workflow.json"}:
                continue
            for path in (item, *item.rglob("*")) if item.is_dir() else (item,):
                relative = path.relative_to(self.fixture.root).as_posix()
                owner, group = _role_names(relative)
                uid = 0 if owner == "bootstrap" else self.fixture.profile.roles[owner].uid
                gid = 0 if group == "bootstrap" else self.fixture.profile.roles[group].gid
                os.chown(path, uid, gid)

    def snapshot(self):
        return verification_snapshot(self.fixture.root, self.fixture.profile,
            original_root=self.fixture.root, excludes=_runtime_excludes(self.fixture.root), role_for_path=_role_names)

    def test_promoted_cross_uid_git_is_verified_only_on_root_projection(self):
        before = workflow._tree_inventory(self.fixture.root)
        with self.assertRaises((subprocess.CalledProcessError, PermissionError)):
            workflow.verify_workspace(self.fixture.root)
        with self.snapshot() as snapshot:
            self.assertEqual(snapshot_owner_uid(snapshot, snapshot.root, self.fixture.root), 0)
            self.assertEqual((snapshot.root / "state/binding.json").stat().st_uid, 0)
            summary = workflow.verify_workspace(snapshot.root, require_quiescent=True,
                original_root=self.fixture.root, _snapshot=snapshot)
            self.assertEqual(summary["workflow_state"], "promoted")
            closure = verify_complete_inventory(snapshot.root)
            self.assertEqual(closure["binding"]["base_sha"], summary["accepted_sha"])
            self.assertEqual(len(closure["artifacts"]), 1)
            self.assertTrue((snapshot.root / "attempts/repair-value-attempt-1/reservation.json").is_file())
            self.assertFalse((snapshot.root / "state/.workflow.lock").exists())
        self.assertEqual(before, workflow._tree_inventory(self.fixture.root))
        with self.assertRaises(PermissionError):
            snapshot_owner_uid(snapshot, snapshot.root, self.fixture.root)

    def test_executable_git_configuration_rejected_before_git(self):
        config = self.fixture.root / "canonical/.git/config"
        with config.open("a") as stream:
            stream.write("\n[filter \"unsafe\"]\n clean = touch /tmp/should-never-run\n")
        with patch("control_plane.project_integrator.subprocess.run", side_effect=AssertionError("Git ran before metadata admission")):
            with self.assertRaises((PermissionError, ValueError)):
                with self.snapshot():
                    self.fail("unsafe config admitted")

    def test_projection_tamper_and_forged_override_rejected(self):
        with self.snapshot() as snapshot:
            modified = snapshot.root / "canonical/value.py"
            modified.write_text("VALUE = 3\n")
            with self.assertRaises(PermissionError):
                snapshot_owner_uid(snapshot, snapshot.root, self.fixture.root)
            forged = replace(snapshot, _token=object())
            with self.assertRaises(PermissionError):
                snapshot_owner_uid(forged, forged.root, self.fixture.root)

    def test_packed_replacement_history_rejected_before_git(self):
        refs = self.fixture.root / "canonical/.git/packed-refs"
        refs.write_text("a" * 40 + " refs/replace/" + "b" * 40 + "\n")
        os.chown(refs, 61112, 61112)
        with patch("control_plane.project_integrator.subprocess.run", side_effect=AssertionError("Git ran before metadata admission")):
            with self.assertRaisesRegex(PermissionError, "replacement refs"):
                with self.snapshot():
                    self.fail("replacement history admitted")

    def test_subprocess_has_closed_environment_and_fixed_action(self):
        with self.snapshot() as snapshot:
            trusted = self.fixture.directory / "trusted-code"
            (trusted / "control_plane").mkdir(parents=True)
            script = trusted / "control_plane/_verification_snapshot.py"
            script.write_text("# fixed verifier fixture\n")
            self.fixture.profile.paths["trusted_code_root"] = str(trusted)
            with patch("control_plane.execution_profile.load_execution_profile", return_value=self.fixture.profile), \
                 patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "malicious", "PYTHONPATH": "/untrusted"}), \
                 patch("control_plane._verification_snapshot._run_verifier", return_value=SimpleNamespace(returncode=0, stdout=b'{"verified":true}', stderr=b"")) as run:
                self.assertEqual(verify_backup_snapshot(snapshot), {"verified": True})
            arguments, options = run.call_args
            self.assertEqual(arguments[0][1:3], ["-I", "-B"])
            self.assertEqual(arguments[0][3:], [str(script), "--verify-backup", str(snapshot.manifest)])
            self.assertNotIn("GIT_CONFIG_COUNT", options["environment"])
            self.assertNotIn("PYTHONPATH", options["environment"])
            self.assertEqual(options["environment"]["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(options["environment"]["GIT_NO_REPLACE_OBJECTS"], "1")
            self.fixture.profile.tools["git"].path = "/usr/bin/false"
            with patch("control_plane.execution_profile.load_execution_profile", return_value=self.fixture.profile), \
                 patch("control_plane._verification_snapshot._run_verifier") as run:
                with self.assertRaisesRegex(PermissionError, "pinned system git"):
                    verify_backup_snapshot(snapshot)
                run.assert_not_called()

    def test_verifier_output_and_child_lifetime_are_bounded(self):
        with self.assertRaisesRegex(PermissionError, "output exceeds"):
            _run_verifier([sys.executable, "-I", "-c", "import os; os.write(2,b'x'*1000000)"],
                environment={"PATH": os.defpath}, cwd=self.fixture.directory, max_output_bytes=128)
        marker = self.fixture.directory / "child-pid"
        code = "import os,time,pathlib; pid=os.fork(); pathlib.Path(%r).write_text(str(pid)) if pid else None; time.sleep(10)" % str(marker)
        with self.assertRaises(TimeoutError):
            _run_verifier([sys.executable, "-I", "-c", code], environment={"PATH": os.defpath},
                cwd=self.fixture.directory, timeout_seconds=0.3)
        child = int(marker.read_text())
        statfile = Path("/proc") / str(child) / "stat"
        self.assertTrue(not statfile.exists() or statfile.read_text().split()[2] == "Z")


if __name__ == "__main__":
    unittest.main()
