"""Verification may read a trusted other owner but cannot publish through its API."""

import grp
import hashlib
import os
import stat
import unittest
from contextlib import ExitStack
from unittest.mock import patch

from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_integrator import ProjectIntegrator
from tests import test_project_coordinator as coordinator_fixtures
from tests import test_project_integrator as integrator_fixtures


def inventory(root):
    """Include bytes, ownership, modes and mtimes, but exclude read access times."""
    result = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = path.lstat()
        content = (
            os.readlink(path) if path.is_symlink()
            else hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file()
            else None
        )
        result[str(path.relative_to(root))] = (
            metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid,
            metadata.st_size, metadata.st_mtime_ns, content,
        )
    return result


class IntegratorVerificationViewTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integrator_fixtures.ProjectIntegratorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def view(self, owner_uid=None, **kwargs):
        fixture = self.fixture
        return ProjectIntegrator(
            fixture.repo, fixture.binding, fixture.public_key, fixture.rubric,
            fixture.accepted_ref,
            verification_owner_uid=os.geteuid() if owner_uid is None else owner_uid,
            **kwargs,
        )

    def test_invalid_owner_uid_rejected_before_configuration_reads(self):
        for invalid in (True, False, -1, 2**32 - 1, 2**32, 1.0, "0", [], {}):
            with self.subTest(uid=invalid), patch(
                "control_plane.project_integrator.sha256_file",
                side_effect=AssertionError("configuration was read"),
            ), self.assertRaisesRegex(ValueError, "integer UID"):
                self.view(invalid)

    def test_current_owner_view_reads_without_changing_any_inventory(self):
        fixture = self.fixture
        # Force status to need an index refresh unless optional locks are disabled.
        source = fixture.repo / "src/base.txt"
        metadata = source.stat()
        os.utime(source, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
        before = inventory(fixture.root)
        view = self.view()
        self.assertEqual(view.verification_owner_uid, os.geteuid())
        self.assertEqual(view._read_binding()[0]["base_sha"], fixture.base)
        view.assert_verification_configuration()
        self.assertIsNone(view._ref_sha(view.accepted_ref))
        view._validate_candidate(fixture.candidate, fixture.base, ["src/"])
        self.assertTrue(view._workspace_is_clean())
        self.assertEqual(inventory(fixture.root), before)

    def test_real_other_owner_binding_requires_exact_trusted_uid(self):
        fixture = self.fixture
        original = fixture.binding.stat()
        other_uid = 65534 if original.st_uid != 65534 else 65533
        try:
            os.chown(fixture.binding, other_uid, original.st_gid)
        except PermissionError:
            self.skipTest("changing fixture ownership requires chown authority")
        self.addCleanup(os.chown, fixture.binding, original.st_uid, original.st_gid)
        self.assertNotEqual(fixture.binding.stat().st_uid, os.geteuid())
        before = inventory(fixture.root)
        with self.assertRaisesRegex(PermissionError, "owner or mode"):
            fixture.integrator._read_binding()
        with self.assertRaisesRegex(PermissionError, "owner or mode"):
            self.view()._read_binding()
        value, observed = self.view(other_uid)._read_binding()
        self.assertEqual(observed.st_uid, other_uid)
        self.assertEqual(value, {"repo": "codex_opensource", "base_sha": fixture.base})
        self.assertEqual(inventory(fixture.root), before)

    def test_verification_keeps_mode_group_symlink_and_schema_checks(self):
        fixture = self.fixture
        for mode in (0o400, 0o444, 0o640, 0o660):
            with self.subTest(mode=oct(mode)):
                fixture.binding.chmod(mode)
                with self.assertRaisesRegex(PermissionError, "owner or mode"):
                    self.view()._read_binding()
        fixture.binding.chmod(0o440)
        other_group = next(
            (entry for entry in grp.getgrall() if entry.gr_gid != fixture.binding.stat().st_gid),
            None,
        )
        if other_group is not None:
            with self.assertRaisesRegex(PermissionError, "configured worker group"):
                self.view(expected_binding_group=other_group.gr_name)._read_binding()
        saved = fixture.binding.read_bytes()
        fixture.binding.chmod(0o640)
        fixture.binding.write_text('{"repo":"codex_opensource","base_sha":"bad"}')
        fixture.binding.chmod(0o440)
        with self.assertRaisesRegex(PermissionError, "values are invalid"):
            self.view()._read_binding()
        fixture.binding.chmod(0o640)
        fixture.binding.write_bytes(saved)
        fixture.binding.chmod(0o440)
        target = fixture.binding.with_name("real-binding.json")
        fixture.binding.rename(target)
        fixture.binding.symlink_to(target)
        with self.assertRaisesRegex(PermissionError, "non-symlink"):
            self.view()._read_binding()

    def test_every_mutator_rejects_before_locks_validation_hooks_or_effects(self):
        fixture = self.fixture
        view = self.view()
        metadata = fixture.binding.stat()
        before = inventory(fixture.root)

        def forbidden(*args, **kwargs):
            self.fail("verification-only mutation reached an effect or validation")

        def binding_lock():
            with view._binding_lock():
                self.fail("verification-only binding lock was entered")

        operations = {
            "binding lock": binding_lock,
            "import": lambda: view.import_bundle(None),
            "promote": lambda: view.promote(
                fixture.candidate, fixture.base, ["src/"], {}, fixture.evidence,
                expected_task_id="node-1", expected_contract_id="eval-node-1-v1",
                fault_hook=forbidden,
            ),
            "locked promote": lambda: view._promote_locked(
                fixture.candidate, fixture.base, ["src/"], {}, fixture.evidence,
                forbidden,
            ),
            "promotion started": lambda: view.promotion_started(fixture.candidate),
            "reconcile promotion": lambda: view.reconcile_promotion(
                fixture.base, fixture.candidate,
            ),
            "rollback": lambda: view.rollback(fixture.candidate, fault_hook=forbidden),
            "reconcile rollback": lambda: view.reconcile_rollback(
                fixture.candidate, fault_hook=forbidden,
            ),
            "ensure bound publication": view.ensure_bound_publication,
            "atomic binding write": lambda: view._atomic_write(
                {"repo": "codex_opensource", "base_sha": fixture.candidate}, metadata,
            ),
            "update ref": lambda: view._update_ref(
                fixture.accepted_ref, fixture.candidate, None,
            ),
            "publication ensure": lambda: view.publications.ensure(
                fixture.repo, "codex_opensource", fixture.candidate, metadata,
            ),
        }
        with ExitStack() as stack:
            for name in (
                "os.open", "tempfile.mkstemp", "subprocess.run",
                "verify_evaluation", "sha256_file",
                "ProjectIntegrator._read_binding",
                "ProjectIntegrator.assert_verification_configuration",
            ):
                stack.enter_context(patch(
                    "control_plane.project_integrator." + name, side_effect=forbidden,
                ))
            # A caller replacing this convenience method cannot bypass the guard.
            view._require_mutation_authority = lambda: None
            for name, operation in operations.items():
                with self.subTest(operation=name), self.assertRaisesRegex(
                    PermissionError, "verification-only",
                ):
                    operation()
        self.assertEqual(inventory(fixture.root), before)
        self.assertFalse(fixture.binding.with_suffix(".json.lock").exists())

    def test_default_integrator_preserves_mutating_same_uid_authority(self):
        fixture = self.fixture
        self.assertIsNone(fixture.integrator.verification_owner_uid)
        self.assertEqual(fixture.integrator._read_binding()[1].st_uid, os.geteuid())
        result = fixture.promote()
        self.assertEqual(result["base_sha"], fixture.candidate)
        self.assertEqual(fixture.integrator.rollback(fixture.candidate)["base_sha"], fixture.base)


class CoordinatorVerificationViewTests(unittest.TestCase):
    def test_complete_external_verification_preserves_other_owner_workspace(self):
        fixture = coordinator_fixtures.ProjectCoordinatorTests()
        fixture.setUp()
        self.addCleanup(fixture.tearDown)
        fixture.integrate()
        owner_uid = fixture.binding.stat().st_uid
        if os.geteuid() == 0:
            owner_uid = 65534
            os.chown(fixture.binding, owner_uid, fixture.binding.stat().st_gid)
        before = inventory(fixture.root)
        integrator = ProjectIntegrator(
            fixture.repo, fixture.binding, fixture.public_key, fixture.rubric,
            fixture.accepted_ref, verification_owner_uid=owner_uid,
        )
        coordinator = ProjectCoordinator(
            fixture.graph, integrator, fixture.evidence_root, "oss",
        )
        coordinator.assert_publication_integrity()
        ProjectCoordinator.require_external_integrity(
            fixture.graph, {"opensource": coordinator},
        )
        binding, _ = integrator._read_binding()
        pin = integrator.publications.pin_binding(fixture.binding)
        self.assertEqual(pin.base_sha, binding["base_sha"])
        self.assertTrue(stat.S_ISDIR(pin.path.stat().st_mode))
        self.assertEqual(inventory(fixture.root), before)


class CoordinatorMutationDenialTests(unittest.TestCase):
    def setUp(self):
        self.fixture = coordinator_fixtures.ProjectCoordinatorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        fixture = self.fixture
        integrator = ProjectIntegrator(
            fixture.repo, fixture.binding, fixture.public_key, fixture.rubric,
            fixture.accepted_ref, verification_owner_uid=os.geteuid(),
        )
        self.coordinator = ProjectCoordinator(
            fixture.graph, integrator, fixture.evidence_root, "oss",
        )

    def assert_denied_without_effects(self, operations):
        fixture = self.fixture
        before_rows = fixture.integrity_snapshot()
        before_files = inventory(fixture.root)
        statements = []
        fixture.graph.connection.set_trace_callback(statements.append)
        try:
            for name, operation in operations.items():
                with self.subTest(operation=name), self.assertRaisesRegex(
                    PermissionError, "verification-only",
                ):
                    operation()
        finally:
            fixture.graph.connection.set_trace_callback(None)
        self.assertEqual(statements, [], "mutation guard must precede any database access")
        self.assertFalse(fixture.graph.connection.in_transaction)
        self.assertEqual(fixture.integrity_snapshot(), before_rows)
        self.assertEqual(inventory(fixture.root), before_files)

    def test_integration_denies_before_creating_prepared_attempt(self):
        fixture = self.fixture
        self.assertEqual(fixture.graph.connection.execute(
            "SELECT count(*) FROM integration_attempts",
        ).fetchone()[0], 0)
        self.assert_denied_without_effects({
            "integrate": lambda: self.coordinator.integrate(
                "attempt-1", "node-1", fixture.outcome_id, fixture.artifact_id,
                fixture.manifest, "oss", fixture.evidence_root,
            ),
        })
        self.assertEqual(fixture.graph.connection.execute(
            "SELECT count(*) FROM integration_attempts",
        ).fetchone()[0], 0)
        self.assertEqual(fixture.graph.connection.execute(
            "SELECT count(*) FROM publication_journal",
        ).fetchone()[0], 0)

    def test_rollback_denies_before_appending_prepared_journal(self):
        fixture = self.fixture
        fixture.integrate()
        self.assert_denied_without_effects({
            "rollback": lambda: self.coordinator.rollback(
                "rollback-1", "node-1", "attempt-1", 1,
            ),
        })
        self.assertEqual(fixture.graph.connection.execute(
            "SELECT count(*) FROM publication_journal WHERE operation_kind='ROLLBACK'",
        ).fetchone()[0], 0)

    def test_reconcile_denies_prepared_promotion_before_recovery(self):
        fixture = self.fixture
        with self.assertRaises(coordinator_fixtures.SimulatedCrash):
            fixture.integrate(crash_hook=fixture.crash_at("after_ref"))
        self.assertEqual(fixture.coordinator._attempt_by_id("attempt-1")["status"], "PREPARED")
        self.assert_denied_without_effects({
            "reconcile PREPARED": lambda: self.coordinator.reconcile(
                "node-1", fixture.candidate,
            ),
        })

    def test_reconcile_denies_binding_updated_before_graph_finalization(self):
        fixture = self.fixture
        with self.assertRaises(coordinator_fixtures.SimulatedCrash):
            fixture.integrate(crash_hook=fixture.crash_at("after_graph"))
        self.assertEqual(
            fixture.coordinator._attempt_by_id("attempt-1")["status"], "BINDING_UPDATED",
        )
        self.assert_denied_without_effects({
            "reconcile BINDING_UPDATED": lambda: self.coordinator.reconcile(
                "node-1", fixture.candidate,
            ),
        })
        self.assertEqual(fixture.graph.get_node("node-1")["state"], "PASSED")

    def assert_rollback_recovery_denied(self, crash_point, expected_phase):
        fixture = self.fixture
        fixture.integrate()
        with self.assertRaises(coordinator_fixtures.SimulatedCrash):
            fixture.coordinator.rollback(
                "rollback-1", "node-1", "attempt-1", 1,
                fixture.crash_at(crash_point),
            )
        self.assertEqual(
            fixture.coordinator._journal_entries("rollback-1")[-1]["phase"], expected_phase,
        )
        self.assert_denied_without_effects({
            "reconcile rollback": lambda: self.coordinator.reconcile_rollback("rollback-1"),
            "rollback replay": lambda: self.coordinator.rollback(
                "rollback-1", "node-1", "attempt-1", 1,
            ),
        })

    def test_reconcile_rollback_denies_prepared_physical_recovery(self):
        self.assert_rollback_recovery_denied("after_rollback_prepare", "PREPARED")

    def test_reconcile_rollback_denies_published_graph_finalization(self):
        self.assert_rollback_recovery_denied("after_rollback_published", "PUBLISHED")

    def test_private_mutation_seams_reject_before_connection_or_graph_access(self):
        fixture = self.fixture
        coordinator = self.coordinator

        def writer_lock():
            with coordinator._publication_writer_lock():
                self.fail("verification-only coordinator acquired a writer lock")

        operations = {
            "writer lock": writer_lock,
            "prepare attempt": lambda: coordinator._prepare_attempt(
                "attempt-1", "node-1", fixture.base, fixture.candidate,
                "a" * 64, "b" * 64, fixture.artifact_id, fixture.outcome_id,
                0, "opensource",
            ),
            "finalize promotion": lambda: coordinator._finalize_promotion(
                "attempt-1", "node-1", fixture.candidate,
            ),
            "complete promotion": lambda: coordinator._complete_locked(
                {}, {}, fixture.candidate, None,
            ),
            "record promotion": lambda: coordinator._record_promotion_locked({}, {}, {}, {}),
            "complete rollback": lambda: coordinator._complete_rollback({}, None),
            "append journal": lambda: coordinator._append_journal_locked(
                operation_id="rollback-1", operation_kind="ROLLBACK", phase="PREPARED",
                project="opensource", goal_id="goal-1", node_id="node-1",
                integration_attempt_id="attempt-1", version_before=1, version_after=2,
                from_sha=fixture.candidate, to_sha=fixture.base,
                from_generation=fixture.candidate, to_generation=fixture.base,
                affected_graph_sha256="c" * 64, affected_graph_json="{}",
            ),
        }
        coordinator.integrator._require_mutation_authority = lambda: None
        with patch(
            "control_plane.sqlite_runtime.connect_database",
            side_effect=AssertionError("verification-only coordinator opened a writer"),
        ):
            self.assert_denied_without_effects(operations)


if __name__ == "__main__":
    unittest.main()
