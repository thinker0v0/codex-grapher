"""Canonical Git durability precedes binding and graph publication completion.

These are ordering/fault fixtures, not a claim of power-loss durability. Compose
the signed coordinator fixture without inheriting its unrelated test suite.
"""

from contextlib import contextmanager
import errno
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from control_plane.project_integrator import ProjectIntegrator
from tests import test_project_coordinator as coordinator_fixtures


@unittest.skipUnless(Path("/proc/self/fd").is_dir(), "descriptor observations require Linux procfs")
class GitDurabilityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = coordinator_fixtures.ProjectCoordinatorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.addCleanup(self.fixture.graph.connection.close)
        self.integrator = self.fixture.coordinator.integrator
        self.metadata = self.fixture.repo / ".git"
        self.candidate_ref = self.metadata / "refs/ai-ops/candidates/node-1" / self.fixture.candidate
        self.accepted_ref = self.metadata / self.fixture.accepted_ref
        self.rollback_ref = self.metadata / self.integrator._rollback_ref(self.fixture.candidate)

    @staticmethod
    def descriptor_path(descriptor):
        return Path(os.readlink(f"/proc/self/fd/{descriptor}"))

    @contextmanager
    def fsync_trace(self, *, reject=None):
        original = os.fsync
        seen = []

        def observed(descriptor):
            path = self.descriptor_path(descriptor)
            seen.append(path)
            if path == reject:
                raise OSError(errno.EIO, "injected canonical Git fsync failure", str(path))
            return original(descriptor)

        with patch("control_plane.project_integrator.os.fsync", side_effect=observed):
            yield seen

    def binding_sha(self):
        return json.loads(self.fixture.binding.read_bytes())["base_sha"]

    def assert_promotion_unfinished(self):
        attempt = self.fixture.graph.connection.execute(
            "SELECT status FROM integration_attempts WHERE attempt_id='attempt-1'"
        ).fetchone()
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt["status"], "PREPARED")
        self.assertEqual(self.fixture.graph.get_node("node-1")["state"], "PASSED")
        self.assertEqual(self.fixture.graph.get_node("node-2")["state"], "BLOCKED")
        self.assertEqual(self.fixture.graph.connection.execute(
            "SELECT count(*) FROM publication_journal "
            "WHERE operation_id='attempt-1' AND phase='COMPLETED'"
        ).fetchone()[0], 0)

    def assert_ref_failure_blocks_promotion(self, target):
        binding_before = self.fixture.binding.read_bytes()
        with self.fsync_trace(reject=target) as seen:
            with self.assertRaises(OSError):
                self.fixture.integrate()
        self.assertIn(target, seen, "the failure must hit the actual canonical ref descriptor")
        self.assertEqual(self.fixture.binding.read_bytes(), binding_before)
        self.assert_promotion_unfinished()
        return seen

    def test_candidate_ref_fsync_failure_cannot_publish_binding_or_complete_graph(self):
        self.assert_ref_failure_blocks_promotion(self.candidate_ref)

    def test_rollback_ref_fsync_failure_cannot_publish_binding_or_complete_graph(self):
        self.assert_ref_failure_blocks_promotion(self.rollback_ref)

    def test_accepted_ref_fsync_failure_cannot_publish_binding_or_complete_graph(self):
        self.assert_ref_failure_blocks_promotion(self.accepted_ref)

    def test_ref_directory_fsync_failure_cannot_publish_binding_or_complete_graph(self):
        seen = self.assert_ref_failure_blocks_promotion(self.candidate_ref.parent)
        self.assertLess(seen.index(self.candidate_ref), seen.index(self.candidate_ref.parent))

    def test_packed_object_fsync_failure_cannot_publish_binding_or_complete_graph(self):
        subprocess.run(
            ["git", "-C", self.fixture.repo, "repack", "-ad"],
            check=True, capture_output=True,
        )
        packs = list((self.metadata / "objects/pack").glob("*.pack"))
        self.assertEqual(len(packs), 1)
        self.assert_ref_failure_blocks_promotion(packs[0])

    def assert_canonical_closure_flushed(self, seen):
        candidate_object = self.metadata / "objects" / self.fixture.candidate[:2] / self.fixture.candidate[2:]
        required = {self.candidate_ref, self.rollback_ref, self.accepted_ref, candidate_object}
        for leaf in tuple(required):
            ancestor = leaf.parent
            while ancestor != self.fixture.repo.parent:
                required.add(ancestor)
                ancestor = ancestor.parent
        self.assertTrue(required <= set(seen), f"canonical flush omitted: {required - set(seen)}")
        # Every final traversal must flush children before their directory entry.
        last = {path: index for index, path in enumerate(seen)}
        for path in required - {self.fixture.repo}:
            self.assertLess(last[path], last[path.parent], f"parent flushed before child: {path}")

    def test_refs_objects_and_ancestors_are_flushed_before_hook_and_binding_replace(self):
        original_replace = os.replace
        checkpoints = []

        with self.fsync_trace() as seen:
            def observe_replace(source, destination, *args, **kwargs):
                if Path(destination) == self.fixture.binding:
                    self.assert_canonical_closure_flushed(seen)
                    checkpoints.append("binding")
                return original_replace(source, destination, *args, **kwargs)

            def hook(point):
                if point == "after_ref":
                    self.assert_canonical_closure_flushed(seen)
                    self.assertEqual(self.binding_sha(), self.fixture.base)
                    checkpoints.append("after_ref")

            with patch("control_plane.project_integrator.os.replace", side_effect=observe_replace):
                result = self.fixture.integrate(crash_hook=hook)
        self.assertEqual(checkpoints, ["after_ref", "binding"])
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(self.binding_sha(), self.fixture.candidate)

    def test_rollback_predecessor_is_durable_before_accepted_ref_advances(self):
        original_update = self.integrator._update_ref
        observed_advance = []
        with self.fsync_trace() as seen:
            def observe_update(reference, new_sha, old_sha):
                if reference == self.fixture.accepted_ref and new_sha == self.fixture.candidate:
                    self.assert_canonical_closure_flushed(seen)
                    self.assertEqual(self.binding_sha(), self.fixture.base)
                    observed_advance.append(new_sha)
                return original_update(reference, new_sha, old_sha)

            with patch.object(self.integrator, "_update_ref", side_effect=observe_update):
                result = self.fixture.integrate()
        self.assertEqual(observed_advance, [self.fixture.candidate])
        self.assertEqual(result["status"], "COMPLETED")

    def test_promotion_recovery_with_matching_binding_still_requires_git_durability(self):
        with self.assertRaises(coordinator_fixtures.SimulatedCrash):
            self.fixture.integrate(crash_hook=self.fixture.crash_at("after_binding"))
        binding_before = self.fixture.binding.read_bytes()
        self.assertEqual(self.binding_sha(), self.fixture.candidate)
        with self.fsync_trace(reject=self.accepted_ref) as seen, patch.object(
            self.integrator, "_atomic_write", side_effect=AssertionError("equal binding must not be rewritten")
        ):
            with self.assertRaises(OSError):
                self.fixture.coordinator.reconcile("node-1", self.fixture.candidate)
        self.assertIn(self.accepted_ref, seen)
        self.assertEqual(self.fixture.binding.read_bytes(), binding_before)
        self.assert_promotion_unfinished()
        self.assertEqual(self.fixture.coordinator.reconcile("node-1", self.fixture.candidate)["status"], "COMPLETED")

    def test_rollback_recovery_with_matching_binding_still_requires_git_durability(self):
        self.fixture.integrate()
        with self.assertRaises(coordinator_fixtures.SimulatedCrash):
            self.fixture.coordinator.rollback(
                "rollback-1", "node-1", "attempt-1", 1,
                self.fixture.crash_at("after_rollback_binding"),
            )
        binding_before = self.fixture.binding.read_bytes()
        self.assertEqual(self.binding_sha(), self.fixture.base)
        with self.fsync_trace(reject=self.accepted_ref) as seen, patch.object(
            self.integrator, "_atomic_write", side_effect=AssertionError("equal binding must not be rewritten")
        ):
            with self.assertRaises(OSError):
                self.fixture.coordinator.reconcile_rollback("rollback-1")
        self.assertIn(self.accepted_ref, seen)
        self.assertEqual(self.fixture.binding.read_bytes(), binding_before)
        phases = self.fixture.graph.connection.execute(
            "SELECT phase FROM publication_journal WHERE operation_id='rollback-1' ORDER BY sequence"
        ).fetchall()
        self.assertEqual([row[0] for row in phases], ["PREPARED"])
        self.assertEqual(self.fixture.coordinator.publication_head()["sha"], self.fixture.candidate)
        self.assertEqual(self.fixture.coordinator.reconcile_rollback("rollback-1")["status"], "COMPLETED")

    def test_initial_bound_publication_flushes_canonical_worktree_as_well_as_git(self):
        source = self.fixture.repo / "src/base.txt"
        with self.fsync_trace() as seen:
            publication = self.integrator.ensure_bound_publication()
        for path in (source, source.parent, self.metadata / "HEAD", self.metadata, self.fixture.repo):
            self.assertIn(path, seen)
        self.assertLess(seen.index(source), seen.index(source.parent))
        self.assertLess(seen.index(source.parent), seen.index(self.fixture.repo))
        self.assertEqual(publication.base_sha, self.fixture.base)
        self.assertEqual(self.binding_sha(), self.fixture.base)

    def test_initial_canonical_worktree_flush_error_prevents_success(self):
        source = self.fixture.repo / "src/base.txt"
        binding_before = self.fixture.binding.read_bytes()
        with self.fsync_trace(reject=source) as seen:
            with self.assertRaises(OSError):
                self.integrator.ensure_bound_publication()
        self.assertIn(source, seen)
        self.assertEqual(self.fixture.binding.read_bytes(), binding_before)

    def test_metadata_symlink_is_rejected_without_flushing_its_target(self):
        outside = self.fixture.root / "outside-ref"
        outside.write_bytes(b"external bytes must remain untouched\n")
        entry = self.metadata / "refs/unsafe-link"
        entry.symlink_to(outside)
        with self.fsync_trace() as seen:
            with self.assertRaises((OSError, PermissionError, ValueError)):
                self.integrator._durable_canonical()
        self.assertNotIn(outside, seen)
        self.assertEqual(outside.read_bytes(), b"external bytes must remain untouched\n")

    def test_linked_git_directory_is_rejected_without_flushing_external_metadata(self):
        outside = self.fixture.root / "external-git"
        self.metadata.rename(outside)
        self.metadata.symlink_to(outside, target_is_directory=True)
        with self.fsync_trace() as seen:
            with self.assertRaises((OSError, PermissionError, ValueError)):
                self.integrator._durable_canonical()
        self.assertFalse(any(path == outside or outside in path.parents for path in seen))

    def test_special_metadata_entry_is_rejected_before_a_blocking_open(self):
        entry = self.metadata / "refs/unsafe-fifo"
        os.mkfifo(entry)
        original_open = os.open

        def guarded_open(path, flags, *args, **kwargs):
            if os.fspath(path) == entry.name or os.fspath(path) == str(entry):
                self.assertTrue(flags & os.O_NONBLOCK, "special entry must not be opened with blocking flags")
            return original_open(path, flags, *args, **kwargs)

        with patch("control_plane.project_integrator.os.open", side_effect=guarded_open):
            with self.assertRaises((OSError, PermissionError, ValueError)):
                self.integrator._durable_canonical()

    def test_verification_only_integrator_cannot_flush_canonical_state(self):
        fixture = self.fixture
        view = ProjectIntegrator(
            fixture.repo, fixture.binding, fixture.public_key, fixture.rubric, fixture.accepted_ref,
            verification_owner_uid=os.geteuid(),
        )
        with patch("control_plane.project_integrator.os.fsync", side_effect=AssertionError("verification performed fsync")):
            with self.assertRaises(PermissionError):
                view._durable_canonical(include_worktree=True)

    @unittest.skipUnless(os.geteuid() == 0, "foreign-owner fixture requires chown authority")
    def test_foreign_owned_metadata_is_rejected(self):
        path = self.metadata / "HEAD"
        original = path.stat()
        os.chown(path, 61112, original.st_gid)
        self.addCleanup(os.chown, path, original.st_uid, original.st_gid)
        with self.fsync_trace() as seen:
            with self.assertRaises((OSError, PermissionError, ValueError)):
                self.integrator._durable_canonical()
        self.assertNotIn(path, seen)


if __name__ == "__main__":
    unittest.main()
