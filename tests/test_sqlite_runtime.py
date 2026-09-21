import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from control_plane.graph_bootstrap import apply_database
from control_plane.graph_schema import SchemaError
from control_plane.project_graph import ProjectGraph
from control_plane.sqlite_runtime import (
    FIXED_VERSION, SQLiteRuntimeError, UNPATCHED_LIBRARY_SHA256,
    connect_database, maintain_journal_mode, runtime_identity, runtime_status,
    sqlite_doctor, validate_attestation,
    verify_database_policy,
)
from control_plane.task_controller import TaskController


FIXED_ATTESTATION = os.environ.get("CODEX_GRAPHER_SQLITE_ATTESTATION")


class SQLiteRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "graph.sqlite"

    def boot(self):
        apply_database(self.database)
        connection = connect_database(self.database)
        self.addCleanup(connection.close)
        return connection

    def subprocess_open(self):
        return subprocess.run([
            sys.executable, "-c",
            "from pathlib import Path; from control_plane.sqlite_runtime import connect_database; "
            "import sys; c=connect_database(Path(sys.argv[1])); c.close()",
            str(self.database),
        ], capture_output=True, text=True, timeout=15)

    def test_real_default_graph_controller_and_auxiliary_durability(self):
        connection = self.boot()
        graph = ProjectGraph(self.database)
        self.addCleanup(graph.connection.close)
        auxiliary = connect_database(self.database, owner=graph.connection.owner)
        self.addCleanup(auxiliary.close)
        controller = TaskController(self.root / "controller.sqlite")
        self.addCleanup(controller.connection.close)
        self.assertIs(connection.owner, auxiliary.owner)
        for current in (connection, graph.connection, auxiliary, controller.connection):
            self.assertEqual(current.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(current.execute("PRAGMA synchronous").fetchone()[0], 3)
            self.assertEqual(current.runtime_report["support_status"], "SUPPORTED_AVOIDANCE")
        self.assertFalse(Path(f"{self.database}-wal").exists())

    def test_process_owner_remains_until_last_auxiliary_connection_closes(self):
        connection = self.boot()
        auxiliary = connect_database(self.database, owner=connection.owner)
        self.addCleanup(auxiliary.close)
        self.assertNotEqual(self.subprocess_open().returncode, 0)
        connection.close()
        denied = self.subprocess_open()
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("another process owner", denied.stderr)
        auxiliary.close()
        self.assertEqual(self.subprocess_open().returncode, 0)

    def test_auxiliary_different_database_owner_rejects(self):
        connection = self.boot()
        other = self.root / "other.sqlite"
        apply_database(other)
        before = other.read_bytes()
        with self.assertRaisesRegex(SQLiteRuntimeError, "different owner"):
            connect_database(other, owner=connection.owner)
        self.assertEqual(before, other.read_bytes())

    def test_unknown_runtime_and_known_unpatched_status_are_distinct(self):
        identity = runtime_identity()
        self.assertTrue(identity["library_mapping_verified"])
        self.assertEqual(len(identity["library_sha256"]), 64)
        with patch("control_plane.sqlite_runtime.runtime_identity", return_value={
            **identity, "library_sha256": "0" * 64,
        }):
            self.assertEqual(runtime_status()["patch_status"], "UNPROVEN")
        with patch("control_plane.sqlite_runtime.runtime_identity", return_value={
            **identity, "library_sha256": UNPATCHED_LIBRARY_SHA256,
        }):
            self.assertEqual(runtime_status()["patch_status"], "UNPATCHED")

    def test_wal_without_fixed_attestation_rejects_before_creating_database(self):
        with self.assertRaisesRegex(SQLiteRuntimeError, "verified fixed"):
            connect_database(self.database, create=True, profile="wal-full")
        self.assertFalse(self.database.exists())
        self.assertFalse(Path(f"{self.database}.owner.lock").exists())

    def test_existing_wal_rejects_without_touching_database_or_sidecars(self):
        apply_database(self.database)
        raw = sqlite3.connect(self.database)
        self.addCleanup(raw.close)
        raw.execute("PRAGMA journal_mode=WAL")
        raw.execute("CREATE TABLE sentinel(value)")
        raw.execute("INSERT INTO sentinel VALUES ('preserve')")
        raw.commit()
        paths = [self.database, Path(f"{self.database}-wal"), Path(f"{self.database}-shm")]
        before = {path: path.read_bytes() for path in paths}
        with self.assertRaisesRegex(SchemaError, "offline maintenance"):
            ProjectGraph(self.database)
        with self.assertRaisesRegex(SQLiteRuntimeError, "offline maintenance"):
            TaskController(self.database)
        self.assertEqual(before, {path: path.read_bytes() for path in paths})

    def test_graph_apply_rejects_existing_wal_without_sidecars(self):
        apply_database(self.database)
        with sqlite3.connect(self.database) as raw:
            raw.execute("PRAGMA journal_mode=WAL")
        raw.close()
        before = self.database.read_bytes()
        with self.assertRaisesRegex(SchemaError, "offline maintenance"):
            apply_database(self.database)
        self.assertEqual(before, self.database.read_bytes())

    def test_fake_and_duplicate_attestations_cannot_enable_wal(self):
        attestation = self.root / "attestation.json"
        for content in ('{"fixed":true}', '{"schema_version":1,"schema_version":1}'):
            attestation.write_text(content)
            self.assertNotEqual(runtime_status(attestation)["patch_status"], "FIXED")
            with self.assertRaises(SQLiteRuntimeError):
                validate_attestation(attestation)
            with self.assertRaises(SQLiteRuntimeError):
                connect_database(self.database, create=True, profile="wal-full", attestation=attestation)
        self.assertFalse(self.database.exists())

    def test_doctor_never_bootstraps_or_claims_unobserved_connection_support(self):
        before = list(self.root.iterdir())
        result = sqlite_doctor(database=self.database)
        self.assertEqual(result["support_status"], "UNPROVEN")
        self.assertFalse(result["owner_lock"])
        self.assertEqual(before, list(self.root.iterdir()))
        connection = self.boot()
        before = self.database.read_bytes()
        result = sqlite_doctor(database=self.database)
        self.assertEqual(result["journal_mode"], "delete")
        self.assertTrue(result["owner_lock"])
        self.assertIsNone(result["synchronous"])
        self.assertEqual(before, self.database.read_bytes())

    def test_database_symlink_hardlink_and_lock_symlink_reject(self):
        original = self.root / "original.sqlite"
        apply_database(original)
        self.database.symlink_to(original)
        with self.assertRaises(SQLiteRuntimeError):
            connect_database(self.database)
        self.database.unlink()
        os.link(original, self.database)
        with self.assertRaises(SQLiteRuntimeError):
            connect_database(self.database)
        self.database.unlink()
        self.database.write_bytes(original.read_bytes())
        Path(f"{self.database}.owner.lock").symlink_to(self.root / "unrelated")
        with self.assertRaises(OSError):
            connect_database(self.database)
        self.assertFalse((self.root / "unrelated").exists())

    def test_lock_replacement_and_inherited_fork_connection_fail_closed(self):
        connection = self.boot()
        cursor = connection.execute("SELECT 1")
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            denials = 0
            for action in (lambda: connection.execute("SELECT 1"), lambda: cursor.execute("SELECT 1"),
                           lambda: connection.__exit__(None, None, None), connection.close):
                try:
                    action()
                except SQLiteRuntimeError:
                    denials += 1
            os.write(write_fd, str(denials).encode())
            os.close(write_fd)
            os._exit(0)
        os.close(write_fd)
        result = os.read(read_fd, 100)
        os.close(read_fd)
        os.waitpid(pid, 0)
        self.assertEqual(result, b"4")
        lock = Path(f"{self.database}.owner.lock")
        lock.rename(self.root / "old-owner-lock")
        lock.touch(mode=0o600)
        with self.assertRaisesRegex(SQLiteRuntimeError, "replaced"):
            connection.execute("SELECT 1")
        with self.assertRaisesRegex(SQLiteRuntimeError, "replaced"):
            cursor.execute("SELECT 1")
        with self.assertRaisesRegex(SQLiteRuntimeError, "replaced"):
            connection.__exit__(None, None, None)

    def test_empty_runtime_database_is_not_initialized(self):
        self.database.touch()
        with self.assertRaisesRegex(SQLiteRuntimeError, "explicitly bootstrapped"):
            connect_database(self.database)
        self.assertEqual(self.database.read_bytes(), b"")

    def test_explicit_bootstrap_requires_closed_default_graph_owner(self):
        connection = self.boot()
        before = self.database.read_bytes()
        with self.assertRaisesRegex(SchemaError, "writers closed"):
            apply_database(self.database)
        self.assertEqual(before, self.database.read_bytes())
        connection.close()
        apply_database(self.database)

    def test_unfixed_maintenance_leaves_source_and_backup_destination_unchanged(self):
        apply_database(self.database)
        before = self.database.read_bytes()
        with self.assertRaisesRegex(SQLiteRuntimeError, "verified fixed"):
            maintain_journal_mode(self.database, self.root / "backup", attestation=self.root / "absent")
        self.assertEqual(before, self.database.read_bytes())
        self.assertFalse((self.root / "backup").exists())


@unittest.skipUnless(FIXED_ATTESTATION, "requires explicit provisioned fixed runtime and attestation")
class FixedSQLiteRuntimeTests(SQLiteRuntimeTests):
    def test_actual_fixed_library_source_and_wal_full_with_reopen(self):
        runtime = validate_attestation(FIXED_ATTESTATION)
        self.assertEqual(runtime["version"], FIXED_VERSION)
        apply_database(self.database, sqlite_profile="wal-full", sqlite_attestation=FIXED_ATTESTATION)
        graph = ProjectGraph(self.database, sqlite_profile="wal-full", sqlite_attestation=FIXED_ATTESTATION)
        self.addCleanup(graph.connection.close)
        graph.create_goal("fixed-runtime", "opensource", "durable WAL", "a" * 40)
        self.assertEqual(graph.connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(graph.connection.execute("PRAGMA synchronous").fetchone()[0], 2)
        self.assertEqual(graph.connection.runtime_report["support_status"], "SUPPORTED_FIXED_WAL")
        graph.connection.close()
        before = self.database.read_bytes()
        verified = verify_database_policy(self.database, profile="wal-full", attestation=FIXED_ATTESTATION)
        self.assertEqual(verified["journal_mode"], "wal")
        self.assertEqual(before, self.database.read_bytes())
        reopened = ProjectGraph(self.database, sqlite_profile="wal-full", sqlite_attestation=FIXED_ATTESTATION)
        self.addCleanup(reopened.connection.close)
        self.assertEqual(reopened.connection.execute("SELECT count(*) FROM goals").fetchone()[0], 1)

    def test_legacy_wal_denied_until_explicit_backed_up_maintenance(self):
        apply_database(self.database)
        raw = sqlite3.connect(self.database)
        raw.execute("PRAGMA journal_mode=WAL")
        raw.close()
        before = self.database.read_bytes()
        with self.assertRaisesRegex(SQLiteRuntimeError, "offline maintenance"):
            connect_database(self.database, profile="wal-full", attestation=FIXED_ATTESTATION)
        self.assertEqual(before, self.database.read_bytes())
        backup = self.root / "backup"
        result = maintain_journal_mode(self.database, backup, target_profile="wal-full", attestation=FIXED_ATTESTATION)
        self.assertEqual(result["status"], "MAINTAINED")
        self.assertEqual((backup / self.database.name).read_bytes(), before)
        connection = connect_database(self.database, profile="wal-full", attestation=FIXED_ATTESTATION)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
        connection.close()
        second = self.root / "backup-delete"
        maintain_journal_mode(self.database, second, target_profile="delete-extra", attestation=FIXED_ATTESTATION)
        default = connect_database(self.database)
        self.addCleanup(default.close)
        self.assertEqual(default.execute("PRAGMA journal_mode").fetchone()[0], "delete")

    def test_fixed_runtime_does_not_silently_change_delete_to_wal(self):
        apply_database(self.database)
        before = self.database.read_bytes()
        with self.assertRaisesRegex(SQLiteRuntimeError, "offline maintenance"):
            connect_database(self.database, profile="wal-full", attestation=FIXED_ATTESTATION)
        self.assertEqual(before, self.database.read_bytes())

    def test_changed_attestation_and_receipt_reject(self):
        runtime = validate_attestation(FIXED_ATTESTATION)
        apply_database(self.database, sqlite_profile="wal-full", sqlite_attestation=FIXED_ATTESTATION)
        receipt = Path(f"{self.database}.sqlite-runtime.json")
        value = json.loads(receipt.read_text())
        value["runtime"]["library_sha256"] = "0" * 64
        receipt.write_text(json.dumps(value))
        before = self.database.read_bytes()
        with self.assertRaisesRegex(SQLiteRuntimeError, "binding mismatch"):
            connect_database(self.database, profile="wal-full", attestation=FIXED_ATTESTATION)
        self.assertEqual(before, self.database.read_bytes())
        changed = self.root / "attestation.json"
        data = json.loads(Path(FIXED_ATTESTATION).read_text())
        data["library_sha256"] = "f" * 64
        changed.write_text(json.dumps(data))
        with self.assertRaisesRegex(SQLiteRuntimeError, "mismatch"):
            validate_attestation(changed)

    def test_maintenance_refuses_live_owner(self):
        connection = self.boot()
        with self.assertRaisesRegex(SQLiteRuntimeError, "writers closed"):
            maintain_journal_mode(self.database, self.root / "backup", attestation=FIXED_ATTESTATION)
        self.assertFalse((self.root / "backup").exists())

    def test_maintenance_excludes_new_same_process_owner_during_backup(self):
        import shutil
        apply_database(self.database)
        copy = shutil.copyfileobj
        denied = []
        def try_open_then_copy(*args, **kwargs):
            with self.assertRaisesRegex(SQLiteRuntimeError, "exclusive offline maintenance"):
                connect_database(self.database)
            denied.append(True)
            return copy(*args, **kwargs)
        with patch("control_plane.sqlite_runtime.shutil.copyfileobj", side_effect=try_open_then_copy):
            maintain_journal_mode(self.database, self.root / "backup", attestation=FIXED_ATTESTATION)
        self.assertTrue(denied)

    def test_verified_offline_copy_can_check_original_receipt_without_runtime_relocation(self):
        import shutil
        apply_database(self.database, sqlite_profile="wal-full", sqlite_attestation=FIXED_ATTESTATION)
        copy = self.root / "copy.sqlite"
        receipt = Path(f"{self.database}.sqlite-runtime.json")
        copy_receipt = Path(f"{copy}.sqlite-runtime.json")
        shutil.copyfile(self.database, copy)
        shutil.copyfile(receipt, copy_receipt)
        # Receipt validation on an archive does not depend on original storage.
        self.database.rename(self.root / "original-offline.sqlite")
        before = (copy.read_bytes(), copy_receipt.read_bytes())
        with self.assertRaisesRegex(SQLiteRuntimeError, "binding mismatch"):
            verify_database_policy(copy, profile="wal-full", attestation=FIXED_ATTESTATION)
        verified = verify_database_policy(copy, profile="wal-full", attestation=FIXED_ATTESTATION,
                                          original_database=self.database)
        self.assertEqual(verified["receipt_bound_database"], str(self.database))
        with self.assertRaisesRegex(SQLiteRuntimeError, "binding mismatch"):
            connect_database(copy, profile="wal-full", attestation=FIXED_ATTESTATION)
        self.assertEqual(before, (copy.read_bytes(), copy_receipt.read_bytes()))


if __name__ == "__main__":
    unittest.main()
