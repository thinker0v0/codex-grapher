"""Public diagnostics must fail closed without changing their source database."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from control_plane.cli import main, offline_database_guard, read_only_graph
from control_plane.graph_bootstrap import apply_database
from control_plane.graph_schema import SchemaError
from control_plane.project_graph import ProjectGraph


class CLITest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "graph.sqlite"
        apply_database(self.database)
        graph = ProjectGraph(self.database)
        graph.create_goal("goal", "opensource", "Example", "a" * 40)
        spec = {"timeout_seconds": 60, "evaluator_contract_id": "cli-fixture"}
        graph.add_node("build", "goal", "BUILD", spec, ["src/"])
        graph.add_node("follow", "goal", "BUILD", spec, ["test/"], dependencies=["build"])
        graph.create_goal("other", "business", "Other project", "b" * 40)
        graph.add_node("other-node", "other", "BUILD", spec, ["other/"])
        graph.connection.close()
        self.database.chmod(0o640)

    def invoke(self, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = main(list(arguments))
        return code, output.getvalue(), errors.getvalue()

    def inventory(self):
        return {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode,
                         p.stat().st_mtime_ns) for p in self.root.iterdir() if p.is_file()}

    def test_status_reports_versions_blockers_and_scoped_integrity_without_mutation(self):
        before = self.inventory()
        code, output, errors = self.invoke("status", "--database", str(self.database), "--project", "opensource", "--json")
        self.assertEqual((code, errors), (0, ""))
        value = json.loads(output)
        nodes = {item["node_id"]: item for item in value["nodes"]}
        self.assertEqual(set(nodes), {"build", "follow"})
        self.assertEqual(nodes["build"]["version"], 0)
        self.assertEqual(nodes["follow"]["blockers"], ["dependency build is READY"])
        self.assertEqual(value["database_integrity"], "VERIFIED")
        self.assertEqual(value["external_evidence"], "UNPROVEN")
        self.assertEqual(value["release_verdict"], "NOT_PASS")
        self.assertNotIn("lease_id", output)
        self.assertEqual(self.inventory(), before)

    def test_events_and_inspect_use_exact_ids_and_event_hashes(self):
        before = self.inventory()
        code, output, _ = self.invoke("events", "--database", str(self.database), "--node", "follow", "--json")
        events = json.loads(output)["events"]
        self.assertEqual(code, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["node_id"], "follow")
        self.assertEqual(len(events[0]["event_hash"]), 64)
        code, output, _ = self.invoke("inspect", "follow", "--database", str(self.database), "--json")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)["nodes"][0]["event_head"]["event_hash"], events[0]["event_hash"])
        self.assertEqual(self.inventory(), before)

    def test_missing_database_is_not_created(self):
        missing = self.root / "missing.sqlite"
        before = self.inventory()
        code, output, errors = self.invoke("status", "--database", str(missing), "--json")
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output)["ok"])
        self.assertEqual(errors, "")
        self.assertFalse(missing.exists())
        self.assertEqual(self.inventory(), before)

    def test_missing_node_and_cross_project_lookup_fail_cleanly(self):
        for node, project in (("missing", "opensource"), ("other-node", "opensource")):
            code, output, errors = self.invoke("inspect", node, "--database", str(self.database), "--project", project, "--json")
            self.assertEqual(code, 2)
            self.assertIn("does not exist", json.loads(output)["error"])
            self.assertNotIn("Traceback", output + errors)

    def test_live_wal_is_refused_without_ignoring_uncheckpointed_state(self):
        # A foreign/legacy WAL writer is deliberately constructed outside the
        # product's new runtime admission policy, solely to test read-only denial.
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE legacy_uncheckpointed(value TEXT)")
            connection.commit()
            self.assertTrue(Path(str(self.database) + "-wal").exists())
            before = self.inventory()
            code, output, errors = self.invoke("status", "--database", str(self.database), "--json")
            self.assertEqual(code, 2)
            message = json.loads(output)["error"]
            self.assertIn("offline", message)
            self.assertIn("--socket", message)
            self.assertIn("Do not delete sidecars", message)
            self.assertEqual(errors, "")
            self.assertEqual(self.inventory(), before)
        finally:
            connection.close()

    def test_live_delete_owner_is_refused_even_without_journal_sidecars(self):
        graph = ProjectGraph(self.database)
        try:
            self.assertEqual(graph.connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertFalse(Path(str(self.database) + "-journal").exists())
            before = self.inventory()
            code, output, errors = self.invoke("status", "--database", str(self.database), "--json")
            self.assertEqual(code, 2)
            self.assertIn("offline owner", json.loads(output)["error"])
            self.assertEqual(errors, "")
            self.assertEqual(self.inventory(), before)
        finally:
            graph.connection.close()

    def test_nested_offline_verification_holds_the_same_exclusive_guard(self):
        before = self.inventory()
        with offline_database_guard(self.database):
            with read_only_graph(self.database) as graph:
                self.assertEqual(graph.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            # Finishing a nested verifier must not release the outer barrier.
            with self.assertRaisesRegex(SchemaError, "owner|owned"):
                ProjectGraph(self.database)
        self.assertEqual(self.inventory(), before)
        graph = ProjectGraph(self.database)
        graph.connection.close()

    @unittest.skipUnless(hasattr(os, "fork"), "requires POSIX fork")
    def test_inherited_offline_guard_cannot_authorize_a_child(self):
        before = self.inventory()
        with offline_database_guard(self.database):
            child = os.fork()
            if child == 0:
                try:
                    with offline_database_guard(self.database):
                        os._exit(10)
                except ValueError as error:
                    os._exit(0 if "identity changed" in str(error) else 11)
                except BaseException:
                    os._exit(12)
            _, status = os.waitpid(child, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)
            with read_only_graph(self.database) as graph:
                self.assertEqual(graph.connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        self.assertEqual(self.inventory(), before)

    def test_dangling_sidecar_symlink_also_refuses_snapshot(self):
        Path(str(self.database) + "-wal").symlink_to(self.root / "missing-wal")
        code, output, _ = self.invoke("status", "--database", str(self.database), "--json")
        self.assertEqual(code, 2)
        self.assertIn("offline", json.loads(output)["error"])

    def test_database_symlink_is_rejected(self):
        link = self.root / "link.sqlite"
        link.symlink_to(self.database)
        code, output, _ = self.invoke("status", "--database", str(link), "--json")
        self.assertEqual(code, 2)
        self.assertIn("symlink", json.loads(output)["error"])

    def test_hard_link_cannot_hide_live_wal_state(self):
        alias = self.root / "alias.sqlite"
        os.link(self.database, alias)
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE legacy_wal_only(value TEXT)")
            connection.commit()
            self.assertTrue(Path(str(self.database) + "-wal").exists())
            self.assertFalse(Path(str(alias) + "-wal").exists())
            before = self.inventory()
            code, output, _ = self.invoke("status", "--database", str(alias), "--json")
            self.assertEqual(code, 2)
            self.assertIn("hard link", json.loads(output)["error"])
            self.assertEqual(self.inventory(), before)
        finally:
            connection.close()

    def test_corrupt_event_chain_fails_without_repair(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE events SET event_hash=? WHERE node_id='build'", ("f" * 64,))
        connection.close()
        before = self.inventory()
        code, output, errors = self.invoke("events", "--database", str(self.database), "--json")
        self.assertEqual(code, 2)
        self.assertIn("integrity", json.loads(output)["error"])
        self.assertNotIn("Traceback", output + errors)
        self.assertEqual(self.inventory(), before)

    def test_foreign_or_old_schema_and_non_sqlite_fail_without_migration(self):
        for contents in (b"not a database", b""):
            with self.subTest(contents=contents):
                self.database.write_bytes(contents)
                before = self.inventory()
                code, output, errors = self.invoke("status", "--database", str(self.database), "--json")
                self.assertEqual(code, 2)
                self.assertFalse(json.loads(output)["ok"])
                self.assertNotIn("Traceback", output + errors)
                self.assertEqual(self.inventory(), before)

    def test_future_schema_is_rejected_without_migration(self):
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA user_version=99")
        connection.close()
        before = self.inventory()
        code, output, _ = self.invoke("status", "--database", str(self.database), "--json")
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output)["ok"])
        self.assertEqual(self.inventory(), before)

    def test_task_policy_must_be_explicit_and_exact_for_diagnostics(self):
        from control_plane.evaluation_policy import load_task_policy
        policy_path = self.root / "policy.json"
        policy_value = {"schema_version": 1, "name": "CLI task", "threshold": 95,
                        "sections": {"acceptance": {"minimum": 95, "maximum": 100}},
                        "mandatory_gates": ["tests"]}
        policy_path.write_text(json.dumps(policy_value))
        policy = load_task_policy(policy_path)
        self.database = self.root / "policy.sqlite"
        apply_database(self.database)
        graph = ProjectGraph(self.database, rubric_sha256=policy.sha256, evaluation_policy=policy)
        graph.create_goal("goal", "opensource", "Policy task", "a" * 40)
        graph.add_node("task-policy-node", "goal", "BUILD", {"evaluator_contract_id": "policy-fixture"}, ["policy/"])
        graph.connection.close()
        before = self.inventory()
        code, output, _ = self.invoke("status", "--database", str(self.database), "--json")
        self.assertEqual(code, 2)
        self.assertIn("policy", json.loads(output)["error"])
        code, output, _ = self.invoke("status", "--database", str(self.database), "--policy", str(policy_path), "--json")
        self.assertEqual(code, 0, output)
        self.assertEqual(json.loads(output)["external_evidence"], "UNPROVEN")
        self.assertEqual(self.inventory(), before)
        policy_value["name"] = "Another policy"
        policy_path.write_text(json.dumps(policy_value))
        before = self.inventory()
        code, output, _ = self.invoke("status", "--database", str(self.database), "--policy", str(policy_path), "--json")
        self.assertEqual(code, 2)
        self.assertIn("policy", json.loads(output)["error"])
        self.assertEqual(self.inventory(), before)

    def test_socket_denial_is_an_error_and_live_response_is_scoped(self):
        with patch("control_plane.graph_client.request", return_value={"ok": False, "error": "role denied"}):
            code, output, _ = self.invoke("status", "--socket", str(self.root / "service.sock"), "--json")
        self.assertEqual(code, 2)
        self.assertIn("denied", json.loads(output)["error"])
        with patch("control_plane.graph_client.request", return_value={"ok": True, "result": [{"node_id": "live"}]}):
            code, output, _ = self.invoke("status", "--socket", str(self.root / "service.sock"), "--json")
        self.assertEqual(code, 0)
        value = json.loads(output)
        self.assertEqual(value["source"], "authorized_graph_service")
        self.assertEqual(value["status"], [{"node_id": "live"}])
        self.assertEqual(value["release_verdict"], "NOT_PASS")

    def test_snapshot_cleanup_even_if_consumer_raises(self):
        before = self.inventory()
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with read_only_graph(self.database) as graph:
                snapshot = graph.database
                self.assertNotEqual(snapshot, self.database)
                raise RuntimeError("consumer")
        self.assertFalse(snapshot.exists())
        self.assertEqual(self.inventory(), before)

    def test_doctor_reports_missing_prerequisites_without_installation(self):
        before = self.inventory()
        with patch.dict(os.environ, {"PATH": ""}):
            code, output, errors = self.invoke("doctor", "--json")
        self.assertEqual(code, 1)
        self.assertEqual(errors, "")
        value = json.loads(output)
        checks = {item["name"]: item for item in value["checks"]}
        self.assertFalse(checks["git"]["ok"])
        self.assertFalse(checks["openssl_ed25519"]["ok"])
        self.assertIn("no installation", value["scope"])
        self.assertEqual(self.inventory(), before)

    def test_recovery_requires_explicit_persistent_workspace(self):
        code, output, errors = self.invoke("demo", "--operation", "recover", "--json")
        self.assertEqual(code, 2)
        self.assertIn("--workspace", json.loads(output)["error"])
        self.assertEqual(errors, "")

    def test_backup_and_restore_emit_the_completed_operation_receipts(self):
        from control_plane.workspace_backup import BackupReceipt, RestoreReceipt
        archive = self.root / "backup.tar"
        profile = self.root / "profile.json"
        backup = BackupReceipt(str(archive), "a" * 64, 2048, str(self.root), "workspace", 12)
        restored = RestoreReceipt(str(self.root), "workspace", "a" * 64, True,
                                  {"integrity_verified": True}, "provision matching signer separately")
        with patch("control_plane.cli._workflow_kind", return_value="repository-workflow"), \
             patch("control_plane.workspace_backup.backup_workspace", return_value=backup) as operation:
            code, output, errors = self.invoke("backup", "--workspace", str(self.root),
                                                "--output", str(archive), "--json")
        operation.assert_called_once_with(self.root, archive)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(output), backup.to_dict())
        with patch("control_plane.workspace_backup.restore_workspace", return_value=restored) as operation:
            code, output, errors = self.invoke("restore", "--backup", str(archive),
                                                "--workspace", str(self.root), "--profile", str(profile), "--json")
        operation.assert_called_once_with(archive, self.root, profile)
        self.assertEqual((code, errors), (0, ""))
        self.assertEqual(json.loads(output), restored.to_dict())

    def test_text_error_has_no_traceback(self):
        code, output, errors = self.invoke("status", "--database", str(self.root / "missing"))
        self.assertEqual((code, output), (2, ""))
        self.assertTrue(errors.startswith("codex-grapher:"))
        self.assertNotIn("Traceback", errors)


if __name__ == "__main__":
    unittest.main()
