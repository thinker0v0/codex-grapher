import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from control_plane.graph_bootstrap import apply_database, inspect_database
from control_plane.graph_schema import (
    APPLICATION_ID,
    BUZZ_DDL,
    BUZZ_INGRESS_DDL,
    CORE_DDL,
    CURRENT_DDL,
    INTEGRATION_DDL,
    LEGACY_INTEGRATION_DDL,
    SCHEMA_VERSION,
    SchemaError,
    V1_INTEGRATION_DDL,
    V2_CORE_DDL,
    V2_EVIDENCE_DDL,
    V2_INTEGRATION_DDL,
    V2_PUBLICATION_DDL,
    V3_INTEGRATION_DDL,
    V3_EVIDENCE_DDL,
    V4_EVIDENCE_DDL,
    PUBLICATION_DDL,
    ensure_current_schema,
    inspect_schema,
)
from control_plane.project_graph import ProjectGraph


SHA = "a" * 40

V2_REPOSITORY_DDL = (
    *V2_CORE_DDL,
    V2_INTEGRATION_DDL,
    *BUZZ_DDL,
    BUZZ_INGRESS_DDL,
    *V2_EVIDENCE_DDL,
    *V2_PUBLICATION_DDL,
)

V3_REPOSITORY_DDL = (
    *CORE_DDL,
    V3_INTEGRATION_DDL,
    *BUZZ_DDL,
    BUZZ_INGRESS_DDL,
    *V3_EVIDENCE_DDL,
    *PUBLICATION_DDL,
)

V4_REPOSITORY_DDL = (
    *CORE_DDL,
    V3_INTEGRATION_DDL,
    *BUZZ_DDL,
    BUZZ_INGRESS_DDL,
    *V4_EVIDENCE_DDL,
    *PUBLICATION_DDL,
)

MIGRATION_PREDECESSORS = {
    "v0": (V2_CORE_DDL, 0, 0, False),
    "v1": (
        (*V2_CORE_DDL, V1_INTEGRATION_DDL, *BUZZ_DDL),
        APPLICATION_ID, 1, False,
    ),
    "v2": (V2_REPOSITORY_DDL, APPLICATION_ID, 2, False),
    "v3": (V3_REPOSITORY_DDL, APPLICATION_ID, 3, True),
    "v4": (V4_REPOSITORY_DDL, APPLICATION_ID, 4, True),
}

CURRENT_TABLES = {
    "goals",
    "nodes",
    "dependencies",
    "events",
    "evaluation_ledger",
    "integration_attempts",
    "buzz_threads",
    "buzz_audit",
    "buzz_ingress_responses",
    "evidence_artifacts",
    "evaluation_claims",
    "evaluation_outcomes",
    "publication_heads",
    "publication_journal_tail",
    "publication_journal",
}


def digest(value):
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class GraphSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def database(self, name="graph.sqlite"):
        return self.root / name

    def legacy(self, path, statements=V2_CORE_DDL, application_id=0, user_version=0):
        connection = sqlite3.connect(path)
        for statement in statements:
            connection.execute(statement)
        connection.execute(f"PRAGMA application_id={application_id}")
        connection.execute(f"PRAGMA user_version={user_version}")
        connection.commit()
        return connection

    def assert_rejected_without_mutation(self, path, reason=None):
        before = path.read_bytes()
        before_mtime = path.stat().st_mtime_ns
        plan = inspect_database(path)
        self.assertEqual(plan.action, "reject")
        if reason is not None:
            self.assertIn(reason, plan.reason)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mtime_ns, before_mtime)
        with self.assertRaises(SchemaError):
            apply_database(path)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mtime_ns, before_mtime)
        return plan

    def legacy_with_buzz_thread(
        self, path, predecessor, *, thread_project="opensource", goal_id="goal",
    ):
        statements, application_id, user_version, needs_tail = MIGRATION_PREDECESSORS[
            predecessor
        ]
        if predecessor == "v0":
            statements = (*statements, *BUZZ_DDL)
        connection = self.legacy(
            path, statements, application_id=application_id,
            user_version=user_version,
        )
        if needs_tail:
            connection.execute(
                "INSERT INTO publication_journal_tail VALUES(1,NULL,NULL)"
            )
        self.add_node(connection)
        connection.execute(
            "INSERT INTO buzz_threads(thread_id,sender_pubkey,project,goal_id) "
            "VALUES('thread','sender',?,?)",
            (thread_project, goal_id),
        )
        connection.commit()
        connection.close()

    def add_node(self, connection, state="READY"):
        connection.execute(
            "INSERT INTO goals(goal_id,project,objective,accepted_sha,state,idempotency_key) "
            "VALUES('goal','opensource','fixture',?,'ACTIVE','goal')", (SHA,),
        )
        connection.execute(
            "INSERT INTO nodes(node_id,goal_id,kind,spec_json,spec_hash,write_set_json,state,version,base_sha) "
            "VALUES('node','goal','BUILD','{}',?,'[\"src/\"]',?,0,?)",
            (digest({}), state, SHA),
        )
        payload = digest({})
        event_hash = digest({
            "node": "node", "version": 0, "old": None, "new": state,
            "reason": "fixture", "payload": payload, "previous": None,
        })
        connection.execute(
            "INSERT INTO events(node_id,version,old_state,new_state,reason,payload_hash,previous_hash,event_hash) "
            "VALUES('node',0,NULL,?,'fixture',?,NULL,?)", (state, payload, event_hash),
        )
        connection.commit()

    def legacy_with_history(
        self, path, predecessor, events, node_state, node_version,
        project="opensource",
    ):
        statements, application_id, user_version, needs_tail = MIGRATION_PREDECESSORS[
            predecessor
        ]
        connection = self.legacy(
            path, statements, application_id=application_id,
            user_version=user_version,
        )
        if needs_tail:
            connection.execute(
                "INSERT INTO publication_journal_tail VALUES(1,NULL,NULL)"
            )
        connection.execute(
            "INSERT INTO goals(goal_id,project,objective,accepted_sha,state,idempotency_key) "
            "VALUES('goal',?,'fixture',?,'ACTIVE','goal')", (project, SHA),
        )
        connection.execute(
            "INSERT INTO nodes(node_id,goal_id,kind,spec_json,spec_hash,write_set_json,"
            "state,version,base_sha) VALUES('node','goal','BUILD','{}',?,"
            "'[\"src/\"]',?,?,?)",
            (digest({}), node_state, node_version, SHA),
        )
        previous = None
        for sequence, (version, old_state, new_state) in enumerate(events):
            reason = f"fixture-{sequence}"
            payload = digest({"sequence": sequence})
            event_hash = digest({
                "node": "node", "version": version, "old": old_state,
                "new": new_state, "reason": reason, "payload": payload,
                "previous": previous,
            })
            connection.execute(
                "INSERT INTO events(node_id,version,old_state,new_state,reason,"
                "payload_hash,previous_hash,event_hash) VALUES('node',?,?,?,?,?,?,?)",
                (
                    version, old_state, new_state, reason, payload, previous,
                    event_hash,
                ),
            )
            previous = event_hash
        connection.commit()
        connection.close()

    def test_missing_database_dry_run_is_read_only_then_apply_is_idempotent(self):
        path = self.database()
        plan = inspect_database(path)
        self.assertEqual((plan.status, plan.action), ("empty", "create"))
        self.assertFalse(path.exists())

        first = apply_database(path)
        self.assertTrue(first.changed)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        second = apply_database(path)
        self.assertFalse(second.changed)
        connection = sqlite3.connect(path)
        try:
            self.assertEqual(connection.execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(inspect_schema(connection).action, "none")
        finally:
            connection.close()

    def test_read_only_dry_run_does_not_change_known_legacy_database(self):
        path = self.database()
        connection = self.legacy(path)
        self.add_node(connection)
        connection.close()
        before = path.read_bytes()
        before_mtime = path.stat().st_mtime_ns

        plan = inspect_database(path)

        self.assertEqual((plan.status, plan.action, plan.legacy_variant),
                         ("legacy", "migrate", "graph-core"))
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mtime_ns, before_mtime)

    def test_read_only_dry_run_rejects_online_or_uncheckpointed_sidecars(self):
        path = self.database()
        connection = self.legacy(path)
        connection.close()
        wal = Path(f"{path}-wal")
        wal.write_bytes(b"synthetic-not-a-real-wal")
        before = wal.read_bytes()
        with self.assertRaisesRegex(SchemaError, "offline database"):
            inspect_database(path)
        with self.assertRaisesRegex(SchemaError, "offline database"):
            apply_database(path)
        self.assertEqual(wal.read_bytes(), before)

    def test_exact_core_fixture_migrates_without_losing_active_rows(self):
        path = self.database()
        connection = self.legacy(path)
        self.add_node(connection)
        connection.close()

        migrated = apply_database(path)

        self.assertTrue(migrated.changed)
        connection = sqlite3.connect(path)
        try:
            self.assertEqual(connection.execute("SELECT state FROM nodes WHERE node_id='node'").fetchone()[0], "READY")
            self.assertEqual(
                {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )},
                CURRENT_TABLES,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT singleton,last_sequence,last_hash FROM publication_journal_tail"
                ).fetchone(),
                (1, None, None),
            )
            self.assertEqual(inspect_schema(connection).status, "current")
        finally:
            connection.close()

    def test_pre_manifest_and_nullable_manifest_empty_journals_are_exactly_migrated(self):
        for suffix, alter in (("old", False), ("nullable", True)):
            with self.subTest(suffix=suffix):
                path = self.database(f"{suffix}.sqlite")
                connection = self.legacy(
                    path, (*V2_CORE_DDL, LEGACY_INTEGRATION_DDL, *BUZZ_DDL),
                )
                if alter:
                    connection.execute("ALTER TABLE integration_attempts ADD COLUMN manifest_hash TEXT")
                connection.commit()
                connection.close()
                self.assertTrue(apply_database(path).changed)
                connection = sqlite3.connect(path)
                try:
                    columns = connection.execute("PRAGMA table_info(integration_attempts)").fetchall()
                    manifest = next(row for row in columns if row[1] == "manifest_hash")
                    self.assertEqual(manifest[3], 1)
                    self.assertEqual(inspect_schema(connection).status, "current")
                finally:
                    connection.close()

    def test_exact_repository_v1_migrates_clean_active_rows(self):
        path = self.database("repository-v1.sqlite")
        connection = self.legacy(
            path,
            (*V2_CORE_DDL, V1_INTEGRATION_DDL, *BUZZ_DDL),
            application_id=APPLICATION_ID,
            user_version=1,
        )
        self.add_node(connection, "READY")
        connection.close()

        plan = inspect_database(path)
        self.assertEqual((plan.action, plan.legacy_variant), ("migrate", "repository-v1"))
        self.assertTrue(apply_database(path).changed)

        connection = sqlite3.connect(path)
        try:
            self.assertEqual(connection.execute("SELECT state FROM nodes").fetchone()[0], "READY")
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM integration_attempts").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM evaluation_outcomes").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(inspect_schema(connection).status, "current")
        finally:
            connection.close()

    def test_exact_repository_v2_migrates_clean_active_rows(self):
        path = self.database("repository-v2.sqlite")
        connection = self.legacy(
            path,
            V2_REPOSITORY_DDL,
            application_id=APPLICATION_ID,
            user_version=2,
        )
        self.add_node(connection, "READY")
        connection.close()

        plan = inspect_database(path)
        self.assertEqual((plan.action, plan.legacy_variant), ("migrate", "repository-v2"))
        self.assertTrue(apply_database(path).changed)

        connection = sqlite3.connect(path)
        try:
            self.assertEqual(connection.execute("SELECT state FROM nodes").fetchone()[0], "READY")
            self.assertIsNone(connection.execute("SELECT active_artifact_id FROM nodes").fetchone()[0])
            self.assertEqual(
                {row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )},
                CURRENT_TABLES,
            )
            self.assertEqual(inspect_schema(connection).status, "current")
        finally:
            connection.close()

    def test_exact_repository_v3_migrates_only_offline_and_adds_claim_heartbeat(self):
        path = self.database("repository-v3.sqlite")
        connection = self.legacy(
            path, V3_REPOSITORY_DDL,
            application_id=APPLICATION_ID, user_version=3,
        )
        connection.execute(
            "INSERT INTO publication_journal_tail VALUES(1,NULL,NULL)"
        )
        self.add_node(connection, "READY")
        connection.close()
        before = path.read_bytes()
        plan = inspect_database(path)
        self.assertEqual((plan.action, plan.legacy_variant), ("migrate", "repository-v3"))
        self.assertEqual(path.read_bytes(), before)
        with self.assertRaisesRegex(SchemaError, "refuses implicit graph migration"):
            ProjectGraph(path)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(apply_database(path).changed)
        connection = sqlite3.connect(path)
        try:
            columns = {
                row[1]: row for row in connection.execute(
                    "PRAGMA table_info(evaluation_claims)"
                )
            }
            self.assertIn("heartbeat_at", columns)
            self.assertEqual(columns["heartbeat_at"][3], 1)
            self.assertEqual(inspect_schema(connection).status, "current")
        finally:
            connection.close()

    def test_exact_repository_v4_migrates_to_bound_promotion_snapshots(self):
        path = self.database("repository-v4.sqlite")
        connection = self.legacy(
            path, V4_REPOSITORY_DDL,
            application_id=APPLICATION_ID, user_version=4,
        )
        connection.execute(
            "INSERT INTO publication_journal_tail VALUES(1,NULL,NULL)"
        )
        self.add_node(connection, "READY")
        connection.close()

        plan = inspect_database(path)
        self.assertEqual((plan.action, plan.legacy_variant), ("migrate", "repository-v4"))
        self.assertTrue(apply_database(path).changed)
        connection = sqlite3.connect(path)
        try:
            columns = {
                row[1]: row for row in connection.execute(
                    "PRAGMA table_info(integration_attempts)"
                )
            }
            self.assertEqual(columns["affected_graph_sha256"][3], 1)
            self.assertEqual(columns["affected_graph_json"][3], 1)
            self.assertIsNotNone(connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type='trigger' "
                "AND name='evaluation_outcomes_no_replace'"
            ).fetchone())
            self.assertEqual(inspect_schema(connection).status, "current")
        finally:
            connection.close()

    def test_legacy_publication_tail_must_be_the_exact_empty_anchor(self):
        for suffix, tail in (("missing", None), ("non-null", (1, 99, "f" * 64))):
            with self.subTest(tail=suffix):
                path = self.database(f"repository-v3-tail-{suffix}.sqlite")
                connection = self.legacy(
                    path, V3_REPOSITORY_DDL,
                    application_id=APPLICATION_ID, user_version=3,
                )
                if tail is not None:
                    connection.execute(
                        "INSERT INTO publication_journal_tail VALUES(?,?,?)", tail,
                    )
                self.add_node(connection, "READY")
                connection.close()
                self.assert_rejected_without_mutation(path, "exact empty anchor")

    def test_all_extension_tables_migrate_reopen_and_remain_constructor_independent(self):
        from control_plane.buzz_router import BuzzRouter
        from control_plane.project_coordinator import ProjectCoordinator
        from control_plane.project_integrator import ProjectIntegrator, sha256_file
        from tests.evaluation_helpers import generate_keypair

        path = self.database("repository-v1-extensions.sqlite")
        statements = (
            *V2_CORE_DDL, V2_INTEGRATION_DDL, *BUZZ_DDL, *V2_PUBLICATION_DDL,
            BUZZ_INGRESS_DDL,
        )
        connection = self.legacy(
            path,
            statements,
            application_id=APPLICATION_ID,
            user_version=1,
        )
        self.add_node(connection, "READY")
        connection.close()

        self.assertEqual(
            inspect_database(path).legacy_variant,
            "repository-v1-publication-buzz-ingress",
        )
        apply_database(path)
        _, public_key = generate_keypair(self.root)
        rubric = self.root / "rubric.md"
        rubric.write_text("frozen fixture rubric\n")
        graph = ProjectGraph(path, public_key, sha256_file(rubric))
        routing = self.root / "routing.json"
        routing.write_text("{}\n")
        BuzzRouter(graph, routing, {})
        integrator = ProjectIntegrator(
            self.root, self.root / "binding.json", public_key, rubric,
            "refs/ai-ops/accepted/opensource",
        )
        ProjectCoordinator(graph, integrator)
        self.assertEqual(inspect_schema(graph.connection).status, "current")
        self.assertEqual(
            {row[0] for row in graph.connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )},
            CURRENT_TABLES,
        )
        graph.connection.close()

        reopened = ProjectGraph(path)
        try:
            self.assertEqual(inspect_schema(reopened.connection).status, "current")
            expected_counts = {
                "buzz_ingress_responses": 0,
                "evidence_artifacts": 0,
                "evaluation_claims": 0,
                "evaluation_outcomes": 0,
                "publication_heads": 0,
                "publication_journal": 0,
                "publication_journal_tail": 1,
                "integration_attempts": 0,
            }
            for table, expected in expected_counts.items():
                with self.subTest(table=table):
                    self.assertEqual(
                        reopened.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                        expected,
                    )
        finally:
            reopened.connection.close()

    def test_legacy_sensitive_states_reject_without_mutation(self):
        for state in ("EVIDENCE_PENDING", "EVALUATING", "PASSED", "INTEGRATING", "INTEGRATED"):
            with self.subTest(state=state):
                path = self.database(f"{state}.sqlite")
                connection = self.legacy(path)
                self.add_node(connection, state)
                connection.close()
                self.assert_rejected_without_mutation(path, "requiring external evaluator")

    def test_legacy_unknown_states_reject_without_mutation(self):
        node_path = self.database("unknown-node-state.sqlite")
        connection = self.legacy(node_path)
        self.add_node(connection, "FUTURE_STATE")
        connection.close()
        self.assert_rejected_without_mutation(node_path, "unknown node states")

        goal_path = self.database("unknown-goal-state.sqlite")
        connection = self.legacy(goal_path)
        self.add_node(connection)
        connection.execute("UPDATE goals SET state='FUTURE_STATE' WHERE goal_id='goal'")
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(goal_path, "unknown goal states")

    def test_legacy_event_chain_defects_reject_without_mutation(self):
        defects = (
            ("bad-hash", "UPDATE events SET event_hash='broken'", "does not verify"),
            ("missing-head", "DELETE FROM events", "does not match its event-chain head"),
            ("wrong-head-version", "UPDATE nodes SET version=1", "does not match its event-chain head"),
        )
        for suffix, mutation, reason in defects:
            with self.subTest(defect=suffix):
                path = self.database(f"event-{suffix}.sqlite")
                connection = self.legacy(path)
                self.add_node(connection)
                connection.execute(mutation)
                connection.commit()
                connection.close()
                self.assert_rejected_without_mutation(path, reason)

    def test_v0_through_v4_semantically_invalid_rehashed_histories_reject_unchanged(self):
        defects = {
            "version-skip": (
                [(0, None, "READY"), (2, "READY", "LEASED")],
                "LEASED", 2, "not exactly 0..2",
            ),
            "non-null-genesis": (
                [(0, "BLOCKED", "READY")],
                "READY", 0, "non-NULL old state",
            ),
            "non-adjacent": (
                [(0, None, "READY"), (1, "BLOCKED", "READY")],
                "READY", 1, "not adjacent",
            ),
            "invalid-transition": (
                [(0, None, "READY"), (1, "READY", "RUNNING")],
                "RUNNING", 1, "transition",
            ),
            "final-disagreement": (
                [(0, None, "READY"), (1, "READY", "LEASED")],
                "READY", 1, "event-chain head",
            ),
        }
        for predecessor in MIGRATION_PREDECESSORS:
            for defect, (events, state, version, reason) in defects.items():
                with self.subTest(predecessor=predecessor, defect=defect):
                    path = self.database(f"{predecessor}-{defect}.sqlite")
                    self.legacy_with_history(
                        path, predecessor, events, state, version,
                    )
                    self.assert_rejected_without_mutation(path, reason)

    def test_v0_through_v4_valid_contiguous_histories_migrate_exactly(self):
        events = [
            (0, None, "READY"),
            (1, "READY", "LEASED"),
            (2, "LEASED", "RUNNING"),
            (3, "RUNNING", "READY"),
        ]
        for predecessor in MIGRATION_PREDECESSORS:
            with self.subTest(predecessor=predecessor):
                path = self.database(f"{predecessor}-valid-history.sqlite")
                self.legacy_with_history(
                    path, predecessor, events, "READY", 3,
                )
                before = path.read_bytes()
                self.assertEqual(inspect_database(path).action, "migrate")
                self.assertEqual(path.read_bytes(), before)
                self.assertTrue(apply_database(path).changed)
                connection = sqlite3.connect(path)
                try:
                    self.assertEqual(
                        connection.execute(
                            "SELECT state,version FROM nodes WHERE node_id='node'"
                        ).fetchone(),
                        ("READY", 3),
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT version,old_state,new_state FROM events "
                            "WHERE node_id='node' ORDER BY version"
                        ).fetchall(),
                        events,
                    )
                    self.assertEqual(inspect_schema(connection).status, "current")
                finally:
                    connection.close()

    def test_v0_through_v4_reject_goal_projects_outside_exact_routes_unchanged(self):
        for predecessor in MIGRATION_PREDECESSORS:
            with self.subTest(predecessor=predecessor):
                path = self.database(f"{predecessor}-fin-global.sqlite")
                self.legacy_with_history(
                    path, predecessor, [(0, None, "READY")], "READY", 0,
                    project="fin-global",
                )
                self.assert_rejected_without_mutation(path, "exact active route set")

    def test_v0_through_v4_buzz_threads_require_exact_existing_same_project_goal(self):
        defects = (
            ("orphan", "opensource", "missing-goal"),
            ("cross-project", "business", "goal"),
            ("unknown-route", "fin-global", "goal"),
        )
        for predecessor in MIGRATION_PREDECESSORS:
            for defect, project, goal_id in defects:
                with self.subTest(predecessor=predecessor, defect=defect):
                    path = self.database(f"{predecessor}-buzz-{defect}.sqlite")
                    self.legacy_with_buzz_thread(
                        path, predecessor, thread_project=project, goal_id=goal_id,
                    )
                    self.assert_rejected_without_mutation(
                        path, "contract-route same-project goal",
                    )

    def test_v0_through_v4_nonempty_buzz_threads_migrate_byte_exact_rows(self):
        expected = [("thread", "sender", "opensource", "goal")]
        for predecessor in MIGRATION_PREDECESSORS:
            with self.subTest(predecessor=predecessor):
                path = self.database(f"{predecessor}-buzz-valid.sqlite")
                self.legacy_with_buzz_thread(path, predecessor)
                before = path.read_bytes()
                before_mtime = path.stat().st_mtime_ns
                self.assertEqual(inspect_database(path).action, "migrate")
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(path.stat().st_mtime_ns, before_mtime)
                self.assertTrue(apply_database(path).changed)
                connection = sqlite3.connect(path)
                try:
                    self.assertEqual(
                        connection.execute(
                            "SELECT thread_id,sender_pubkey,project,goal_id "
                            "FROM buzz_threads ORDER BY thread_id"
                        ).fetchall(),
                        expected,
                    )
                    self.assertEqual(inspect_schema(connection).status, "current")
                finally:
                    connection.close()

    def test_v0_through_v4_reject_sensitive_event_history_unchanged(self):
        events = [
            (0, None, "READY"),
            (1, "READY", "LEASED"),
            (2, "LEASED", "RUNNING"),
            (3, "RUNNING", "EVIDENCE_PENDING"),
            (4, "EVIDENCE_PENDING", "READY"),
        ]
        for predecessor in MIGRATION_PREDECESSORS:
            with self.subTest(predecessor=predecessor):
                path = self.database(f"{predecessor}-sensitive-history.sqlite")
                self.legacy_with_history(
                    path, predecessor, events, "READY", 4,
                )
                self.assert_rejected_without_mutation(path, "event history")

    def test_v0_through_v4_duplicate_event_versions_are_structurally_rejected(self):
        for predecessor in MIGRATION_PREDECESSORS:
            with self.subTest(predecessor=predecessor):
                path = self.database(f"{predecessor}-duplicate.sqlite")
                statements, application_id, user_version, needs_tail = (
                    MIGRATION_PREDECESSORS[predecessor]
                )
                connection = self.legacy(
                    path, statements, application_id=application_id,
                    user_version=user_version,
                )
                if needs_tail:
                    connection.execute(
                        "INSERT INTO publication_journal_tail VALUES(1,NULL,NULL)"
                    )
                self.add_node(connection)
                before = path.read_bytes()
                payload = digest({"duplicate": True})
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "INSERT INTO events(node_id,version,old_state,new_state,reason,"
                        "payload_hash,previous_hash,event_hash) VALUES('node',0,NULL,"
                        "'READY','duplicate',?,NULL,?)",
                        (payload, "f" * 64),
                    )
                connection.rollback()
                connection.close()
                self.assertEqual(path.read_bytes(), before)

    def test_legacy_evaluation_and_integration_journal_rows_are_rejected(self):
        ledger_path = self.database("ledger.sqlite")
        connection = self.legacy(ledger_path)
        self.add_node(connection)
        connection.execute(
            "INSERT INTO evaluation_ledger(node_id,task_id,contract_id,evaluation_hash,previous_ledger_hash,ledger_hash) "
            "VALUES('node','node','contract',?,NULL,?)", ("b" * 64, "c" * 64),
        )
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(ledger_path, "cannot be authenticated")

        integration_path = self.database("integration.sqlite")
        connection = self.legacy(integration_path, (*V2_CORE_DDL, V1_INTEGRATION_DDL))
        self.add_node(connection)
        connection.execute(
            "INSERT INTO integration_attempts(attempt_id,node_id,expected_base_sha,candidate_sha,"
            "evaluation_hash,manifest_hash,status) VALUES('attempt','node',?,?,?,?, 'PREPARED')",
            (SHA, "b" * 40, "c" * 64, "d" * 64),
        )
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(integration_path, "cannot be authenticated")

        for column, value in (
            ("result_sha", "b" * 40),
            ("evaluation_hash", "c" * 64),
            ("integration_sha", "d" * 40),
        ):
            with self.subTest(residual_column=column):
                path = self.database(f"residual-{column}.sqlite")
                connection = self.legacy(path)
                self.add_node(connection)
                connection.execute(f"UPDATE nodes SET {column}=? WHERE node_id='node'", (value,))
                connection.commit()
                connection.close()
                self.assert_rejected_without_mutation(
                    path, "unverifiable evaluator/integration fields",
                )

    def test_v2_evidence_and_evaluation_rows_reject_without_mutation(self):
        artifact_id = f"sha256:{'3' * 64}"
        claim_id = f"claim:{'4' * 64}"
        for include_claim in (False, True):
            with self.subTest(include_claim=include_claim):
                path = self.database(f"v2-evidence-claim-{include_claim}.sqlite")
                connection = self.legacy(
                    path,
                    V2_REPOSITORY_DDL,
                    application_id=APPLICATION_ID,
                    user_version=2,
                )
                self.add_node(connection)
                claim_values = (
                    (claim_id, "hermes-evaluator", 0, "2026-08-30T00:00:00Z")
                    if include_claim else (None, None, None, None)
                )
                connection.execute(
                    "INSERT INTO evidence_artifacts(artifact_id,node_id,project,producer_project_id,"
                    "manifest_sha256,manifest_relative_path,task_id,base_sha,candidate_sha,"
                    "contract_sha256,ingress_version,claim_id,claimed_by,claim_version,claimed_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id, "node", "opensource", "oss", "3" * 64,
                        f"sha256/33/{'3' * 64}/manifest.json", "node", SHA, "b" * 40,
                        "5" * 64, 3, *claim_values,
                    ),
                )
                if include_claim:
                    connection.execute(
                        "INSERT INTO evaluation_claims(claim_id,artifact_id,node_id,claim_version,"
                        "claimed_by,status,claimed_at) VALUES(?,?,?,?,?,'ACTIVE',?)",
                        (
                            claim_id, artifact_id, "node", 0, "hermes-evaluator",
                            "2026-08-30T00:00:00Z",
                        ),
                    )
                connection.commit()
                connection.close()
                self.assert_rejected_without_mutation(path, "cannot be authenticated")

    def test_v1_publication_rows_reject_without_mutation(self):
        statements = (
            *V2_CORE_DDL,
            V2_INTEGRATION_DDL,
            *BUZZ_DDL,
            *V2_PUBLICATION_DDL,
        )
        head_path = self.database("publication-head.sqlite")
        connection = self.legacy(
            head_path,
            statements,
            application_id=APPLICATION_ID,
            user_version=1,
        )
        self.add_node(connection)
        connection.execute(
            "INSERT INTO publication_heads(project,version,sha,generation,integration_attempt_id) "
            "VALUES('opensource',1,?,?,NULL)",
            ("b" * 40, "c" * 40),
        )
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(head_path, "cannot be authenticated")

        journal_path = self.database("publication-journal.sqlite")
        connection = self.legacy(
            journal_path,
            statements,
            application_id=APPLICATION_ID,
            user_version=1,
        )
        self.add_node(connection)
        connection.execute(
            "INSERT INTO publication_journal(operation_id,operation_kind,phase,project,goal_id,"
            "node_id,integration_attempt_id,version_before,version_after,from_sha,to_sha,"
            "from_generation,to_generation,previous_hash,entry_hash) "
            "VALUES('operation','PROMOTION','COMPLETED','opensource','goal','node','attempt',"
            "0,1,?,?,?,?,NULL,?)",
            (SHA, "b" * 40, SHA, "b" * 40, "e" * 64),
        )
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(journal_path, "cannot be authenticated")

    def test_unknown_future_partial_and_foreign_schemas_fail_closed(self):
        future = self.database("future.sqlite")
        apply_database(future)
        connection = sqlite3.connect(future)
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(future, "future")

        unknown = self.database("unknown.sqlite")
        apply_database(unknown)
        connection = sqlite3.connect(unknown)
        connection.execute("CREATE TABLE surprise(value TEXT)")
        connection.commit()
        connection.close()
        self.assert_rejected_without_mutation(unknown)

        partial = self.database("partial.sqlite")
        connection = self.legacy(partial, V2_CORE_DDL[:-1])
        connection.close()
        self.assert_rejected_without_mutation(partial, "partial or unknown")

        foreign = self.database("foreign.sqlite")
        connection = self.legacy(
            foreign,
            CURRENT_DDL,
            application_id=7,
            user_version=SCHEMA_VERSION,
        )
        connection.close()
        self.assert_rejected_without_mutation(foreign, "another application")

    def test_project_graph_refuses_missing_database_until_explicit_apply(self):
        path = self.database()
        with self.assertRaisesRegex(SchemaError, "explicitly created"):
            ProjectGraph(path)
        self.assertFalse(path.exists())

        plan = inspect_database(path)
        self.assertEqual((plan.status, plan.action), ("empty", "create"))
        self.assertFalse(path.exists())

        apply_database(path)
        graph = ProjectGraph(path)
        try:
            self.assertEqual(graph.connection.execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
            self.assertEqual(graph.connection.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(inspect_schema(graph.connection).status, "current")
        finally:
            graph.connection.close()

    def test_project_graph_refuses_legacy_database_without_mutating_until_apply(self):
        path = self.database("legacy-runtime.sqlite")
        connection = self.legacy(path)
        self.add_node(connection)
        connection.close()
        before = path.read_bytes()

        with self.assertRaisesRegex(SchemaError, "refuses implicit graph migration"):
            ProjectGraph(path)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(inspect_database(path).action, "migrate")
        self.assertEqual(path.read_bytes(), before)

        self.assertTrue(apply_database(path).changed)
        graph = ProjectGraph(path)
        try:
            self.assertEqual(graph.connection.execute("SELECT state FROM nodes").fetchone()[0], "READY")
            self.assertEqual(inspect_schema(graph.connection).status, "current")
        finally:
            graph.connection.close()

    def test_schema_bootstrap_refuses_an_existing_transaction(self):
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("BEGIN")
            with self.assertRaises(SchemaError):
                ensure_current_schema(connection)
        finally:
            connection.rollback()
            connection.close()


if __name__ == "__main__":
    unittest.main()
