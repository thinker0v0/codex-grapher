"""Versioned SQLite schema and fail-closed legacy migration for the project graph."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from typing import Iterable

from control_plane.graph_state import (
    ACTIVE_PROJECTS,
    INITIAL_NODE_STATES,
    KNOWN_NODE_STATES,
    SENSITIVE_NODE_STATES,
    TRANSITIONS,
)


# ASCII "VAPG". SQLite application IDs are intended to identify the file format.
APPLICATION_ID = 0x56415047
SCHEMA_VERSION = 5

# Repository schema v2.  Keep the exact statements available so the explicit
# bootstrap command can identify (and validate) an installed v2 database.
V2_CORE_DDL = (
    """CREATE TABLE IF NOT EXISTS goals(
      goal_id TEXT PRIMARY KEY, project TEXT NOT NULL, objective TEXT NOT NULL,
      accepted_sha TEXT NOT NULL, state TEXT NOT NULL, idempotency_key TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS nodes(
      node_id TEXT PRIMARY KEY, goal_id TEXT NOT NULL REFERENCES goals(goal_id),
      kind TEXT NOT NULL, spec_json TEXT NOT NULL, spec_hash TEXT NOT NULL,
      write_set_json TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
      attempt INTEGER NOT NULL DEFAULT 0, lease_id TEXT, lease_owner TEXT,
      lease_expires_at TEXT, heartbeat_at TEXT, base_sha TEXT NOT NULL,
      result_sha TEXT, evidence_hash TEXT, evaluation_hash TEXT, integration_sha TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
    """CREATE TABLE IF NOT EXISTS dependencies(
      node_id TEXT NOT NULL REFERENCES nodes(node_id),
      dependency_id TEXT NOT NULL REFERENCES nodes(node_id), PRIMARY KEY(node_id,dependency_id)
    )""",
    """CREATE TABLE IF NOT EXISTS events(
      event_id INTEGER PRIMARY KEY AUTOINCREMENT, node_id TEXT NOT NULL,
      version INTEGER NOT NULL, old_state TEXT, new_state TEXT NOT NULL,
      reason TEXT NOT NULL, payload_hash TEXT NOT NULL, previous_hash TEXT,
      event_hash TEXT NOT NULL UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(node_id,version)
    )""",
    """CREATE TABLE IF NOT EXISTS evaluation_ledger(
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      node_id TEXT NOT NULL UNIQUE REFERENCES nodes(node_id),
      task_id TEXT NOT NULL, contract_id TEXT NOT NULL,
      evaluation_hash TEXT NOT NULL UNIQUE,
      previous_ledger_hash TEXT, ledger_hash TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
)

CORE_DDL = (
    V2_CORE_DDL[0],
    """CREATE TABLE IF NOT EXISTS nodes(
      node_id TEXT PRIMARY KEY, goal_id TEXT NOT NULL REFERENCES goals(goal_id),
      kind TEXT NOT NULL, spec_json TEXT NOT NULL, spec_hash TEXT NOT NULL,
      write_set_json TEXT NOT NULL, state TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0,
      attempt INTEGER NOT NULL DEFAULT 0, lease_id TEXT, lease_owner TEXT,
      lease_expires_at TEXT, heartbeat_at TEXT, base_sha TEXT NOT NULL,
      result_sha TEXT, evidence_hash TEXT, evaluation_hash TEXT, integration_sha TEXT,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      active_artifact_id TEXT REFERENCES evidence_artifacts(artifact_id)
    )""",
    *V2_CORE_DDL[2:],
    """CREATE UNIQUE INDEX IF NOT EXISTS nodes_active_artifact_unique
    ON nodes(active_artifact_id)""",
)

V3_INTEGRATION_DDL = """CREATE TABLE IF NOT EXISTS integration_attempts(
  attempt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, expected_base_sha TEXT NOT NULL,
  candidate_sha TEXT NOT NULL, integration_sha TEXT, evaluation_hash TEXT NOT NULL,
  manifest_hash TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  publication_generation TEXT,
  artifact_id TEXT NOT NULL REFERENCES evidence_artifacts(artifact_id),
  outcome_id TEXT NOT NULL REFERENCES evaluation_outcomes(outcome_id),
  expected_head_version INTEGER NOT NULL,
  UNIQUE(node_id,candidate_sha)
)"""

INTEGRATION_DDL = """CREATE TABLE IF NOT EXISTS integration_attempts(
  attempt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, expected_base_sha TEXT NOT NULL,
  candidate_sha TEXT NOT NULL, integration_sha TEXT, evaluation_hash TEXT NOT NULL,
  manifest_hash TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  publication_generation TEXT,
  artifact_id TEXT NOT NULL REFERENCES evidence_artifacts(artifact_id),
  outcome_id TEXT NOT NULL REFERENCES evaluation_outcomes(outcome_id),
  expected_head_version INTEGER NOT NULL,
  affected_graph_sha256 TEXT NOT NULL,
  affected_graph_json TEXT NOT NULL,
  UNIQUE(node_id,candidate_sha)
)"""

V2_INTEGRATION_DDL = """CREATE TABLE IF NOT EXISTS integration_attempts(
  attempt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, expected_base_sha TEXT NOT NULL,
  candidate_sha TEXT NOT NULL, integration_sha TEXT, evaluation_hash TEXT NOT NULL,
  manifest_hash TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  publication_generation TEXT,
  UNIQUE(node_id,candidate_sha)
)"""

# The exact schema published by repository schema version 1. Version 2 adds the
# nullable publication generation without fabricating values for historical rows.
V1_INTEGRATION_DDL = """CREATE TABLE IF NOT EXISTS integration_attempts(
  attempt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, expected_base_sha TEXT NOT NULL,
  candidate_sha TEXT NOT NULL, integration_sha TEXT, evaluation_hash TEXT NOT NULL,
  manifest_hash TEXT NOT NULL, status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(node_id,candidate_sha)
)"""

# These are part of the shared graph database even when the Buzz adapter has not
# yet been constructed. Keeping them here prevents constructor order from defining
# the on-disk format.
BUZZ_DDL = (
    """CREATE TABLE IF NOT EXISTS buzz_threads(
      thread_id TEXT PRIMARY KEY, sender_pubkey TEXT NOT NULL, project TEXT NOT NULL,
      goal_id TEXT NOT NULL, UNIQUE(sender_pubkey,goal_id)
    )""",
    """CREATE TABLE IF NOT EXISTS buzz_audit(
      audit_id INTEGER PRIMARY KEY AUTOINCREMENT, sender_pubkey TEXT NOT NULL,
      thread_id TEXT NOT NULL, command TEXT NOT NULL, project TEXT,
      goal_id TEXT, request_hash TEXT NOT NULL, outcome TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""",
)

BUZZ_INGRESS_DDL = """CREATE TABLE IF NOT EXISTS buzz_ingress_responses(
  event_id TEXT PRIMARY KEY,
  event_body_hash TEXT NOT NULL,
  sender_pubkey TEXT NOT NULL,
  channel_id TEXT NOT NULL,
  thread_id TEXT NOT NULL,
  route TEXT,
  request_hash TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('PROCESSING','COMPLETE')),
  response_json TEXT,
  response_hash TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK(route IS NULL OR route IN ('nomad','opensource','business','hynix')),
  CHECK(
    (state='PROCESSING' AND response_json IS NULL AND response_hash IS NULL) OR
    (state='COMPLETE' AND response_json IS NOT NULL AND response_hash IS NOT NULL)
  )
)"""

V2_EVIDENCE_DDL = (
    """CREATE TABLE IF NOT EXISTS evidence_artifacts(
      artifact_id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL UNIQUE REFERENCES nodes(node_id),
      project TEXT NOT NULL,
      producer_project_id TEXT NOT NULL,
      manifest_sha256 TEXT NOT NULL UNIQUE,
      manifest_relative_path TEXT NOT NULL UNIQUE,
      task_id TEXT NOT NULL,
      base_sha TEXT NOT NULL,
      candidate_sha TEXT NOT NULL,
      contract_sha256 TEXT NOT NULL,
      ingress_version INTEGER NOT NULL,
      claim_id TEXT UNIQUE,
      claimed_by TEXT,
      claim_version INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      claimed_at TEXT,
      CHECK ((claim_id IS NULL AND claimed_by IS NULL AND claim_version IS NULL AND claimed_at IS NULL)
          OR (claim_id IS NOT NULL AND claimed_by IS NOT NULL AND claim_version IS NOT NULL AND claimed_at IS NOT NULL))
    )""",
    """CREATE TABLE IF NOT EXISTS evaluation_claims(
      claim_id TEXT PRIMARY KEY,
      artifact_id TEXT NOT NULL REFERENCES evidence_artifacts(artifact_id),
      node_id TEXT NOT NULL REFERENCES nodes(node_id),
      claim_version INTEGER NOT NULL,
      claimed_by TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('ACTIVE','EVALUATED','DISPOSED')),
      disposition TEXT CHECK(disposition IN ('RETRY','FAILED_GATE','NEEDS_HUMAN')),
      reason_sha256 TEXT,
      claimed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      resolved_at TEXT,
      UNIQUE(artifact_id,claim_version),
      CHECK (
        (status='ACTIVE' AND disposition IS NULL AND reason_sha256 IS NULL AND resolved_at IS NULL) OR
        (status='EVALUATED' AND disposition IS NULL AND reason_sha256 IS NOT NULL AND resolved_at IS NOT NULL) OR
        (status='DISPOSED' AND disposition IS NOT NULL AND reason_sha256 IS NOT NULL AND resolved_at IS NOT NULL)
      )
    )""",
)

V4_EVIDENCE_DDL = (
    """CREATE TABLE IF NOT EXISTS evidence_artifacts(
      artifact_id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL REFERENCES nodes(node_id),
      attempt INTEGER NOT NULL CHECK(attempt >= 1),
      project TEXT NOT NULL,
      producer_project_id TEXT NOT NULL,
      manifest_sha256 TEXT NOT NULL UNIQUE,
      manifest_relative_path TEXT NOT NULL UNIQUE,
      task_id TEXT NOT NULL,
      base_sha TEXT NOT NULL,
      candidate_sha TEXT NOT NULL,
      contract_sha256 TEXT NOT NULL,
      ingress_version INTEGER NOT NULL,
      claim_id TEXT UNIQUE,
      claimed_by TEXT,
      claim_version INTEGER,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      claimed_at TEXT,
      UNIQUE(node_id,attempt),
      CHECK ((claim_id IS NULL AND claimed_by IS NULL AND claim_version IS NULL AND claimed_at IS NULL)
          OR (claim_id IS NOT NULL AND claimed_by IS NOT NULL AND claim_version IS NOT NULL AND claimed_at IS NOT NULL))
    )""",
    """CREATE TABLE IF NOT EXISTS evaluation_claims(
      claim_id TEXT PRIMARY KEY,
      artifact_id TEXT NOT NULL REFERENCES evidence_artifacts(artifact_id),
      node_id TEXT NOT NULL REFERENCES nodes(node_id),
      claim_version INTEGER NOT NULL,
      claimed_by TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('ACTIVE','EVALUATED','DISPOSED','EXPIRED')),
      disposition TEXT CHECK(disposition IN ('RETRY','FAILED_GATE','NEEDS_HUMAN','EXPIRED')),
      reason_sha256 TEXT,
      claimed_at TEXT NOT NULL,
      heartbeat_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      resolved_at TEXT,
      UNIQUE(artifact_id,claim_version),
      CHECK (
        (status='ACTIVE' AND disposition IS NULL AND reason_sha256 IS NULL AND resolved_at IS NULL) OR
        (status='EVALUATED' AND disposition IS NULL AND reason_sha256 IS NOT NULL AND resolved_at IS NOT NULL) OR
        (status='DISPOSED' AND disposition IN ('RETRY','FAILED_GATE','NEEDS_HUMAN') AND reason_sha256 IS NOT NULL AND resolved_at IS NOT NULL) OR
        (status='EXPIRED' AND disposition='EXPIRED' AND reason_sha256 IS NOT NULL AND resolved_at IS NOT NULL)
      )
    )""",
    """CREATE TABLE IF NOT EXISTS evaluation_outcomes(
      outcome_id TEXT PRIMARY KEY,
      artifact_id TEXT NOT NULL UNIQUE REFERENCES evidence_artifacts(artifact_id),
      node_id TEXT NOT NULL UNIQUE REFERENCES nodes(node_id),
      evaluation_sha256 TEXT NOT NULL UNIQUE,
      canonical_json BLOB NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CHECK(outcome_id='sha256:' || evaluation_sha256)
    )""",
    """CREATE UNIQUE INDEX IF NOT EXISTS evaluation_claims_one_active_node
    ON evaluation_claims(node_id) WHERE status='ACTIVE'""",
    """CREATE TRIGGER IF NOT EXISTS evaluation_outcomes_no_update
    BEFORE UPDATE ON evaluation_outcomes BEGIN
      SELECT RAISE(ABORT,'evaluation outcomes are immutable');
    END""",
    """CREATE TRIGGER IF NOT EXISTS evaluation_outcomes_no_delete
    BEFORE DELETE ON evaluation_outcomes BEGIN
      SELECT RAISE(ABORT,'evaluation outcomes are immutable');
    END""",
)

EVIDENCE_DDL = (
    *V4_EVIDENCE_DDL,
    """CREATE TRIGGER IF NOT EXISTS evaluation_outcomes_no_replace
    BEFORE INSERT ON evaluation_outcomes
    WHEN EXISTS(
      SELECT 1 FROM evaluation_outcomes
      WHERE outcome_id=NEW.outcome_id OR artifact_id=NEW.artifact_id
         OR node_id=NEW.node_id OR evaluation_sha256=NEW.evaluation_sha256
    ) BEGIN
      SELECT RAISE(ABORT,'evaluation outcomes are immutable');
    END""",
)

# Exact repository-v3 evidence shape, retained only for fail-closed offline
# migration into the heartbeat-audited claim schema. Populated evidence tables
# remain unverifiable and are rejected by content validation below.
V3_EVIDENCE_DDL = tuple(
    statement.replace(
        "claimed_at TEXT NOT NULL,\n      heartbeat_at TEXT NOT NULL,\n      expires_at TEXT NOT NULL,",
        "claimed_at TEXT NOT NULL,\n      expires_at TEXT NOT NULL,",
    )
    for statement in V4_EVIDENCE_DDL
)

V2_PUBLICATION_DDL = (
    """CREATE TABLE IF NOT EXISTS publication_heads(
      project TEXT PRIMARY KEY, version INTEGER NOT NULL,
      sha TEXT NOT NULL, generation TEXT NOT NULL,
      integration_attempt_id TEXT, last_journal_hash TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS publication_journal(
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT NOT NULL, operation_kind TEXT NOT NULL,
      phase TEXT NOT NULL, project TEXT NOT NULL, goal_id TEXT NOT NULL,
      node_id TEXT NOT NULL, integration_attempt_id TEXT NOT NULL,
      version_before INTEGER NOT NULL, version_after INTEGER NOT NULL,
      from_sha TEXT NOT NULL, to_sha TEXT NOT NULL,
      from_generation TEXT NOT NULL, to_generation TEXT NOT NULL,
      previous_hash TEXT, entry_hash TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(operation_id,phase)
    )""",
    """CREATE TRIGGER IF NOT EXISTS publication_journal_no_update
    BEFORE UPDATE ON publication_journal BEGIN
      SELECT RAISE(ABORT,'publication journal is append-only');
    END""",
    """CREATE TRIGGER IF NOT EXISTS publication_journal_no_delete
    BEFORE DELETE ON publication_journal BEGIN
      SELECT RAISE(ABORT,'publication journal is append-only');
    END""",
)

PUBLICATION_DDL = (
    V2_PUBLICATION_DDL[0],
    """CREATE TABLE IF NOT EXISTS publication_journal_tail(
      singleton INTEGER PRIMARY KEY CHECK(singleton=1),
      last_sequence INTEGER, last_hash TEXT,
      CHECK((last_sequence IS NULL AND last_hash IS NULL) OR
            (last_sequence IS NOT NULL AND last_hash IS NOT NULL))
    )""",
    """CREATE TABLE IF NOT EXISTS publication_journal(
      sequence INTEGER PRIMARY KEY AUTOINCREMENT,
      operation_id TEXT NOT NULL, operation_kind TEXT NOT NULL,
      phase TEXT NOT NULL, project TEXT NOT NULL, goal_id TEXT NOT NULL,
      node_id TEXT NOT NULL, integration_attempt_id TEXT NOT NULL,
      version_before INTEGER NOT NULL, version_after INTEGER NOT NULL,
      from_sha TEXT NOT NULL, to_sha TEXT NOT NULL,
      from_generation TEXT NOT NULL, to_generation TEXT NOT NULL,
      affected_graph_sha256 TEXT NOT NULL,
      affected_graph_json TEXT NOT NULL,
      previous_hash TEXT, entry_hash TEXT NOT NULL UNIQUE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(operation_id,phase)
    )""",
    *V2_PUBLICATION_DDL[2:],
)

CURRENT_DDL = (
    *CORE_DDL, INTEGRATION_DDL, *BUZZ_DDL, BUZZ_INGRESS_DDL,
    *EVIDENCE_DDL, *PUBLICATION_DDL,
)

# Historical coordinator variants. They are recognized only so empty journals can
# be replaced by the exact current table. Rows are never guessed or rewritten.
LEGACY_INTEGRATION_DDL = """CREATE TABLE IF NOT EXISTS integration_attempts(
  attempt_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, expected_base_sha TEXT NOT NULL,
  candidate_sha TEXT NOT NULL, integration_sha TEXT, evaluation_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(node_id,candidate_sha)
)"""

class SchemaError(RuntimeError):
    """The database cannot be identified or migrated without unsafe inference."""


@dataclass(frozen=True)
class SchemaPlan:
    status: str
    action: str
    application_id: int
    user_version: int
    schema_sha256: str
    tables: tuple[str, ...]
    legacy_variant: str | None = None
    reason: str | None = None
    changed: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _normalize_sql(sql: str | None) -> str | None:
    if sql is None:
        return None
    compact = " ".join(sql.split())
    return re.sub(r"\s*([(),])\s*", r"\1", compact)


def _schema_signature(connection: sqlite3.Connection) -> tuple[tuple[str, str, str, str | None], ...]:
    rows = connection.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
    ).fetchall()
    return tuple((row[0], row[1], row[2], _normalize_sql(row[3])) for row in rows)


def _signature_for(statements: Iterable[str], alter_manifest: bool = False) -> tuple[tuple[str, str, str, str | None], ...]:
    connection = sqlite3.connect(":memory:")
    try:
        for statement in statements:
            connection.execute(statement)
        if alter_manifest:
            connection.execute("ALTER TABLE integration_attempts ADD COLUMN manifest_hash TEXT")
        return _schema_signature(connection)
    finally:
        connection.close()


CURRENT_SIGNATURE = _signature_for(CURRENT_DDL)


def _legacy_signatures() -> dict[tuple[tuple[str, str, str, str | None], ...], str]:
    variants: dict[tuple[tuple[str, str, str, str | None], ...], str] = {}

    def add(name: str, statements: Iterable[str], alter_manifest: bool = False) -> None:
        variants[_signature_for(statements, alter_manifest)] = name

    add("graph-core", V2_CORE_DDL)
    add("graph-core-integration", (*V2_CORE_DDL, V1_INTEGRATION_DDL))
    add("graph-core-buzz", (*V2_CORE_DDL, *BUZZ_DDL))
    add("graph-core-integration-buzz", (*V2_CORE_DDL, V1_INTEGRATION_DDL, *BUZZ_DDL))
    add("graph-core-pre-manifest-journal", (*V2_CORE_DDL, LEGACY_INTEGRATION_DDL))
    add("graph-core-pre-manifest-journal-buzz", (*V2_CORE_DDL, LEGACY_INTEGRATION_DDL, *BUZZ_DDL))
    add("graph-core-nullable-manifest-journal", (*V2_CORE_DDL, LEGACY_INTEGRATION_DDL), True)
    add(
        "graph-core-nullable-manifest-journal-buzz",
        (*V2_CORE_DDL, LEGACY_INTEGRATION_DDL, *BUZZ_DDL),
        True,
    )
    return variants


LEGACY_SIGNATURES = _legacy_signatures()


def _version_one_signatures() -> dict[tuple[tuple[str, str, str, str | None], ...], str]:
    """Exact repository-v1 shapes, including constructor-created extensions."""
    variants: dict[tuple[tuple[str, str, str, str | None], ...], str] = {}

    def add(name: str, statements: Iterable[str]) -> None:
        variants[_signature_for(statements)] = name

    base = (*V2_CORE_DDL, V1_INTEGRATION_DDL, *BUZZ_DDL)
    publication = (*V2_CORE_DDL, V2_INTEGRATION_DDL, *BUZZ_DDL, *V2_PUBLICATION_DDL)
    add("repository-v1", base)
    add("repository-v1-buzz-ingress", (*base, BUZZ_INGRESS_DDL))
    add("repository-v1-publication", publication)
    add("repository-v1-publication-buzz-ingress", (*publication, BUZZ_INGRESS_DDL))
    return variants


VERSION_ONE_SIGNATURES = _version_one_signatures()


def _version_two_signatures() -> dict[tuple[tuple[str, str, str, str | None], ...], str]:
    statements = (
        *V2_CORE_DDL, V2_INTEGRATION_DDL, *BUZZ_DDL, BUZZ_INGRESS_DDL,
        *V2_EVIDENCE_DDL, *V2_PUBLICATION_DDL,
    )
    return {_signature_for(statements): "repository-v2"}


VERSION_TWO_SIGNATURES = _version_two_signatures()


def _version_three_signatures() -> dict[tuple[tuple[str, str, str, str | None], ...], str]:
    statements = (
        *CORE_DDL, V3_INTEGRATION_DDL, *BUZZ_DDL, BUZZ_INGRESS_DDL,
        *V3_EVIDENCE_DDL, *PUBLICATION_DDL,
    )
    return {_signature_for(statements): "repository-v3"}


VERSION_THREE_SIGNATURES = _version_three_signatures()


def _version_four_signatures() -> dict[tuple[tuple[str, str, str, str | None], ...], str]:
    statements = (
        *CORE_DDL, V3_INTEGRATION_DDL, *BUZZ_DDL, BUZZ_INGRESS_DDL,
        *V4_EVIDENCE_DDL, *PUBLICATION_DDL,
    )
    return {_signature_for(statements): "repository-v4"}


VERSION_FOUR_SIGNATURES = _version_four_signatures()


def _fingerprint(signature: tuple[tuple[str, str, str, str | None], ...]) -> str:
    encoded = json.dumps(signature, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reject(
    application_id: int,
    user_version: int,
    signature: tuple[tuple[str, str, str, str | None], ...],
    reason: str,
) -> SchemaPlan:
    return SchemaPlan(
        "unsupported", "reject", application_id, user_version, _fingerprint(signature),
        tuple(sorted(row[1] for row in signature if row[0] == "table")), reason=reason,
    )


def _database_checks(connection: sqlite3.Connection) -> str | None:
    quick_check = [row[0] for row in connection.execute("PRAGMA quick_check")]
    if quick_check != ["ok"]:
        return "SQLite quick_check did not pass"
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        return "SQLite foreign-key check did not pass"
    return None


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _legacy_rows_are_verifiable(connection: sqlite3.Connection, tables: set[str]) -> str | None:
    projects = {row[0] for row in connection.execute("SELECT DISTINCT project FROM goals")}
    unknown_projects = projects - ACTIVE_PROJECTS
    if unknown_projects:
        return (
            "legacy database has projects outside the exact active route set: "
            f"{sorted(map(repr, unknown_projects))}"
        )
    goal_states = {row[0] for row in connection.execute("SELECT DISTINCT state FROM goals")}
    unknown_goal_states = goal_states - {"ACTIVE", "COMPLETED", "CANCELLED"}
    if unknown_goal_states:
        return f"legacy database has unknown goal states: {sorted(map(repr, unknown_goal_states))}"
    orphan_node = connection.execute(
        "SELECT n.node_id FROM nodes n LEFT JOIN goals g ON g.goal_id=n.goal_id "
        "WHERE g.goal_id IS NULL ORDER BY n.node_id LIMIT 1"
    ).fetchone()
    if orphan_node is not None:
        return f"legacy node {orphan_node[0]} references a missing goal"
    invalid_dependency = connection.execute(
        "SELECT d.node_id,d.dependency_id FROM dependencies d "
        "LEFT JOIN nodes n ON n.node_id=d.node_id "
        "LEFT JOIN nodes p ON p.node_id=d.dependency_id "
        "WHERE n.node_id IS NULL OR p.node_id IS NULL OR n.goal_id!=p.goal_id "
        "ORDER BY d.node_id,d.dependency_id LIMIT 1"
    ).fetchone()
    if invalid_dependency is not None:
        return (
            "legacy dependency is not bound to two nodes in one goal: "
            f"{invalid_dependency[0]}/{invalid_dependency[1]}"
        )
    if "buzz_threads" in tables:
        invalid_thread = connection.execute(
            "SELECT t.thread_id,t.project,g.project FROM buzz_threads t "
            "LEFT JOIN goals g ON g.goal_id=t.goal_id "
            "WHERE g.goal_id IS NULL OR t.project IS NULL "
            "OR t.project NOT IN ('nomad','opensource','business','hynix') "
            "OR t.project!=g.project ORDER BY t.thread_id LIMIT 1"
        ).fetchone()
        if invalid_thread is not None:
            return (
                "legacy Buzz thread is not bound to one contract-route same-project goal: "
                f"{invalid_thread[0]}"
            )
    states = {row[0] for row in connection.execute("SELECT DISTINCT state FROM nodes")}
    unknown = states - KNOWN_NODE_STATES
    if unknown:
        return f"legacy database has unknown node states: {sorted(map(repr, unknown))}"
    sensitive = states & SENSITIVE_NODE_STATES
    if sensitive:
        return (
            "legacy database has PASS/integration state requiring external evaluator and "
            f"publication proof: {sorted(sensitive)}"
        )
    sensitive_event_states = {
        value
        for row in connection.execute("SELECT old_state,new_state FROM events")
        for value in row
        if value in SENSITIVE_NODE_STATES
    }
    if sensitive_event_states:
        return (
            "legacy database has event history requiring external evaluator and "
            f"publication proof: {sorted(sensitive_event_states)}"
        )
    if connection.execute("SELECT 1 FROM evaluation_ledger LIMIT 1").fetchone() is not None:
        return "legacy evaluation ledger rows cannot be authenticated during schema migration"
    if "integration_attempts" in tables and connection.execute(
        "SELECT 1 FROM integration_attempts LIMIT 1"
    ).fetchone() is not None:
        return "legacy integration journal rows cannot be authenticated during schema migration"
    if "publication_journal_tail" in tables:
        tail_rows = [tuple(row) for row in connection.execute(
            "SELECT singleton,last_sequence,last_hash FROM publication_journal_tail"
        ).fetchall()]
        if tail_rows != [(1, None, None)]:
            return "legacy publication journal tail is not the exact empty anchor"
    for table, label in (
        ("evidence_artifacts", "evidence artifact"),
        ("evaluation_claims", "evaluation claim"),
        ("publication_journal", "publication journal"),
        ("publication_heads", "publication head"),
    ):
        if table in tables and connection.execute(
            f"SELECT 1 FROM {table} LIMIT 1"
        ).fetchone() is not None:
            return f"legacy {label} rows cannot be authenticated during schema migration"
    residual = connection.execute(
        "SELECT node_id FROM nodes WHERE result_sha IS NOT NULL OR evaluation_hash IS NOT NULL "
        "OR integration_sha IS NOT NULL LIMIT 1"
    ).fetchone()
    if residual is not None:
        return f"legacy node {residual[0]} has unverifiable evaluator/integration fields"

    orphan = connection.execute(
        "SELECT e.node_id FROM events e LEFT JOIN nodes n ON n.node_id=e.node_id "
        "WHERE n.node_id IS NULL LIMIT 1"
    ).fetchone()
    if orphan is not None:
        return f"legacy event chain references missing node {orphan[0]}"
    nodes = connection.execute("SELECT node_id,state,version FROM nodes ORDER BY node_id").fetchall()
    for node_id, state, version in nodes:
        rows = connection.execute(
            "SELECT version,old_state,new_state,reason,payload_hash,previous_hash,event_hash "
            "FROM events WHERE node_id=? ORDER BY version", (node_id,),
        ).fetchall()
        if type(version) is not int or version < 0:
            return f"legacy node {node_id} has an invalid event-chain version"
        previous = None
        previous_state = None
        for expected_version, row in enumerate(rows):
            event_version, old_state, new_state = row[:3]
            if type(event_version) is not int or event_version != expected_version:
                return (
                    f"legacy event versions for node {node_id} are not exactly "
                    f"0..{version}"
                )
            if expected_version == 0:
                if old_state is not None:
                    return f"legacy event genesis for node {node_id} has a non-NULL old state"
                if new_state not in INITIAL_NODE_STATES:
                    return f"legacy event genesis for node {node_id} has an invalid initial state"
            else:
                if old_state != previous_state:
                    return f"legacy event states for node {node_id} are not adjacent"
                if new_state not in TRANSITIONS.get(old_state, frozenset()):
                    return (
                        f"legacy event transition for node {node_id} is invalid: "
                        f"{old_state}->{new_state}"
                    )
            if new_state not in KNOWN_NODE_STATES:
                return f"legacy event chain for node {node_id} has an unknown state"
            expected = _digest({
                "node": node_id, "version": event_version,
                "old": old_state, "new": new_state,
                "reason": row[3], "payload": row[4], "previous": previous,
            })
            if row[5] != previous or row[6] != expected:
                return f"legacy event chain for node {node_id} does not verify"
            previous = row[6]
            previous_state = new_state
        if (
            not rows or len(rows) != version + 1
            or rows[-1][0] != version or rows[-1][2] != state
        ):
            return f"legacy node {node_id} does not match its event-chain head"
    return None


def inspect_schema(connection: sqlite3.Connection) -> SchemaPlan:
    """Inspect schema and contents without issuing any mutating SQL."""
    application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
    user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    signature = _schema_signature(connection)
    tables = tuple(sorted(row[1] for row in signature if row[0] == "table"))
    fingerprint = _fingerprint(signature)

    check_error = _database_checks(connection)
    if check_error:
        return _reject(application_id, user_version, signature, check_error)
    if application_id == APPLICATION_ID and user_version > SCHEMA_VERSION:
        return _reject(application_id, user_version, signature, "database schema version is from the future")
    if application_id not in {0, APPLICATION_ID}:
        return _reject(application_id, user_version, signature, "database belongs to another application")

    if signature == CURRENT_SIGNATURE and application_id == APPLICATION_ID and user_version == SCHEMA_VERSION:
        return SchemaPlan("current", "none", application_id, user_version, fingerprint, tables)
    if application_id == APPLICATION_ID and user_version == 1 and signature in VERSION_ONE_SIGNATURES:
        row_error = _legacy_rows_are_verifiable(connection, set(tables))
        if row_error:
            return _reject(application_id, user_version, signature, row_error)
        return SchemaPlan(
            "legacy", "migrate", application_id, user_version, fingerprint, tables,
            legacy_variant=VERSION_ONE_SIGNATURES[signature],
        )
    if application_id == APPLICATION_ID and user_version == 2 and signature in VERSION_TWO_SIGNATURES:
        row_error = _legacy_rows_are_verifiable(connection, set(tables))
        if row_error:
            return _reject(application_id, user_version, signature, row_error)
        return SchemaPlan(
            "legacy", "migrate", application_id, user_version, fingerprint, tables,
            legacy_variant=VERSION_TWO_SIGNATURES[signature],
        )
    if application_id == APPLICATION_ID and user_version == 3 and signature in VERSION_THREE_SIGNATURES:
        row_error = _legacy_rows_are_verifiable(connection, set(tables))
        if row_error:
            return _reject(application_id, user_version, signature, row_error)
        return SchemaPlan(
            "legacy", "migrate", application_id, user_version, fingerprint, tables,
            legacy_variant=VERSION_THREE_SIGNATURES[signature],
        )
    if application_id == APPLICATION_ID and user_version == 4 and signature in VERSION_FOUR_SIGNATURES:
        row_error = _legacy_rows_are_verifiable(connection, set(tables))
        if row_error:
            return _reject(application_id, user_version, signature, row_error)
        return SchemaPlan(
            "legacy", "migrate", application_id, user_version, fingerprint, tables,
            legacy_variant=VERSION_FOUR_SIGNATURES[signature],
        )
    if not signature and application_id == 0 and user_version == 0:
        return SchemaPlan("empty", "create", application_id, user_version, fingerprint, tables)
    if application_id == 0 and user_version == 0 and signature in LEGACY_SIGNATURES:
        row_error = _legacy_rows_are_verifiable(connection, set(tables))
        if row_error:
            return _reject(application_id, user_version, signature, row_error)
        return SchemaPlan(
            "legacy", "migrate", application_id, user_version, fingerprint, tables,
            legacy_variant=LEGACY_SIGNATURES[signature],
        )
    if application_id == APPLICATION_ID or user_version != 0:
        return _reject(
            application_id, user_version, signature,
            "database metadata and exact schema do not describe a supported version",
        )
    return _reject(
        application_id, user_version, signature,
        "unversioned database is not an exact known legacy schema (partial or unknown schema)",
    )


def ensure_current_schema(connection: sqlite3.Connection, allow_create: bool = True) -> SchemaPlan:
    """Create or migrate an exact supported schema in one transaction.

    Existing unknown data is never coerced. In particular, legacy evaluator and
    integration rows require a separate authenticated recovery procedure.
    """
    if connection.in_transaction:
        raise SchemaError("schema bootstrap requires a connection outside a transaction")
    initial = inspect_schema(connection)
    if initial.action == "none":
        return initial
    if initial.action == "reject":
        raise SchemaError(initial.reason or "unsupported graph database")
    if initial.action == "create" and not allow_create:
        raise SchemaError("graph database is empty and schema creation is disabled")

    try:
        connection.execute("BEGIN IMMEDIATE")
        plan = inspect_schema(connection)
        if plan.action == "none":
            connection.commit()
            return plan
        if plan.action == "reject":
            raise SchemaError(plan.reason or "unsupported graph database")
        if plan.action == "create" and not allow_create:
            raise SchemaError("graph database is empty and schema creation is disabled")

        tables = set(plan.tables)
        if plan.action == "migrate":
            # Content validation above proves every replaced security-sensitive
            # table is empty.  Recreate exact constraints instead of inventing
            # attempts, outcome IDs, claim deadlines, or journal affected sets.
            connection.execute("DROP TRIGGER IF EXISTS evaluation_outcomes_no_update")
            connection.execute("DROP TRIGGER IF EXISTS evaluation_outcomes_no_delete")
            connection.execute("DROP TRIGGER IF EXISTS evaluation_outcomes_no_replace")
            connection.execute("DROP TRIGGER IF EXISTS publication_journal_no_update")
            connection.execute("DROP TRIGGER IF EXISTS publication_journal_no_delete")
            for table in (
                "integration_attempts", "evaluation_outcomes", "evaluation_claims",
                "evidence_artifacts", "publication_journal", "publication_heads",
                "publication_journal_tail",
            ):
                if table in tables:
                    connection.execute(f"DROP TABLE {table}")
            node_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(nodes)")
            }
            if "active_artifact_id" not in node_columns:
                connection.execute(
                    "ALTER TABLE nodes ADD COLUMN active_artifact_id TEXT "
                    "REFERENCES evidence_artifacts(artifact_id)"
                )
        for statement in CURRENT_DDL:
            connection.execute(statement)
        connection.execute(
            "INSERT OR IGNORE INTO publication_journal_tail(singleton,last_sequence,last_hash) "
            "VALUES(1,NULL,NULL)"
        )
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        prepared = inspect_schema(connection)
        if prepared.action != "none":
            raise SchemaError(
                prepared.reason or "schema bootstrap did not prepare the exact current schema"
            )
        connection.commit()
    except Exception:
        connection.rollback()
        raise

    current = inspect_schema(connection)
    if current.action != "none":
        raise SchemaError(current.reason or "schema bootstrap did not produce the exact current schema")
    return SchemaPlan(**{**current.to_dict(), "changed": True})
