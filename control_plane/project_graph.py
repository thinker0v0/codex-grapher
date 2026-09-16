#!/usr/bin/env python3
"""Durable, fail-closed project graph state for unattended work."""

from __future__ import annotations

import hashlib
import datetime as dt
import json
import os
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from control_plane.graph_schema import SchemaError, inspect_schema
from control_plane.evidence_ingress import IngressArtifact
from control_plane.evidence_store import (
    EVALUATOR_IDENTITY,
    EVIDENCE_DISPOSITIONS,
    claim_artifact,
    deterministic_claim_id,
    expire_claim,
    get_active_claim,
    get_artifact,
    get_outcome,
    heartbeat_claim,
    register_artifact,
    resolve_claim,
    store_outcome,
)
from control_plane.project_integrator import evaluation_ledger_hash, verify_evaluation
from control_plane.graph_state import (
    ACTIVE_PROJECTS,
    EXCEPTIONAL_EVENT_TRANSITIONS,
    INITIAL_NODE_STATES,
    KNOWN_NODE_STATES,
    TERMINAL,
    TRANSITIONS,
)


PROJECTS = set(ACTIVE_PROJECTS)
CLAIM_STATUSES = frozenset({"ACTIVE", "EVALUATED", "DISPOSED", "EXPIRED"})
CLAIM_DISPOSITION_TARGETS = {
    "RETRY": "READY",
    "FAILED_GATE": "FAILED_GATE",
    "NEEDS_HUMAN": "NEEDS_HUMAN",
}


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _claim_timestamp(value: Any, field: str, *, timezone_required: bool) -> dt.datetime:
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"evaluator claim {field} timestamp is invalid")
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        raise RuntimeError(f"evaluator claim {field} timestamp is invalid") from None
    if timezone_required and parsed.tzinfo is None:
        raise RuntimeError(f"evaluator claim {field} timestamp lacks a timezone")
    return parsed


def _expired_claim_reason(claim: dict[str, Any] | sqlite3.Row) -> str:
    return digest({
        "claim_id": claim["claim_id"],
        "expired_at": claim["expires_at"],
        "recovered_at": claim["resolved_at"],
    })


class ProjectGraph:
    """SQLite checkpoint store with dependency release and resumable leases."""

    def __init__(self, database: Path, evaluator_public_key: Path | None = None,
                 rubric_sha256: str | None = None, allow_cross_thread: bool = False):
        os.umask(0o077)
        self.database = Path(os.path.abspath(database))
        self.evaluator_public_key = evaluator_public_key
        self.rubric_sha256 = rubric_sha256
        if self.database.is_symlink() or not self.database.is_file():
            raise SchemaError(
                "runtime graph database must be explicitly created by graph_bootstrap.py --apply"
            )
        self.connection = sqlite3.connect(
            self.database, check_same_thread=not allow_cross_thread,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        # REPLACE is implemented as DELETE+INSERT by SQLite. Recursive triggers
        # ensure the immutable outcome DELETE trigger also fires for that form.
        self.connection.execute("PRAGMA recursive_triggers=ON")
        plan = inspect_schema(self.connection)
        if plan.action != "none":
            self.connection.close()
            if plan.action == "migrate":
                raise SchemaError(
                    "runtime refuses implicit graph migration; run graph_bootstrap.py "
                    "database --apply while the database is offline"
                )
            raise SchemaError(plan.reason or "unsupported graph database")
        try:
            self.assert_static_integrity()
        except (KeyError, PermissionError, TypeError, ValueError, RuntimeError) as exc:
            self.connection.close()
            raise SchemaError(f"runtime graph content integrity failed: {exc}") from exc
        self.connection.execute("PRAGMA journal_mode=WAL")
        os.chmod(self.database, 0o600)

    def create_goal(self, goal_id: str, project: str, objective: str, accepted_sha: str,
                    idempotency_key: str | None = None) -> dict[str, Any]:
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self._assert_project_has_no_pending_publication(project)
            result = self._create_goal_locked(
                goal_id, project, objective, accepted_sha, idempotency_key,
            )
            self.connection.commit()
            return result
        except Exception:
            self.connection.rollback()
            raise

    def _create_goal_locked(self, goal_id: str, project: str, objective: str, accepted_sha: str,
                            idempotency_key: str | None = None) -> dict[str, Any]:
        """Create or replay a goal inside the caller's transaction."""
        if project not in PROJECTS or len(accepted_sha) != 40:
            raise ValueError("invalid project or accepted SHA")
        self._assert_project_has_no_pending_publication(project)
        head = self.connection.execute(
            "SELECT sha FROM publication_heads WHERE project=?", (project,),
        ).fetchone()
        if head is not None and head["sha"] != accepted_sha:
            raise RuntimeError("goal baseline differs from the project publication head")
        existing_baseline = self.connection.execute(
            "SELECT accepted_sha FROM goals WHERE project=? AND state='ACTIVE' "
            "ORDER BY goal_id LIMIT 1",
            (project,),
        ).fetchone()
        if existing_baseline is not None and existing_baseline["accepted_sha"] != accepted_sha:
            raise RuntimeError("goal baseline differs from the existing project graph")
        idempotency_key = idempotency_key or goal_id
        try:
            self.connection.execute(
                "INSERT INTO goals(goal_id,project,objective,accepted_sha,state,idempotency_key) VALUES(?,?,?,?,?,?)",
                (goal_id, project, objective, accepted_sha, "ACTIVE", idempotency_key),
            )
        except sqlite3.IntegrityError:
            existing = self.connection.execute("SELECT * FROM goals WHERE idempotency_key=?", (idempotency_key,)).fetchone()
            if not existing or (existing["project"], existing["objective"], existing["accepted_sha"]) != (project, objective, accepted_sha):
                raise ValueError("idempotency key reused with different goal") from None
            return dict(existing)
        return dict(self.connection.execute("SELECT * FROM goals WHERE goal_id=?", (goal_id,)).fetchone())

    def add_node(self, node_id: str, goal_id: str, kind: str, spec: dict[str, Any],
                 write_set: list[str], dependencies: list[str] | None = None) -> None:
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self._add_node_locked(node_id, goal_id, kind, spec, write_set, dependencies)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def _add_node_locked(self, node_id: str, goal_id: str, kind: str, spec: dict[str, Any],
                         write_set: list[str], dependencies: list[str] | None = None) -> None:
        """Add a node and its first event inside the caller's transaction."""
        dependencies = dependencies or []
        if not isinstance(spec.get("evaluator_contract_id"), str) or not spec["evaluator_contract_id"]:
            raise ValueError("node requires an evaluator contract ID")
        if not write_set or any(Path(p).is_absolute() or ".." in Path(p).parts for p in write_set):
            raise ValueError("write set must contain scoped relative paths")
        goal = self.connection.execute("SELECT accepted_sha FROM goals WHERE goal_id=?", (goal_id,)).fetchone()
        if not goal:
            raise KeyError(goal_id)
        project = self.connection.execute(
            "SELECT project FROM goals WHERE goal_id=?", (goal_id,),
        ).fetchone()[0]
        self._assert_project_has_no_pending_publication(project)
        for dependency in dependencies:
            owner = self.connection.execute("SELECT goal_id FROM nodes WHERE node_id=?", (dependency,)).fetchone()
            if not owner or owner[0] != goal_id:
                raise ValueError("dependency must exist in the same goal")
        state = "BLOCKED" if dependencies else "READY"
        self.connection.execute(
            "INSERT INTO nodes(node_id,goal_id,kind,spec_json,spec_hash,write_set_json,state,base_sha) VALUES(?,?,?,?,?,?,?,?)",
            (node_id, goal_id, kind, canonical(spec), digest(spec), canonical(write_set), state, goal[0]),
        )
        for dependency in dependencies:
            self.connection.execute("INSERT INTO dependencies VALUES(?,?)", (node_id, dependency))
        self._event(node_id, 0, None, state, "node created", digest(spec))

    def lease(self, node_id: str, expected_version: int, owner: str, ttl_seconds: int = 300) -> dict[str, Any]:
        """Lease only when its write set does not overlap active goals in the project."""
        self.assert_static_integrity()
        if not owner or not 10 <= ttl_seconds <= 3600:
            raise ValueError("lease owner and TTL of 10..3600 seconds required")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            if row["version"] != expected_version or row["state"] != "READY":
                raise ValueError("node is not ready at expected version")
            wanted = {Path(value) for value in json.loads(row["write_set_json"])}
            active = self.connection.execute(
                "SELECT n.node_id,n.write_set_json FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
                "WHERE g.project=(SELECT project FROM goals WHERE goal_id=?) AND g.state='ACTIVE' "
                "AND n.state IN ('LEASED','RUNNING','INTEGRATING') AND n.node_id!=?",
                (row["goal_id"], node_id),
            ).fetchall()
            for other in active:
                held = {Path(value) for value in json.loads(other["write_set_json"])}
                if any(a == b or a in b.parents or b in a.parents for a in wanted for b in held):
                    raise RuntimeError(f"write-set conflict with {other['node_id']}")
            now = dt.datetime.now(dt.timezone.utc)
            lease_id = uuid.uuid4().hex
            version = expected_version + 1
            self.connection.execute(
                "UPDATE nodes SET state='LEASED',version=?,attempt=attempt+1,lease_id=?,lease_owner=?,lease_expires_at=?,heartbeat_at=?,updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND version=? AND state='READY'",
                (version, lease_id, owner, (now + dt.timedelta(seconds=ttl_seconds)).isoformat(),
                 now.isoformat(), node_id, expected_version),
            )
            self._event(node_id, version, row["state"], "LEASED", f"leased to {owner}", digest({"lease_id": lease_id}))
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return self.get_node(node_id)

    def heartbeat(self, node_id: str, lease_id: str, owner: str, ttl_seconds: int = 300) -> dict[str, Any]:
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            if (row["state"] not in {"LEASED", "RUNNING"}
                    or row["lease_id"] != lease_id or row["lease_owner"] != owner):
                raise PermissionError("lease identity mismatch")
            now = dt.datetime.now(dt.timezone.utc)
            if (dt.datetime.fromisoformat(row["lease_expires_at"]) <= now
                    or not 10 <= ttl_seconds <= 3600):
                raise PermissionError("lease expired or invalid TTL")
            self.connection.execute(
                "UPDATE nodes SET heartbeat_at=?,lease_expires_at=?,updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND lease_id=?",
                (now.isoformat(), (now + dt.timedelta(seconds=ttl_seconds)).isoformat(), node_id, lease_id),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return self.get_node(node_id)

    @staticmethod
    def _lease_is_live(row: dict[str, Any], now: dt.datetime | None = None) -> bool:
        now = now or dt.datetime.now(dt.timezone.utc)
        try:
            expiry = dt.datetime.fromisoformat(row["lease_expires_at"])
        except (TypeError, ValueError):
            return False
        return (
            expiry.tzinfo is not None
            and expiry > now
            and bool(row["lease_id"])
            and bool(row["lease_owner"])
        )

    def start(self, node_id: str, expected_version: int, lease_id: str, owner: str) -> dict[str, Any]:
        """Start only under the exact, unexpired worker lease."""
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            if (
                row["state"] != "LEASED" or row["version"] != expected_version
                or row["lease_id"] != lease_id or row["lease_owner"] != owner
                or not self._lease_is_live(row)
            ):
                raise PermissionError("worker start requires the exact unexpired lease")
            result = self._transition_locked(
                row, expected_version, "RUNNING", "worker started",
            )
            self.connection.commit()
            return result
        except Exception:
            self.connection.rollback()
            raise

    def get_node(self, node_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM nodes WHERE node_id=?", (node_id,)).fetchone()
        if not row:
            raise KeyError(node_id)
        return dict(row)

    def _assert_project_has_no_pending_publication(
        self, project: str, allowed_operation_id: str | None = None,
    ) -> None:
        pending_promotion = self.connection.execute(
            "SELECT a.attempt_id FROM integration_attempts a "
            "JOIN nodes n ON n.node_id=a.node_id "
            "JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE g.project=? AND a.status!='COMPLETED' "
            "AND (? IS NULL OR a.attempt_id!=?) LIMIT 1",
            (project, allowed_operation_id, allowed_operation_id),
        ).fetchone()
        if pending_promotion:
            raise RuntimeError("project graph is frozen by a pending publication promotion")
        pending_rollback = self.connection.execute(
            "SELECT 1 FROM publication_journal WHERE project=? AND operation_kind='ROLLBACK' "
            "AND (? IS NULL OR operation_id!=?) GROUP BY operation_id "
            "HAVING SUM(phase='COMPLETED')=0 LIMIT 1",
            (project, allowed_operation_id, allowed_operation_id),
        ).fetchone()
        if pending_rollback:
            raise RuntimeError("project graph is frozen by a prepared publication rollback")

    def _assert_node_has_no_pending_publication(
        self, row: dict[str, Any], allowed_operation_id: str | None = None,
    ) -> None:
        project = self.connection.execute(
            "SELECT project FROM goals WHERE goal_id=?", (row["goal_id"],),
        ).fetchone()
        if not project:
            raise KeyError(row["goal_id"])
        self._assert_project_has_no_pending_publication(
            project[0], allowed_operation_id,
        )

    def transition(self, node_id: str, expected_version: int, target: str, reason: str,
                   evidence: dict[str, Any] | None = None,
                   *, publication_operation_id: str | None = None) -> dict[str, Any]:
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(
                row, publication_operation_id,
            )
            result = self._transition_locked(
                row, expected_version, target, reason, evidence,
            )
            self.connection.commit()
            return result
        except Exception:
            self.connection.rollback()
            raise

    def _transition_locked(
        self, row: dict[str, Any], expected_version: int, target: str, reason: str,
        evidence: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Apply one transition inside the caller's IMMEDIATE transaction."""
        node_id = row["node_id"]
        if row["version"] != expected_version:
            raise ValueError("optimistic version conflict")
        if row["state"] in TERMINAL or target not in TRANSITIONS.get(row["state"], set()):
            raise ValueError(f"forbidden transition {row['state']} -> {target}")
        if target in {"EVIDENCE_PENDING", "EVALUATING"}:
            raise ValueError(
                "evidence states require immutable ingress and evaluator claim APIs"
            )
        if row["state"] == "EVALUATING" and self.connection.execute(
            "SELECT 1 FROM evidence_artifacts WHERE node_id=? AND claim_id IS NOT NULL",
            (node_id,),
        ).fetchone():
            raise ValueError("claimed evidence requires the evaluator disposition API")
        if target == "PASSED":
            ledger = self.connection.execute(
                "SELECT evaluation_hash FROM evaluation_ledger WHERE node_id=?", (node_id,)
            ).fetchone()
            if (row["state"] != "INTEGRATING" or not row["result_sha"] or not row["evidence_hash"]
                    or not row["evaluation_hash"] or not ledger or ledger[0] != row["evaluation_hash"]):
                raise ValueError("PASS requires the node's existing verified evaluator record")
        evidence_hash = digest(evidence) if evidence else row["evidence_hash"]
        lease_id = uuid.uuid4().hex if target == "LEASED" else row["lease_id"]
        clear_lease = target not in {"LEASED", "RUNNING"}
        attempt = row["attempt"] + (target == "LEASED")
        version = expected_version + 1
        changed = self.connection.execute(
            "UPDATE nodes SET state=?,version=?,attempt=?,lease_id=?,"
            "lease_owner=CASE WHEN ? THEN NULL ELSE lease_owner END,"
            "lease_expires_at=CASE WHEN ? THEN NULL ELSE lease_expires_at END,"
            "heartbeat_at=CASE WHEN ? THEN NULL ELSE heartbeat_at END,"
            "evidence_hash=?,updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND version=?",
            (
                target, version, attempt, None if clear_lease else lease_id,
                int(clear_lease), int(clear_lease), int(clear_lease), evidence_hash,
                node_id, expected_version,
            ),
        ).rowcount
        if changed != 1:
            raise ValueError("concurrent transition")
        self._event(
            node_id, version, row["state"], target, reason,
            evidence_hash or digest({}),
        )
        return self.get_node(node_id)

    def record_ingressed_evidence(
        self,
        node_id: str,
        expected_version: int,
        artifact: IngressArtifact,
    ) -> dict[str, Any]:
        """Bind one server-ingressed artifact and enter EVIDENCE_PENDING atomically."""
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            project_row = self.connection.execute(
                "SELECT project FROM goals WHERE goal_id=?", (row["goal_id"],)
            ).fetchone()
            if not project_row:
                raise KeyError(row["goal_id"])
            project = project_row[0]
            if row["state"] == "EVIDENCE_PENDING" and row["version"] == expected_version + 1:
                durable = register_artifact(
                    self.connection, node_id, project, artifact, expected_version,
                    row["attempt"],
                )
                if (
                    row["evidence_hash"] != durable["manifest_sha256"]
                    or row["active_artifact_id"] != durable["artifact_id"]
                ):
                    raise ValueError("artifact replay differs from node evidence")
                self.connection.commit()
                return {"node": row, "artifact": durable}
            if row["state"] != "RUNNING" or row["version"] != expected_version:
                raise ValueError("node is not awaiting ingressed evidence")
            if not self._lease_is_live(row):
                raise PermissionError("artifact ingress requires an unexpired worker lease")
            if artifact.base_sha != row["base_sha"] or artifact.candidate_sha == row["base_sha"]:
                raise PermissionError("artifact Git binding does not match the running node")
            durable = register_artifact(
                self.connection, node_id, project, artifact, expected_version,
                row["attempt"],
            )
            version = expected_version + 1
            changed = self.connection.execute(
                "UPDATE nodes SET state='EVIDENCE_PENDING',version=?,evidence_hash=?,"
                "active_artifact_id=?,lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,"
                "heartbeat_at=NULL,"
                "updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND version=? AND state='RUNNING'",
                (
                    version, artifact.manifest_sha256, artifact.artifact_id,
                    node_id, expected_version,
                ),
            ).rowcount
            if changed != 1:
                raise ValueError("concurrent evidence registration")
            self._event(
                node_id, version, "RUNNING", "EVIDENCE_PENDING",
                "immutable evaluator artifact ingressed", artifact.manifest_sha256,
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {"node": self.get_node(node_id), "artifact": get_artifact(
            self.connection, artifact.artifact_id, expected_node_id=node_id,
        )}

    def claim_evidence(
        self,
        node_id: str,
        expected_version: int,
        artifact_id: str,
        claimant: str,
        ttl_seconds: int = 600,
    ) -> dict[str, Any]:
        """Let only the evaluator claim the node artifact and enter EVALUATING."""
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            request_version = expected_version
            if row["state"] == "EVALUATING" and row["active_artifact_id"] == artifact_id:
                active = self.connection.execute(
                    "SELECT c.*,a.claim_id AS artifact_claim_id,a.node_id AS artifact_node_id "
                    "FROM evaluation_claims c JOIN evidence_artifacts a "
                    "ON a.artifact_id=c.artifact_id WHERE c.claim_id=a.claim_id "
                    "AND c.artifact_id=? AND c.status='ACTIVE'",
                    (artifact_id,),
                ).fetchone()
                if not active:
                    raise PermissionError("evaluating node has no durable active claim")
                now = dt.datetime.now(dt.timezone.utc)
                try:
                    expiry = dt.datetime.fromisoformat(active["expires_at"])
                except (TypeError, ValueError):
                    raise PermissionError("active evaluator claim has an invalid expiry") from None
                if expiry.tzinfo is None:
                    raise PermissionError("active evaluator claim expiry lacks a timezone")
                if expiry <= now:
                    if request_version != row["version"]:
                        raise ValueError("expired claim recovery requires the current graph version")
                    self._recover_claim_locked(row, active, now)
                    row = self.get_node(node_id)
                    expected_version = row["version"]
                elif (
                    row["version"] == expected_version + 2
                    and active["claim_version"] == expected_version + 1
                    and active["claimed_by"] == claimant
                ):
                    artifact = get_artifact(
                        self.connection, artifact_id, expected_node_id=node_id,
                    )
                    self.connection.commit()
                    return {"node": row, "artifact": artifact}
            if row["state"] == "EVALUATING" and row["version"] == expected_version + 1:
                artifact = claim_artifact(
                    self.connection, artifact_id, node_id, expected_version, claimant,
                    ttl_seconds,
                )
                self.connection.commit()
                return {"node": row, "artifact": artifact}
            if row["state"] != "EVIDENCE_PENDING" or row["version"] != expected_version:
                raise ValueError("node evidence is not available for this claim")
            artifact = get_artifact(
                self.connection, artifact_id, expected_node_id=node_id,
            )
            if (
                row["evidence_hash"] != artifact["manifest_sha256"]
                or row["active_artifact_id"] != artifact_id
                or row["attempt"] != artifact["attempt"]
            ):
                raise PermissionError("artifact does not match the node evidence hash")
            artifact = claim_artifact(
                self.connection, artifact_id, node_id, expected_version, claimant,
                ttl_seconds,
            )
            version = expected_version + 1
            changed = self.connection.execute(
                "UPDATE nodes SET state='EVALUATING',version=?,updated_at=CURRENT_TIMESTAMP "
                "WHERE node_id=? AND version=? AND state='EVIDENCE_PENDING'",
                (version, node_id, expected_version),
            ).rowcount
            if changed != 1:
                raise ValueError("concurrent evidence claim")
            self._event(
                node_id, version, "EVIDENCE_PENDING", "EVALUATING",
                "independent evaluator claimed immutable artifact",
                digest({"artifact_id": artifact_id, "claim_id": artifact["claim_id"]}),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {"node": self.get_node(node_id), "artifact": get_artifact(
            self.connection, artifact_id, expected_node_id=node_id,
        )}

    def heartbeat_evidence_claim(
        self,
        node_id: str,
        expected_version: int,
        artifact_id: str,
        claim_id: str,
        claimant: str,
        ttl_seconds: int = 600,
    ) -> dict[str, Any]:
        """Extend only the exact claim for the active artifact and graph version."""
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            if (
                row["state"] != "EVALUATING"
                or row["version"] != expected_version
                or row["active_artifact_id"] != artifact_id
            ):
                raise PermissionError("claim heartbeat requires the exact evaluating node")
            claim = heartbeat_claim(
                self.connection, artifact_id, node_id, claim_id,
                expected_version - 1, claimant, ttl_seconds,
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {"node": self.get_node(node_id), "claim": claim}

    def record_evaluation(
        self,
        node_id: str,
        expected_version: int,
        artifact_id: str,
        evaluation: dict[str, Any],
        evidence_manifest: Path,
    ) -> dict[str, Any]:
        """Verify and persist one signed PASS as immutable content-addressed bytes."""
        self.assert_static_integrity()
        if self.evaluator_public_key is None or self.rubric_sha256 is None:
            raise PermissionError("evaluator public key and frozen rubric hash are not configured")
        row = self.get_node(node_id)
        self._assert_node_has_no_pending_publication(row)
        if row["state"] == "PASSED" and row["version"] == expected_version + 1:
            outcome = self.connection.execute(
                "SELECT outcome_id FROM evaluation_outcomes WHERE node_id=? AND artifact_id=?",
                (node_id, artifact_id),
            ).fetchone()
            if not outcome:
                raise PermissionError("passed node has no durable evaluation outcome")
            _, durable_evaluation = self.verify_recorded_outcome(
                node_id, outcome["outcome_id"], artifact_id, evidence_manifest,
            )
            if durable_evaluation != evaluation:
                raise ValueError("evaluation replay differs from durable outcome")
            return {"node": row, "outcome": get_outcome(
                self.connection, outcome["outcome_id"],
                expected_artifact_id=artifact_id, expected_node_id=node_id,
            )}
        if row["state"] != "EVALUATING" or row["version"] != expected_version:
            raise ValueError("node is not awaiting this evaluation")
        artifact = get_artifact(
            self.connection, artifact_id, expected_node_id=node_id,
        )
        if (
            row["active_artifact_id"] != artifact_id
            or row["evidence_hash"] != artifact["manifest_sha256"]
            or row["attempt"] != artifact["attempt"]
        ):
            raise PermissionError("evaluation artifact is not the node's active attempt")
        claim = get_active_claim(
            self.connection, artifact_id, expected_node_id=node_id,
            expected_claimant="hermes-evaluator",
        )
        if claim["claim_version"] != expected_version - 1:
            raise PermissionError("evaluation claim is not bound to the graph version")
        contract_id = json.loads(row["spec_json"])["evaluator_contract_id"]
        previous_row = self.connection.execute(
            "SELECT ledger_hash FROM evaluation_ledger ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_ledger_hash = previous_row[0] if previous_row else None
        verify_evaluation(
            evaluation, self.evaluator_public_key, evidence_manifest, self.rubric_sha256,
            expected_task_id=node_id, expected_contract_id=contract_id,
            expected_artifact_id=artifact_id, expected_claim_id=claim["claim_id"],
            expected_previous_ledger_hash=previous_ledger_hash,
        )
        result_sha = evaluation["evaluated_git_sha"]
        evaluation_hash = digest(evaluation)
        version = expected_version + 1
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            if row["state"] != "EVALUATING" or row["version"] != expected_version:
                raise ValueError("node is not awaiting this evaluation")
            current_previous = self.connection.execute(
                "SELECT ledger_hash FROM evaluation_ledger ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if (current_previous[0] if current_previous else None) != previous_ledger_hash:
                raise ValueError("concurrent evaluator ledger append")
            artifact = get_artifact(
                self.connection, artifact_id, expected_node_id=node_id,
            )
            get_active_claim(
                self.connection, artifact_id, expected_node_id=node_id,
                expected_claimant="hermes-evaluator",
            )
            if (
                artifact["manifest_sha256"] != evaluation["evidence_manifest_sha256"]
                or artifact["candidate_sha"] != result_sha
                or row["active_artifact_id"] != artifact_id
            ):
                raise PermissionError("active evaluator claim differs from the verified evaluation")
            outcome = store_outcome(
                self.connection, artifact_id, node_id, evaluation,
            )
            resolve_claim(
                self.connection, artifact_id, node_id,
                artifact["claimed_by"], evaluation_hash,
            )
            changed = self.connection.execute(
                "UPDATE nodes SET state='PASSED',version=?,result_sha=?,evaluation_hash=?,evidence_hash=?,updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND version=?",
                (version, result_sha, evaluation_hash, evaluation["evidence_manifest_sha256"], node_id, expected_version),
            ).rowcount
            if changed != 1:
                raise ValueError("concurrent evaluation")
            self.connection.execute(
                "INSERT INTO evaluation_ledger(node_id,task_id,contract_id,evaluation_hash,previous_ledger_hash,ledger_hash) "
                "VALUES(?,?,?,?,?,?)",
                (node_id, evaluation["task_id"], evaluation["contract_id"], evaluation_hash,
                 evaluation["previous_ledger_hash"], evaluation["ledger_hash"]),
            )
            self._event(node_id, version, row["state"], "PASSED", "verified independent evaluation", evaluation_hash)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {"node": self.get_node(node_id), "outcome": get_outcome(
            self.connection, outcome["outcome_id"],
            expected_artifact_id=artifact_id, expected_node_id=node_id,
        )}

    def reject_evidence(
        self,
        node_id: str,
        expected_version: int,
        artifact_id: str,
        disposition: str,
        reason_sha256: str,
        claimant: str,
    ) -> dict[str, Any]:
        """Resolve a claimed artifact without creating any PASS or promotion record."""
        self.assert_static_integrity()
        if disposition not in EVIDENCE_DISPOSITIONS:
            raise ValueError("evaluator disposition must be RETRY, FAILED_GATE, or NEEDS_HUMAN")
        target = {
            "RETRY": "READY",
            "FAILED_GATE": "FAILED_GATE",
            "NEEDS_HUMAN": "NEEDS_HUMAN",
        }[disposition]
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(row)
            if row["state"] == target and row["version"] == expected_version + 1:
                claim = self.connection.execute(
                    "SELECT * FROM evaluation_claims WHERE artifact_id=? AND node_id=? "
                    "AND claim_version=?",
                    (artifact_id, node_id, expected_version - 1),
                ).fetchone()
                if not claim or (
                    claim["status"], claim["disposition"], claim["reason_sha256"]
                ) != ("DISPOSED", disposition, reason_sha256):
                    raise ValueError("evaluator disposition replay differs from durable state")
                self.connection.commit()
                return {"node": row, "claim": dict(claim)}
            if row["state"] != "EVALUATING" or row["version"] != expected_version:
                raise ValueError("node is not awaiting this evaluator disposition")
            claim = get_active_claim(
                self.connection, artifact_id, expected_node_id=node_id,
                expected_claimant=claimant,
            )
            if claim["claim_version"] != expected_version - 1:
                raise ValueError("evaluator disposition does not match the claimed graph version")
            resolved = resolve_claim(
                self.connection, artifact_id, node_id, claimant, reason_sha256,
                disposition=disposition,
            )
            version = expected_version + 1
            changed = self.connection.execute(
                "UPDATE nodes SET state=?,version=?,"
                "active_artifact_id=CASE WHEN ?='RETRY' THEN NULL ELSE active_artifact_id END,"
                "evidence_hash=CASE WHEN ?='RETRY' THEN NULL ELSE evidence_hash END,"
                "result_sha=CASE WHEN ?='RETRY' THEN NULL ELSE result_sha END,"
                "evaluation_hash=CASE WHEN ?='RETRY' THEN NULL ELSE evaluation_hash END,"
                "lease_id=NULL,lease_owner=NULL,lease_expires_at=NULL,heartbeat_at=NULL,"
                "updated_at=CURRENT_TIMESTAMP "
                "WHERE node_id=? AND version=? AND state='EVALUATING'",
                (
                    target, version, disposition, disposition, disposition, disposition,
                    node_id, expected_version,
                ),
            ).rowcount
            if changed != 1:
                raise ValueError("concurrent evaluator disposition")
            self._event(
                node_id, version, "EVALUATING", target,
                f"independent evaluator disposition {disposition}", reason_sha256,
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return {"node": self.get_node(node_id), "claim": resolved}

    def validate_recorded_outcome(
        self,
        node_id: str,
        outcome_id: str,
        artifact_id: str,
        evidence_manifest: Path,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Authorize integration state, then reverify the recorded signed outcome."""
        row = self.get_node(node_id)
        if row["state"] not in {"PASSED", "INTEGRATING", "INTEGRATED"}:
            raise PermissionError("only a passed node may enter or recover integration")
        return self.verify_recorded_outcome(
            node_id, outcome_id, artifact_id, evidence_manifest,
        )

    def verify_recorded_outcome(
        self,
        node_id: str,
        outcome_id: str,
        artifact_id: str,
        evidence_manifest: Path,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """State-independently reverify one canonical outcome and its full DB closure."""
        if self.evaluator_public_key is None or self.rubric_sha256 is None:
            raise PermissionError("evaluator public key and frozen rubric hash are not configured")
        row = self.get_node(node_id)
        try:
            contract_id = json.loads(row["spec_json"])["evaluator_contract_id"]
        except (KeyError, TypeError, json.JSONDecodeError):
            raise PermissionError("recorded node evaluator contract is invalid") from None
        context = self.connection.execute(
            "SELECT project FROM goals WHERE goal_id=?", (row["goal_id"],),
        ).fetchone()
        if not context:
            raise PermissionError("recorded outcome node lost its project goal")
        outcome = get_outcome(
            self.connection, outcome_id,
            expected_artifact_id=artifact_id, expected_node_id=node_id,
        )
        evaluation = outcome["evaluation"]
        artifact = get_artifact(
            self.connection, artifact_id, expected_node_id=node_id,
            expected_project=context["project"],
        )
        if (
            row["active_artifact_id"] != artifact_id
            or row["attempt"] != artifact["attempt"]
            or artifact["task_id"] != node_id
            or row["base_sha"] != artifact["base_sha"]
            or artifact["manifest_sha256"] != evaluation.get("evidence_manifest_sha256")
            or artifact["candidate_sha"] != evaluation.get("evaluated_git_sha")
            or outcome["evaluation_sha256"] != digest(evaluation)
        ):
            raise PermissionError("durable outcome/artifact/node binding is invalid")
        claim = self.connection.execute(
            "SELECT * FROM evaluation_claims WHERE claim_id=?",
            (evaluation.get("claim_id"),),
        ).fetchone()
        if (
            not claim
            or claim["artifact_id"] != artifact_id
            or claim["node_id"] != node_id
            or claim["claimed_by"] != "hermes-evaluator"
            or claim["status"] != "EVALUATED"
            or claim["disposition"] is not None
            or claim["reason_sha256"] != digest(evaluation)
            or type(claim["claim_version"]) is not int
            or claim["claim_version"] < 0
            or claim["claim_id"] != deterministic_claim_id(
                artifact_id, node_id, claim["claim_version"], "hermes-evaluator",
            )
            or not isinstance(claim["resolved_at"], str)
            or not claim["resolved_at"]
            or (
                artifact["claim_id"], artifact["claimed_by"],
                artifact["claim_version"], artifact["claimed_at"],
            ) != (None, None, None, None)
        ):
            raise PermissionError("durable outcome is not bound to its resolved evaluator claim")
        competing_claims = self.connection.execute(
            "SELECT COUNT(*) FROM evaluation_claims WHERE status='EVALUATED' "
            "AND (artifact_id=? OR node_id=?)",
            (artifact_id, node_id),
        ).fetchone()[0]
        if competing_claims != 1:
            raise PermissionError("durable outcome has ambiguous evaluated-claim closure")
        ledger = self.connection.execute(
            "SELECT * FROM evaluation_ledger WHERE node_id=?", (node_id,)
        ).fetchone()
        if (
            not ledger
            or row["evaluation_hash"] != digest(evaluation)
            or ledger["node_id"] != node_id
            or ledger["task_id"] != node_id
            or ledger["contract_id"] != contract_id
            or ledger["evaluation_hash"] != row["evaluation_hash"]
            or ledger["previous_ledger_hash"] != evaluation.get("previous_ledger_hash")
            or ledger["ledger_hash"] != evaluation.get("ledger_hash")
            or evaluation.get("task_id") != node_id
            or evaluation.get("contract_id") != contract_id
            or evaluation.get("artifact_id") != artifact_id
            or evaluation.get("claim_id") != claim["claim_id"]
        ):
            raise PermissionError("evaluation does not match the node's recorded PASS")
        verify_evaluation(
            evaluation, self.evaluator_public_key, evidence_manifest, self.rubric_sha256,
            expected_task_id=node_id, expected_contract_id=contract_id,
            expected_artifact_id=artifact_id,
            expected_claim_id=claim["claim_id"],
            expected_previous_ledger_hash=ledger["previous_ledger_hash"],
        )
        if row["result_sha"] != evaluation["evaluated_git_sha"]:
            raise PermissionError("evaluation candidate does not match the node's recorded result")
        if row["evidence_hash"] != evaluation["evidence_manifest_sha256"]:
            raise PermissionError("evaluation evidence does not match the node's recorded evidence")
        return row, evaluation

    def record_integration(
        self, node_id: str, expected_version: int, integration_sha: str,
        *, publication_operation_id: str | None = None,
    ) -> dict[str, Any]:
        self.assert_static_integrity()
        if len(integration_sha) != 40:
            raise ValueError("integration SHA is invalid")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.get_node(node_id)
            self._assert_node_has_no_pending_publication(
                row, publication_operation_id,
            )
            if row["state"] != "INTEGRATING" or row["version"] != expected_version:
                raise ValueError("node is not awaiting integration")
            result = self._record_integration_locked(
                row, expected_version, integration_sha,
            )
            # Public callers cannot commit an INTEGRATED event without the exact
            # already-completed durable attempt. Coordinator finalization uses
            # the locked helper and its explicitly bounded same-transaction
            # BINDING_UPDATED transient instead.
            self.assert_static_integrity()
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return result

    def _record_integration_locked(
        self, row: dict[str, Any], expected_version: int, integration_sha: str,
    ) -> dict[str, Any]:
        """Record the integrated origin inside the coordinator's transaction."""
        if row["state"] != "INTEGRATING" or row["version"] != expected_version:
            raise ValueError("node is not awaiting integration")
        version = expected_version + 1
        changed = self.connection.execute(
            "UPDATE nodes SET state='INTEGRATED',version=?,integration_sha=?,"
            "updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND version=?",
            (version, integration_sha, row["node_id"], expected_version),
        ).rowcount
        if changed != 1:
            raise ValueError("concurrent integration record")
        self._event(
            row["node_id"], version, row["state"], "INTEGRATED",
            "verified atomic integration", integration_sha,
        )
        return self.get_node(row["node_id"])

    def reconcile_worker(self, node_id: str, expected_version: int, returncode: int,
                         controller_state: str | None, evidence: dict[str, Any] | None) -> dict[str, Any]:
        """Never equate rc=0 with success; require controller state and evidence."""
        if returncode == 0 and controller_state == "EVIDENCE_PENDING" and evidence:
            return self.transition(
                node_id, expected_version, "READY",
                "legacy reconcile cannot admit evidence; immutable ingress is required",
            )
        if returncode == 0 and not controller_state:
            return self.transition(node_id, expected_version, "READY", "unknown controller state; safe retry")
        return self.transition(node_id, expected_version, "READY", f"worker rc={returncode}; retryable")

    def recover_leases(self, force_startup: bool = False) -> int:
        self.assert_static_integrity()
        recovered_claims = self.recover_evaluator_claims()
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        rows = self.connection.execute(
            "SELECT node_id,version,state FROM nodes WHERE "
            "state IN ('LEASED','RUNNING') AND (? OR lease_expires_at<=?)",
            (int(force_startup), now),
        ).fetchall()
        integration_table = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='integration_attempts'"
        ).fetchone()
        integrating = self.connection.execute(
            "SELECT node_id,version,state FROM nodes WHERE state='INTEGRATING'"
        ).fetchall()
        for row in integrating:
            if integration_table and self.connection.execute(
                "SELECT 1 FROM integration_attempts WHERE node_id=? AND status!='COMPLETED'",
                (row["node_id"],),
            ).fetchone():
                # The coordinator owns recovery once an integration journal has
                # been prepared.  Generic lease cleanup must not erase evidence
                # of a ref/publication/binding operation in flight.
                continue
            rows.append(row)
        for row in rows:
            target = "PASSED" if row["state"] == "INTEGRATING" else "READY"
            self.transition(row["node_id"], row["version"], target, "startup lease recovery")
        return recovered_claims + len(rows)

    def recover_evaluator_claims(self, now: dt.datetime | None = None) -> int:
        """Event and release every expired claim without discarding its artifact."""
        self.assert_static_integrity()
        now = now or dt.datetime.now(dt.timezone.utc)
        if now.tzinfo is None:
            raise ValueError("claim recovery clock must be timezone-aware")
        rows = self.connection.execute(
            "SELECT c.*,a.claim_id AS artifact_claim_id,a.node_id AS artifact_node_id "
            "FROM evaluation_claims c JOIN evidence_artifacts a ON a.artifact_id=c.artifact_id "
            "WHERE c.status='ACTIVE' ORDER BY c.claimed_at,c.claim_id"
        ).fetchall()
        expired: list[sqlite3.Row] = []
        for row in rows:
            try:
                expiry = dt.datetime.fromisoformat(row["expires_at"])
            except (TypeError, ValueError):
                raise PermissionError("active evaluator claim has an invalid expiry") from None
            if expiry.tzinfo is None:
                raise PermissionError("active evaluator claim expiry lacks a timezone")
            if expiry <= now:
                expired.append(row)
        if not expired:
            return 0
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            for claim in expired:
                node = self.get_node(claim["node_id"])
                self._assert_node_has_no_pending_publication(node)
                self._recover_claim_locked(node, claim, now)
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        return len(expired)

    def _recover_claim_locked(
        self, node: dict[str, Any], claim: sqlite3.Row, now: dt.datetime,
    ) -> None:
        """Recover one proven-overdue claim inside the caller's IMMEDIATE transaction."""
        if (
            node["state"] != "EVALUATING"
            or node["active_artifact_id"] != claim["artifact_id"]
            or claim["artifact_claim_id"] != claim["claim_id"]
            or claim["artifact_node_id"] != claim["node_id"]
            or claim["claim_version"] != node["version"] - 1
        ):
            raise PermissionError("expired evaluator claim disagrees with graph state")
        try:
            expiry = dt.datetime.fromisoformat(claim["expires_at"])
        except (TypeError, ValueError):
            raise PermissionError("active evaluator claim has an invalid expiry") from None
        if expiry.tzinfo is None or expiry > now:
            raise PermissionError("evaluator claim is not recoverably expired")
        reason_hash = digest({
            "claim_id": claim["claim_id"],
            "expired_at": claim["expires_at"],
            "recovered_at": now.isoformat(),
        })
        expire_claim(
            self.connection, claim["artifact_id"], claim["node_id"],
            reason_hash, now=now,
        )
        version = node["version"] + 1
        changed = self.connection.execute(
            "UPDATE nodes SET state='EVIDENCE_PENDING',version=?,"
            "updated_at=CURRENT_TIMESTAMP WHERE node_id=? AND version=? "
            "AND state='EVALUATING' AND active_artifact_id=?",
            (version, claim["node_id"], node["version"], claim["artifact_id"]),
        ).rowcount
        if changed != 1:
            raise ValueError("concurrent evaluator claim recovery")
        self._event(
            claim["node_id"], version, "EVALUATING", "EVIDENCE_PENDING",
            "expired evaluator claim recovered", reason_hash,
        )

    def assert_static_integrity(
        self, *, allow_completion_append_transient: bool = False,
    ) -> None:
        """Verify every DB-only route, graph, claim, and evaluator-ledger closure."""
        foreign = self.connection.execute("PRAGMA foreign_key_check").fetchone()
        if foreign is not None:
            raise RuntimeError("graph database contains a foreign-key violation")

        route_columns = (
            ("goals", "project", False),
            ("evidence_artifacts", "project", False),
            ("buzz_threads", "project", False),
            ("buzz_ingress_responses", "route", True),
            ("publication_heads", "project", False),
            ("publication_journal", "project", False),
        )
        for table, column, nullable in route_columns:
            values = {
                row[0] for row in self.connection.execute(
                    f"SELECT DISTINCT {column} FROM {table}"
                ).fetchall()
            }
            invalid = {
                value for value in values
                if not (nullable and value is None) and value not in ACTIVE_PROJECTS
            }
            if invalid:
                raise RuntimeError(
                    f"{table}.{column} contains a route outside the exact active set: "
                    f"{sorted(map(repr, invalid))}"
                )
        invalid_thread = self.connection.execute(
            "SELECT t.thread_id FROM buzz_threads t LEFT JOIN goals g ON g.goal_id=t.goal_id "
            "WHERE g.goal_id IS NULL OR t.project!=g.project ORDER BY t.thread_id LIMIT 1"
        ).fetchone()
        if invalid_thread:
            raise RuntimeError(
                "Buzz thread is not bound to one existing same-project goal: "
                f"{invalid_thread['thread_id']}"
            )
        invalid_artifact_route = self.connection.execute(
            "SELECT a.artifact_id FROM evidence_artifacts a "
            "JOIN nodes n ON n.node_id=a.node_id "
            "JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE a.project!=g.project ORDER BY a.artifact_id LIMIT 1"
        ).fetchone()
        if invalid_artifact_route:
            raise RuntimeError(
                "evidence artifact is bound across graph projects: "
                f"{invalid_artifact_route['artifact_id']}"
            )
        invalid_active_artifact = self.connection.execute(
            "SELECT n.node_id FROM nodes n "
            "LEFT JOIN evidence_artifacts a ON a.artifact_id=n.active_artifact_id "
            "WHERE n.active_artifact_id IS NOT NULL AND (a.artifact_id IS NULL "
            "OR a.node_id!=n.node_id OR a.attempt!=n.attempt "
            "OR a.manifest_sha256 IS NOT n.evidence_hash) "
            "ORDER BY n.node_id LIMIT 1"
        ).fetchone()
        if invalid_active_artifact:
            raise RuntimeError(
                "node active artifact pointer is not graph-closed: "
                f"{invalid_active_artifact['node_id']}"
            )

        orphan_attempt = self.connection.execute(
            "SELECT a.attempt_id FROM integration_attempts a "
            "LEFT JOIN nodes n ON n.node_id=a.node_id WHERE n.node_id IS NULL LIMIT 1"
        ).fetchone()
        if orphan_attempt:
            raise RuntimeError(
                f"integration attempt lost its graph node: {orphan_attempt['attempt_id']}"
            )
        orphan_event = self.connection.execute(
            "SELECT e.node_id FROM events e LEFT JOIN nodes n ON n.node_id=e.node_id "
            "WHERE n.node_id IS NULL LIMIT 1"
        ).fetchone()
        if orphan_event:
            raise RuntimeError(f"event chain references a missing node: {orphan_event['node_id']}")
        for row in self.connection.execute(
            "SELECT node_id FROM nodes ORDER BY node_id"
        ).fetchall():
            if not self.verify_event_chain(row["node_id"]):
                raise RuntimeError(f"node event chain is invalid: {row['node_id']}")

        self._assert_completed_promotion_origin_integrity(
            allow_completion_append_transient=allow_completion_append_transient,
        )
        self._assert_evaluation_integrity()
        self._assert_integration_event_integrity(
            allow_completion_append_transient=allow_completion_append_transient,
        )

    def _assert_completed_promotion_origin_integrity(
        self, *, allow_completion_append_transient: bool,
    ) -> None:
        """Bind completed attempts/origins to one immutable promotion completion."""
        completed_attempt_ids: set[str] = set()
        for raw_attempt in self.connection.execute(
            "SELECT a.*,n.goal_id,n.base_sha AS origin_base_sha,"
            "n.state AS origin_state,n.integration_sha AS origin_integration_sha,"
            "n.result_sha AS origin_result_sha,"
            "g.project AS graph_project,e.node_id AS artifact_node_id,"
            "e.base_sha AS artifact_base_sha FROM integration_attempts a "
            "JOIN nodes n ON n.node_id=a.node_id "
            "JOIN goals g ON g.goal_id=n.goal_id "
            "JOIN evidence_artifacts e ON e.artifact_id=a.artifact_id "
            "WHERE a.status='COMPLETED' ORDER BY a.attempt_id"
        ).fetchall():
            attempt = dict(raw_attempt)
            rows = self.connection.execute(
                "SELECT * FROM publication_journal WHERE operation_kind='PROMOTION' "
                "AND phase='COMPLETED' AND (operation_id=? OR integration_attempt_id=?) "
                "ORDER BY sequence",
                (attempt["attempt_id"], attempt["attempt_id"]),
            ).fetchall()
            if len(rows) != 1:
                raise RuntimeError(
                    "completed integration attempt lacks one exact promotion journal: "
                    f"{attempt['attempt_id']}"
                )
            entry = rows[0]
            if (
                entry["operation_id"] != attempt["attempt_id"]
                or entry["integration_attempt_id"] != attempt["attempt_id"]
                or entry["node_id"] != attempt["node_id"]
                or entry["goal_id"] != attempt["goal_id"]
                or entry["project"] != attempt["graph_project"]
                or entry["from_sha"] != attempt["expected_base_sha"]
                or entry["from_generation"] != attempt["expected_base_sha"]
                or attempt["origin_base_sha"] != attempt["expected_base_sha"]
                or attempt["origin_state"] != "INTEGRATED"
                or attempt["origin_integration_sha"] != attempt["integration_sha"]
                or attempt["origin_result_sha"] != attempt["candidate_sha"]
                or attempt["artifact_node_id"] != attempt["node_id"]
                or attempt["artifact_base_sha"] != attempt["expected_base_sha"]
                or attempt["candidate_sha"] != attempt["integration_sha"]
                or attempt["publication_generation"] != attempt["integration_sha"]
                or entry["to_sha"] != attempt["integration_sha"]
                or entry["to_generation"] != attempt["publication_generation"]
            ):
                raise RuntimeError(
                    "completed promotion origin base/attempt/journal binding is invalid: "
                    f"{attempt['node_id']}/{attempt['attempt_id']}"
                )
            try:
                affected = json.loads(entry["affected_graph_json"])
            except (TypeError, json.JSONDecodeError):
                raise RuntimeError(
                    "completed promotion origin snapshot is invalid"
                ) from None
            affected_nodes = affected.get("nodes") if isinstance(affected, dict) else None
            affected_goals = affected.get("goals") if isinstance(affected, dict) else None
            origin_rows = [
                origin for origin in affected.get("nodes", [])
                if isinstance(origin, dict)
                and origin.get("node_id") == attempt["node_id"]
                and origin.get("goal_id") == attempt["goal_id"]
                and origin.get("base_sha") == attempt["expected_base_sha"]
            ] if isinstance(affected_nodes, list) else []
            origin_goals = [
                goal for goal in affected_goals
                if isinstance(goal, dict)
                and goal.get("goal_id") == attempt["goal_id"]
                and goal.get("accepted_sha") == attempt["expected_base_sha"]
            ] if isinstance(affected_goals, list) else []
            if (
                not isinstance(affected, dict)
                or not isinstance(affected_nodes, list)
                or not isinstance(affected_goals, list)
                or entry["affected_graph_json"] != canonical(affected)
                or entry["affected_graph_sha256"] != digest(affected)
                or affected.get("project") != attempt["graph_project"]
                or affected.get("from_sha") != attempt["expected_base_sha"]
                or len(origin_rows) != 1
                or len(origin_goals) != 1
            ):
                raise RuntimeError(
                    "completed promotion origin snapshot/base binding is invalid"
                )
            completed_attempt_ids.add(attempt["attempt_id"])

        for entry in self.connection.execute(
            "SELECT operation_id,integration_attempt_id FROM publication_journal "
            "WHERE operation_kind='PROMOTION' AND phase='COMPLETED' ORDER BY sequence"
        ).fetchall():
            if (
                entry["operation_id"] != entry["integration_attempt_id"]
                or entry["integration_attempt_id"] not in completed_attempt_ids
            ):
                raise RuntimeError(
                    "completed integration attempt is missing from its exact promotion journal"
                )

        for node in self.connection.execute(
            "SELECT node_id,goal_id,base_sha,integration_sha FROM nodes "
            "WHERE state='INTEGRATED' OR integration_sha IS NOT NULL ORDER BY node_id"
        ).fetchall():
            attempts = self.connection.execute(
                "SELECT attempt_id,expected_base_sha FROM integration_attempts "
                "WHERE node_id=? AND status='COMPLETED' AND integration_sha=?",
                (node["node_id"], node["integration_sha"]),
            ).fetchall()
            if len(attempts) == 1:
                attempt = attempts[0]
                if (
                    node["base_sha"] != attempt["expected_base_sha"]
                    or attempt["attempt_id"] not in completed_attempt_ids
                ):
                    raise RuntimeError(
                        "completed integration origin base differs from its immutable promotion"
                    )
                continue
            if allow_completion_append_transient and not attempts:
                pending = self.connection.execute(
                    "SELECT attempt_id,expected_base_sha FROM integration_attempts "
                    "WHERE node_id=? AND status='BINDING_UPDATED' AND integration_sha=?",
                    (node["node_id"], node["integration_sha"]),
                ).fetchall()
                if len(pending) == 1 and node["base_sha"] == pending[0]["expected_base_sha"]:
                    continue
            raise RuntimeError(
                "integrated origin lacks one exact completed integration attempt/promotion"
            )

    def _assert_integration_event_integrity(
        self, *, allow_completion_append_transient: bool,
    ) -> None:
        """Bind every integrated node event to its exact durable completion attempt."""
        allowed_statuses = {"COMPLETED"}
        if allow_completion_append_transient:
            # ProjectCoordinator enables this only inside its IMMEDIATE completion
            # transaction, after BINDING_UPDATED and before the journal append and
            # COMPLETED compare-and-swap commit together.
            allowed_statuses.add("BINDING_UPDATED")
        for node in self.connection.execute(
            "SELECT node_id,state,version,integration_sha FROM nodes "
            "WHERE state='INTEGRATED' OR integration_sha IS NOT NULL "
            "ORDER BY node_id"
        ).fetchall():
            if (
                node["state"] != "INTEGRATED"
                or not isinstance(node["integration_sha"], str)
                or len(node["integration_sha"]) != 40
                or any(
                    character not in "0123456789abcdef"
                    for character in node["integration_sha"]
                )
            ):
                raise RuntimeError("integrated node SHA/state binding is invalid")
            events = self.connection.execute(
                "SELECT version,old_state,new_state,reason,payload_hash FROM events "
                "WHERE node_id=? AND old_state='INTEGRATING' AND new_state='INTEGRATED'",
                (node["node_id"],),
            ).fetchall()
            if len(events) != 1 or (
                events[0]["version"], events[0]["reason"],
                events[0]["payload_hash"],
            ) != (
                node["version"], "verified atomic integration",
                node["integration_sha"],
            ):
                raise RuntimeError("integrated node resolution event is invalid")
            attempts = self.connection.execute(
                "SELECT attempt_id,status,candidate_sha,integration_sha "
                "FROM integration_attempts WHERE node_id=? AND integration_sha=? "
                "ORDER BY attempt_id",
                (node["node_id"], node["integration_sha"]),
            ).fetchall()
            matching = [
                attempt for attempt in attempts
                if attempt["status"] in allowed_statuses
                and attempt["candidate_sha"] == node["integration_sha"]
            ]
            if len(attempts) != 1 or len(matching) != 1:
                raise RuntimeError(
                    "integrated node lacks one exact completed integration attempt"
                )

    def _assert_evaluation_integrity(self) -> None:
        """Close claims and the global evaluator ledger over canonical outcomes."""
        claim_rows = [dict(row) for row in self.connection.execute(
            "SELECT * FROM evaluation_claims ORDER BY claimed_at,claim_id"
        ).fetchall()]
        claims = {row["claim_id"]: row for row in claim_rows}
        if len(claims) != len(claim_rows):
            raise RuntimeError("evaluator claim identity is duplicated")

        for claim in claim_rows:
            status = claim["status"]
            if status not in CLAIM_STATUSES:
                raise RuntimeError("evaluator claim status is invalid")
            if (
                claim["claimed_by"] != EVALUATOR_IDENTITY
                or type(claim["claim_version"]) is not int
                or claim["claim_version"] < 0
                or claim["claim_id"] != deterministic_claim_id(
                    claim["artifact_id"], claim["node_id"],
                    claim["claim_version"], claim["claimed_by"],
                )
            ):
                raise RuntimeError("evaluator claim deterministic identity is invalid")
            for field in ("claimed_at", "heartbeat_at", "expires_at"):
                _claim_timestamp(claim[field], field, timezone_required=True)
            if status == "ACTIVE":
                if (
                    claim["disposition"], claim["reason_sha256"],
                    claim["resolved_at"],
                ) != (None, None, None):
                    raise RuntimeError("active evaluator claim has terminal resolution metadata")
            else:
                if not _is_sha256(claim["reason_sha256"]):
                    raise RuntimeError("terminal evaluator claim resolution hash is invalid")
                _claim_timestamp(
                    claim["resolved_at"], "resolved_at", timezone_required=False,
                )
                if status == "EVALUATED" and claim["disposition"] is not None:
                    raise RuntimeError("evaluated claim has a disposition")
                if status == "DISPOSED" and claim["disposition"] not in CLAIM_DISPOSITION_TARGETS:
                    raise RuntimeError("disposed evaluator claim disposition is invalid")
                if status == "EXPIRED" and (
                    claim["disposition"] != "EXPIRED"
                    or claim["reason_sha256"] != _expired_claim_reason(claim)
                ):
                    raise RuntimeError("expired evaluator claim resolution binding is invalid")
            try:
                artifact = get_artifact(
                    self.connection, claim["artifact_id"],
                    expected_node_id=claim["node_id"],
                )
            except (KeyError, PermissionError, TypeError, ValueError) as exc:
                raise RuntimeError("evaluator claim lost its artifact binding") from exc
            event = self.connection.execute(
                "SELECT old_state,new_state,reason,payload_hash FROM events "
                "WHERE node_id=? AND version=?",
                (claim["node_id"], claim["claim_version"] + 1),
            ).fetchone()
            if not event or (
                event["old_state"], event["new_state"], event["reason"],
                event["payload_hash"],
            ) != (
                "EVIDENCE_PENDING", "EVALUATING",
                "independent evaluator claimed immutable artifact",
                digest({
                    "artifact_id": claim["artifact_id"],
                    "claim_id": claim["claim_id"],
                }),
            ):
                raise RuntimeError("evaluator claim is not bound to its exact graph event")
            if status == "ACTIVE":
                node = self.get_node(claim["node_id"])
                if (
                    node["state"] != "EVALUATING"
                    or node["version"] != claim["claim_version"] + 1
                    or node["active_artifact_id"] != claim["artifact_id"]
                    or (
                        artifact["claim_id"], artifact["claimed_by"],
                        artifact["claim_version"], artifact["claimed_at"],
                    ) != (
                        claim["claim_id"], claim["claimed_by"],
                        claim["claim_version"], claim["claimed_at"],
                    )
                ):
                    raise RuntimeError("active evaluator claim pointer is not graph-closed")
                continue

            target: str
            reason: str
            if status == "EVALUATED":
                target = "PASSED"
                reason = "verified independent evaluation"
            elif status == "DISPOSED":
                target = CLAIM_DISPOSITION_TARGETS[claim["disposition"]]
                reason = f"independent evaluator disposition {claim['disposition']}"
            else:
                target = "EVIDENCE_PENDING"
                reason = "expired evaluator claim recovered"
            resolution_event = self.connection.execute(
                "SELECT old_state,new_state,reason,payload_hash FROM events "
                "WHERE node_id=? AND version=?",
                (claim["node_id"], claim["claim_version"] + 2),
            ).fetchone()
            if not resolution_event or (
                resolution_event["old_state"], resolution_event["new_state"],
                resolution_event["reason"], resolution_event["payload_hash"],
            ) != (
                "EVALUATING", target, reason, claim["reason_sha256"],
            ):
                raise RuntimeError(
                    f"{status.lower()} evaluator claim resolution event is invalid"
                )

            pointer = (
                artifact["claim_id"], artifact["claimed_by"],
                artifact["claim_version"], artifact["claimed_at"],
            )
            if pointer != (None, None, None, None):
                # Expiry can be followed by a later claim of the same immutable
                # artifact.  The terminal claim must never remain selected, but
                # a strictly later ACTIVE pointer is a valid historical flow.
                pointed_claim = claims.get(artifact["claim_id"])
                if (
                    not pointed_claim
                    or pointed_claim["status"] != "ACTIVE"
                    or pointed_claim["artifact_id"] != claim["artifact_id"]
                    or pointed_claim["claim_version"] <= claim["claim_version"]
                ):
                    raise RuntimeError("terminal evaluator claim left a stale artifact pointer")

        for artifact in self.connection.execute(
            "SELECT * FROM evidence_artifacts ORDER BY artifact_id"
        ).fetchall():
            pointer = (
                artifact["claim_id"], artifact["claimed_by"],
                artifact["claim_version"], artifact["claimed_at"],
            )
            if artifact["claim_id"] is None:
                if pointer != (None, None, None, None):
                    raise RuntimeError("artifact has a partial evaluator claim pointer")
                continue
            claim = claims.get(artifact["claim_id"])
            if not claim or claim["status"] != "ACTIVE" or (
                claim["artifact_id"], claim["node_id"], claim["claimed_by"],
                claim["claim_version"], claim["claimed_at"],
            ) != (
                artifact["artifact_id"], artifact["node_id"],
                artifact["claimed_by"], artifact["claim_version"],
                artifact["claimed_at"],
            ):
                raise RuntimeError("artifact evaluator claim pointer is not active and exact")

        previous_ledger_hash = None
        outcome_ids: set[str] = set()
        evaluated_claim_ids: set[str] = set()
        ledger_rows = self.connection.execute(
            "SELECT * FROM evaluation_ledger ORDER BY sequence"
        ).fetchall()
        for expected_sequence, ledger in enumerate(ledger_rows, start=1):
            if ledger["previous_ledger_hash"] != previous_ledger_hash:
                raise RuntimeError("evaluation ledger predecessor adjacency is invalid")
            if (
                type(ledger["sequence"]) is not int
                or ledger["sequence"] != expected_sequence
            ):
                raise RuntimeError("evaluation ledger sequence adjacency is invalid")
            outcome_rows = self.connection.execute(
                "SELECT outcome_id FROM evaluation_outcomes "
                "WHERE node_id=? OR evaluation_sha256=?",
                (ledger["node_id"], ledger["evaluation_hash"]),
            ).fetchall()
            if len(outcome_rows) != 1:
                raise RuntimeError("evaluation ledger row lacks one canonical outcome")
            try:
                outcome = get_outcome(
                    self.connection, outcome_rows[0]["outcome_id"],
                    expected_node_id=ledger["node_id"],
                )
                artifact = get_artifact(
                    self.connection, outcome["artifact_id"],
                    expected_node_id=ledger["node_id"],
                )
                node = self.get_node(ledger["node_id"])
                spec = json.loads(node["spec_json"])
            except (KeyError, PermissionError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("evaluation ledger durable binding is invalid") from exc
            evaluation = outcome["evaluation"]
            try:
                derived_ledger_hash = evaluation_ledger_hash(evaluation)
                evaluation_hash = digest(evaluation)
                contract_id = spec["evaluator_contract_id"]
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeError("evaluation ledger canonical content is invalid") from exc
            if (
                outcome["evaluation_sha256"] != ledger["evaluation_hash"]
                or evaluation_hash != ledger["evaluation_hash"]
                or ledger["task_id"] != ledger["node_id"]
                or evaluation.get("task_id") != ledger["node_id"]
                or ledger["contract_id"] != contract_id
                or evaluation.get("contract_id") != contract_id
                or evaluation.get("artifact_id") != artifact["artifact_id"]
                or node["active_artifact_id"] != artifact["artifact_id"]
                or node["attempt"] != artifact["attempt"]
                or node["evaluation_hash"] != ledger["evaluation_hash"]
                or node["result_sha"] != evaluation.get("evaluated_git_sha")
                or node["evidence_hash"] != evaluation.get("evidence_manifest_sha256")
                or artifact["candidate_sha"] != evaluation.get("evaluated_git_sha")
                or artifact["manifest_sha256"] != evaluation.get("evidence_manifest_sha256")
                or evaluation.get("previous_ledger_hash") != previous_ledger_hash
                or ledger["ledger_hash"] != derived_ledger_hash
                or evaluation.get("ledger_hash") != derived_ledger_hash
            ):
                raise RuntimeError("evaluation ledger row-to-outcome binding is invalid")

            evaluated = [
                claim for claim in claim_rows
                if claim["status"] == "EVALUATED"
                and (
                    claim["artifact_id"] == artifact["artifact_id"]
                    or claim["node_id"] == ledger["node_id"]
                )
            ]
            active = [
                claim for claim in claim_rows
                if claim["status"] == "ACTIVE"
                and (
                    claim["artifact_id"] == artifact["artifact_id"]
                    or claim["node_id"] == ledger["node_id"]
                )
            ]
            if (
                len(evaluated) != 1 or active
                or evaluation.get("claim_id") != evaluated[0]["claim_id"]
                or evaluated[0]["artifact_id"] != artifact["artifact_id"]
                or evaluated[0]["node_id"] != ledger["node_id"]
                or evaluated[0]["reason_sha256"] != evaluation_hash
                or (
                    artifact["claim_id"], artifact["claimed_by"],
                    artifact["claim_version"], artifact["claimed_at"],
                ) != (None, None, None, None)
            ):
                raise RuntimeError("completed evaluation claim closure is invalid")
            outcome_ids.add(outcome["outcome_id"])
            evaluated_claim_ids.add(evaluated[0]["claim_id"])
            previous_ledger_hash = ledger["ledger_hash"]

        durable_outcomes = {
            row[0] for row in self.connection.execute(
                "SELECT outcome_id FROM evaluation_outcomes"
            ).fetchall()
        }
        if durable_outcomes != outcome_ids:
            raise RuntimeError("canonical evaluation outcome lacks one ledger row")
        durable_evaluated_claims = {
            row[0] for row in self.connection.execute(
                "SELECT claim_id FROM evaluation_claims WHERE status='EVALUATED'"
            ).fetchall()
        }
        if durable_evaluated_claims != evaluated_claim_ids:
            raise RuntimeError("evaluated claim lacks one canonical outcome")
        evaluated_nodes = {
            row[0] for row in self.connection.execute(
                "SELECT node_id FROM nodes WHERE evaluation_hash IS NOT NULL "
                "OR result_sha IS NOT NULL OR state IN ('PASSED','INTEGRATING','INTEGRATED')"
            ).fetchall()
        }
        ledger_nodes = {row["node_id"] for row in ledger_rows}
        if evaluated_nodes != ledger_nodes:
            raise RuntimeError("evaluated graph node lacks one exact ledger row")

    def verify_event_chain(self, node_id: str) -> bool:
        node = self.connection.execute(
            "SELECT state,version FROM nodes WHERE node_id=?", (node_id,),
        ).fetchone()
        if not node or type(node["version"]) is not int or node["version"] < 0:
            return False
        rows = self.connection.execute(
            "SELECT * FROM events WHERE node_id=? ORDER BY version", (node_id,),
        ).fetchall()
        if len(rows) != node["version"] + 1:
            return False
        previous_hash = None
        previous_state = None
        for expected_version, row in enumerate(rows):
            if type(row["version"]) is not int or row["version"] != expected_version:
                return False
            if expected_version == 0:
                if row["old_state"] is not None or row["new_state"] not in INITIAL_NODE_STATES:
                    return False
            elif (
                row["old_state"] != previous_state
                or not self._valid_recorded_event_transition(
                    node_id, row["version"], row["old_state"],
                    row["new_state"], row["reason"], row["payload_hash"],
                )
            ):
                return False
            if row["new_state"] not in KNOWN_NODE_STATES:
                return False
            expected_hash = digest({
                "node": node_id, "version": row["version"],
                "old": row["old_state"], "new": row["new_state"],
                "reason": row["reason"], "payload": row["payload_hash"],
                "previous": previous_hash,
            })
            if (
                row["previous_hash"] != previous_hash
                or row["event_hash"] != expected_hash
            ):
                return False
            previous_hash = row["event_hash"]
            previous_state = row["new_state"]
        return rows[-1]["new_state"] == node["state"]

    def _valid_recorded_event_transition(
        self,
        node_id: str,
        version: int,
        old: str,
        new: str,
        reason: str,
        payload_hash: str,
    ) -> bool:
        """Authorize standard transitions or prove one exact internal exception."""
        if new in TRANSITIONS.get(old, frozenset()):
            return True
        if reason not in EXCEPTIONAL_EVENT_TRANSITIONS.get((old, new), frozenset()):
            return False
        if (old, new, reason) == (
            "EVALUATING", "EVIDENCE_PENDING", "expired evaluator claim recovered",
        ):
            claim_version = version - 2
            if claim_version < 0:
                return False
            claims = self.connection.execute(
                "SELECT * FROM evaluation_claims WHERE node_id=? AND claim_version=? "
                "AND status='EXPIRED' AND disposition='EXPIRED'",
                (node_id, claim_version),
            ).fetchall()
            if len(claims) != 1:
                return False
            claim = claims[0]
            try:
                _claim_timestamp(
                    claim["resolved_at"], "resolved_at", timezone_required=False,
                )
                _claim_timestamp(
                    claim["expires_at"], "expires_at", timezone_required=True,
                )
            except RuntimeError:
                return False
            return (
                claim["claimed_by"] == EVALUATOR_IDENTITY
                and claim["claim_id"] == deterministic_claim_id(
                    claim["artifact_id"], node_id, claim_version,
                    claim["claimed_by"],
                )
                and claim["reason_sha256"] == payload_hash
                and claim["reason_sha256"] == _expired_claim_reason(claim)
            )

        operation_kind = {
            "project-global promotion baseline rebind": "PROMOTION",
            "project-global publication rollback baseline rebind": "ROLLBACK",
        }.get(reason)
        if operation_kind is None or old != new:
            return False
        context = self.connection.execute(
            "SELECT n.goal_id,g.project FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE n.node_id=?", (node_id,),
        ).fetchone()
        if not context:
            return False
        proofs = 0
        for entry in self.connection.execute(
            "SELECT * FROM publication_journal WHERE operation_kind=? "
            "AND phase='COMPLETED' AND project=? ORDER BY sequence",
            (operation_kind, context["project"]),
        ).fetchall():
            try:
                affected = json.loads(entry["affected_graph_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if (
                entry["affected_graph_json"]
                != json.dumps(affected, sort_keys=True, separators=(",", ":"))
                or entry["affected_graph_sha256"] != digest(affected)
                or not isinstance(affected, dict)
                or not isinstance(affected.get("nodes"), list)
            ):
                continue
            bound_nodes = [
                node for node in affected["nodes"]
                if isinstance(node, dict)
                and node.get("node_id") == node_id
                and node.get("goal_id") == context["goal_id"]
                and node.get("version") == version - 1
                and node.get("state") == old
                and node.get("base_sha") == entry["from_sha"]
            ]
            identity_field = "attempt_id" if operation_kind == "PROMOTION" else "rollback_id"
            if len(bound_nodes) == 1 and payload_hash == digest({
                identity_field: entry["operation_id"],
                "from_sha": entry["from_sha"],
                "to_sha": entry["to_sha"],
            }):
                proofs += 1
        return proofs == 1

    def portfolio_status(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT g.project,g.goal_id,g.objective,g.accepted_sha,g.state AS goal_state,"
            "n.node_id,n.kind,n.state,n.attempt,n.evaluation_hash,n.integration_sha,"
            "a.artifact_id,a.manifest_sha256,a.claim_id "
            "FROM goals g LEFT JOIN nodes n ON n.goal_id=g.goal_id "
            "LEFT JOIN evidence_artifacts a ON a.artifact_id=n.active_artifact_id "
            "ORDER BY g.project,n.rowid"
        ).fetchall()
        return [dict(row) for row in rows]

    def release_dependencies(self, goal_id: str) -> list[str]:
        self.assert_static_integrity()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            project = self.connection.execute(
                "SELECT project FROM goals WHERE goal_id=?", (goal_id,),
            ).fetchone()
            if not project:
                raise KeyError(goal_id)
            self._assert_project_has_no_pending_publication(project[0])
            released = self._release_dependencies_locked(goal_id)
            self.connection.commit()
            return released
        except Exception:
            self.connection.rollback()
            raise

    def _release_dependencies_locked(self, goal_id: str) -> list[str]:
        """Release dependency nodes inside the caller's existing transaction."""
        rows = self.connection.execute(
            "SELECT node_id,version FROM nodes WHERE goal_id=? AND state='BLOCKED'", (goal_id,)
        ).fetchall()
        released = []
        for row in rows:
            pending = self.connection.execute(
                "SELECT COUNT(*) FROM dependencies d JOIN nodes n ON n.node_id=d.dependency_id WHERE d.node_id=? AND n.state!='INTEGRATED'",
                (row["node_id"],),
            ).fetchone()[0]
            if pending == 0:
                version = row["version"] + 1
                changed = self.connection.execute(
                    "UPDATE nodes SET state='READY',version=?,updated_at=CURRENT_TIMESTAMP "
                    "WHERE node_id=? AND version=? AND state='BLOCKED'",
                    (version, row["node_id"], row["version"]),
                ).rowcount
                if changed != 1:
                    raise ValueError("concurrent dependency release")
                self._event(
                    row["node_id"], version, "BLOCKED", "READY", "dependencies integrated", digest({})
                )
                released.append(row["node_id"])
        return released

    def _event(self, node_id: str, version: int, old: str | None, new: str, reason: str, payload_hash: str) -> None:
        previous = self.connection.execute(
            "SELECT version,new_state,event_hash FROM events WHERE node_id=? "
            "ORDER BY version DESC LIMIT 1", (node_id,),
        ).fetchone()
        if version == 0:
            if previous is not None or old is not None or new not in INITIAL_NODE_STATES:
                raise ValueError("node event genesis is invalid")
        elif (
            previous is None
            or previous["version"] != version - 1
            or previous["new_state"] != old
            or not self._valid_recorded_event_transition(
                node_id, version, str(old), new, reason, payload_hash,
            )
        ):
            raise ValueError("node event transition is not contiguous and authorized")
        if new not in KNOWN_NODE_STATES:
            raise ValueError("node event state is unknown")
        previous_hash = previous["event_hash"] if previous else None
        event_hash = digest({"node": node_id, "version": version, "old": old, "new": new,
                             "reason": reason, "payload": payload_hash, "previous": previous_hash})
        self.connection.execute(
            "INSERT INTO events(node_id,version,old_state,new_state,reason,payload_hash,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)",
            (node_id, version, old, new, reason, payload_hash, previous_hash, event_hash),
        )
