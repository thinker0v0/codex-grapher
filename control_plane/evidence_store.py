"""Durable metadata for server-ingressed evaluator artifacts."""

from __future__ import annotations

import hashlib
import datetime as dt
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from control_plane.evidence_ingress import ARTIFACT_ID, IngressArtifact, resolve_manifest
from control_plane.graph_state import ACTIVE_PROJECTS


HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
PROJECTS = set(ACTIVE_PROJECTS)
PROJECT_WORKERS = {
    "nomad": "fin-korea", "opensource": "oss",
    "business": "business", "hynix": "hynix",
}
EVALUATOR_IDENTITY = "hermes-evaluator"
EVIDENCE_DISPOSITIONS = {"RETRY", "FAILED_GATE", "NEEDS_HUMAN"}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def deterministic_claim_id(
    artifact_id: str, node_id: str, claim_version: int, claimant: str,
) -> str:
    """Derive the sole durable identity for one evaluator claim request."""
    subject = {
        "artifact_id": artifact_id,
        "node_id": node_id,
        "version": claim_version,
        "claimant": claimant,
    }
    return f"claim:{hashlib.sha256(_canonical(subject)).hexdigest()}"


def _validate_record(
    node_id: str, project: str, artifact: IngressArtifact,
    ingress_version: int, expected_attempt: int,
) -> None:
    if project not in PROJECTS or not isinstance(node_id, str) or not node_id:
        raise ValueError("artifact graph binding is invalid")
    if type(ingress_version) is not int or ingress_version < 0:
        raise ValueError("artifact ingress version is invalid")
    if type(expected_attempt) is not int or expected_attempt < 1:
        raise ValueError("artifact attempt binding is invalid")
    if type(artifact.attempt) is not int or artifact.attempt < 1:
        raise ValueError("artifact attempt binding is invalid")
    if artifact.attempt != expected_attempt:
        raise ValueError("artifact attempt differs from the graph attempt")
    if not ARTIFACT_ID.fullmatch(artifact.artifact_id):
        raise ValueError("artifact ID is invalid")
    if artifact.artifact_id != f"sha256:{artifact.manifest_sha256}":
        raise ValueError("artifact ID is not derived from the manifest hash")
    if not HEX64.fullmatch(artifact.manifest_sha256) or not HEX64.fullmatch(artifact.contract_sha256):
        raise ValueError("artifact hash binding is invalid")
    if not HEX40.fullmatch(artifact.base_sha) or not HEX40.fullmatch(artifact.candidate_sha):
        raise ValueError("artifact Git binding is invalid")
    expected_path = (
        Path("sha256") / artifact.manifest_sha256[:2] /
        artifact.manifest_sha256 / "manifest.json"
    )
    if artifact.manifest_relative_path != str(expected_path):
        raise ValueError("artifact manifest path is not server-derived")
    if artifact.task_id != node_id:
        raise ValueError("artifact task does not match its graph node")
    if artifact.project_id != PROJECT_WORKERS[project]:
        raise ValueError("artifact producer project does not match its graph route")


def register_artifact(
    connection: sqlite3.Connection,
    node_id: str,
    project: str,
    artifact: IngressArtifact,
    ingress_version: int,
    expected_attempt: int,
) -> dict[str, Any]:
    """Insert one immutable node artifact or return its exact idempotent replay."""
    _validate_record(node_id, project, artifact, ingress_version, expected_attempt)
    values = (
        artifact.artifact_id, node_id, artifact.attempt, project, artifact.project_id,
        artifact.manifest_sha256, artifact.manifest_relative_path, artifact.task_id,
        artifact.base_sha, artifact.candidate_sha, artifact.contract_sha256,
        ingress_version,
    )
    existing = connection.execute(
        "SELECT * FROM evidence_artifacts WHERE (node_id=? AND attempt=?) OR artifact_id=?",
        (node_id, artifact.attempt, artifact.artifact_id),
    ).fetchall()
    if existing:
        if len(existing) != 1:
            raise ValueError("artifact replay collides with durable records")
        row = existing[0]
        actual = tuple(row[name] for name in (
            "artifact_id", "node_id", "attempt", "project", "producer_project_id",
            "manifest_sha256", "manifest_relative_path", "task_id", "base_sha",
            "candidate_sha", "contract_sha256", "ingress_version",
        ))
        if actual != values:
            raise ValueError("artifact replay differs from the durable record")
        return dict(row)
    connection.execute(
        "INSERT INTO evidence_artifacts(artifact_id,node_id,attempt,project,producer_project_id,"
        "manifest_sha256,manifest_relative_path,task_id,base_sha,candidate_sha,"
        "contract_sha256,ingress_version) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        values,
    )
    return dict(connection.execute(
        "SELECT * FROM evidence_artifacts WHERE artifact_id=?", (artifact.artifact_id,)
    ).fetchone())


def get_artifact(
    connection: sqlite3.Connection,
    artifact_id: str,
    *,
    expected_node_id: str | None = None,
    expected_project: str | None = None,
) -> dict[str, Any]:
    if not isinstance(artifact_id, str) or not ARTIFACT_ID.fullmatch(artifact_id):
        raise PermissionError("artifact ID is invalid")
    row = connection.execute(
        "SELECT * FROM evidence_artifacts WHERE artifact_id=?", (artifact_id,)
    ).fetchone()
    if not row:
        raise KeyError(artifact_id)
    result = dict(row)
    expected_path = (
        Path("sha256") / result["manifest_sha256"][:2]
        / result["manifest_sha256"] / "manifest.json"
    ) if isinstance(result.get("manifest_sha256"), str) else None
    if (
        result.get("project") not in PROJECTS
        or result.get("producer_project_id")
        != PROJECT_WORKERS.get(result.get("project"))
        or not isinstance(result.get("node_id"), str)
        or not result["node_id"]
        or result.get("task_id") != result["node_id"]
        or type(result.get("attempt")) is not int
        or result["attempt"] < 1
        or type(result.get("ingress_version")) is not int
        or result["ingress_version"] < 0
        or not isinstance(result.get("manifest_sha256"), str)
        or not HEX64.fullmatch(result["manifest_sha256"])
        or not isinstance(result.get("contract_sha256"), str)
        or not HEX64.fullmatch(result["contract_sha256"])
        or not isinstance(result.get("base_sha"), str)
        or not HEX40.fullmatch(result["base_sha"])
        or not isinstance(result.get("candidate_sha"), str)
        or not HEX40.fullmatch(result["candidate_sha"])
        or result.get("manifest_relative_path") != str(expected_path)
    ):
        raise PermissionError("durable artifact record binding is invalid")
    if expected_node_id is not None and result["node_id"] != expected_node_id:
        raise PermissionError("artifact belongs to a different node")
    if expected_project is not None and result["project"] != expected_project:
        raise PermissionError("artifact belongs to a different project")
    if result["artifact_id"] != f"sha256:{result['manifest_sha256']}":
        raise PermissionError("durable artifact ID/hash binding is invalid")
    return result


def claim_artifact(
    connection: sqlite3.Connection,
    artifact_id: str,
    node_id: str,
    expected_version: int,
    claimant: str,
    ttl_seconds: int = 600,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    if claimant != EVALUATOR_IDENTITY:
        raise PermissionError("only the independent evaluator may claim evidence")
    if type(ttl_seconds) is not int or not 10 <= ttl_seconds <= 3600:
        raise ValueError("evaluator claim TTL must be 10..3600 seconds")
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("evaluator claim clock must be timezone-aware")
    expires_at = (now + dt.timedelta(seconds=ttl_seconds)).isoformat()
    artifact = get_artifact(connection, artifact_id, expected_node_id=node_id)
    claim_id = deterministic_claim_id(
        artifact_id, node_id, expected_version, claimant,
    )
    if artifact["claim_id"] is not None:
        if (
            artifact["claim_id"], artifact["claimed_by"], artifact["claim_version"]
        ) != (claim_id, claimant, expected_version):
            raise ValueError("evidence is already claimed by a different request")
        claim = connection.execute(
            "SELECT * FROM evaluation_claims WHERE claim_id=?", (claim_id,)
        ).fetchone()
        if not claim or (
            claim["artifact_id"], claim["node_id"], claim["claim_version"],
            claim["claimed_by"], claim["status"],
        ) != (artifact_id, node_id, expected_version, claimant, "ACTIVE"):
            raise ValueError("durable evaluator claim differs from the artifact pointer")
        get_active_claim(
            connection, artifact_id, expected_node_id=node_id,
            expected_claimant=claimant, now=now,
        )
        return artifact
    connection.execute(
        "INSERT INTO evaluation_claims(claim_id,artifact_id,node_id,claim_version,claimed_by,"
        "status,claimed_at,heartbeat_at,expires_at) VALUES(?,?,?,?,?,'ACTIVE',?,?,?)",
        (
            claim_id, artifact_id, node_id, expected_version, claimant,
            now.isoformat(), now.isoformat(), expires_at,
        ),
    )
    changed = connection.execute(
        "UPDATE evidence_artifacts SET claim_id=?,claimed_by=?,claim_version=?,"
        "claimed_at=? WHERE artifact_id=? AND claim_id IS NULL",
        (claim_id, claimant, expected_version, now.isoformat(), artifact_id),
    ).rowcount
    if changed != 1:
        raise ValueError("concurrent evidence claim")
    return get_artifact(connection, artifact_id, expected_node_id=node_id)


def get_active_claim(
    connection: sqlite3.Connection,
    artifact_id: str,
    *,
    expected_node_id: str | None = None,
    expected_claimant: str | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Return the exact active claim selected by the immutable artifact pointer."""
    artifact = get_artifact(
        connection, artifact_id, expected_node_id=expected_node_id,
    )
    if artifact["claim_id"] is None:
        raise PermissionError("artifact has no active evaluator claim")
    row = connection.execute(
        "SELECT * FROM evaluation_claims WHERE claim_id=?", (artifact["claim_id"],)
    ).fetchone()
    if not row:
        raise PermissionError("artifact claim pointer has no durable claim")
    claim = dict(row)
    expected = (
        artifact_id, artifact["node_id"], artifact["claim_version"],
        artifact["claimed_by"], "ACTIVE",
    )
    actual = (
        claim["artifact_id"], claim["node_id"], claim["claim_version"],
        claim["claimed_by"], claim["status"],
    )
    if actual != expected:
        raise PermissionError("artifact claim pointer and durable claim disagree")
    if expected_claimant is not None and claim["claimed_by"] != expected_claimant:
        raise PermissionError("artifact is claimed by another evaluator identity")
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        expires_at = dt.datetime.fromisoformat(claim["expires_at"])
    except (TypeError, ValueError):
        raise PermissionError("artifact claim expiry is invalid") from None
    if expires_at.tzinfo is None or expires_at <= now:
        raise PermissionError("artifact evaluator claim has expired")
    return claim


def heartbeat_claim(
    connection: sqlite3.Connection,
    artifact_id: str,
    node_id: str,
    claim_id: str,
    claim_version: int,
    claimant: str,
    ttl_seconds: int = 600,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Extend only the exact live evaluator claim selected by the node API."""
    if claimant != EVALUATOR_IDENTITY:
        raise PermissionError("only the independent evaluator may heartbeat evidence")
    if type(ttl_seconds) is not int or not 10 <= ttl_seconds <= 3600:
        raise ValueError("evaluator claim TTL must be 10..3600 seconds")
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("evaluator claim heartbeat clock must be timezone-aware")
    claim = get_active_claim(
        connection, artifact_id, expected_node_id=node_id,
        expected_claimant=claimant, now=now,
    )
    if claim["claim_id"] != claim_id or claim["claim_version"] != claim_version:
        raise PermissionError("evaluator claim heartbeat binding mismatch")
    try:
        previous_expiry = dt.datetime.fromisoformat(claim["expires_at"])
    except (TypeError, ValueError):
        raise PermissionError("artifact claim expiry is invalid") from None
    expires_at = now + dt.timedelta(seconds=ttl_seconds)
    if expires_at <= previous_expiry:
        raise ValueError("evaluator claim heartbeat must extend its expiry")
    changed = connection.execute(
        "UPDATE evaluation_claims SET heartbeat_at=?,expires_at=? "
        "WHERE claim_id=? AND artifact_id=? "
        "AND node_id=? AND claim_version=? AND claimed_by=? AND status='ACTIVE' "
        "AND expires_at=?",
        (
            now.isoformat(), expires_at.isoformat(), claim_id, artifact_id, node_id,
            claim_version, claimant, claim["expires_at"],
        ),
    ).rowcount
    if changed != 1:
        raise ValueError("concurrent evaluator claim heartbeat")
    return dict(connection.execute(
        "SELECT * FROM evaluation_claims WHERE claim_id=?", (claim_id,),
    ).fetchone())


def resolve_claim(
    connection: sqlite3.Connection,
    artifact_id: str,
    node_id: str,
    claimant: str,
    resolution_sha256: str,
    *,
    disposition: str | None = None,
) -> dict[str, Any]:
    """Resolve one active claim as evaluated or with a bounded non-PASS disposition."""
    if claimant != EVALUATOR_IDENTITY:
        raise PermissionError("only the independent evaluator may resolve evidence")
    if not isinstance(resolution_sha256, str) or not HEX64.fullmatch(resolution_sha256):
        raise ValueError("evaluation claim resolution hash is invalid")
    if disposition is not None and disposition not in EVIDENCE_DISPOSITIONS:
        raise ValueError("evaluation claim disposition is invalid")
    claim = get_active_claim(
        connection, artifact_id, expected_node_id=node_id, expected_claimant=claimant,
    )
    status = "DISPOSED" if disposition is not None else "EVALUATED"
    changed = connection.execute(
        "UPDATE evaluation_claims SET status=?,disposition=?,reason_sha256=?,"
        "resolved_at=CURRENT_TIMESTAMP WHERE claim_id=? AND status='ACTIVE'",
        (status, disposition, resolution_sha256, claim["claim_id"]),
    ).rowcount
    if changed != 1:
        raise ValueError("concurrent evaluator claim resolution")
    cleared = connection.execute(
        "UPDATE evidence_artifacts SET claim_id=NULL,claimed_by=NULL,claim_version=NULL,"
        "claimed_at=NULL WHERE artifact_id=? AND claim_id=?",
        (artifact_id, claim["claim_id"]),
    ).rowcount
    if cleared != 1:
        raise ValueError("evaluator claim pointer changed during resolution")
    return dict(connection.execute(
        "SELECT * FROM evaluation_claims WHERE claim_id=?", (claim["claim_id"],)
    ).fetchone())


def expire_claim(
    connection: sqlite3.Connection,
    artifact_id: str,
    node_id: str,
    resolution_sha256: str,
    *,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Expire one overdue claim and clear its mutable artifact pointer."""
    if not isinstance(resolution_sha256, str) or not HEX64.fullmatch(resolution_sha256):
        raise ValueError("claim expiry resolution hash is invalid")
    artifact = get_artifact(connection, artifact_id, expected_node_id=node_id)
    if artifact["claim_id"] is None:
        raise PermissionError("artifact has no claim to expire")
    row = connection.execute(
        "SELECT * FROM evaluation_claims WHERE claim_id=?", (artifact["claim_id"],)
    ).fetchone()
    if not row or row["status"] != "ACTIVE":
        raise PermissionError("artifact claim pointer is not active")
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        expires_at = dt.datetime.fromisoformat(row["expires_at"])
    except (TypeError, ValueError):
        raise PermissionError("artifact claim expiry is invalid") from None
    if expires_at.tzinfo is None or expires_at > now:
        raise PermissionError("artifact evaluator claim has not expired")
    changed = connection.execute(
        "UPDATE evaluation_claims SET status='EXPIRED',disposition='EXPIRED',"
        "reason_sha256=?,resolved_at=? WHERE claim_id=? AND status='ACTIVE'",
        (resolution_sha256, now.isoformat(), row["claim_id"]),
    ).rowcount
    if changed != 1:
        raise ValueError("concurrent evaluator claim expiry")
    cleared = connection.execute(
        "UPDATE evidence_artifacts SET claim_id=NULL,claimed_by=NULL,claim_version=NULL,"
        "claimed_at=NULL WHERE artifact_id=? AND claim_id=?",
        (artifact_id, row["claim_id"]),
    ).rowcount
    if cleared != 1:
        raise ValueError("evaluator claim pointer changed during expiry")
    return dict(connection.execute(
        "SELECT * FROM evaluation_claims WHERE claim_id=?", (row["claim_id"],)
    ).fetchone())


def store_outcome(
    connection: sqlite3.Connection,
    artifact_id: str,
    node_id: str,
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    """Persist canonical signed evaluation bytes under their content hash."""
    get_artifact(connection, artifact_id, expected_node_id=node_id)
    canonical_json = _canonical(evaluation)
    evaluation_sha256 = hashlib.sha256(canonical_json).hexdigest()
    outcome_id = f"sha256:{evaluation_sha256}"
    existing = connection.execute(
        "SELECT * FROM evaluation_outcomes WHERE outcome_id=? OR artifact_id=? OR node_id=?",
        (outcome_id, artifact_id, node_id),
    ).fetchall()
    if existing:
        if len(existing) != 1:
            raise ValueError("evaluation outcome collides with durable records")
        row = dict(existing[0])
        if (
            row["outcome_id"], row["artifact_id"], row["node_id"],
            row["evaluation_sha256"], bytes(row["canonical_json"]),
        ) != (outcome_id, artifact_id, node_id, evaluation_sha256, canonical_json):
            raise ValueError("evaluation outcome replay differs from durable bytes")
        return row
    connection.execute(
        "INSERT INTO evaluation_outcomes(outcome_id,artifact_id,node_id,evaluation_sha256,canonical_json) "
        "VALUES(?,?,?,?,?)",
        (outcome_id, artifact_id, node_id, evaluation_sha256, canonical_json),
    )
    return get_outcome(
        connection, outcome_id, expected_artifact_id=artifact_id, expected_node_id=node_id,
    )


def get_outcome(
    connection: sqlite3.Connection,
    outcome_id: str,
    *,
    expected_artifact_id: str | None = None,
    expected_node_id: str | None = None,
) -> dict[str, Any]:
    if not isinstance(outcome_id, str) or not ARTIFACT_ID.fullmatch(outcome_id):
        raise PermissionError("evaluation outcome ID is invalid")
    row = connection.execute(
        "SELECT * FROM evaluation_outcomes WHERE outcome_id=?", (outcome_id,)
    ).fetchone()
    if not row:
        raise KeyError(outcome_id)
    result = dict(row)
    canonical_json = bytes(result["canonical_json"])
    if (
        outcome_id != f"sha256:{hashlib.sha256(canonical_json).hexdigest()}"
        or result["evaluation_sha256"] != outcome_id.removeprefix("sha256:")
    ):
        raise PermissionError("durable evaluation outcome hash binding is invalid")
    try:
        evaluation = json.loads(canonical_json)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PermissionError("durable evaluation outcome is invalid JSON") from None
    if _canonical(evaluation) != canonical_json:
        raise PermissionError("durable evaluation outcome is not canonical JSON")
    if expected_artifact_id is not None and result["artifact_id"] != expected_artifact_id:
        raise PermissionError("evaluation outcome belongs to another artifact")
    if expected_node_id is not None and result["node_id"] != expected_node_id:
        raise PermissionError("evaluation outcome belongs to another node")
    result.pop("canonical_json")
    result["evaluation"] = evaluation
    return result


def resolve_artifact(
    connection: sqlite3.Connection,
    artifact_id: str,
    target_root: Path,
    *,
    expected_node_id: str | None = None,
    expected_project: str | None = None,
) -> tuple[dict[str, Any], Path]:
    artifact = get_artifact(
        connection, artifact_id,
        expected_node_id=expected_node_id, expected_project=expected_project,
    )
    path = resolve_manifest(
        target_root, artifact["manifest_relative_path"], artifact["manifest_sha256"],
    )
    return artifact, path
