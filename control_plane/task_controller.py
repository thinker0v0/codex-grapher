#!/usr/bin/env python3
"""Small fail-closed task state controller for a single VPS.

The controller is intentionally stdlib-only and stores every state change as an
append-only SQLite event. It does not execute arbitrary commands.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import copy
from pathlib import Path
from typing import Any

if __package__:
    from .sqlite_runtime import connect_database
else:
    # The explicit legacy installer places these two modules side by side.
    from sqlite_runtime import connect_database


TERMINAL = {
    "REJECTED", "CANCELLED", "FAILED_PERMANENT", "FAILED_BUDGET",
    "FAILED_TIMEOUT", "FAILED_STAGNATION", "FAILED_GATE", "NEEDS_HUMAN",
    "SUPERSEDED", "COMPLETED",
}

TRANSITIONS = {
    "RECEIVED": {"AUTHORIZED", "REJECTED"},
    "AUTHORIZED": {"NORMALIZED", "REJECTED"},
    "NORMALIZED": {"PLANNED", "REJECTED"},
    "PLANNED": {"QUEUED", "REJECTED"},
    "QUEUED": {"LEASED", "CANCELLED", "FAILED_BUDGET", "FAILED_TIMEOUT"},
    "LEASED": {"RUNNING", "QUEUED", "CANCELLED"},
    "RUNNING": {"EVIDENCE_PENDING", "CANCELLED", "FAILED_PERMANENT", "FAILED_BUDGET", "FAILED_TIMEOUT", "FAILED_GATE"},
    "EVIDENCE_PENDING": {"EVALUATING", "FAILED_GATE"},
    "EVALUATING": {"REWORK_REQUESTED", "PASSED", "FAILED_GATE", "NEEDS_HUMAN"},
    "REWORK_REQUESTED": {"QUEUED", "FAILED_STAGNATION", "FAILED_BUDGET", "FAILED_TIMEOUT"},
    "PASSED": {"HUMAN_APPROVAL_PENDING", "COMPLETED"},
    "HUMAN_APPROVAL_PENDING": {"COMPLETED", "REJECTED", "NEEDS_HUMAN"},
}

REQUIRED = {
    "project_id", "task_id", "requester_identity", "authorization", "idempotency_key", "repo",
    "base_sha", "objective", "acceptance_criteria", "required_tests",
    "allowed_paths", "allowed_tools", "forbidden_actions", "budget", "deadline",
    "timeout_seconds", "max_iterations", "cancellation_token", "builder_identity",
    "evaluator_contract_id",
}
ALLOWED_PROJECTS = {"fin-global", "fin-korea", "hynix", "business", "oss"}
EXPECTED_REPOS = {
    "fin-global": "codex_finance",
    "fin-korea": "codex_finance",
    "hynix": "codex_hynix",
    "business": "codex_business",
    "oss": "codex_opensource",
}


def utcnow() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def authorization_subject(contract: dict[str, Any]) -> dict[str, Any]:
    """Return the immutable task fields an authorization approves.

    Evidence and signature digests are locators and cannot be included in the
    signed subject without creating a circular hash dependency.
    """
    subject = copy.deepcopy(contract)
    authorization = subject.get("authorization", {})
    authorization.pop("evidence_sha256", None)
    authorization.pop("signature_sha256", None)
    authorization.pop("subject_sha256", None)
    return subject


def authorization_subject_hash(contract: dict[str, Any]) -> str:
    return canonical_hash(authorization_subject(contract))


def verify_authorization_envelope(contract: dict[str, Any], envelope: dict[str, Any]) -> None:
    """Bind a root-signed envelope to the exact task authority being exercised."""
    authorization = contract["authorization"]
    subject_hash = authorization_subject_hash(contract)
    expected = {
        "decision": "allow",
        "policy_version": authorization["policy_version"],
        "subject_sha256": subject_hash,
        "requester_identity": contract["requester_identity"],
        "project_id": contract["project_id"],
        "builder_identity": contract["builder_identity"],
        "repo": contract["repo"],
        "base_sha": contract["base_sha"],
        "allowed_paths": contract["allowed_paths"],
        "allowed_tools": contract["allowed_tools"],
        "budget": contract["budget"],
        "authorized_at": authorization["authorized_at"],
        "expires_at": authorization["expires_at"],
    }
    if envelope != expected:
        raise ValueError("authorization envelope does not match contract subject")


def validate_contract(contract: dict[str, Any]) -> None:
    missing = sorted(REQUIRED - contract.keys())
    if missing:
        raise ValueError(f"missing fields: {', '.join(missing)}")
    if contract["project_id"] not in ALLOWED_PROJECTS:
        raise ValueError("project_id is not allowlisted")
    if len(contract["idempotency_key"]) < 16 or len(contract["cancellation_token"]) < 16:
        raise ValueError("idempotency and cancellation keys must be at least 16 characters")
    if not isinstance(contract["base_sha"], str) or len(contract["base_sha"]) != 40:
        raise ValueError("base_sha must be a 40-character Git SHA")
    if not contract["acceptance_criteria"] or not contract["required_tests"] or not contract["allowed_paths"] or not contract["allowed_tools"]:
        raise ValueError("acceptance_criteria, required_tests, allowed_paths, and allowed_tools must be non-empty")
    if contract["repo"] != EXPECTED_REPOS[contract["project_id"]]:
        raise ValueError("repo does not match project allowlist")
    for allowed_path in contract["allowed_paths"]:
        candidate = Path(allowed_path)
        if candidate.is_absolute() or ".." in candidate.parts or str(candidate) in {"", "."}:
            raise ValueError("allowed_paths must be relative, scoped paths")
    budget = contract["budget"]
    if not isinstance(budget, dict) or budget.get("max_cost_usd", 0) <= 0 or budget.get("max_tokens", 0) <= 0:
        raise ValueError("positive max_cost_usd and max_tokens are required")
    if not 1 <= contract["timeout_seconds"] <= 21600:
        raise ValueError("timeout_seconds out of range")
    if not 1 <= contract["max_iterations"] <= 5:
        raise ValueError("max_iterations out of range")
    deadline = dt.datetime.fromisoformat(contract["deadline"].replace("Z", "+00:00"))
    if deadline <= dt.datetime.now(dt.timezone.utc):
        raise ValueError("deadline is not in the future")
    expected_builder = f"hermes-{contract['project_id']}"
    if contract["builder_identity"] != expected_builder:
        raise ValueError("builder_identity does not match project")
    authorization = contract["authorization"]
    if not isinstance(authorization, dict) or authorization.get("decision") != "allow":
        raise ValueError("explicit allow authorization is required")
    evidence_hash = authorization.get("evidence_sha256", "")
    if len(evidence_hash) != 64 or any(c not in "0123456789abcdef" for c in evidence_hash):
        raise ValueError("authorization evidence hash is invalid")
    signature_hash = authorization.get("signature_sha256", "")
    if len(signature_hash) != 64 or any(c not in "0123456789abcdef" for c in signature_hash):
        raise ValueError("authorization signature hash is invalid")
    subject_hash = authorization.get("subject_sha256", "")
    if subject_hash != authorization_subject_hash(contract):
        raise ValueError("authorization subject hash does not match contract")
    authorized_at = dt.datetime.fromisoformat(authorization["authorized_at"].replace("Z", "+00:00"))
    expires_at = dt.datetime.fromisoformat(authorization["expires_at"].replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    if not authorized_at <= now < expires_at:
        raise ValueError("authorization is not currently valid")


class TaskController:
    def __init__(self, database: Path, *, sqlite_profile: str = "delete-extra",
                 sqlite_attestation: Path | None = None):
        self.database = database
        os.umask(0o077)
        self.connection = connect_database(database, create=True, profile=sqlite_profile,
                                           attestation=sqlite_attestation)
        os.chmod(database, 0o600)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS tasks (
              task_id TEXT PRIMARY KEY,
              project_id TEXT NOT NULL,
              idempotency_key TEXT NOT NULL,
              input_hash TEXT NOT NULL,
              contract_json TEXT NOT NULL,
              state TEXT NOT NULL,
              version INTEGER NOT NULL DEFAULT 0,
              attempt_count INTEGER NOT NULL DEFAULT 0,
              cost_usd REAL NOT NULL DEFAULT 0,
              tokens INTEGER NOT NULL DEFAULT 0,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(project_id, idempotency_key)
            );
            CREATE TABLE IF NOT EXISTS task_events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              task_id TEXT NOT NULL REFERENCES tasks(task_id),
              version INTEGER NOT NULL,
              from_state TEXT,
              to_state TEXT NOT NULL,
              reason TEXT NOT NULL,
              created_at TEXT NOT NULL,
              event_hash TEXT NOT NULL UNIQUE,
              UNIQUE(task_id, version)
            );
            """
        )

    def recover_orphaned_executions(self) -> list[dict[str, Any]]:
        """Terminalize leases/processes that cannot survive controller boot."""
        recovered: list[dict[str, Any]] = []
        rows = self.connection.execute(
            "SELECT * FROM tasks WHERE state IN ('LEASED','RUNNING') ORDER BY created_at"
        ).fetchall()
        for row in rows:
            target = "CANCELLED" if row["state"] == "LEASED" else "FAILED_PERMANENT"
            reason = "controller startup recovered orphaned lease" if row["state"] == "LEASED" else "controller startup recovered orphaned execution"
            now = utcnow()
            version = row["version"] + 1
            with self.connection:
                changed = self.connection.execute(
                    "UPDATE tasks SET state=?,version=?,updated_at=? WHERE task_id=? AND version=? AND state=?",
                    (target, version, now, row["task_id"], row["version"], row["state"]),
                ).rowcount
                if changed == 1:
                    self._append_event(row["task_id"], version, row["state"], target, reason, now)
                    recovered.append(self.get(row["task_id"]))
        return recovered

    def submit(self, contract: dict[str, Any]) -> dict[str, Any]:
        validate_contract(contract)
        digest = canonical_hash(contract)
        now = utcnow()
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO tasks(task_id,project_id,idempotency_key,input_hash,contract_json,state,created_at,updated_at) VALUES(?,?,?,?,?,'RECEIVED',?,?)",
                    (contract["task_id"], contract["project_id"], contract["idempotency_key"], digest,
                     json.dumps(contract, sort_keys=True), now, now),
                )
                self._append_event(contract["task_id"], 0, None, "RECEIVED", "submitted", now)
        except sqlite3.IntegrityError:
            row = self.connection.execute(
                "SELECT * FROM tasks WHERE project_id=? AND idempotency_key=?",
                (contract["project_id"], contract["idempotency_key"]),
            ).fetchone()
            if row and row["input_hash"] == digest:
                return self.get(row["task_id"])
            raise ValueError("idempotency key reused with different input")
        return self.get(contract["task_id"])

    def _append_event(self, task_id: str, version: int, old: str | None, new: str, reason: str, now: str) -> None:
        previous = self.connection.execute(
            "SELECT event_hash FROM task_events WHERE task_id=? ORDER BY version DESC LIMIT 1", (task_id,)
        ).fetchone()
        payload = {"task_id": task_id, "version": version, "from": old, "to": new,
                   "reason": reason, "created_at": now, "previous": previous[0] if previous else None}
        self.connection.execute(
            "INSERT INTO task_events(task_id,version,from_state,to_state,reason,created_at,event_hash) VALUES(?,?,?,?,?,?,?)",
            (task_id, version, old, new, reason, now, canonical_hash(payload)),
        )

    def _get(self, task_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not row:
            raise KeyError(task_id)
        return dict(row)

    def get(self, task_id: str) -> dict[str, Any]:
        row = self._get(task_id)
        row.pop("contract_json", None)
        return row

    def transition(self, task_id: str, expected_version: int, target: str, reason: str) -> dict[str, Any]:
        row = self._get(task_id)
        if row["version"] != expected_version:
            raise ValueError("optimistic version conflict")
        if row["state"] in TERMINAL or target not in TRANSITIONS.get(row["state"], set()):
            raise ValueError(f"forbidden transition {row['state']} -> {target}")
        contract = json.loads(row["contract_json"])
        if dt.datetime.fromisoformat(contract["deadline"].replace("Z", "+00:00")) <= dt.datetime.now(dt.timezone.utc):
            target, reason = "FAILED_TIMEOUT", "deadline exceeded"
        if row["cost_usd"] >= contract["budget"]["max_cost_usd"] or row["tokens"] >= contract["budget"]["max_tokens"]:
            target, reason = "FAILED_BUDGET", "budget exhausted"
        if target == "LEASED" and row["attempt_count"] >= contract["max_iterations"]:
            target, reason = "FAILED_STAGNATION", "maximum iterations reached"
        now = utcnow()
        new_version = expected_version + 1
        attempts = row["attempt_count"] + (1 if target == "LEASED" else 0)
        with self.connection:
            changed = self.connection.execute(
                "UPDATE tasks SET state=?,version=?,attempt_count=?,updated_at=? WHERE task_id=? AND version=?",
                (target, new_version, attempts, now, task_id, expected_version),
            ).rowcount
            if changed != 1:
                raise ValueError("optimistic version conflict")
            self._append_event(task_id, new_version, row["state"], target, reason, now)
        return self.get(task_id)

    def record_usage(self, task_id: str, cost_usd: float, tokens: int) -> dict[str, Any]:
        if cost_usd < 0 or tokens < 0:
            raise ValueError("usage cannot be negative")
        with self.connection:
            self.connection.execute(
                "UPDATE tasks SET cost_usd=cost_usd+?,tokens=tokens+?,updated_at=? WHERE task_id=?",
                (cost_usd, tokens, utcnow(), task_id),
            )
        return self.get(task_id)

    def verify_event_chain(self, task_id: str) -> bool:
        rows = self.connection.execute(
            "SELECT * FROM task_events WHERE task_id=? ORDER BY version", (task_id,)
        ).fetchall()
        previous = None
        for row in rows:
            payload = {"task_id": row["task_id"], "version": row["version"],
                       "from": row["from_state"], "to": row["to_state"],
                       "reason": row["reason"], "created_at": row["created_at"],
                       "previous": previous}
            if canonical_hash(payload) != row["event_hash"]:
                return False
            previous = row["event_hash"]
        return bool(rows)

    def cancel(self, task_id: str, token: str) -> dict[str, Any]:
        with self.connection:
            row = self._get(task_id)
            contract = json.loads(row["contract_json"])
            if token != contract["cancellation_token"]:
                raise ValueError("invalid cancellation token")
            if row["state"] in TERMINAL:
                return self.get(task_id)
            now = utcnow()
            version = row["version"] + 1
            changed = self.connection.execute(
                "UPDATE tasks SET state='CANCELLED',version=?,updated_at=? WHERE task_id=? AND version=? AND state=?",
                (version, now, task_id, row["version"], row["state"]),
            ).rowcount
            if changed != 1:
                raise ValueError("cancellation version conflict")
            self._append_event(task_id, version, row["state"], "CANCELLED", "authorized cancellation", now)
        return self.get(task_id)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    submit = sub.add_parser("submit"); submit.add_argument("contract", type=Path)
    move = sub.add_parser("transition"); move.add_argument("task_id"); move.add_argument("version", type=int); move.add_argument("target"); move.add_argument("reason")
    cancel = sub.add_parser("cancel"); cancel.add_argument("task_id"); cancel.add_argument("token")
    usage = sub.add_parser("usage"); usage.add_argument("task_id"); usage.add_argument("cost_usd", type=float); usage.add_argument("tokens", type=int)
    verify = sub.add_parser("verify-chain"); verify.add_argument("task_id")
    get = sub.add_parser("get"); get.add_argument("task_id")
    subject = sub.add_parser("authorization-subject-hash"); subject.add_argument("contract", type=Path)
    auth = sub.add_parser("verify-authorization"); auth.add_argument("contract", type=Path); auth.add_argument("envelope", type=Path)
    args = parser.parse_args()
    if args.command == "authorization-subject-hash":
        contract = json.loads(args.contract.read_text())
        print(authorization_subject_hash(contract))
        return 0
    if args.command == "verify-authorization":
        contract = json.loads(args.contract.read_text())
        validate_contract(contract)
        verify_authorization_envelope(contract, json.loads(args.envelope.read_text()))
        print(json.dumps({"valid": True, "subject_sha256": authorization_subject_hash(contract)}))
        return 0
    controller = TaskController(args.db)
    if args.command == "submit": result = controller.submit(json.loads(args.contract.read_text()))
    elif args.command == "transition": result = controller.transition(args.task_id, args.version, args.target, args.reason)
    elif args.command == "cancel": result = controller.cancel(args.task_id, args.token)
    elif args.command == "usage": result = controller.record_usage(args.task_id, args.cost_usd, args.tokens)
    elif args.command == "verify-chain":
        print(json.dumps({"task_id": args.task_id, "valid": controller.verify_event_chain(args.task_id)}))
        return 0 if controller.verify_event_chain(args.task_id) else 3
    else: result = controller.get(args.task_id)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"DENIED: {exc}", file=sys.stderr)
        raise SystemExit(2)
