"""Behavioral Buzz command boundary; transport text never grants authority."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from control_plane.graph_planner import plan_goal
from control_plane.graph_state import TRANSITIONS
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_graph import ProjectGraph, digest


COMMANDS = {"goal", "status", "evidence", "approve", "reject", "cancel", "resume"}
INTEGRITY_ERRORS = (
    KeyError,
    OSError,
    PermissionError,
    TypeError,
    ValueError,
    RuntimeError,
    json.JSONDecodeError,
)


class BuzzMutationIntegrityError(RuntimeError):
    """The durable graph or publication projection failed closed."""


class _CommandDenied(Exception):
    """An expected command denial detected before its graph mutation."""


class BuzzRouter:
    def __init__(
        self,
        graph: ProjectGraph,
        routing_config: Path,
        templates: dict[str, list[dict[str, Any]]],
        full_integrity_verifiers: Mapping[str, ProjectCoordinator] | None = None,
    ):
        self.graph = graph
        self.config = json.loads(routing_config.read_text())
        self.templates = templates
        self.full_integrity_verifiers = (
            ProjectCoordinator.normalize_external_integrity_map(
                self.graph, full_integrity_verifiers,
            )
        )

    def assert_mutation_integrity(self) -> None:
        """Reuse the service gate for every durable PASS/publication boundary."""
        self.full_integrity_verifiers = (
            ProjectCoordinator.require_external_integrity(
                self.graph, self.full_integrity_verifiers,
            )
        )

    def handle(self, sender_pubkey: str, thread_id: str, request: dict[str, Any]) -> dict[str, Any]:
        """Handle one standalone command as one graph-and-audit transaction."""

        connection = self.graph.connection
        if connection.in_transaction:
            raise RuntimeError(
                "standalone Buzz routing cannot run inside an existing transaction"
            )
        try:
            connection.execute("BEGIN IMMEDIATE")
            response = self.handle_locked(sender_pubkey, thread_id, request)
            self._transaction_checkpoint("before_commit")
            connection.commit()
            return response
        except BuzzMutationIntegrityError as exc:
            connection.rollback()
            # A corrupt or incomplete projection freezes every Buzz write,
            # including denial/audit rows, until root-owned recovery succeeds.
            return {"ok": False, "error": str(exc)}
        except INTEGRITY_ERRORS as exc:
            connection.rollback()
            return {"ok": False, "error": str(exc)}
        except Exception:
            connection.rollback()
            raise

    def handle_locked(
        self, sender_pubkey: str, thread_id: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        """Route and audit inside the caller's transaction without ending it."""

        connection = self.graph.connection
        if not connection.in_transaction:
            raise RuntimeError("locked Buzz routing requires an active transaction")
        self._assert_mutation_integrity_locked()

        identity = self.config["identity_map"].get(sender_pubkey)
        command = request.get("command")
        project = request.get("project")
        denial_reason = None
        if (
            not identity
            or identity.get("role") != "operator"
            or type(command) is not str
            or command not in COMMANDS
            or command not in identity["commands"]
        ):
            denial_reason = "identity or command denied"
        elif project is not None and (
            type(project) is not str or project not in identity["projects"]
        ):
            denial_reason = "project denied"

        binding = None
        if denial_reason is None:
            binding = connection.execute(
                "SELECT * FROM buzz_threads WHERE thread_id=?", (thread_id,)
            ).fetchone()
            if binding and (
                binding["sender_pubkey"] != sender_pubkey
                or (project and binding["project"] != project)
            ):
                denial_reason = "thread is bound to another identity or project"

        if denial_reason is None:
            try:
                result = self._dispatch_locked(
                    sender_pubkey, thread_id, command, project, request, binding
                )
            except _CommandDenied as exc:
                denial_reason = str(exc)
            else:
                self._transaction_checkpoint("after_dispatch")
                self._audit_locked(
                    sender_pubkey,
                    thread_id,
                    command,
                    project,
                    result.get("goal_id"),
                    request,
                    "ALLOW",
                )
                self._transaction_checkpoint("after_audit")
                response = {"ok": True, **result}

        if denial_reason is not None:
            self._audit_locked(
                sender_pubkey,
                thread_id,
                str(command),
                project if type(project) is str else None,
                request.get("goal_id"),
                request,
                "DENY",
            )
            self._transaction_checkpoint("after_audit")
            response = {"ok": False, "error": denial_reason}

        self._assert_mutation_integrity_locked()
        return response

    def _assert_mutation_integrity_locked(self) -> None:
        if not self.graph.connection.in_transaction:
            raise RuntimeError("Buzz integrity recheck requires an active transaction")
        try:
            self.assert_mutation_integrity()
        except INTEGRITY_ERRORS as exc:
            raise BuzzMutationIntegrityError(str(exc)) from exc

    def _dispatch_locked(
        self,
        sender: str,
        thread: str,
        command: str,
        project: str | None,
        request: dict[str, Any],
        binding: Any,
    ) -> dict[str, Any]:
        if not self.graph.connection.in_transaction:
            raise RuntimeError("locked Buzz dispatch requires an active transaction")
        if command == "goal":
            if not project or binding:
                raise _CommandDenied(
                    "new goal requires an unbound thread and explicit project"
                )
            try:
                goal_id = request["goal_id"]
                objective = request["objective"]
                accepted_sha = request["accepted_sha"]
            except KeyError as exc:
                raise _CommandDenied(f"{exc.args[0]} required") from None
            if project not in self.templates:
                raise _CommandDenied("project has no graph template")
            nodes = plan_goal(
                self.graph,
                self.templates,
                goal_id,
                project,
                objective,
                accepted_sha,
                manage_transaction=False,
            )
            self.graph.connection.execute(
                "INSERT INTO buzz_threads VALUES(?,?,?,?)",
                (thread, sender, project, goal_id),
            )
            return {"project": project, "goal_id": goal_id, "state": "ACTIVE", "accepted_sha": accepted_sha,
                    "next_node": nodes[0], "node_count": len(nodes)}
        if command == "status" and not project:
            return {"portfolio": self.graph.portfolio_status()}
        if not binding:
            raise _CommandDenied("thread has no goal binding")
        goal_id = binding["goal_id"]
        node_id = request.get("node_id")
        if command == "status":
            return {"project": binding["project"], "goal_id": goal_id,
                    "nodes": [row for row in self.graph.portfolio_status() if row["goal_id"] == goal_id]}
        if not node_id:
            raise _CommandDenied("node_id required")
        try:
            node = self.graph.get_node(node_id)
        except KeyError:
            raise _CommandDenied("node does not exist") from None
        if node["goal_id"] != goal_id:
            raise _CommandDenied("cross-goal node denied")
        if command == "evidence":
            return {"project": binding["project"], "goal_id": goal_id, "node_id": node_id,
                    "state": node["state"], "evidence_hash": node["evidence_hash"],
                    "evaluation_hash": node["evaluation_hash"], "integration_sha": node["integration_sha"]}
        if command in {"cancel", "reject", "approve", "resume"}:
            current_binding = self.graph.connection.execute(
                "SELECT * FROM buzz_threads WHERE thread_id=?", (thread,),
            ).fetchone()
            if not current_binding or (
                current_binding["sender_pubkey"],
                current_binding["project"],
                current_binding["goal_id"],
            ) != (sender, binding["project"], goal_id):
                raise _CommandDenied("thread binding changed before Buzz mutation")
            node = self.graph.get_node(node_id)
            if node["goal_id"] != goal_id:
                raise _CommandDenied("cross-goal node denied")
            self.graph._assert_node_has_no_pending_publication(node)
            if command in {"approve", "resume"}:
                if node["state"] != "NEEDS_HUMAN":
                    raise _CommandDenied(
                        "ordinary approval only resumes a persisted human gate"
                    )
                target = "READY"
            else:
                target = "CANCELLED"
            if target not in TRANSITIONS.get(node["state"], set()):
                raise _CommandDenied(
                    f"forbidden transition {node['state']} -> {target}"
                )
            node = self.graph._transition_locked(
                node,
                node["version"],
                target,
                f"Buzz {command} by mapped operator",
            )
        return {"project": binding["project"], "goal_id": goal_id, "node_id": node_id, "state": node["state"]}

    def scheduled_digest(self) -> dict[str, Any]:
        self.assert_mutation_integrity()
        rows = self.graph.portfolio_status()
        return {"projects": sorted({row["project"] for row in rows}), "active_goals": len({row["goal_id"] for row in rows}),
                "needs_human": sum(row["state"] == "NEEDS_HUMAN" for row in rows), "digest_hash": digest(rows)}

    def _audit_locked(
        self,
        sender: str,
        thread: str,
        command: str,
        project: str | None,
        goal_id: str | None,
        request: dict[str, Any],
        outcome: str,
    ) -> None:
        if not self.graph.connection.in_transaction:
            raise RuntimeError("locked Buzz audit requires an active transaction")
        self.graph.connection.execute(
            "INSERT INTO buzz_audit(sender_pubkey,thread_id,command,project,goal_id,request_hash,outcome) VALUES(?,?,?,?,?,?,?)",
            (sender, thread, command, project, goal_id, digest(request), outcome),
        )

    def _transaction_checkpoint(self, stage: str) -> None:
        """No-op fault boundary overridden only by deterministic local tests."""
