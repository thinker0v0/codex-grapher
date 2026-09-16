#!/usr/bin/env python3
"""Root-owned Unix-socket API joining planners, builders, evaluator, and integrator."""

from __future__ import annotations

import argparse
import concurrent.futures
import grp
import hashlib
import json
import os
import pwd
import socket
import sqlite3
import stat
import struct
import threading
from pathlib import Path
from typing import Any

from control_plane.artifact_builder import SAFE_ID
from control_plane.evidence_ingress import EvidenceIngress
from control_plane.evidence_store import get_active_claim, resolve_artifact
from control_plane.graph_planner import load_templates, plan_goal
from control_plane.project_graph import ProjectGraph
from control_plane.project_integrator import ProjectIntegrator
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.runtime_config import load_runtime


MAX_REQUEST = 1024 * 1024
PROJECT_USERS = {"hermes-fin-korea": "nomad", "hermes-oss": "opensource",
                 "hermes-business": "business", "hermes-hynix": "hynix"}


def _assert_no_pending_publication_mutation(
    graph: ProjectGraph, project: str | None = None,
) -> None:
    """Freeze API mutations while a project-global physical update is recoverable."""
    parameters: tuple[Any, ...] = ()
    project_filter = ""
    if project is not None:
        project_filter = " AND g.project=?"
        parameters = (project,)
    pending_promotion = graph.connection.execute(
        "SELECT 1 FROM integration_attempts a JOIN nodes n ON n.node_id=a.node_id "
        "JOIN goals g ON g.goal_id=n.goal_id WHERE a.status!='COMPLETED'"
        + project_filter + " LIMIT 1",
        parameters,
    ).fetchone()
    rollback_parameters: tuple[Any, ...] = () if project is None else (project,)
    rollback_filter = "" if project is None else " WHERE project=?"
    pending_rollback = graph.connection.execute(
        "SELECT 1 FROM publication_journal" + rollback_filter
        + " GROUP BY project,operation_id "
        "HAVING operation_kind='ROLLBACK' AND SUM(phase='COMPLETED')=0 LIMIT 1",
        rollback_parameters,
    ).fetchone()
    if pending_promotion or pending_rollback:
        raise RuntimeError("project graph is frozen by a pending publication operation")


def node_project(graph: ProjectGraph, node_id: str) -> str:
    row = graph.connection.execute(
        "SELECT g.project FROM nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE n.node_id=?", (node_id,)
    ).fetchone()
    if not row:
        raise KeyError(node_id)
    return row[0]


def _read_task_contract(
    runtime_entry: dict[str, str], node_id: str, expected_base_sha: str,
) -> tuple[str, list[str]]:
    """Read the one root-owned router contract derived from runtime and node identity."""
    if not isinstance(node_id, str) or not SAFE_ID.fullmatch(node_id):
        raise PermissionError("node ID is unsafe for the router-contract namespace")
    contract_root = Path(runtime_entry["repo"]).parent / "runtime" / "router-contracts"
    if contract_root.is_symlink() or not contract_root.is_dir():
        raise PermissionError("router-contract root is unsafe")
    root_descriptor = os.open(
        contract_root, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        descriptor = os.open(
            f"{node_id}.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=root_descriptor,
        )
    finally:
        os.close(root_descriptor)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or before.st_mode & 0o022
            or before.st_size > MAX_REQUEST
        ):
            raise PermissionError("router contract must be owner-controlled and single-link")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_REQUEST:
                raise PermissionError("router contract exceeds the request limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        fingerprint = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(after) or total != after.st_size:
            raise PermissionError("router contract changed while being read")
    finally:
        os.close(descriptor)
    contract_bytes = b"".join(chunks)
    try:
        contract = json.loads(contract_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PermissionError("router contract is invalid JSON") from None
    expected_project_id = runtime_entry["worker_project_id"]
    if (
        not isinstance(contract, dict)
        or contract.get("task_id") != node_id
        or contract.get("project_id") != expected_project_id
        or contract.get("base_sha") != expected_base_sha
        or contract.get("builder_identity") != f"hermes-{expected_project_id}"
    ):
        raise PermissionError("router contract does not match the graph/runtime binding")
    required_tests = contract.get("required_tests")
    if not isinstance(required_tests, list) or not required_tests or not all(
        isinstance(command, str) and command and "\x00" not in command
        for command in required_tests
    ):
        raise PermissionError("router contract required tests are invalid")
    return hashlib.sha256(contract_bytes).hexdigest(), required_tests


def dispatch(graph: ProjectGraph, templates: dict[str, list[dict[str, Any]]], username: str,
             request: dict[str, Any], coordinators: dict[str, ProjectCoordinator] | None = None,
             runtime: dict[str, dict[str, str]] | None = None) -> Any:
    # This shared gate orders DB closure, exact map coverage, durable evidence,
    # and physical projection before authorization, status, or mutation logic.
    coordinators = ProjectCoordinator.require_external_integrity(
        graph, coordinators,
    )
    action = request.get("action")
    if action == "status" and (username == "root" or username == "hermes-evaluator" or username in PROJECT_USERS):
        project = request.get("project")
        rows = graph.portfolio_status()
        if username in PROJECT_USERS and username != "hermes-oss":
            project = PROJECT_USERS[username]
        return [row for row in rows if not project or row["project"] == project]
    if action == "create_goal" and username == "hermes-oss":
        _assert_no_pending_publication_mutation(graph, request["project"])
        return plan_goal(graph, templates, request["goal_id"], request["project"], request["objective"], request["accepted_sha"])
    if action in {"lease", "start", "reconcile", "ingest_evidence"} and username in PROJECT_USERS:
        node_id = request["node_id"]
        project = node_project(graph, node_id)
        if project != PROJECT_USERS[username]:
            raise PermissionError("builder cannot access another project")
        _assert_no_pending_publication_mutation(graph, project)
        row = graph.get_node(node_id)
        if action == "lease":
            return graph.lease(node_id, request["version"], username, int(request.get("ttl_seconds", 300)))
        ingress_replay = (
            action == "ingest_evidence"
            and row["state"] == "EVIDENCE_PENDING"
            and row["version"] == request.get("version", -2) + 1
        )
        if not ingress_replay and (
            row["lease_owner"] != username or row["lease_id"] != request.get("lease_id")
        ):
            raise PermissionError("exact lease required")
        if action == "start":
            return graph.start(
                node_id, request["version"], request["lease_id"], username,
            )
        if action == "ingest_evidence":
            if not runtime:
                raise PermissionError("immutable evidence runtime is not configured")
            if type(request.get("returncode")) is not int or request["returncode"] != 0:
                raise PermissionError("artifact ingress requires a zero worker return code")
            if request.get("controller_state") != "EVIDENCE_PENDING":
                raise PermissionError("artifact ingress requires the verified controller state")
            if "manifest_relative_path" in request or "contract_path" in request:
                raise PermissionError("artifact and contract paths are server-derived")
            if not ingress_replay and (
                row["state"] != "RUNNING"
                or row["version"] != request["version"]
                or not graph._lease_is_live(row)
            ):
                raise PermissionError(
                    "artifact ingress requires the exact live running lease"
                )
            runtime_entry = runtime[project]
            source_root = Path(runtime_entry["repo"]).parent / "runtime" / "evidence"
            target_root = Path(runtime_entry["evidence_root"])
            contract_sha256, required_tests = _read_task_contract(
                runtime_entry, node_id, row["base_sha"],
            )
            artifact = EvidenceIngress(source_root, target_root).ingest(
                expected_task_id=node_id,
                expected_attempt=int(row["attempt"]),
                expected_project_id=runtime_entry["worker_project_id"],
                expected_base_sha=row["base_sha"],
                expected_contract_sha256=contract_sha256,
                expected_required_tests=required_tests,
            )
            return graph.record_ingressed_evidence(
                node_id, request["version"], artifact,
            )
        return graph.reconcile_worker(node_id, request["version"], int(request["returncode"]),
                                      request.get("controller_state"), request.get("evidence"))
    if action == "claim_evidence" and username == "hermes-evaluator" and runtime:
        project = node_project(graph, request["node_id"])
        _assert_no_pending_publication_mutation(graph, project)
        _, manifest_path = resolve_artifact(
            graph.connection, request["artifact_id"], Path(runtime[project]["evidence_root"]),
            expected_node_id=request["node_id"], expected_project=project,
        )
        claimed = graph.claim_evidence(
            request["node_id"], request["version"], request["artifact_id"], username,
            int(request.get("ttl_seconds", 600)),
        )
        return {**claimed, "manifest_path": str(manifest_path)}
    if action == "heartbeat_evidence_claim" and username == "hermes-evaluator" and runtime:
        project = node_project(graph, request["node_id"])
        _assert_no_pending_publication_mutation(graph, project)
        resolve_artifact(
            graph.connection, request["artifact_id"],
            Path(runtime[project]["evidence_root"]),
            expected_node_id=request["node_id"], expected_project=project,
        )
        return graph.heartbeat_evidence_claim(
            request["node_id"], request["version"], request["artifact_id"],
            request["claim_id"], username, int(request.get("ttl_seconds", 600)),
        )
    if action == "evaluate" and username == "hermes-evaluator" and runtime:
        project = node_project(graph, request["node_id"])
        # EVALUATING is intentionally not retrospectively sensitive. Require
        # this project's exact coordinator prospectively before the first PASS
        # and canonical outcome can be committed.
        coordinators = ProjectCoordinator.require_external_integrity(
            graph, coordinators, additional_required_projects={project},
        )
        _assert_no_pending_publication_mutation(graph, project)
        if "evidence_manifest" in request:
            raise PermissionError("evaluator must submit the durable artifact ID, not a path")
        artifact, manifest_path = resolve_artifact(
            graph.connection, request["artifact_id"], Path(runtime[project]["evidence_root"]),
            expected_node_id=request["node_id"], expected_project=project,
        )
        node = graph.get_node(request["node_id"])
        if not (
            node["state"] == "PASSED"
            and node["version"] == request["version"] + 1
        ):
            get_active_claim(
                graph.connection, request["artifact_id"],
                expected_node_id=request["node_id"], expected_claimant=username,
            )
        if request["evaluation"].get("evaluated_git_sha") != artifact["candidate_sha"]:
            raise PermissionError("evaluation candidate differs from the durable artifact")
        return graph.record_evaluation(
            request["node_id"], request["version"], request["artifact_id"],
            request["evaluation"], manifest_path,
        )
    if action == "reject_evidence" and username == "hermes-evaluator" and runtime:
        _assert_no_pending_publication_mutation(
            graph, node_project(graph, request["node_id"]),
        )
        if "reason" in request or "evidence_manifest" in request:
            raise PermissionError("evaluator disposition accepts hashes and artifact IDs only")
        project = node_project(graph, request["node_id"])
        resolve_artifact(
            graph.connection, request["artifact_id"], Path(runtime[project]["evidence_root"]),
            expected_node_id=request["node_id"], expected_project=project,
        )
        return graph.reject_evidence(
            request["node_id"], request["version"], request["artifact_id"],
            request["disposition"], request["reason_sha256"], username,
        )
    if action == "integrate" and username == "root" and runtime is not None:
        project = node_project(graph, request["node_id"])
        coordinator = coordinators.get(project)
        if coordinator is None:
            raise PermissionError("integration project coordinator is not configured")
        if (
            "evidence_manifest" in request or "evaluation" in request
            or "artifact_id" not in request or "outcome_id" not in request
        ):
            raise PermissionError(
                "integration requires durable artifact/outcome IDs, never caller bytes or paths"
            )
        _, manifest_path = resolve_artifact(
            graph.connection, request["artifact_id"], Path(runtime[project]["evidence_root"]),
            expected_node_id=request["node_id"], expected_project=project,
        )
        return coordinator.integrate(
            request["attempt_id"], request["node_id"], request["outcome_id"],
            request["artifact_id"], manifest_path,
            runtime[project]["worker_project_id"],
            Path(runtime[project]["evidence_root"]),
        )
    if action == "rollback" and username == "root":
        project = node_project(graph, request["node_id"])
        coordinator = coordinators.get(project)
        if coordinator is None:
            raise PermissionError("rollback project coordinator is not configured")
        return coordinator.rollback(
            request["rollback_id"], request["node_id"],
            request["integration_attempt_id"], int(request["expected_head_version"]),
        )
    if action == "recover" and username == "root":
        _assert_no_pending_publication_mutation(graph)
        return {"recovered": graph.recover_leases(force_startup=bool(request.get("force_startup", False)))}
    raise PermissionError("role is not authorized for graph action")


def build_coordinators(
    graph: ProjectGraph,
    runtime: dict[str, dict[str, str]],
    evaluator_public_key: Path,
    rubric_path: Path,
) -> dict[str, ProjectCoordinator]:
    """Build each project integrator with its worker-runtime publication root."""
    return {
        project: ProjectCoordinator(graph, ProjectIntegrator(
            Path(value["repo"]), Path(value["binding"]), evaluator_public_key,
            rubric_path, value["accepted_ref"], f"hermes-{value['worker_project_id']}",
            publication_root=Path(value["binding"]).parent / "publications",
        ), Path(value["evidence_root"]), value["worker_project_id"])
        for project, value in runtime.items()
    }


def reconcile_startup(
    graph: ProjectGraph,
    coordinators: dict[str, ProjectCoordinator] | None,
) -> None:
    """Finish journaled side effects before generic node/lease recovery."""
    coordinators = ProjectCoordinator.require_external_integrity(
        graph, coordinators,
    )
    pending = graph.connection.execute(
        "SELECT a.node_id,a.candidate_sha,g.project FROM integration_attempts a "
        "JOIN nodes n ON n.node_id=a.node_id JOIN goals g ON g.goal_id=n.goal_id "
        "WHERE a.status!='COMPLETED'"
    ).fetchall()
    for attempt in pending:
        coordinators[attempt["project"]].reconcile(
            attempt["node_id"], attempt["candidate_sha"],
        )
    for coordinator in coordinators.values():
        for rollback_id in coordinator.pending_rollbacks():
            coordinator.reconcile_rollback(rollback_id)
    for coordinator in coordinators.values():
        coordinator.integrator.ensure_bound_publication()
    coordinators = ProjectCoordinator.require_external_integrity(
        graph, coordinators,
    )
    graph.recover_leases()


def serve(socket_path: Path, database: Path, templates_path: Path, evaluator_public_key: Path,
          rubric_path: Path, runtime_path: Path, socket_group: str) -> None:
    graph = ProjectGraph(database, evaluator_public_key, hashlib.sha256(rubric_path.read_bytes()).hexdigest(),
                         allow_cross_thread=True)
    templates = load_templates(templates_path)
    runtime = load_runtime(runtime_path)
    coordinators = build_coordinators(graph, runtime, evaluator_public_key, rubric_path)
    reconcile_startup(graph, coordinators)
    socket_path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chown(socket_path, 0, grp.getgrnam(socket_group).gr_gid)
    os.chmod(socket_path, 0o660)
    server.listen(32)
    database_lock = threading.RLock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="graph-api") as workers:
        while True:
            connection, _ = server.accept()
            workers.submit(handle, connection, graph, templates, coordinators, runtime, database_lock)


def handle(connection: socket.socket, graph: ProjectGraph, templates: dict[str, list[dict[str, Any]]],
           coordinators: dict[str, ProjectCoordinator], runtime: dict[str, dict[str, str]],
           database_lock: threading.RLock) -> None:
    with connection:
        try:
            _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            username = pwd.getpwuid(uid).pw_name
            payload = b""
            while not payload.endswith(b"\n") and len(payload) <= MAX_REQUEST:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                payload += chunk
            if len(payload) > MAX_REQUEST:
                raise ValueError("request exceeds 1 MiB")
            with database_lock:
                response = {"ok": True, "result": dispatch(graph, templates, username, json.loads(payload), coordinators, runtime)}
        except Exception as exc:
            response = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        connection.sendall(json.dumps(response, sort_keys=True).encode() + b"\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--templates", type=Path, required=True)
    parser.add_argument("--evaluator-public-key", type=Path, required=True)
    parser.add_argument("--rubric", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--socket-group", default="ai-ops-graph")
    args = parser.parse_args()
    serve(args.socket, args.database, args.templates, args.evaluator_public_key,
          args.rubric, args.runtime, args.socket_group)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
