"""Deterministic domain DAG creation and evidence-driven compute decisions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from control_plane.project_graph import ProjectGraph, canonical, digest


def load_templates(path: Path) -> dict[str, list[dict[str, Any]]]:
    value = json.loads(path.read_text())
    if set(value) != {"nomad", "opensource", "business", "hynix"}:
        raise ValueError("templates must define exactly four projects")
    for project, nodes in value.items():
        if not nodes or len({node["kind"] for node in nodes}) != len(nodes):
            raise ValueError(f"{project} has empty or duplicate stages")
        for node in nodes:
            if not node.get("write_set") or not node.get("acceptance"):
                raise ValueError(f"{project}/{node.get('kind')} lacks executable contract")
    return value


def plan_goal(graph: ProjectGraph, templates: dict[str, list[dict[str, Any]]], goal_id: str,
              project: str, objective: str, accepted_sha: str, *,
              manage_transaction: bool = True) -> list[str]:
    if project not in templates:
        raise ValueError("project has no graph template")
    idempotency_key = f"{project}:{objective}:{accepted_sha}"
    planned: list[dict[str, Any]] = []
    previous = None
    for index, template in enumerate(templates[project], 1):
        node_id = f"{goal_id}-{index:02d}-{template['kind'].lower()}"
        spec = {"objective": objective, "acceptance": template["acceptance"],
                "human_gate": bool(template.get("human_gate", False)), "project": project,
                "evaluator_contract_id": f"{node_id}:evaluation:v1"}
        planned.append({
            "node_id": node_id,
            "kind": template["kind"],
            "spec": spec,
            "write_set": template["write_set"],
            "dependencies": [previous] if previous else [],
        })
        previous = node_id
    try:
        if manage_transaction:
            graph.connection.execute("BEGIN IMMEDIATE")
        elif not graph.connection.in_transaction:
            raise RuntimeError("caller-managed goal planning requires an active transaction")
        graph.assert_static_integrity()
        matches = graph.connection.execute(
            "SELECT * FROM goals WHERE goal_id=? OR idempotency_key=?", (goal_id, idempotency_key)
        ).fetchall()
        if matches:
            if len(matches) != 1:
                raise ValueError("goal replay collides with existing identity")
            existing = matches[0]
            expected_goal = (goal_id, project, objective, accepted_sha, idempotency_key)
            actual_goal = (
                existing["goal_id"], existing["project"], existing["objective"],
                existing["accepted_sha"], existing["idempotency_key"],
            )
            if actual_goal != expected_goal:
                raise ValueError("goal replay does not match the existing goal")
            existing_nodes = graph.connection.execute(
                "SELECT * FROM nodes WHERE goal_id=? ORDER BY rowid", (goal_id,)
            ).fetchall()
            if len(existing_nodes) != len(planned):
                raise ValueError("goal replay does not match the existing node set")
            for row, expected in zip(existing_nodes, planned):
                immutable = (
                    row["node_id"], row["kind"], row["spec_json"], row["spec_hash"],
                    row["write_set_json"],
                )
                expected_immutable = (
                    expected["node_id"], expected["kind"], canonical(expected["spec"]),
                    digest(expected["spec"]), canonical(expected["write_set"]),
                )
                dependencies = [item[0] for item in graph.connection.execute(
                    "SELECT dependency_id FROM dependencies WHERE node_id=? ORDER BY dependency_id",
                    (row["node_id"],),
                ).fetchall()]
                if immutable != expected_immutable or dependencies != sorted(expected["dependencies"]):
                    raise ValueError("goal replay does not match the existing graph")
        else:
            graph._create_goal_locked(
                goal_id, project, objective, accepted_sha, idempotency_key
            )
            for node in planned:
                graph._add_node_locked(
                    node["node_id"], goal_id, node["kind"], node["spec"],
                    node["write_set"], node["dependencies"],
                )
        if manage_transaction:
            graph.connection.commit()
    except Exception:
        if manage_transaction:
            graph.connection.rollback()
        raise
    return [node["node_id"] for node in planned]


def compute_decision(attempts: list[dict[str, Any]], value: str, uncertainty: str) -> dict[str, Any]:
    """Allocate work from evidence; prevent identical blind retries."""
    if not attempts:
        return {"action": "BUILD", "candidates": 2 if value == "high" and uncertainty == "high" else 1}
    last = attempts[-1]
    repeated = sum(1 for item in attempts if item.get("root_cause") == last.get("root_cause") and not item.get("progress"))
    if repeated >= 2:
        return {"action": "PIVOT", "candidates": 1, "reason": "same root cause twice without evidence gain"}
    if last.get("verifier_feedback"):
        return {"action": "REWORK", "candidates": 1, "reason": "actionable verifier feedback"}
    return {"action": "DIAGNOSE", "candidates": 1, "reason": "new evidence required"}
