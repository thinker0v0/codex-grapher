#!/usr/bin/env python3
"""Run a temporary two-node graph without workers, credentials, or services."""

import json
from pathlib import Path
import sys
import tempfile

# Support the documented command from a source checkout without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_plane.graph_bootstrap import apply_database
from control_plane.project_graph import ProjectGraph


def main():
    with tempfile.TemporaryDirectory(prefix="codex-grapher-demo-") as temporary:
        database = Path(temporary) / "graph.sqlite"
        apply_database(database)
        graph = ProjectGraph(database)
        try:
            # This placeholder is a fixture baseline, not a verified Git commit.
            graph.create_goal(
                "offline-demo", "opensource", "Demonstrate dependency scheduling",
                "0" * 40, idempotency_key="offline-demo-v1",
            )
            for node_id, dependencies in (("build", []), ("review", ["build"])):
                graph.add_node(
                    node_id, "offline-demo", "BUILD" if node_id == "build" else "REVIEW",
                    {"acceptance": ["Illustrate scheduling only"],
                     "evaluator_contract_id": "offline-demo-evaluation",
                     "timeout_seconds": 60, "budget": {"model_calls": 0}},
                    [f"example/{node_id}/"], dependencies=dependencies,
                )
            initial = {row["node_id"]: row["state"] for row in graph.portfolio_status()}
            leased = graph.lease("build", 0, "offline-demo-worker", ttl_seconds=60)
            running = graph.start("build", leased["version"], leased["lease_id"], "offline-demo-worker")
            released = graph.release_dependencies("offline-demo")
            try:
                graph.lease("review", 0, "offline-demo-worker", ttl_seconds=60)
            except ValueError as error:
                dependency_denial = str(error)
            else:
                raise RuntimeError("dependent node unexpectedly became runnable")
            graph.assert_static_integrity()
            final = {row["node_id"]: row["state"] for row in graph.portfolio_status()}
            if initial != {"build": "READY", "review": "BLOCKED"} or final != {
                "build": "RUNNING", "review": "BLOCKED",
            } or released:
                raise RuntimeError("unexpected scheduling result")
            print(json.dumps({
                "scope": "offline scheduling fixture; no work executed",
                "initial": initial,
                "build_transitions": [initial["build"], leased["state"], running["state"]],
                "final": final,
                "released_dependencies": released,
                "blocked_lease_reason": dependency_denial,
                "explanation": "Review stays blocked until build is independently evaluated and integrated.",
                "release_verdict": "NOT_PASS",
            }, indent=2))
        finally:
            graph.connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
