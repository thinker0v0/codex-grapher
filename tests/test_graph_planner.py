import tempfile
import unittest
import copy
import concurrent.futures
from pathlib import Path

from control_plane.graph_bootstrap import apply_database
from control_plane.graph_planner import compute_decision, load_templates, plan_goal
from control_plane.project_graph import ProjectGraph


ROOT = Path(__file__).resolve().parents[1]
SHA = "c" * 40


def open_graph(path):
    path = Path(path)
    if not path.exists():
        apply_database(path)
    return ProjectGraph(path)


class GraphPlannerTests(unittest.TestCase):
    def test_four_domain_graphs_have_expected_safety_stages(self):
        templates = load_templates(ROOT / "config/project-graphs.json")
        expected = {"nomad": {"POINT_IN_TIME_DATA", "LEAKAGE_AUDIT", "WALK_FORWARD", "PAPER"},
                    "opensource": {"SECURITY_LICENSE", "DOCS_USER_SIM"},
                    "business": {"MARKET_EVIDENCE", "USER_SIMULATION"},
                    "hynix": {"SOURCE_DATE_CHECK", "CONTRADICTION_REVIEW"}}
        for project, stages in expected.items():
            self.assertTrue(stages.issubset({node["kind"] for node in templates[project]}))

    def test_each_project_builds_a_durable_dependency_graph(self):
        templates = load_templates(ROOT / "config/project-graphs.json")
        with tempfile.TemporaryDirectory() as temporary:
            graph = open_graph(Path(temporary) / "graph.db")
            for project in templates:
                nodes = plan_goal(graph, templates, f"goal-{project}", project, f"deliver verified {project} outcome", SHA)
                self.assertGreaterEqual(len(nodes), 6)
                self.assertEqual(graph.get_node(nodes[0])["state"], "READY")
                self.assertTrue(all(graph.get_node(node)["state"] == "BLOCKED" for node in nodes[1:]))
            self.assertEqual({row["project"] for row in graph.portfolio_status()}, set(templates))

    def test_adaptive_policy_uses_progress_not_token_consumption(self):
        self.assertEqual(compute_decision([], "high", "high")["candidates"], 2)
        attempts = [{"root_cause": "bad-data", "progress": False}, {"root_cause": "bad-data", "progress": False}]
        self.assertEqual(compute_decision(attempts, "high", "high")["action"], "PIVOT")
        self.assertNotIn("tokens", compute_decision(attempts, "high", "high"))

    def test_identical_goal_replay_is_idempotent_but_mismatch_fails(self):
        templates = load_templates(ROOT / "config/project-graphs.json")
        with tempfile.TemporaryDirectory() as temporary:
            graph = open_graph(Path(temporary) / "graph.db")
            first = plan_goal(
                graph, templates, "goal-replay", "opensource",
                "deliver a replay-safe graph", SHA,
            )
            graph.lease(first[0], 0, "worker", 60)
            counts = tuple(graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0] for table in ("goals", "nodes", "dependencies", "events"))
            second = plan_goal(
                graph, templates, "goal-replay", "opensource",
                "deliver a replay-safe graph", SHA,
            )
            self.assertEqual(second, first)
            self.assertEqual(tuple(graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0] for table in ("goals", "nodes", "dependencies", "events")), counts)
            with self.assertRaises(ValueError):
                plan_goal(
                    graph, templates, "goal-replay", "opensource",
                    "a mismatched replay objective", SHA,
                )
            changed = copy.deepcopy(templates)
            changed["opensource"][0]["acceptance"].append("new mutable criterion")
            with self.assertRaises(ValueError):
                plan_goal(
                    graph, changed, "goal-replay", "opensource",
                    "deliver a replay-safe graph", SHA,
                )

    def test_goal_plan_rolls_back_all_rows_when_a_later_node_is_invalid(self):
        templates = load_templates(ROOT / "config/project-graphs.json")
        broken = copy.deepcopy(templates)
        broken["opensource"][1]["write_set"] = ["../outside"]
        with tempfile.TemporaryDirectory() as temporary:
            graph = open_graph(Path(temporary) / "graph.db")
            with self.assertRaises(ValueError):
                plan_goal(
                    graph, broken, "goal-atomic", "opensource",
                    "atomically build the full graph", SHA,
                )
            for table in ("goals", "nodes", "dependencies", "events"):
                self.assertEqual(
                    graph.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                    table,
                )

    def test_concurrent_identical_goal_plans_create_one_complete_graph(self):
        templates = load_templates(ROOT / "config/project-graphs.json")
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "graph.db"
            initial = open_graph(database)
            initial.connection.close()

            def submit():
                graph = ProjectGraph(database)
                try:
                    return plan_goal(
                        graph, templates, "goal-concurrent", "opensource",
                        "concurrently create one graph", SHA,
                    )
                finally:
                    graph.connection.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: submit(), range(2)))
            self.assertEqual(results[0], results[1])
            graph = ProjectGraph(database)
            self.assertEqual(
                graph.connection.execute(
                    "SELECT COUNT(*) FROM goals WHERE goal_id='goal-concurrent'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                graph.connection.execute(
                    "SELECT COUNT(*) FROM nodes WHERE goal_id='goal-concurrent'"
                ).fetchone()[0],
                len(results[0]),
            )


if __name__ == "__main__":
    unittest.main()
