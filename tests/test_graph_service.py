import tempfile
import unittest
import concurrent.futures
import hashlib
import json
import os
import subprocess
from pathlib import Path

from control_plane.graph_planner import load_templates
from control_plane.graph_bootstrap import apply_database
from control_plane.graph_service import (
    build_coordinators,
    dispatch,
    reconcile_startup,
)
from control_plane.project_graph import ProjectGraph
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_integrator import ProjectIntegrator
from tests.evaluation_helpers import generate_keypair, make_evaluation


ROOT = Path(__file__).resolve().parents[1]
SHA = "e" * 40


class GraphServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.private_key, self.public_key = generate_keypair(self.root)
        self.rubric = self.root / "RUBRIC.md"
        self.rubric.write_text("frozen fixture rubric\n")
        database = self.root / "graph.db"
        apply_database(database)
        self.graph = ProjectGraph(
            database, self.public_key,
            hashlib.sha256(self.rubric.read_bytes()).hexdigest(),
        )
        self.templates = load_templates(ROOT / "config/project-graphs.json")
        self.nodes = dispatch(self.graph, self.templates, "hermes-oss", {
            "action":"create_goal", "goal_id":"goal-nomad-service", "project":"nomad",
            "objective":"deliver verified finance research", "accepted_sha":SHA})

    def tearDown(self):
        self.temp.cleanup()

    def test_planner_can_create_and_project_builder_can_lease(self):
        row = dispatch(self.graph, self.templates, "hermes-fin-korea", {"action":"lease", "node_id":self.nodes[0], "version":0})
        self.assertEqual(row["lease_owner"], "hermes-fin-korea")

    def test_stale_reconcile_lease_is_denied_before_node_or_evidence_mutation(self):
        first = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "lease", "node_id": self.nodes[0], "version": 0,
        })
        self.graph.recover_leases(force_startup=True)
        second = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "lease", "node_id": self.nodes[0], "version": 2,
        })
        running = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "start", "node_id": self.nodes[0], "version": second["version"],
            "lease_id": second["lease_id"],
        })
        before = self.graph.get_node(self.nodes[0])
        event_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM events WHERE node_id=?", (self.nodes[0],)
        ).fetchone()[0]
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "hermes-fin-korea", {
                "action": "reconcile", "node_id": self.nodes[0], "version": running["version"],
                "lease_id": first["lease_id"], "returncode": 0,
                "controller_state": "EVIDENCE_PENDING", "evidence": {"sha": SHA},
            })
        self.assertEqual(self.graph.get_node(self.nodes[0]), before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM events WHERE node_id=?", (self.nodes[0],)
        ).fetchone()[0], event_count)
        reconciled = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "reconcile", "node_id": self.nodes[0], "version": running["version"],
            "lease_id": second["lease_id"], "returncode": 0,
            "controller_state": "EVIDENCE_PENDING", "evidence": {"sha": SHA},
        })
        self.assertEqual(reconciled["state"], "READY")
        self.assertIsNone(reconciled["evidence_hash"])

    def test_cross_project_builder_and_builder_integration_are_denied(self):
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "hermes-business", {"action":"lease", "node_id":self.nodes[0], "version":0})
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "hermes-fin-korea", {"action":"integrated", "node_id":self.nodes[0], "version":0, "integration_sha":SHA})
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "root", {"action":"integrated", "node_id":self.nodes[0], "version":0, "integration_sha":SHA})
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "root", {"action":"integrate", "node_id":self.nodes[0]})

    def test_status_scope_and_recovery_roles(self):
        self.assertTrue(dispatch(self.graph, self.templates, "hermes-fin-korea", {"action":"status"}))
        self.assertEqual(dispatch(self.graph, self.templates, "root", {"action":"recover"})["recovered"], 0)
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "hermes-evaluator", {"action":"recover"})

    def test_cross_thread_database_mode_supports_service_workers(self):
        self.graph.connection.close()
        database = Path(self.temp.name) / "threaded.db"
        apply_database(database)
        graph = ProjectGraph(database, allow_cross_thread=True)
        dispatch(graph, self.templates, "hermes-oss", {"action":"create_goal", "goal_id":"threaded-goal",
                 "project":"opensource", "objective":"deliver verified threaded service", "accepted_sha":SHA})
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            rows = pool.submit(dispatch, graph, self.templates, "hermes-oss", {"action":"status"}).result()
        self.assertTrue(rows)

    def evidence_runtime(self):
        worker = self.root / "worker"
        (worker / "workspace").mkdir(parents=True, exist_ok=True)
        source = worker / "runtime" / "evidence"
        source.mkdir(parents=True, exist_ok=True)
        (worker / "runtime" / "router-contracts").mkdir(parents=True, exist_ok=True)
        target = self.root / "evaluator-artifacts"
        target.mkdir(exist_ok=True)
        return {
            "nomad": {
                "worker_project_id": "fin-korea",
                "repo": str(worker / "workspace"),
                "binding": str(worker / "runtime" / "binding.json"),
                "evidence_root": str(target),
                "accepted_ref": "refs/ai-ops/accepted/nomad",
            }
        }, source, target

    def exact_coordinator(self, runtime, project="nomad"):
        entry = runtime[project]
        repo = Path(entry["repo"])
        subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
        binding = Path(entry["binding"])
        binding.write_text(json.dumps({"repo": "fixture", "base_sha": SHA}) + "\n")
        binding.chmod(0o440)
        return ProjectCoordinator(
            self.graph,
            ProjectIntegrator(
                repo, binding, self.public_key, self.rubric,
                entry["accepted_ref"],
                publication_root=binding.parent / "publications",
            ),
            Path(entry["evidence_root"]), entry["worker_project_id"],
        )

    def test_fresh_graph_accepts_none_and_empty_external_integrity_maps(self):
        reconcile_startup(self.graph, None)
        reconcile_startup(self.graph, {})
        self.assertTrue(dispatch(
            self.graph, self.templates, "root", {"action": "status"},
            coordinators=None,
        ))
        self.assertTrue(dispatch(
            self.graph, self.templates, "root", {"action": "status"},
            coordinators={},
        ))

    @staticmethod
    def write_manifest(source: Path, task_id: str, candidate: str) -> str:
        root = source / task_id / "attempt-1"
        output_dir = root / "required-tests"
        output_dir.mkdir(parents=True)
        bundle = b"fixture candidate bundle\n"
        output = b"fixture test passed\n"
        path_check = b'{"valid":true,"violations":[]}\n'
        (root / "candidate.bundle").write_bytes(bundle)
        (root / "path-check.json").write_bytes(path_check)
        (output_dir / "0000.output").write_bytes(output)
        contract = {
            "task_id": task_id,
            "project_id": "fin-korea",
            "base_sha": SHA,
            "builder_identity": "hermes-fin-korea",
            "required_tests": ["fixture-test"],
        }
        contract_bytes = (
            json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()
        contract_path = source.parent / "router-contracts" / f"{task_id}.json"
        contract_path.write_bytes(contract_bytes)
        contract_path.chmod(0o600)
        manifest = {
            "schema_version": 4,
            "task_id": task_id,
            "attempt": 1,
            "project_id": "fin-korea",
            "base_sha": SHA,
            "candidate_sha": candidate,
            "producer_identity": "hermes-fin-korea",
            "created_at": "2026-08-30T00:00:00+00:00",
            "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
            "path_check": {
                "path": "path-check.json",
                "sha256": hashlib.sha256(path_check).hexdigest(),
                "byte_length": len(path_check),
            },
            "bundle": {
                "path": "candidate.bundle", "sha256": hashlib.sha256(bundle).hexdigest(),
                "byte_length": len(bundle),
            },
            "required_tests": [{
                "sequence": 0, "command": "fixture-test", "candidate_sha": candidate,
                "exit_code": 0,
                "output": {
                    "path": "required-tests/0000.output",
                    "sha256": hashlib.sha256(output).hexdigest(), "byte_length": len(output),
                },
            }],
        }
        relative = f"{task_id}/attempt-1/manifest.json"
        (source / relative).write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n"
        )
        return relative

    def test_artifact_id_lifecycle_is_role_scoped_replay_safe_and_path_free(self):
        runtime, source, _ = self.evidence_runtime()
        node_id = self.nodes[0]
        candidate = "f" * 40
        relative = self.write_manifest(source, node_id, candidate)
        leased = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "lease", "node_id": node_id, "version": 0,
        })
        running = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "start", "node_id": node_id, "version": leased["version"],
            "lease_id": leased["lease_id"],
        })
        request = {
            "action": "ingest_evidence", "node_id": node_id,
            "version": running["version"], "lease_id": leased["lease_id"],
            "returncode": 0, "controller_state": "EVIDENCE_PENDING",
        }
        with self.assertRaises(PermissionError):
            dispatch(
                self.graph, self.templates, "hermes-fin-korea",
                {**request, "manifest_relative_path": "another-node/manifest.json"},
                runtime=runtime,
            )
        self.assertEqual(self.graph.get_node(node_id)["state"], "RUNNING")
        ingressed = dispatch(
            self.graph, self.templates, "hermes-fin-korea", request, runtime=runtime,
        )
        replay = dispatch(
            self.graph, self.templates, "hermes-fin-korea", request, runtime=runtime,
        )
        self.assertEqual(replay["artifact"]["artifact_id"], ingressed["artifact"]["artifact_id"])
        artifact_id = ingressed["artifact"]["artifact_id"]
        claim_request = {
            "action": "claim_evidence", "node_id": node_id,
            "version": ingressed["node"]["version"], "artifact_id": artifact_id,
        }
        for username in ("hermes-fin-korea", "root", "hermes-business"):
            with self.subTest(username=username), self.assertRaises(PermissionError):
                dispatch(self.graph, self.templates, username, claim_request, runtime=runtime)
        claimed = dispatch(
            self.graph, self.templates, "hermes-evaluator", claim_request, runtime=runtime,
        )
        claim_replay = dispatch(
            self.graph, self.templates, "hermes-evaluator", claim_request, runtime=runtime,
        )
        self.assertEqual(claim_replay["artifact"]["claim_id"], claimed["artifact"]["claim_id"])
        self.assertEqual(claimed["node"]["state"], "EVALUATING")
        heartbeat = dispatch(self.graph, self.templates, "hermes-evaluator", {
            "action": "heartbeat_evidence_claim", "node_id": node_id,
            "version": claimed["node"]["version"], "artifact_id": artifact_id,
            "claim_id": claimed["artifact"]["claim_id"], "ttl_seconds": 1200,
        }, runtime=runtime)
        self.assertEqual(
            heartbeat["claim"]["claim_id"], claimed["artifact"]["claim_id"],
        )

        coordinator = self.exact_coordinator(runtime)
        coordinator_map = {"nomad": coordinator}
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "hermes-evaluator", {
                "action": "evaluate", "node_id": node_id,
                "version": claimed["node"]["version"], "artifact_id": artifact_id,
                "evidence_manifest": claimed["manifest_path"], "evaluation": {},
            }, coordinators=coordinator_map, runtime=runtime)
        contract_id = json.loads(self.graph.get_node(node_id)["spec_json"])["evaluator_contract_id"]
        evaluation = make_evaluation(
            self.private_key, Path(claimed["manifest_path"]), self.rubric,
            task_id=node_id, contract_id=contract_id, candidate_sha=candidate,
            artifact_id=artifact_id, claim_id=claimed["artifact"]["claim_id"],
        )
        with self.assertRaisesRegex(RuntimeError, "lack exact coordinators"):
            dispatch(self.graph, self.templates, "hermes-evaluator", {
                "action": "evaluate", "node_id": node_id,
                "version": claimed["node"]["version"], "artifact_id": artifact_id,
                "evaluation": evaluation,
            }, runtime=runtime)
        self.assertEqual(self.graph.get_node(node_id)["state"], "EVALUATING")
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM evaluation_outcomes"
        ).fetchone()[0], 0)
        passed = dispatch(self.graph, self.templates, "hermes-evaluator", {
            "action": "evaluate", "node_id": node_id,
            "version": claimed["node"]["version"], "artifact_id": artifact_id,
            "evaluation": evaluation,
        }, coordinators=coordinator_map, runtime=runtime)
        self.assertEqual(passed["node"]["state"], "PASSED")
        self.assertEqual(
            passed["outcome"]["artifact_id"], artifact_id,
        )

    def test_ingress_denies_hardlinked_or_changed_root_contract_without_state_mutation(self):
        runtime, source, _ = self.evidence_runtime()
        node_id = self.nodes[0]
        self.write_manifest(source, node_id, "f" * 40)
        leased = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "lease", "node_id": node_id, "version": 0,
        })
        running = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "start", "node_id": node_id, "version": leased["version"],
            "lease_id": leased["lease_id"],
        })
        request = {
            "action": "ingest_evidence", "node_id": node_id,
            "version": running["version"], "lease_id": leased["lease_id"],
            "returncode": 0, "controller_state": "EVIDENCE_PENDING",
        }
        contract = source.parent / "router-contracts" / f"{node_id}.json"
        extra_link = contract.with_suffix(".hardlink")
        os.link(contract, extra_link)
        with self.assertRaises(PermissionError):
            dispatch(
                self.graph, self.templates, "hermes-fin-korea", request, runtime=runtime,
            )
        extra_link.unlink()
        value = json.loads(contract.read_text())
        value["required_tests"] = ["worker-selected-command"]
        contract.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        contract.chmod(0o600)
        with self.assertRaises(PermissionError):
            dispatch(
                self.graph, self.templates, "hermes-fin-korea", request, runtime=runtime,
            )
        self.assertEqual(self.graph.get_node(node_id)["state"], "RUNNING")
        self.assertEqual(
            self.graph.connection.execute("SELECT COUNT(*) FROM evidence_artifacts").fetchone()[0],
            0,
        )

    def test_expired_ingress_is_denied_before_evaluator_store_side_effect(self):
        runtime, source, target = self.evidence_runtime()
        node_id = self.nodes[0]
        self.write_manifest(source, node_id, "f" * 40)
        leased = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "lease", "node_id": node_id, "version": 0,
        })
        running = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "start", "node_id": node_id, "version": leased["version"],
            "lease_id": leased["lease_id"],
        })
        self.graph.connection.execute(
            "UPDATE nodes SET lease_expires_at='2000-01-01T00:00:00+00:00' "
            "WHERE node_id=?", (node_id,),
        )
        self.graph.connection.commit()
        before = sorted(str(path.relative_to(target)) for path in target.rglob("*"))
        with self.assertRaises(PermissionError):
            dispatch(self.graph, self.templates, "hermes-fin-korea", {
                "action": "ingest_evidence", "node_id": node_id,
                "version": running["version"], "lease_id": leased["lease_id"],
                "returncode": 0, "controller_state": "EVIDENCE_PENDING",
            }, runtime=runtime)
        after = sorted(str(path.relative_to(target)) for path in target.rglob("*"))
        self.assertEqual(after, before)
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM evidence_artifacts"
        ).fetchone()[0], 0)

    def test_corrupt_publication_projection_blocks_status_and_create_before_mutation(self):
        self.graph.connection.execute(
            "INSERT INTO publication_heads(project,version,sha,generation) "
            "VALUES('opensource',1,?,?)", (SHA, SHA),
        )
        self.graph.connection.commit()
        goal_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0]
        with self.assertRaises(RuntimeError):
            dispatch(self.graph, self.templates, "root", {"action": "status"})
        with self.assertRaises(RuntimeError):
            dispatch(self.graph, self.templates, "hermes-oss", {
                "action": "create_goal", "goal_id": "blocked-corruption",
                "project": "opensource", "objective": "must not mutate",
                "accepted_sha": SHA,
            })
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0], goal_count)

    def test_unknown_current_route_freezes_service_before_any_mutation(self):
        self.graph.connection.execute(
            "UPDATE goals SET project='fin-global' WHERE goal_id='goal-nomad-service'"
        )
        self.graph.connection.commit()
        before = {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("goals", "nodes", "events")
        }
        with self.assertRaisesRegex(RuntimeError, "exact active set"):
            dispatch(self.graph, self.templates, "root", {"action": "status"})
        with self.assertRaisesRegex(RuntimeError, "exact active set"):
            dispatch(self.graph, self.templates, "hermes-oss", {
                "action": "create_goal", "goal_id": "unknown-route-blocked",
                "project": "opensource", "objective": "must remain unpersisted",
                "accepted_sha": SHA,
            })
        self.assertEqual({
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in ("goals", "nodes", "events")
        }, before)

    def test_live_dispatch_blocks_physical_projection_mismatch_before_mutation(self):
        runtime, _, _ = self.evidence_runtime()
        coordinator = self.exact_coordinator(runtime)
        binding = Path(runtime["nomad"]["binding"])
        binding.chmod(0o640)
        binding.write_text(
            json.dumps({"repo": "fixture", "base_sha": "f" * 40}) + "\n"
        )
        binding.chmod(0o440)
        goal_count = self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0]
        coordinators = {"nomad": coordinator}
        with self.assertRaisesRegex(RuntimeError, "pre-head binding"):
            dispatch(
                self.graph, self.templates, "root", {"action": "status"},
                coordinators=coordinators,
            )
        with self.assertRaisesRegex(RuntimeError, "pre-head binding"):
            dispatch(
                self.graph, self.templates, "hermes-oss", {
                    "action": "create_goal", "goal_id": "physical-drift",
                    "project": "nomad", "objective": "must not persist",
                    "accepted_sha": SHA,
                }, coordinators=coordinators,
            )
        self.assertEqual(self.graph.connection.execute(
            "SELECT COUNT(*) FROM goals"
        ).fetchone()[0], goal_count)

    def test_evaluator_disposition_endpoint_is_role_scoped_and_never_passes(self):
        runtime, source, _ = self.evidence_runtime()
        node_id = self.nodes[0]
        self.write_manifest(source, node_id, "f" * 40)
        leased = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "lease", "node_id": node_id, "version": 0,
        })
        running = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "start", "node_id": node_id, "version": leased["version"],
            "lease_id": leased["lease_id"],
        })
        ingressed = dispatch(self.graph, self.templates, "hermes-fin-korea", {
            "action": "ingest_evidence", "node_id": node_id,
            "version": running["version"], "lease_id": leased["lease_id"],
            "returncode": 0, "controller_state": "EVIDENCE_PENDING",
        }, runtime=runtime)
        artifact_id = ingressed["artifact"]["artifact_id"]
        claimed = dispatch(self.graph, self.templates, "hermes-evaluator", {
            "action": "claim_evidence", "node_id": node_id,
            "version": ingressed["node"]["version"], "artifact_id": artifact_id,
        }, runtime=runtime)
        request = {
            "action": "reject_evidence", "node_id": node_id,
            "version": claimed["node"]["version"], "artifact_id": artifact_id,
            "disposition": "NEEDS_HUMAN", "reason_sha256": "8" * 64,
        }
        for username in ("root", "hermes-fin-korea", "hermes-business"):
            with self.subTest(username=username), self.assertRaises(PermissionError):
                dispatch(self.graph, self.templates, username, request, runtime=runtime)
        disposed = dispatch(
            self.graph, self.templates, "hermes-evaluator", request, runtime=runtime,
        )
        self.assertEqual(disposed["node"]["state"], "NEEDS_HUMAN")
        self.assertEqual(disposed["claim"]["disposition"], "NEEDS_HUMAN")
        self.assertIsNone(disposed["node"]["evaluation_hash"])
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT COUNT(*) FROM evaluation_ledger WHERE node_id=?", (node_id,),
            ).fetchone()[0],
            0,
        )

    def test_startup_builds_explicit_publication_roots(self):
        runtime, _, _ = self.evidence_runtime()
        coordinators = build_coordinators(
            self.graph, runtime, self.public_key, self.rubric,
        )
        expected_root = Path(runtime["nomad"]["binding"]).parent / "publications"
        self.assertEqual(coordinators["nomad"].integrator.publications.root, expected_root)


if __name__ == "__main__":
    unittest.main()
