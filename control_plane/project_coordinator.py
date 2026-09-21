"""Crash-reconcilable evaluator-to-integrator-to-graph orchestration."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

from control_plane.evidence_store import get_artifact, get_outcome, resolve_artifact
from control_plane.project_graph import PROJECTS, ProjectGraph, digest
from control_plane.project_integrator import ProjectIntegrator, sha256_file


CrashHook = Callable[[str], None]


class ProjectCoordinator:
    def __init__(
        self, graph: ProjectGraph, integrator: ProjectIntegrator,
        evidence_root: Path | None = None, worker_project_id: str | None = None,
    ):
        if (evidence_root is None) != (worker_project_id is None):
            raise ValueError("durable recovery requires both evidence root and worker project ID")
        self.graph = graph
        self.integrator = integrator
        self.evidence_root = (
            Path(evidence_root).resolve() if evidence_root is not None else None
        )
        self.worker_project_id = worker_project_id
        ProjectCoordinator.assert_verification_configuration(self)

    def assert_verification_configuration(self) -> None:
        """Reject disagreeing trust inputs before Git, binding or database effects."""
        if type(self.integrator) is not ProjectIntegrator:
            raise TypeError("external integrity requires an actual ProjectIntegrator")
        ProjectIntegrator.assert_verification_configuration(self.integrator)
        if self.graph.rubric_sha256 != self.integrator.rubric_sha256:
            raise PermissionError("graph and integrator frozen rubric hashes disagree")
        if self.graph.evaluation_policy != self.integrator.evaluation_policy:
            raise PermissionError("graph and integrator evaluation policies disagree")
        graph_key = self.graph.evaluator_public_key
        integrator_key = self.integrator.evaluator_public_key
        if graph_key is None:
            raise PermissionError("graph evaluator public key is not configured")
        graph_key = Path(graph_key)
        for key in (graph_key, integrator_key):
            if key.is_symlink() or not key.is_file():
                raise PermissionError("evaluator public key must be a regular non-symlink file")
        if sha256_file(graph_key) != sha256_file(integrator_key):
            raise PermissionError("graph and integrator evaluator public keys disagree")

    @staticmethod
    def require_external_integrity(
        graph: ProjectGraph,
        coordinators: Mapping[str, "ProjectCoordinator"] | None,
        *,
        additional_required_projects: set[str] | frozenset[str] | None = None,
    ) -> dict[str, "ProjectCoordinator"]:
        """Close DB state, coordinator coverage, durable bytes, then physical state."""
        # This is deliberately first: neither caller-controlled map behavior nor
        # filesystem/Git inspection may precede the database-only closure gate.
        ProjectCoordinator.assert_graph_publication_integrity(graph)

        normalized = ProjectCoordinator.normalize_external_integrity_map(
            graph, coordinators,
        )

        required = {
            row[0] for row in graph.connection.execute(
                "SELECT g.project FROM evaluation_outcomes o "
                "JOIN nodes n ON n.node_id=o.node_id "
                "JOIN goals g ON g.goal_id=n.goal_id "
                "UNION SELECT g.project FROM nodes n "
                "JOIN goals g ON g.goal_id=n.goal_id "
                "WHERE n.state IN ('PASSED','INTEGRATING','INTEGRATED') "
                "UNION SELECT g.project FROM integration_attempts a "
                "JOIN nodes n ON n.node_id=a.node_id "
                "JOIN goals g ON g.goal_id=n.goal_id "
                "UNION SELECT project FROM publication_journal WHERE phase='COMPLETED'"
            ).fetchall()
        }
        if additional_required_projects is not None:
            if not isinstance(additional_required_projects, (set, frozenset)):
                raise TypeError("additional required projects must be an exact set")
            invalid = {
                project for project in additional_required_projects
                if type(project) is not str or project not in PROJECTS
            }
            if invalid:
                raise ValueError("additional required projects contain an unknown project")
            required.update(additional_required_projects)
        missing = required - set(normalized)
        if missing:
            raise RuntimeError(
                "projects requiring external integrity lack exact coordinators: "
                f"{sorted(missing)}"
            )

        # Verify all explicitly configured projects, not merely the required
        # subset. This preserves pre-head physical drift detection while fresh
        # graphs can still intentionally pass None or an empty mapping.
        for project in sorted(normalized):
            # Invoke the class implementation unbound so an instance attribute
            # cannot shadow this security boundary with a no-op.
            ProjectCoordinator.assert_publication_integrity(normalized[project])
        return normalized

    @staticmethod
    def normalize_external_integrity_map(
        graph: ProjectGraph,
        coordinators: Mapping[str, "ProjectCoordinator"] | None,
    ) -> dict[str, "ProjectCoordinator"]:
        """Copy and structurally bind an optional coordinator mapping."""

        if coordinators is None:
            normalized: dict[str, ProjectCoordinator] = {}
        else:
            if not isinstance(coordinators, Mapping):
                raise TypeError("external integrity coordinators must be a mapping or None")
            normalized = dict(coordinators)

        for project, verifier in normalized.items():
            if type(project) is not str or project not in PROJECTS:
                raise ValueError("external integrity coordinator has an unknown project")
            if type(verifier) is not ProjectCoordinator:
                raise TypeError("external integrity requires an actual ProjectCoordinator")
            if type(verifier.integrator) is not ProjectIntegrator:
                raise TypeError("external integrity requires an actual ProjectIntegrator")
            if verifier.graph is not graph:
                raise ValueError("external integrity coordinator is bound to another graph")
            if verifier.integrator.project != project:
                raise ValueError("external integrity coordinator is bound to another project")
            ProjectCoordinator.assert_verification_configuration(verifier)
        return normalized

    @contextmanager
    def _publication_writer_lock(self):
        """Exclude every SQLite writer across verified physical publication I/O."""
        ProjectIntegrator._require_mutation_authority(self.integrator)
        from control_plane.sqlite_runtime import connect_database
        connection = connect_database(
            self.graph.database, owner=self.graph.connection.owner,
            profile=self.graph.connection.sqlite_profile,
            attestation=self.graph.connection.sqlite_attestation,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def integrate(
        self,
        attempt_id: str,
        node_id: str,
        outcome_id: str,
        artifact_id: str,
        evidence_manifest: Path,
        worker_project_id: str,
        evidence_root: Path,
        crash_hook: CrashHook | None = None,
    ) -> dict[str, Any]:
        """Preflight every immutable binding before journal, fetch, ref, or binding mutation."""
        ProjectIntegrator._require_mutation_authority(self.integrator)
        ProjectCoordinator.assert_publication_integrity(self)
        ProjectGraph._assert_no_human_gate(self.graph.get_node(node_id))
        if self.evidence_root is not None and evidence_root.resolve() != self.evidence_root:
            raise PermissionError("integration evidence root differs from durable recovery config")
        if self.worker_project_id is not None and worker_project_id != self.worker_project_id:
            raise PermissionError("integration worker project differs from durable recovery config")
        node, evaluation = self.graph.validate_recorded_outcome(
            node_id, outcome_id, artifact_id, evidence_manifest,
        )
        context = self._node_context(node_id)
        if context["project"] != self.integrator.project:
            raise PermissionError("node project does not match the configured integrator")
        spec = json.loads(node["spec_json"])
        candidate = self.integrator.preflight_bundle(
            evidence_manifest,
            evidence_root,
            expected_project_id=worker_project_id,
            expected_task_id=node_id,
            expected_base_sha=node["base_sha"],
            expected_candidate_sha=node["result_sha"],
        )
        if candidate.manifest_sha256 != evaluation["evidence_manifest_sha256"]:
            raise PermissionError("preflight manifest bytes differ from the node's recorded evidence")
        evaluation_hash = digest(evaluation)
        try:
            existing = self._attempt(node_id, candidate.candidate_sha)
        except KeyError:
            existing = None
        was_existing = existing is not None
        if existing is not None:
            expected = (
                attempt_id, node["base_sha"], evaluation_hash,
                candidate.manifest_sha256, artifact_id, outcome_id,
            )
            actual = (
                existing["attempt_id"], existing["expected_base_sha"],
                existing["evaluation_hash"], existing["manifest_hash"],
                existing["artifact_id"], existing["outcome_id"],
            )
            if actual != expected:
                raise ValueError("integration idempotency conflict")
            if existing["status"] == "COMPLETED":
                return existing
            recovered = self.reconcile(
                node_id, candidate.candidate_sha, crash_hook=crash_hook,
            )
            if recovered["status"] == "COMPLETED":
                return recovered
            expected_head_version = int(existing["expected_head_version"])
        else:
            expected_head_version = self._expected_promotion_head_version(node["base_sha"])
        attempt = self._prepare_attempt(
            attempt_id, node_id, node["base_sha"], candidate.candidate_sha,
            evaluation_hash, candidate.manifest_sha256, artifact_id, outcome_id,
            expected_head_version, context["project"],
        )
        if attempt["status"] == "COMPLETED":
            return attempt
        if was_existing and attempt["status"] in {"PREPARED", "BINDING_UPDATED"}:
            recovered = self.reconcile(node_id, candidate.candidate_sha, crash_hook=crash_hook)
            if recovered["status"] == "COMPLETED":
                return recovered

        # A separate IMMEDIATE transaction keeps PREPARED durable while
        # excluding every DB writer across import/ref/binding side effects.
        with self._publication_writer_lock() as writer:
            ProjectCoordinator.assert_publication_integrity(self)
            self._assert_prepared_promotion_ready(attempt, node_id)
            node = self.graph.get_node(node_id)
            if node["state"] != "PASSED":
                raise PermissionError("only a PASSED node may begin promotion")
            imported_sha = self.integrator.import_bundle(candidate)
            if imported_sha != node["result_sha"]:
                raise PermissionError("imported candidate differs from the node's recorded result")
            promoted = self.integrator.promote(
                imported_sha, node["base_sha"], json.loads(node["write_set_json"]),
                evaluation, evidence_manifest,
                expected_task_id=node_id,
                expected_contract_id=spec["evaluator_contract_id"],
                fault_hook=crash_hook,
            )
            integration_sha = promoted["integration_sha"]
            changed = writer.execute(
                "UPDATE integration_attempts SET integration_sha=?,publication_generation=?,"
                "status='BINDING_UPDATED',updated_at=CURRENT_TIMESTAMP "
                "WHERE attempt_id=? AND status='PREPARED' AND integration_sha IS NULL",
                (integration_sha, promoted["publication_generation"], attempt_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("promotion attempt changed during physical publication")
        return self._finalize_promotion(
            attempt_id, node_id, integration_sha, crash_hook,
        )

    def reconcile(self, node_id: str, candidate_sha: str,
                  crash_hook: CrashHook | None = None) -> dict[str, Any]:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        ProjectCoordinator.assert_publication_integrity(self)
        attempt = self._attempt(node_id, candidate_sha)
        self._validate_attempt_evidence(attempt)
        if attempt["status"] == "COMPLETED":
            return attempt
        ProjectGraph._assert_no_human_gate(self.graph.get_node(node_id))
        if attempt["status"] == "PREPARED":
            with self._publication_writer_lock() as writer:
                ProjectCoordinator.assert_publication_integrity(self)
                self._assert_prepared_promotion_ready(attempt, node_id)
                integration_sha = self.integrator.reconcile_promotion(
                    attempt["expected_base_sha"], candidate_sha,
                )
                if integration_sha:
                    changed = writer.execute(
                        "UPDATE integration_attempts SET integration_sha=?,"
                        "publication_generation=?,status='BINDING_UPDATED',"
                        "updated_at=CURRENT_TIMESTAMP WHERE attempt_id=? "
                        "AND status='PREPARED' AND integration_sha IS NULL",
                        (integration_sha, candidate_sha, attempt["attempt_id"]),
                    ).rowcount
                    if changed != 1:
                        raise RuntimeError("promotion recovery attempt changed during publication")
            if not integration_sha:
                return self._attempt(node_id, candidate_sha)
        elif attempt["status"] == "BINDING_UPDATED":
            integration_sha = attempt["integration_sha"]
            if integration_sha != candidate_sha:
                raise RuntimeError("bound promotion lacks its exact integration SHA")
        else:
            raise RuntimeError("incomplete promotion status is invalid")
        return self._finalize_promotion(
            attempt["attempt_id"], node_id, integration_sha, crash_hook,
        )

    def publication_head(self, project: str | None = None) -> dict[str, Any]:
        ProjectCoordinator.assert_publication_integrity(self)
        project = project or self.integrator.project
        if project != self.integrator.project:
            raise PermissionError("publication head is owned by another project integrator")
        row = self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project=?", (project,)
        ).fetchone()
        if not row:
            raise KeyError(project)
        return dict(row)

    def rollback(
        self, rollback_id: str, node_id: str, integration_attempt_id: str,
        expected_head_version: int, crash_hook: CrashHook | None = None,
    ) -> dict[str, Any]:
        """Prepare or replay one graph-bound, version-CAS rollback operation."""
        ProjectIntegrator._require_mutation_authority(self.integrator)
        ProjectCoordinator.assert_publication_integrity(self)
        existing = self._journal_entries(rollback_id)
        if existing:
            prepared = existing[0]
            expected = (node_id, integration_attempt_id, expected_head_version)
            actual = (
                prepared["node_id"], prepared["integration_attempt_id"],
                prepared["version_before"],
            )
            if actual != expected or prepared["operation_kind"] != "ROLLBACK":
                raise ValueError("rollback idempotency conflict")
            return self.reconcile_rollback(rollback_id, crash_hook)

        attempt = self._attempt_by_id(integration_attempt_id)
        if attempt["node_id"] != node_id or attempt["status"] != "COMPLETED":
            raise PermissionError("rollback requires the completed integration attempt")
        node = self.graph.get_node(node_id)
        context = self._node_context(node_id)
        if context["project"] != self.integrator.project:
            raise PermissionError("rollback node belongs to another project")
        if node["state"] != "INTEGRATED" or node["integration_sha"] != attempt["integration_sha"]:
            raise PermissionError("rollback must retain and bind the historical integrated node")
        head = self.publication_head(context["project"])
        from_sha = attempt["integration_sha"]
        to_sha = attempt["expected_base_sha"]
        from_generation = attempt["publication_generation"] or from_sha
        if (head["version"] != expected_head_version or head["sha"] != from_sha
                or head["generation"] != from_generation
                or head["integration_attempt_id"] != integration_attempt_id
                or context["accepted_sha"] != from_sha):
            raise RuntimeError("rollback publication-head compare-and-swap conflict")
        affected = self._rollback_affected_graph(context["project"], from_sha)
        self._assert_quiescent_affected_graph(affected)
        affected_json = json.dumps(affected, sort_keys=True, separators=(",", ":"))
        # Promotion always creates the predecessor publication before changing
        # the accepted ref.  Re-verification binds PREPARED to immutable bytes.
        predecessor = self.integrator.publications.verify(context["repo_name"], to_sha)
        replay = False
        try:
            self.graph.connection.execute("BEGIN IMMEDIATE")
            ProjectCoordinator.assert_publication_integrity(self)
            raced = self._journal_entries(rollback_id)
            if raced:
                prepared = raced[0]
                if (
                    prepared["operation_kind"] != "ROLLBACK"
                    or (prepared["node_id"], prepared["integration_attempt_id"],
                        prepared["version_before"])
                    != (node_id, integration_attempt_id, expected_head_version)
                ):
                    raise ValueError("rollback idempotency conflict")
                replay = True
            if replay:
                self.graph.connection.commit()
            else:
                self.graph._assert_project_has_no_pending_publication(context["project"])
                attempt = self._attempt_by_id(integration_attempt_id)
                node = self.graph.get_node(node_id)
                context = self._node_context(node_id)
                head = self.graph.connection.execute(
                    "SELECT * FROM publication_heads WHERE project=?", (context["project"],),
                ).fetchone()
                if (
                    attempt["node_id"] != node_id or attempt["status"] != "COMPLETED"
                    or node["state"] != "INTEGRATED"
                    or node["integration_sha"] != attempt["integration_sha"]
                    or not head or head["version"] != expected_head_version
                    or head["sha"] != from_sha or head["generation"] != from_generation
                    or head["integration_attempt_id"] != integration_attempt_id
                    or context["accepted_sha"] != from_sha
                ):
                    raise RuntimeError("rollback admission changed before PREPARED")
                affected = self._rollback_affected_graph(context["project"], from_sha)
                self._assert_quiescent_affected_graph(affected)
                affected_json = json.dumps(affected, sort_keys=True, separators=(",", ":"))
                self._append_journal_locked(
                    operation_id=rollback_id, operation_kind="ROLLBACK", phase="PREPARED",
                    project=context["project"], goal_id=node["goal_id"], node_id=node_id,
                    integration_attempt_id=integration_attempt_id,
                    version_before=expected_head_version,
                    version_after=expected_head_version + 1,
                    from_sha=from_sha, to_sha=to_sha,
                    from_generation=from_generation,
                    to_generation=predecessor.generation,
                    affected_graph_sha256=digest(affected),
                    affected_graph_json=affected_json,
                )
                self.graph.connection.commit()
        except Exception:
            self.graph.connection.rollback()
            raise
        if replay:
            return self.reconcile_rollback(rollback_id, crash_hook)
        if crash_hook:
            crash_hook("after_rollback_prepare")
        return self.reconcile_rollback(rollback_id, crash_hook)

    def reconcile_rollback(
        self, rollback_id: str, crash_hook: CrashHook | None = None,
    ) -> dict[str, Any]:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        ProjectCoordinator.assert_publication_integrity(self)
        entries = self._journal_entries(rollback_id)
        if not entries:
            raise KeyError(rollback_id)
        prepared = entries[0]
        if prepared["operation_kind"] != "ROLLBACK" or prepared["phase"] != "PREPARED":
            raise RuntimeError("rollback journal does not begin with PREPARED")
        if prepared["project"] != self.integrator.project:
            raise PermissionError("rollback journal belongs to another project")
        phases = {entry["phase"] for entry in entries}
        if "COMPLETED" in phases:
            return self._rollback_result(prepared, "COMPLETED")
        head = self.publication_head(prepared["project"])
        if head["integration_attempt_id"] != prepared["integration_attempt_id"]:
            raise RuntimeError("rollback replay no longer owns the publication head")
        # Exclude every other SQLite writer across the last logical checks,
        # accepted-ref/binding mutation, and the durable PUBLISHED phase.  A
        # process crash may still leave a legal PREPARED physical prefix, but
        # no concurrent journal or graph mutation can invalidate the frozen
        # affected set after physical rollback begins.
        with self._publication_writer_lock() as writer:
            ProjectCoordinator.assert_publication_integrity(self)
            head = self.publication_head(prepared["project"])
            if (head["version"] != prepared["version_before"]
                    or head["sha"] != prepared["from_sha"]
                    or head["generation"] != prepared["from_generation"]
                    or head["integration_attempt_id"]
                    != prepared["integration_attempt_id"]):
                raise RuntimeError("rollback replay lost its publication-head CAS")
            self._assert_prepared_affected_graph(prepared)

            physical = self.integrator.reconcile_rollback(
                prepared["from_sha"], expected_previous_sha=prepared["to_sha"],
                fault_hook=crash_hook,
            )
            if physical["publication_generation"] != prepared["to_generation"]:
                raise RuntimeError("rollback publication generation differs from its journal")
            if "PUBLISHED" not in phases:
                self._append_journal_locked(
                    **self._journal_identity(prepared), phase="PUBLISHED",
                    connection=writer,
                )
        if crash_hook:
            crash_hook("after_rollback_published")
        return self._complete_rollback(prepared, crash_hook)

    def pending_rollbacks(self) -> list[str]:
        rows = self.graph.connection.execute(
            "SELECT operation_id,MAX(sequence) FROM publication_journal "
            "WHERE project=? AND operation_kind='ROLLBACK' GROUP BY operation_id "
            "HAVING SUM(phase='COMPLETED')=0 ORDER BY MIN(sequence)",
            (self.integrator.project,),
        ).fetchall()
        return [row[0] for row in rows]

    def verify_publication_journal(self) -> bool:
        try:
            ProjectCoordinator.assert_publication_integrity(self)
        except (
            KeyError, OSError, PermissionError, TypeError, ValueError,
            RuntimeError, json.JSONDecodeError,
        ):
            return False
        return True

    def assert_publication_integrity(self) -> None:
        ProjectCoordinator.assert_graph_publication_integrity(self.graph)
        ProjectCoordinator.assert_verification_configuration(self)
        ProjectCoordinator._assert_durable_evidence_integrity(self)
        ProjectCoordinator._assert_physical_publication_integrity(self)

    def _assert_durable_evidence_integrity(self) -> None:
        """Reverify every canonical project outcome and each attempt exactly once."""
        outcomes = self.graph.connection.execute(
            "SELECT o.outcome_id,o.artifact_id,o.node_id FROM evaluation_outcomes o "
            "JOIN nodes n ON n.node_id=o.node_id "
            "JOIN goals g ON g.goal_id=n.goal_id WHERE g.project=? "
            "ORDER BY o.outcome_id",
            (self.integrator.project,),
        ).fetchall()
        attempts = [dict(row) for row in self.graph.connection.execute(
            "SELECT a.* FROM integration_attempts a "
            "JOIN nodes n ON n.node_id=a.node_id "
            "JOIN goals g ON g.goal_id=n.goal_id WHERE g.project=? "
            "ORDER BY a.attempt_id",
            (self.integrator.project,),
        ).fetchall()]
        if not outcomes and not attempts:
            return
        if self.evidence_root is None or self.worker_project_id is None:
            raise RuntimeError(
                "durable outcome evidence recovery bindings are not configured"
            )
        verified: dict[str, tuple[Any, ...]] = {}
        for outcome in outcomes:
            verified[outcome["outcome_id"]] = self._validate_outcome_evidence(
                outcome["node_id"], outcome["outcome_id"], outcome["artifact_id"],
            )
        for attempt in attempts:
            self._validate_attempt_evidence(attempt, verified_outcomes=verified)

    def _validate_outcome_evidence(
        self, node_id: str, outcome_id: str, artifact_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any], Path, dict[str, Any], Any]:
        """Resolve an outcome's exact inventory and signed, manifest-derived bindings."""
        if self.evidence_root is None or self.worker_project_id is None:
            raise RuntimeError("coordinator durable recovery bindings are not configured")
        context = self._node_context(node_id)
        if context["project"] != self.integrator.project:
            raise PermissionError("durable outcome belongs to another project coordinator")
        artifact, manifest = resolve_artifact(
            self.graph.connection, artifact_id, self.evidence_root,
            expected_node_id=node_id, expected_project=context["project"],
        )
        node, evaluation = self.graph.verify_recorded_outcome(
            node_id, outcome_id, artifact_id, manifest,
        )
        candidate = self.integrator.preflight_bundle(
            manifest, self.evidence_root,
            expected_project_id=self.worker_project_id,
            expected_task_id=node_id,
            expected_base_sha=artifact["base_sha"],
            expected_candidate_sha=artifact["candidate_sha"],
        )
        if (
            artifact["task_id"] != candidate.task_id
            or artifact["attempt"] != candidate.attempt
            or artifact["producer_project_id"] != candidate.project_id
            or artifact["base_sha"] != candidate.base_sha
            or artifact["candidate_sha"] != candidate.candidate_sha
            or artifact["contract_sha256"] != candidate.contract_sha256
            or artifact["manifest_sha256"] != candidate.manifest_sha256
            or node["active_artifact_id"] != artifact_id
            or node["result_sha"] != candidate.candidate_sha
            or node["evidence_hash"] != candidate.manifest_sha256
            or digest(evaluation) != node["evaluation_hash"]
        ):
            raise PermissionError(
                "durable outcome bytes differ from their manifest-derived graph bindings"
            )
        return node, evaluation, manifest, artifact, candidate

    def _validate_attempt_evidence(
        self, attempt: dict[str, Any], *,
        verified_outcomes: dict[str, tuple[Any, ...]] | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], Path]:
        """Reload every recovery input from durable IDs and reverify its bytes."""
        if self.evidence_root is None or self.worker_project_id is None:
            raise RuntimeError("coordinator durable recovery bindings are not configured")
        cached = (
            verified_outcomes.get(attempt["outcome_id"])
            if verified_outcomes is not None else None
        )
        if cached is None:
            cached = self._validate_outcome_evidence(
                attempt["node_id"], attempt["outcome_id"], attempt["artifact_id"],
            )
        node, evaluation, manifest, artifact, candidate = cached
        if (
            attempt["node_id"] != node["node_id"]
            or attempt["artifact_id"] != artifact["artifact_id"]
            or attempt["outcome_id"] != f"sha256:{digest(evaluation)}"
            or artifact["task_id"] != candidate.task_id
            or artifact["attempt"] != candidate.attempt
            or artifact["producer_project_id"] != candidate.project_id
            or artifact["base_sha"] != candidate.base_sha
            or artifact["candidate_sha"] != candidate.candidate_sha
            or artifact["contract_sha256"] != candidate.contract_sha256
            or artifact["manifest_sha256"] != attempt["manifest_hash"]
            or candidate.manifest_sha256 != attempt["manifest_hash"]
            or candidate.base_sha != attempt["expected_base_sha"]
            or candidate.candidate_sha != attempt["candidate_sha"]
            or digest(evaluation) != attempt["evaluation_hash"]
            or node["result_sha"] != attempt["candidate_sha"]
        ):
            raise PermissionError("integration recovery inputs differ from durable attempt bindings")
        return node, evaluation, manifest

    def _assert_physical_publication_integrity(self) -> None:
        """Bind the logical head to the exact accepted ref and worker selector."""
        project = self.integrator.project
        binding, _ = self.integrator._read_binding()
        accepted_sha = self.integrator._ref_sha(self.integrator.accepted_ref)
        head_row = self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project=?", (project,),
        ).fetchone()
        head = dict(head_row) if head_row else None
        pending_promotions = [dict(row) for row in self.graph.connection.execute(
            "SELECT a.* FROM integration_attempts a "
            "JOIN nodes n ON n.node_id=a.node_id JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE g.project=? AND a.status!='COMPLETED' ORDER BY a.created_at,a.attempt_id",
            (project,),
        ).fetchall()]
        pending_rollback_ids = self.pending_rollbacks()
        if len(pending_promotions) + len(pending_rollback_ids) > 1:
            raise RuntimeError("project has multiple incomplete physical publication operations")

        baselines = {
            row[0] for row in self.graph.connection.execute(
                "SELECT DISTINCT accepted_sha FROM goals "
                "WHERE project=? AND state='ACTIVE'", (project,),
            ).fetchall()
        }
        if len(baselines) > 1:
            raise RuntimeError("project graph has multiple active baselines")
        graph_baseline = head["sha"] if head is not None else next(
            iter(baselines), binding["base_sha"],
        )
        self._assert_project_graph_baseline_coherent(project, graph_baseline)

        if head is not None:
            if head["generation"] != head["sha"]:
                raise RuntimeError("publication head generation is not SHA-addressed")
            pin = self.integrator.publications.verify(binding["repo"], head["generation"])
            if (pin.base_sha, pin.generation) != (head["sha"], head["generation"]):
                raise RuntimeError("publication generation does not match the logical head")

        if pending_promotions:
            attempt = pending_promotions[0]
            before, after = attempt["expected_base_sha"], attempt["candidate_sha"]
            if attempt["status"] == "PREPARED":
                if attempt["integration_sha"] is not None or attempt["publication_generation"] is not None:
                    raise RuntimeError("PREPARED promotion has premature physical outcome fields")
                allowed = {(before, before), (after, before), (after, after)}
                if head is None:
                    allowed.add((None, before))
            elif attempt["status"] == "BINDING_UPDATED":
                if (
                    attempt["integration_sha"] != after
                    or attempt["publication_generation"] != after
                ):
                    raise RuntimeError("BINDING_UPDATED promotion outcome fields are invalid")
                allowed = {(after, after)}
            else:
                raise RuntimeError("pending promotion status is invalid")
            if (accepted_sha, binding["base_sha"]) not in allowed:
                raise RuntimeError("pending promotion ref/binding projection is invalid")
            if accepted_sha == after or binding["base_sha"] == after:
                self.integrator.publications.verify(binding["repo"], after)
            return

        if pending_rollback_ids:
            entries = self._journal_entries(pending_rollback_ids[0])
            prepared = entries[0]
            before, after = prepared["from_sha"], prepared["to_sha"]
            rollback_sha = self.integrator._ref_sha(
                self.integrator._rollback_ref(before)
            )
            if rollback_sha != after:
                raise RuntimeError(
                    "pending rollback predecessor ref does not match its journal"
                )
            if entries[-1]["phase"] == "PREPARED":
                allowed = {(before, before), (after, before), (after, after)}
            elif entries[-1]["phase"] == "PUBLISHED":
                allowed = {(after, after)}
            else:
                raise RuntimeError("pending rollback phase is invalid")
            if (accepted_sha, binding["base_sha"]) not in allowed:
                raise RuntimeError("pending rollback ref/binding projection is invalid")
            self.integrator.publications.verify(binding["repo"], after)
            return

        if head is not None:
            if (accepted_sha, binding["base_sha"]) != (head["sha"], head["sha"]):
                raise RuntimeError("accepted ref/binding do not project the publication head")
        else:
            baseline = graph_baseline
            mismatch = self.graph.connection.execute(
                "SELECT n.node_id FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
                "WHERE g.project=? AND g.state='ACTIVE' AND n.state!='INTEGRATED' "
                "AND n.base_sha!=? LIMIT 1",
                (project, baseline),
            ).fetchone()
            if mismatch or binding["base_sha"] != baseline:
                raise RuntimeError("pre-head binding differs from the active project graph baseline")
            if accepted_sha not in {None, baseline}:
                raise RuntimeError("accepted ref differs from the pre-head project graph baseline")

    @staticmethod
    def assert_graph_publication_integrity(
        graph: ProjectGraph, *, allow_completion_append_transient: bool = False,
    ) -> None:
        """Fail closed unless the journal chain and every head projection agree."""
        graph.assert_static_integrity(
            allow_completion_append_transient=allow_completion_append_transient,
        )
        rows = [dict(row) for row in graph.connection.execute(
            "SELECT * FROM publication_journal ORDER BY sequence"
        ).fetchall()]
        tail_rows = graph.connection.execute(
            "SELECT singleton,last_sequence,last_hash FROM publication_journal_tail"
        ).fetchall()
        if len(tail_rows) != 1 or tail_rows[0]["singleton"] != 1:
            raise RuntimeError("publication journal tail anchor is absent or duplicated")
        expected_tail = (
            (rows[-1]["sequence"], rows[-1]["entry_hash"])
            if rows else (None, None)
        )
        if (tail_rows[0]["last_sequence"], tail_rows[0]["last_hash"]) != expected_tail:
            raise RuntimeError("publication journal tail anchor does not match the journal")
        previous = None
        operations: dict[str, list[dict[str, Any]]] = {}
        completed_by_project: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            if row["operation_kind"] not in {"PROMOTION", "ROLLBACK"}:
                raise RuntimeError("publication journal operation kind is invalid")
            try:
                affected = json.loads(row["affected_graph_json"])
            except (TypeError, json.JSONDecodeError):
                raise RuntimeError("publication journal affected graph is invalid") from None
            if not isinstance(affected, dict) or set(affected) != {
                "project", "from_sha", "head", "goals", "nodes",
            }:
                raise RuntimeError("publication journal affected graph shape is invalid")
            affected_head = affected.get("head")
            if not isinstance(affected_head, dict) or set(affected_head) != {
                "version", "sha", "generation", "integration_attempt_id",
                "last_journal_hash",
            }:
                raise RuntimeError("publication journal affected head shape is invalid")
            goals = affected.get("goals")
            nodes = affected.get("nodes")
            if (
                not isinstance(goals, list) or not isinstance(nodes, list)
                or any(not isinstance(goal, dict) for goal in goals)
                or any(not isinstance(node, dict) for node in nodes)
                or len({goal.get("goal_id") for goal in goals}) != len(goals)
                or len({node.get("node_id") for node in nodes}) != len(nodes)
                or any(goal.get("accepted_sha") != row["from_sha"] for goal in goals)
                or any(node.get("base_sha") != row["from_sha"] for node in nodes)
            ):
                raise RuntimeError("publication journal affected rows are invalid")
            if (
                row["affected_graph_json"] != json.dumps(
                    affected, sort_keys=True, separators=(",", ":"),
                )
                or row["affected_graph_sha256"] != digest(affected)
                or affected["project"] != row["project"]
                or affected["from_sha"] != row["from_sha"]
                or affected_head["version"] != row["version_before"]
                or affected_head["sha"] != row["from_sha"]
                or affected_head["generation"] != row["from_generation"]
                or row["previous_hash"] != previous
                or row["entry_hash"] != digest(
                    ProjectCoordinator._journal_hash_subject(row, previous)
                )
            ):
                raise RuntimeError("publication journal hash chain is corrupt")
            previous = row["entry_hash"]
            operations.setdefault(row["operation_id"], []).append(row)
            if row["phase"] == "COMPLETED":
                completed_by_project.setdefault(row["project"], []).append(row)

        for operation_id, entries in operations.items():
            kind = entries[0]["operation_kind"]
            expected_phases = (
                ["COMPLETED"] if kind == "PROMOTION"
                else ["PREPARED", "PUBLISHED", "COMPLETED"][:len(entries)]
            )
            phases = [entry["phase"] for entry in entries]
            if phases != expected_phases:
                raise RuntimeError(
                    f"publication journal phase sequence is invalid for {operation_id}"
                )
            identity = ProjectCoordinator._journal_identity(entries[0])
            if any(
                ProjectCoordinator._journal_identity(entry) != identity
                or entry["operation_kind"] != kind
                for entry in entries[1:]
            ):
                raise RuntimeError("publication journal operation identity changed")

        pending_projects: dict[str, str] = {}
        for operation_id, entries in operations.items():
            if entries[-1]["phase"] == "COMPLETED":
                continue
            project = entries[0]["project"]
            if project in pending_projects:
                raise RuntimeError("project has multiple incomplete publication operations")
            pending_projects[project] = operation_id

        all_heads = {
            row["project"]: dict(row) for row in graph.connection.execute(
                "SELECT * FROM publication_heads"
            ).fetchall()
        }
        heads = dict(all_heads)
        for project, completed in completed_by_project.items():
            previous_completed: dict[str, Any] | None = None
            for entry in completed:
                if entry["version_after"] != entry["version_before"] + 1:
                    raise RuntimeError("publication journal version step is invalid")
                affected_head = json.loads(entry["affected_graph_json"])["head"]
                if previous_completed is None:
                    if (
                        entry["version_before"] != 0
                        or affected_head["integration_attempt_id"] is not None
                        or affected_head["last_journal_hash"] is not None
                    ):
                        raise RuntimeError("publication journal genesis binding is invalid")
                elif (
                    entry["version_before"] != previous_completed["version_after"]
                    or entry["from_sha"] != previous_completed["to_sha"]
                    or entry["from_generation"] != previous_completed["to_generation"]
                    or affected_head["integration_attempt_id"]
                    != previous_completed["integration_attempt_id"]
                    or affected_head["last_journal_hash"] != previous_completed["entry_hash"]
                ):
                    raise RuntimeError("publication journal completed projections are discontinuous")
                previous_completed = entry
            last = completed[-1]
            head = heads.pop(project, None)
            if not head or (
                head["version"], head["sha"], head["generation"],
                head["integration_attempt_id"], head["last_journal_hash"],
            ) != (
                last["version_after"], last["to_sha"], last["to_generation"],
                last["integration_attempt_id"], last["entry_hash"],
            ):
                raise RuntimeError("publication head does not project the journal")
        for operation_id, entries in operations.items():
            if entries[-1]["phase"] == "COMPLETED":
                continue
            first = entries[0]
            head = all_heads.get(first["project"])
            affected_head = json.loads(first["affected_graph_json"])["head"]
            if not head or (
                head["version"], head["sha"], head["generation"],
                head["integration_attempt_id"], head["last_journal_hash"],
            ) != (
                affected_head["version"], affected_head["sha"],
                affected_head["generation"], affected_head["integration_attempt_id"],
                affected_head["last_journal_hash"],
            ):
                raise RuntimeError(
                    f"pending publication operation {operation_id} lost its head projection"
                )
        for head in heads.values():
            if (
                head["version"] != 0 or head["sha"] != head["generation"]
                or head["integration_attempt_id"] is not None
                or head["last_journal_hash"] is not None
            ):
                raise RuntimeError("publication head has no journal projection")

        ProjectCoordinator._assert_completed_database_closure(
            graph, rows,
            allow_completion_append_transient=allow_completion_append_transient,
        )

        # The journal/head projection also owns the baseline of every active
        # same-project graph.  This DB-only check protects direct Buzz callers
        # as well as the graph service; historical INTEGRATED nodes retain the
        # SHA they actually integrated and are intentionally excluded.
        active_projects = {
            row[0] for row in graph.connection.execute(
                "SELECT DISTINCT project FROM goals WHERE state='ACTIVE'"
            ).fetchall()
        }
        for project in set(all_heads) | active_projects:
            active_baselines = {
                row[0] for row in graph.connection.execute(
                    "SELECT DISTINCT accepted_sha FROM goals "
                    "WHERE project=? AND state='ACTIVE'",
                    (project,),
                ).fetchall()
            }
            head = all_heads.get(project)
            if head is not None:
                baseline = head["sha"]
                if active_baselines - {baseline}:
                    raise RuntimeError(
                        "active project goal does not project the publication baseline"
                    )
            else:
                if len(active_baselines) > 1:
                    raise RuntimeError("pre-head project graph has multiple active baselines")
                if not active_baselines:
                    continue
                baseline = next(iter(active_baselines))
            mismatch = graph.connection.execute(
                "SELECT n.node_id FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
                "WHERE g.project=? AND g.state='ACTIVE' AND n.state!='INTEGRATED' "
                "AND n.base_sha!=? ORDER BY n.node_id LIMIT 1",
                (project, baseline),
            ).fetchone()
            if mismatch:
                raise RuntimeError(
                    "active project node does not project the publication baseline: "
                    f"{mismatch['node_id']}"
                )

    @staticmethod
    def _assert_completed_database_closure(
        graph: ProjectGraph, journal_rows: list[dict[str, Any]], *,
        allow_completion_append_transient: bool = False,
    ) -> None:
        """Require forward and reverse closure of journal, attempt, node, and IDs."""
        completed = [row for row in journal_rows if row["phase"] == "COMPLETED"]
        promotions: dict[str, list[dict[str, Any]]] = {}
        for entry in completed:
            attempt_row = graph.connection.execute(
                "SELECT * FROM integration_attempts WHERE attempt_id=?",
                (entry["integration_attempt_id"],),
            ).fetchone()
            if not attempt_row:
                raise RuntimeError(
                    "completed publication journal lost its integration attempt"
                )
            attempt = dict(attempt_row)
            node_row = graph.connection.execute(
                "SELECT n.*,g.project AS graph_project,g.goal_id AS graph_goal_id "
                "FROM nodes n JOIN goals g ON g.goal_id=n.goal_id WHERE n.node_id=?",
                (attempt["node_id"],),
            ).fetchone()
            if not node_row:
                raise RuntimeError("completed integration attempt lost its graph node")
            node = dict(node_row)
            try:
                artifact = get_artifact(
                    graph.connection, attempt["artifact_id"],
                    expected_node_id=attempt["node_id"],
                    expected_project=node["graph_project"],
                )
                outcome = get_outcome(
                    graph.connection, attempt["outcome_id"],
                    expected_artifact_id=attempt["artifact_id"],
                    expected_node_id=attempt["node_id"],
                )
            except (KeyError, PermissionError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    "completed integration attempt lost its artifact/outcome binding"
                ) from exc
            common = (
                attempt["status"] == "COMPLETED"
                and attempt["node_id"] == entry["node_id"] == node["node_id"]
                and entry["project"] == node["graph_project"]
                and entry["goal_id"] == node["graph_goal_id"]
                and attempt["integration_sha"] == attempt["candidate_sha"]
                and attempt["publication_generation"] == attempt["candidate_sha"]
                and node["state"] == "INTEGRATED"
                and node["base_sha"] == attempt["expected_base_sha"]
                and node["integration_sha"] == attempt["integration_sha"]
                and node["result_sha"] == attempt["candidate_sha"]
                and node["active_artifact_id"] == attempt["artifact_id"]
                and node["evaluation_hash"] == attempt["evaluation_hash"]
                and node["evidence_hash"] == attempt["manifest_hash"]
                and artifact["manifest_sha256"] == attempt["manifest_hash"]
                and artifact["base_sha"] == attempt["expected_base_sha"]
                and artifact["candidate_sha"] == attempt["candidate_sha"]
                and outcome["evaluation_sha256"] == attempt["evaluation_hash"]
            )
            if not common:
                raise RuntimeError(
                    "completed publication journal/attempt/node evidence binding is invalid"
                )
            if entry["operation_kind"] == "PROMOTION":
                promotions.setdefault(attempt["attempt_id"], []).append(entry)
                if (
                    entry["operation_id"] != attempt["attempt_id"]
                    or entry["integration_attempt_id"] != attempt["attempt_id"]
                    or entry["version_before"] != attempt["expected_head_version"]
                    or entry["from_sha"] != attempt["expected_base_sha"]
                    or entry["to_sha"] != attempt["integration_sha"]
                    or entry["from_generation"] != attempt["expected_base_sha"]
                    or entry["to_generation"] != attempt["publication_generation"]
                    or entry["affected_graph_sha256"]
                    != attempt["affected_graph_sha256"]
                    or entry["affected_graph_json"] != attempt["affected_graph_json"]
                ):
                    raise RuntimeError(
                        "completed promotion journal differs from its exact attempt"
                    )
            elif entry["operation_kind"] == "ROLLBACK":
                affected_head = json.loads(entry["affected_graph_json"])["head"]
                if (
                    affected_head["integration_attempt_id"] != attempt["attempt_id"]
                    or entry["from_sha"] != attempt["integration_sha"]
                    or entry["to_sha"] != attempt["expected_base_sha"]
                    or entry["from_generation"] != attempt["publication_generation"]
                    or entry["to_generation"] != attempt["expected_base_sha"]
                ):
                    raise RuntimeError(
                        "completed rollback journal differs from its exact attempt"
                    )

        completed_attempts = [dict(row) for row in graph.connection.execute(
            "SELECT * FROM integration_attempts WHERE status='COMPLETED' "
            "ORDER BY attempt_id"
        ).fetchall()]
        for attempt in completed_attempts:
            exact = promotions.get(attempt["attempt_id"], [])
            if len(exact) != 1:
                raise RuntimeError(
                    "completed integration attempt lacks one exact promotion journal"
                )
        integrated_nodes = graph.connection.execute(
            "SELECT node_id,integration_sha FROM nodes WHERE state='INTEGRATED' "
            "ORDER BY node_id"
        ).fetchall()
        for node in integrated_nodes:
            attempts = graph.connection.execute(
                "SELECT attempt_id FROM integration_attempts WHERE node_id=? "
                "AND status='COMPLETED' AND integration_sha=?",
                (node["node_id"], node["integration_sha"]),
            ).fetchall()
            if len(attempts) == 1:
                continue
            # Promotion finalization transitions the origin inside the same
            # IMMEDIATE transaction before it appends the COMPLETED entry and
            # flips BINDING_UPDATED to COMPLETED. That state is never committed
            # on its own, but the append precondition verifier must recognize it.
            if allow_completion_append_transient and not attempts:
                pending = graph.connection.execute(
                    "SELECT attempt_id FROM integration_attempts WHERE node_id=? "
                    "AND status='BINDING_UPDATED' AND integration_sha=?",
                    (node["node_id"], node["integration_sha"]),
                ).fetchall()
                if len(pending) == 1:
                    continue
            raise RuntimeError(
                "integrated node lacks one exact completed integration attempt"
            )

    def _prepare_attempt(
        self, attempt_id: str, node_id: str, expected_base_sha: str,
        candidate_sha: str, evaluation_hash: str, manifest_hash: str,
        artifact_id: str, outcome_id: str,
        expected_head_version: int, project: str,
    ) -> dict[str, Any]:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        ProjectGraph._assert_no_human_gate(self.graph.get_node(node_id))
        try:
            self.graph.connection.execute("BEGIN IMMEDIATE")
            existing = self.graph.connection.execute(
                "SELECT * FROM integration_attempts WHERE attempt_id=? "
                "OR (node_id=? AND candidate_sha=?)",
                (attempt_id, node_id, candidate_sha),
            ).fetchall()
            if existing:
                if len(existing) != 1:
                    raise ValueError("integration attempt identity collides")
                row = dict(existing[0])
                expected = (
                    attempt_id, node_id, expected_base_sha, candidate_sha,
                    evaluation_hash, manifest_hash, artifact_id, outcome_id,
                    expected_head_version,
                )
                actual = tuple(row[name] for name in (
                    "attempt_id", "node_id", "expected_base_sha", "candidate_sha",
                    "evaluation_hash", "manifest_hash", "artifact_id", "outcome_id",
                    "expected_head_version",
                ))
                if actual != expected:
                    raise ValueError("integration idempotency conflict")
                self.graph.connection.commit()
                return row
            ProjectCoordinator.assert_publication_integrity(self)
            ProjectGraph._assert_no_human_gate(self.graph.get_node(node_id))
            self.graph._assert_project_has_no_pending_publication(project)
            if self._expected_promotion_head_version(expected_base_sha) != expected_head_version:
                raise RuntimeError("promotion publication-head version changed before PREPARED")
            affected = self._promotion_affected_graph(project, expected_base_sha)
            self._assert_promotion_quiescent(affected, node_id, {"PASSED"})
            affected_json = json.dumps(affected, sort_keys=True, separators=(",", ":"))
            self.graph.connection.execute(
                "INSERT INTO integration_attempts("
                "attempt_id,node_id,expected_base_sha,candidate_sha,evaluation_hash,manifest_hash,"
                "artifact_id,outcome_id,expected_head_version,affected_graph_sha256,"
                "affected_graph_json,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,'PREPARED')",
                (
                    attempt_id, node_id, expected_base_sha, candidate_sha,
                    evaluation_hash, manifest_hash, artifact_id, outcome_id,
                    expected_head_version, digest(affected), affected_json,
                ),
            )
            self.graph.connection.commit()
        except Exception:
            self.graph.connection.rollback()
            raise
        return self._attempt(node_id, candidate_sha)

    def _finalize_promotion(
        self, attempt_id: str, node_id: str, integration_sha: str,
        crash_hook: CrashHook | None = None,
    ) -> dict[str, Any]:
        """Commit origin lifecycle, global graph rebind, journal, and head together."""
        ProjectIntegrator._require_mutation_authority(self.integrator)
        try:
            self.graph.connection.execute("BEGIN IMMEDIATE")
            ProjectCoordinator.assert_publication_integrity(self)
            node = self.graph.get_node(node_id)
            ProjectGraph._assert_no_human_gate(node)
            attempt = self._attempt_by_id(attempt_id)
            if attempt["status"] != "BINDING_UPDATED":
                raise RuntimeError("promotion finalization requires BINDING_UPDATED")
            self.graph._assert_node_has_no_pending_publication(node, attempt_id)
            if node["state"] == "PASSED":
                node = self.graph._transition_locked(
                    node, node["version"], "INTEGRATING",
                    "accepted-state update durably reconciled",
                )
            if node["state"] == "INTEGRATING":
                node = self.graph._record_integration_locked(
                    node, node["version"], integration_sha,
                )
            if crash_hook:
                crash_hook("after_graph")
            result = self._complete_locked(
                attempt, node, integration_sha, crash_hook,
            )
            self.graph.connection.commit()
        except Exception:
            self.graph.connection.rollback()
            raise
        return result

    def _complete_locked(
        self, attempt: dict[str, Any], node: dict[str, Any], integration_sha: str,
        crash_hook: CrashHook | None,
    ) -> dict[str, Any]:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        attempt_id = attempt["attempt_id"]
        node_id = node["node_id"]
        if attempt["node_id"] != node_id or attempt["integration_sha"] != integration_sha:
            raise RuntimeError("completion journal does not match the integrated node")
        if node["state"] != "INTEGRATED" or node["integration_sha"] != integration_sha:
            raise RuntimeError("completion requires the node's recorded integration SHA")
        context = self._node_context(node_id)
        if context["project"] != self.integrator.project:
            raise PermissionError("integration completion belongs to another project")
        recorded, affected = self._assert_prepared_promotion_graph(
            attempt, node_id,
        )
        self._assert_promotion_quiescent(affected, node_id, {"INTEGRATED"})
        self._record_promotion_locked(attempt, node, context, recorded)
        changed_goals = 0
        for affected_goal in affected["goals"]:
            changed_goals += self.graph.connection.execute(
                "UPDATE goals SET accepted_sha=? WHERE goal_id=? AND accepted_sha=?",
                (
                    integration_sha, affected_goal["goal_id"],
                    attempt["expected_base_sha"],
                ),
            ).rowcount
        if changed_goals != len(affected["goals"]):
            raise RuntimeError("promotion affected-goal compare-and-swap conflict")
        for affected_node in affected["nodes"]:
            if affected_node["state"] == "INTEGRATED":
                continue
            version = affected_node["version"] + 1
            changed = self.graph.connection.execute(
                "UPDATE nodes SET base_sha=?,version=?,updated_at=CURRENT_TIMESTAMP "
                "WHERE node_id=? AND version=? AND state=? AND base_sha=?",
                (
                    integration_sha, version, affected_node["node_id"],
                    affected_node["version"], affected_node["state"],
                    attempt["expected_base_sha"],
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError("promotion affected-node compare-and-swap conflict")
            self.graph._event(
                affected_node["node_id"], version,
                affected_node["state"], affected_node["state"],
                "project-global promotion baseline rebind",
                digest({
                    "attempt_id": attempt_id,
                    "from_sha": attempt["expected_base_sha"],
                    "to_sha": integration_sha,
                }),
            )
        for affected_goal in affected["goals"]:
            self.graph._release_dependencies_locked(affected_goal["goal_id"])
        changed = self.graph.connection.execute(
            "UPDATE integration_attempts SET status='COMPLETED',updated_at=CURRENT_TIMESTAMP WHERE attempt_id=?",
            (attempt_id,),
        ).rowcount
        if changed != 1:
            raise RuntimeError("completion journal disappeared")
        if crash_hook:
            crash_hook("before_completion_commit")
        return self._attempt(node_id, attempt["candidate_sha"])

    def _record_promotion_locked(
        self, attempt: dict[str, Any], node: dict[str, Any], context: dict[str, Any],
        affected: dict[str, Any],
    ) -> None:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        project = context["project"]
        generation = attempt["publication_generation"] or attempt["integration_sha"]
        head = self.graph.connection.execute(
            "SELECT * FROM publication_heads WHERE project=?", (project,)
        ).fetchone()
        if head is None:
            self.graph.connection.execute(
                "INSERT INTO publication_heads(project,version,sha,generation) VALUES(?,0,?,?)",
                (project, attempt["expected_base_sha"], attempt["expected_base_sha"]),
            )
            head = self.graph.connection.execute(
                "SELECT * FROM publication_heads WHERE project=?", (project,)
            ).fetchone()
        head = dict(head)
        if (head["version"], head["sha"], head["generation"]) != (
            attempt["expected_head_version"], attempt["expected_base_sha"],
            attempt["expected_base_sha"],
        ):
            raise RuntimeError("promotion publication-head compare-and-swap conflict")
        affected_json = json.dumps(affected, sort_keys=True, separators=(",", ":"))
        entry = self._append_journal_locked(
            operation_id=attempt["attempt_id"], operation_kind="PROMOTION",
            phase="COMPLETED", project=project, goal_id=node["goal_id"],
            node_id=node["node_id"], integration_attempt_id=attempt["attempt_id"],
            version_before=head["version"], version_after=head["version"] + 1,
            from_sha=attempt["expected_base_sha"], to_sha=attempt["integration_sha"],
            from_generation=head["generation"], to_generation=generation,
            affected_graph_sha256=digest(affected),
            affected_graph_json=affected_json,
        )
        changed = self.graph.connection.execute(
            "UPDATE publication_heads SET version=?,sha=?,generation=?,"
            "integration_attempt_id=?,last_journal_hash=? "
            "WHERE project=? AND version=? AND sha=? AND generation=? "
            "AND integration_attempt_id IS ? AND last_journal_hash IS ?",
            (
                head["version"] + 1, attempt["integration_sha"], generation,
                attempt["attempt_id"], entry["entry_hash"], project,
                head["version"], attempt["expected_base_sha"], head["generation"],
                head["integration_attempt_id"], head["last_journal_hash"],
            ),
        ).rowcount
        if changed != 1:
            raise RuntimeError("concurrent promotion publication-head update")

    def _complete_rollback(
        self, prepared: dict[str, Any], crash_hook: CrashHook | None,
    ) -> dict[str, Any]:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        try:
            self.graph.connection.execute("BEGIN IMMEDIATE")
            ProjectCoordinator.assert_publication_integrity(self)
            node = self.graph.get_node(prepared["node_id"])
            context = self._node_context(prepared["node_id"])
            attempt = self._attempt_by_id(prepared["integration_attempt_id"])
            head = self.graph.connection.execute(
                "SELECT * FROM publication_heads WHERE project=?", (prepared["project"],)
            ).fetchone()
            if (not head or head["version"] != prepared["version_before"]
                    or head["sha"] != prepared["from_sha"]
                    or head["generation"] != prepared["from_generation"]
                    or head["integration_attempt_id"]
                    != prepared["integration_attempt_id"]):
                raise RuntimeError("rollback completion lost publication-head CAS")
            if (context["project"] != prepared["project"]
                    or context["accepted_sha"] != prepared["from_sha"]):
                raise RuntimeError("rollback graph baseline changed after PREPARED")
            if (node["state"] != "INTEGRATED"
                    or node["integration_sha"] != prepared["from_sha"]
                    or attempt["status"] != "COMPLETED"):
                raise RuntimeError("rollback historical integration binding changed")
            affected = self._assert_prepared_affected_graph(prepared)
            goal_ids = [goal["goal_id"] for goal in affected["goals"]]
            entry = self._append_journal_locked(
                **self._journal_identity(prepared), phase="COMPLETED"
            )
            changed_goals = 0
            for goal_id in goal_ids:
                changed_goals += self.graph.connection.execute(
                    "UPDATE goals SET accepted_sha=? WHERE goal_id=? AND accepted_sha=?",
                    (prepared["to_sha"], goal_id, prepared["from_sha"]),
                ).rowcount
            if changed_goals != len(goal_ids):
                raise RuntimeError("rollback affected-goal compare-and-swap conflict")

            # Rebase every quiescent same-project node bound to the rolled-back
            # baseline.  Historical integrated nodes and their evidence are never
            # rewritten; every other rebase receives a versioned audit event.
            for affected_node in affected["nodes"]:
                if affected_node["state"] == "INTEGRATED":
                    continue
                new_version = affected_node["version"] + 1
                changed = self.graph.connection.execute(
                    "UPDATE nodes SET base_sha=?,version=?,updated_at=CURRENT_TIMESTAMP "
                    "WHERE node_id=? AND version=? AND state=? AND base_sha=?",
                    (
                        prepared["to_sha"], new_version, affected_node["node_id"],
                        affected_node["version"], affected_node["state"],
                        prepared["from_sha"],
                    ),
                ).rowcount
                if changed != 1:
                    raise RuntimeError("rollback affected-node compare-and-swap conflict")
                self.graph._event(
                    affected_node["node_id"], new_version,
                    affected_node["state"], affected_node["state"],
                    "project-global publication rollback baseline rebind",
                    digest({
                        "rollback_id": prepared["operation_id"],
                        "from_sha": prepared["from_sha"],
                        "to_sha": prepared["to_sha"],
                    }),
                )
            changed = self.graph.connection.execute(
                "UPDATE publication_heads SET version=?,sha=?,generation=?,"
                "integration_attempt_id=?,last_journal_hash=? "
                "WHERE project=? AND version=? AND sha=? AND generation=? "
                "AND integration_attempt_id IS ? AND last_journal_hash IS ?",
                (
                    prepared["version_after"], prepared["to_sha"],
                    prepared["to_generation"], prepared["integration_attempt_id"],
                    entry["entry_hash"], prepared["project"],
                    prepared["version_before"], prepared["from_sha"],
                    prepared["from_generation"],
                    affected["head"]["integration_attempt_id"],
                    affected["head"]["last_journal_hash"],
                ),
            ).rowcount
            if changed != 1:
                raise RuntimeError("concurrent rollback publication-head update")
            if crash_hook:
                crash_hook("before_rollback_completion_commit")
            self.graph.connection.commit()
        except Exception:
            self.graph.connection.rollback()
            raise
        return self._rollback_result(prepared, "COMPLETED")

    def _append_journal_locked(
        self, *, operation_id: str, operation_kind: str, phase: str,
        project: str, goal_id: str, node_id: str, integration_attempt_id: str,
        version_before: int, version_after: int, from_sha: str, to_sha: str,
        from_generation: str, to_generation: str,
        affected_graph_sha256: str, affected_graph_json: str,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        ProjectIntegrator._require_mutation_authority(self.integrator)
        # The caller holds an IMMEDIATE transaction. Recheck the full logical
        # projection at the last point before any append/head mutation.
        ProjectCoordinator.assert_graph_publication_integrity(
            self.graph, allow_completion_append_transient=True,
        )
        database = connection or self.graph.connection
        existing = database.execute(
            "SELECT * FROM publication_journal WHERE operation_id=? AND phase=?",
            (operation_id, phase),
        ).fetchone()
        identity = {
            "operation_id": operation_id, "operation_kind": operation_kind,
            "phase": phase, "project": project, "goal_id": goal_id,
            "node_id": node_id, "integration_attempt_id": integration_attempt_id,
            "version_before": version_before, "version_after": version_after,
            "from_sha": from_sha, "to_sha": to_sha,
            "from_generation": from_generation, "to_generation": to_generation,
            "affected_graph_sha256": affected_graph_sha256,
            "affected_graph_json": affected_graph_json,
        }
        if existing:
            row = dict(existing)
            if any(row[name] != value for name, value in identity.items()):
                raise ValueError("publication journal idempotency conflict")
            return row
        previous_row = database.execute(
            "SELECT sequence,entry_hash FROM publication_journal ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_sequence = previous_row["sequence"] if previous_row else None
        previous = previous_row["entry_hash"] if previous_row else None
        entry_hash = digest({**identity, "previous_hash": previous})
        database.execute(
            "INSERT INTO publication_journal("
            "operation_id,operation_kind,phase,project,goal_id,node_id,"
            "integration_attempt_id,version_before,version_after,from_sha,to_sha,"
            "from_generation,to_generation,affected_graph_sha256,affected_graph_json,"
            "previous_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                operation_id, operation_kind, phase, project, goal_id, node_id,
                integration_attempt_id, version_before, version_after, from_sha, to_sha,
                from_generation, to_generation, affected_graph_sha256,
                affected_graph_json, previous, entry_hash,
            ),
        )
        inserted = dict(database.execute(
            "SELECT * FROM publication_journal WHERE operation_id=? AND phase=?",
            (operation_id, phase),
        ).fetchone())
        changed = database.execute(
            "UPDATE publication_journal_tail SET last_sequence=?,last_hash=? "
            "WHERE singleton=1 AND last_sequence IS ? AND last_hash IS ?",
            (inserted["sequence"], inserted["entry_hash"], previous_sequence, previous),
        ).rowcount
        if changed != 1:
            raise RuntimeError("publication journal tail compare-and-swap conflict")
        return inserted

    @staticmethod
    def _journal_identity(row: dict[str, Any]) -> dict[str, Any]:
        return {
            name: row[name] for name in (
                "operation_id", "operation_kind", "project", "goal_id", "node_id",
                "integration_attempt_id", "version_before", "version_after",
                "from_sha", "to_sha", "from_generation", "to_generation",
                "affected_graph_sha256", "affected_graph_json",
            )
        }

    @staticmethod
    def _journal_hash_subject(row: dict[str, Any], previous: str | None) -> dict[str, Any]:
        return {
            **ProjectCoordinator._journal_identity(row),
            "phase": row["phase"], "previous_hash": previous,
        }

    def _journal_entries(self, operation_id: str) -> list[dict[str, Any]]:
        rows = self.graph.connection.execute(
            "SELECT * FROM publication_journal WHERE operation_id=? ORDER BY sequence",
            (operation_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _rollback_result(prepared: dict[str, Any], status: str) -> dict[str, Any]:
        return {
            "rollback_id": prepared["operation_id"], "status": status,
            "project": prepared["project"], "goal_id": prepared["goal_id"],
            "node_id": prepared["node_id"],
            "integration_attempt_id": prepared["integration_attempt_id"],
            "from_sha": prepared["from_sha"], "to_sha": prepared["to_sha"],
            "publication_generation": prepared["to_generation"],
            "head_version": prepared["version_after"],
        }

    def _node_context(self, node_id: str) -> dict[str, Any]:
        row = self.graph.connection.execute(
            "SELECT g.project,g.goal_id,g.accepted_sha FROM nodes n "
            "JOIN goals g ON g.goal_id=n.goal_id WHERE n.node_id=?",
            (node_id,),
        ).fetchone()
        if not row:
            raise KeyError(node_id)
        binding, _ = self.integrator._read_binding()
        return {
            "project": row["project"], "goal_id": row["goal_id"],
            "accepted_sha": row["accepted_sha"], "repo_name": binding["repo"],
        }

    def _rollback_affected_graph(self, project: str, from_sha: str) -> dict[str, Any]:
        self._assert_project_graph_baseline_coherent(project, from_sha)
        head_row = self.graph.connection.execute(
            "SELECT version,sha,generation,integration_attempt_id,last_journal_hash "
            "FROM publication_heads WHERE project=?", (project,),
        ).fetchone()
        if not head_row:
            raise RuntimeError("rollback affected graph has no publication head")
        goals = [dict(row) for row in self.graph.connection.execute(
            "SELECT goal_id,accepted_sha FROM goals WHERE project=? AND accepted_sha=? "
            "ORDER BY goal_id",
            (project, from_sha),
        ).fetchall()]
        nodes = [dict(row) for row in self.graph.connection.execute(
            "SELECT n.node_id,n.goal_id,n.version,n.state,n.base_sha,n.attempt,"
            "n.active_artifact_id,n.lease_id,n.lease_owner,n.lease_expires_at,n.heartbeat_at,"
            "EXISTS(SELECT 1 FROM evaluation_claims c WHERE c.node_id=n.node_id "
            "AND c.status='ACTIVE') AS active_claim,"
            "(n.lease_id IS NOT NULL OR n.lease_owner IS NOT NULL OR "
            "n.lease_expires_at IS NOT NULL OR n.heartbeat_at IS NOT NULL) AS active_lease "
            "FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE g.project=? AND n.base_sha=? ORDER BY n.node_id",
            (project, from_sha),
        ).fetchall()]
        return {
            "project": project, "from_sha": from_sha, "head": dict(head_row),
            "goals": goals, "nodes": nodes,
        }

    def _promotion_affected_graph(self, project: str, from_sha: str) -> dict[str, Any]:
        """Snapshot every same-project graph row a global promotion must rebind."""
        self._assert_project_graph_baseline_coherent(project, from_sha)
        head_row = self.graph.connection.execute(
            "SELECT version,sha,generation,integration_attempt_id,last_journal_hash "
            "FROM publication_heads WHERE project=?", (project,),
        ).fetchone()
        head = dict(head_row) if head_row else {
            "version": 0, "sha": from_sha, "generation": from_sha,
            "integration_attempt_id": None, "last_journal_hash": None,
        }
        goals = [dict(row) for row in self.graph.connection.execute(
            "SELECT goal_id,accepted_sha FROM goals WHERE project=? AND accepted_sha=? "
            "ORDER BY goal_id",
            (project, from_sha),
        ).fetchall()]
        nodes = [dict(row) for row in self.graph.connection.execute(
            "SELECT n.node_id,n.goal_id,n.version,n.state,n.base_sha,n.attempt,"
            "n.active_artifact_id,n.lease_id,n.lease_owner,n.lease_expires_at,n.heartbeat_at,"
            "EXISTS(SELECT 1 FROM evaluation_claims c WHERE c.node_id=n.node_id "
            "AND c.status='ACTIVE') AS active_claim,"
            "(n.lease_id IS NOT NULL OR n.lease_owner IS NOT NULL OR "
            "n.lease_expires_at IS NOT NULL OR n.heartbeat_at IS NOT NULL) AS active_lease "
            "FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE g.project=? AND n.base_sha=? ORDER BY n.node_id",
            (project, from_sha),
        ).fetchall()]
        return {
            "project": project, "from_sha": from_sha, "head": head,
            "goals": goals, "nodes": nodes,
        }

    def _assert_prepared_promotion_graph(
        self, attempt: dict[str, Any], origin_node_id: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Require the PREPARED graph snapshot plus only the origin lifecycle."""
        recorded = self._load_prepared_promotion_graph(attempt)
        canonical = json.dumps(recorded, sort_keys=True, separators=(",", ":"))
        expected_current = json.loads(canonical)
        origins = [
            node for node in expected_current.get("nodes", [])
            if node.get("node_id") == origin_node_id
        ]
        if len(origins) != 1 or origins[0].get("state") != "PASSED":
            raise RuntimeError("promotion PREPARED origin binding is invalid")
        origins[0]["state"] = "INTEGRATED"
        origins[0]["version"] += 2
        current = self._promotion_affected_graph(
            self.integrator.project, attempt["expected_base_sha"],
        )
        if current != expected_current:
            raise RuntimeError("promotion affected graph changed after PREPARED")
        return recorded, current

    def _assert_prepared_promotion_ready(
        self, attempt: dict[str, Any], origin_node_id: str,
    ) -> dict[str, Any]:
        """Validate the frozen set before any import/ref/binding recovery side effect."""
        ProjectGraph._assert_no_human_gate(self.graph.get_node(origin_node_id))
        recorded = self._load_prepared_promotion_graph(attempt)
        current = self._promotion_affected_graph(
            self.integrator.project, attempt["expected_base_sha"],
        )
        if current != recorded:
            raise RuntimeError("promotion affected graph changed after PREPARED")
        self._assert_promotion_quiescent(current, origin_node_id, {"PASSED"})
        return recorded

    def _load_prepared_promotion_graph(
        self, attempt: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            recorded = json.loads(attempt["affected_graph_json"])
        except (TypeError, json.JSONDecodeError):
            raise RuntimeError("promotion PREPARED affected graph is invalid") from None
        canonical = json.dumps(recorded, sort_keys=True, separators=(",", ":"))
        head = recorded.get("head") if isinstance(recorded, dict) else None
        if (
            not isinstance(recorded, dict)
            or set(recorded) != {"project", "from_sha", "head", "goals", "nodes"}
            or canonical != attempt["affected_graph_json"]
            or digest(recorded) != attempt["affected_graph_sha256"]
            or recorded.get("project") != self.integrator.project
            or recorded.get("from_sha") != attempt["expected_base_sha"]
            or not isinstance(head, dict)
            or head.get("version") != attempt["expected_head_version"]
            or head.get("sha") != attempt["expected_base_sha"]
            or head.get("generation") != attempt["expected_base_sha"]
        ):
            raise RuntimeError("promotion PREPARED affected graph hash binding is invalid")
        return recorded

    def _assert_project_graph_baseline_coherent(
        self, project: str, baseline_sha: str,
    ) -> None:
        foreign_goal = self.graph.connection.execute(
            "SELECT goal_id FROM goals WHERE project=? AND state='ACTIVE' "
            "AND accepted_sha!=? ORDER BY goal_id LIMIT 1",
            (project, baseline_sha),
        ).fetchone()
        if foreign_goal:
            raise RuntimeError(
                "project graph has an active goal outside the publication baseline: "
                f"{foreign_goal['goal_id']}"
            )
        mismatch = self.graph.connection.execute(
            "SELECT n.node_id FROM nodes n JOIN goals g ON g.goal_id=n.goal_id "
            "WHERE g.project=? AND g.state='ACTIVE' AND n.state!='INTEGRATED' AND ("
            "(g.accepted_sha=? AND n.base_sha!=?) OR "
            "(n.base_sha=? AND g.accepted_sha!=?)) LIMIT 1",
            (project, baseline_sha, baseline_sha, baseline_sha, baseline_sha),
        ).fetchone()
        if mismatch:
            raise RuntimeError(
                f"project graph baseline is internally inconsistent: {mismatch['node_id']}"
            )

    @staticmethod
    def _assert_promotion_quiescent(
        affected: dict[str, Any], origin_node_id: str, origin_states: set[str],
    ) -> None:
        denied = {
            "LEASED", "RUNNING", "EVIDENCE_PENDING", "EVALUATING", "PASSED",
            "INTEGRATING",
        }
        for node in affected["nodes"]:
            if node["node_id"] == origin_node_id and node["state"] in origin_states:
                if node["active_claim"] or node["active_lease"]:
                    raise RuntimeError("promotion origin retains an active lease or claim")
                continue
            if (
                node["state"] in denied or node["active_claim"] or node["active_lease"]
                or (node["state"] != "INTEGRATED" and node["active_artifact_id"] is not None)
            ):
                raise RuntimeError(
                    f"promotion affected node is not quiescent: {node['node_id']}"
                )

    def _expected_promotion_head_version(self, expected_base_sha: str) -> int:
        row = self.graph.connection.execute(
            "SELECT version,sha,generation FROM publication_heads WHERE project=?",
            (self.integrator.project,),
        ).fetchone()
        if row is None:
            return 0
        if (row["sha"], row["generation"]) != (expected_base_sha, expected_base_sha):
            raise RuntimeError("promotion baseline differs from the publication head")
        return int(row["version"])

    @staticmethod
    def _assert_quiescent_affected_graph(affected: dict[str, Any]) -> None:
        denied = {
            "LEASED", "RUNNING", "EVIDENCE_PENDING", "EVALUATING", "PASSED",
            "INTEGRATING",
        }
        for node in affected["nodes"]:
            if (
                node["state"] in denied or node["active_claim"] or node["active_lease"]
                or (node["state"] != "INTEGRATED" and node["active_artifact_id"] is not None)
            ):
                raise RuntimeError(
                    f"rollback affected node is not quiescent: {node['node_id']}"
                )

    def _assert_prepared_affected_graph(self, prepared: dict[str, Any]) -> dict[str, Any]:
        try:
            recorded = json.loads(prepared["affected_graph_json"])
        except (TypeError, json.JSONDecodeError):
            raise RuntimeError("rollback PREPARED affected graph is invalid") from None
        canonical = json.dumps(recorded, sort_keys=True, separators=(",", ":"))
        if (
            canonical != prepared["affected_graph_json"]
            or digest(recorded) != prepared["affected_graph_sha256"]
            or recorded.get("project") != prepared["project"]
            or recorded.get("from_sha") != prepared["from_sha"]
        ):
            raise RuntimeError("rollback PREPARED affected graph hash binding is invalid")
        current = self._rollback_affected_graph(
            prepared["project"], prepared["from_sha"],
        )
        if current != recorded:
            raise RuntimeError("rollback affected graph changed after PREPARED")
        self._assert_quiescent_affected_graph(current)
        return current

    def _attempt(self, node_id: str, candidate_sha: str) -> dict[str, Any]:
        row = self.graph.connection.execute(
            "SELECT * FROM integration_attempts WHERE node_id=? AND candidate_sha=?", (node_id, candidate_sha)
        ).fetchone()
        if not row:
            raise KeyError((node_id, candidate_sha))
        return dict(row)

    def _attempt_by_id(self, attempt_id: str) -> dict[str, Any]:
        row = self.graph.connection.execute(
            "SELECT * FROM integration_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if not row:
            raise KeyError(attempt_id)
        return dict(row)
