#!/usr/bin/env python3
"""Deterministic, fail-closed promotion of independently evaluated Git commits."""

from __future__ import annotations

import base64
import binascii
import fcntl
import grp
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from control_plane.publication_store import PublicationPin, PublicationStore
from control_plane.artifact_builder import safe_relative_artifact_path
from control_plane.evidence_ingress import MANIFEST_V4_FIELDS, validate_manifest_v4
from control_plane.evaluation_policy import TaskEvaluationPolicy, validate_task_policy

REQUIRED_GATES = {f"HG{number}" for number in range(1, 12)}
SECTION_LIMITS = {
    "problem_and_evidence": (8, 10),
    "graph_architecture_and_maximum_results_policy": (17, 18),
    "durability_and_recovery": (11, 12),
    "verification_evaluation_and_cumulative_integration": (17, 18),
    "finance_and_consequential_action_safety": (15, 15),
    "buzz_identity_and_security_boundaries": (11, 12),
    "operator_ux_and_observability": (7, 8),
    "tests_and_representative_evidence": (7, 7),
}
EVALUATION_FIELDS = {
    "evaluation_id", "task_id", "contract_id", "artifact_id", "claim_id",
    "evaluated_git_sha",
    "evidence_manifest_sha256", "rubric_sha256", "section_scores",
    "mandatory_gates", "total_score", "verdict", "evaluator_identity",
    "previous_ledger_hash", "ledger_hash", "signature",
}
MANIFEST_FIELDS = MANIFEST_V4_FIELDS
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
FaultHook = Callable[[str], None]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def evaluation_ledger_hash(evaluation: dict[str, Any]) -> str:
    subject = {name: value for name, value in evaluation.items() if name not in {"signature", "ledger_hash"}}
    return hashlib.sha256(canonical(subject)).hexdigest()


def _is_number(value: Any) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _verify_openssl_signature(subject: bytes, signature: bytes, public_key: Path) -> None:
    if public_key.is_symlink() or not public_key.is_file():
        raise PermissionError("evaluator public key must be a regular non-symlink file")
    with tempfile.TemporaryDirectory(prefix="ai-ops-evaluation-") as temporary:
        root = Path(temporary)
        message_path = root / "evaluation.json"
        signature_path = root / "evaluation.sig"
        message_path.write_bytes(subject)
        signature_path.write_bytes(signature)
        completed = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_key),
             "-sigfile", str(signature_path), "-in", str(message_path)],
            check=False, capture_output=True,
        )
    if completed.returncode != 0:
        raise PermissionError("invalid evaluator signature")


def verify_evaluation(
    evaluation: dict[str, Any],
    public_key: Path,
    evidence_manifest: Path,
    expected_rubric_sha256: str,
    *,
    expected_task_id: str,
    expected_contract_id: str,
    expected_artifact_id: str | object = ...,
    expected_claim_id: str | object = ...,
    expected_previous_ledger_hash: str | None | object = ...,
    evaluation_policy: TaskEvaluationPolicy | None = None,
) -> None:
    """Enforce the frozen score contract and verify an Ed25519 public-key signature."""
    fields = EVALUATION_FIELDS
    sections = SECTION_LIMITS
    gates_required = REQUIRED_GATES
    threshold = 95
    if evaluation_policy is not None:
        validate_task_policy(evaluation_policy, expected_rubric_sha256)
        fields = fields | {"schema_version", "policy_sha256"}
        sections = {name: (minimum, maximum) for name, minimum, maximum in evaluation_policy.sections}
        gates_required = evaluation_policy.mandatory_gates
        threshold = evaluation_policy.threshold
    if not isinstance(evaluation, dict) or set(evaluation) != fields:
        raise PermissionError("evaluation does not match the exact result schema")
    if evaluation_policy is not None:
        if type(evaluation["schema_version"]) is not int or evaluation["schema_version"] != 4:
            raise PermissionError("task evaluation requires schema version 4")
        if evaluation["policy_sha256"] != evaluation_policy.sha256:
            raise PermissionError("task evaluation policy hash mismatch")
    for field in ("evaluation_id", "task_id", "contract_id", "evaluator_identity"):
        if not isinstance(evaluation[field], str) or not evaluation[field]:
            raise PermissionError(f"evaluation {field} is invalid")
    if (
        not isinstance(evaluation["artifact_id"], str)
        or not re.fullmatch(r"sha256:[a-f0-9]{64}", evaluation["artifact_id"])
    ):
        raise PermissionError("evaluation artifact_id is invalid")
    if (
        not isinstance(evaluation["claim_id"], str)
        or not re.fullmatch(r"claim:[a-f0-9]{64}", evaluation["claim_id"])
    ):
        raise PermissionError("evaluation claim_id is invalid")
    if not isinstance(evaluation["evaluated_git_sha"], str) or not HEX40.fullmatch(evaluation["evaluated_git_sha"]):
        raise PermissionError("evaluation evaluated_git_sha is invalid")
    for field in ("evidence_manifest_sha256", "rubric_sha256", "ledger_hash"):
        if not isinstance(evaluation[field], str) or not HEX64.fullmatch(evaluation[field]):
            raise PermissionError(f"evaluation {field} is invalid")
    previous = evaluation["previous_ledger_hash"]
    if previous is not None and (not isinstance(previous, str) or not HEX64.fullmatch(previous)):
        raise PermissionError("evaluation previous ledger hash is invalid")
    if not isinstance(evaluation["signature"], str) or not evaluation["signature"]:
        raise PermissionError("evaluation signature is invalid")

    scores = evaluation["section_scores"]
    if not isinstance(scores, dict) or set(scores) != set(sections):
        raise PermissionError("evaluation must contain the exact frozen section score set")
    for section, (minimum, maximum) in sections.items():
        score = scores[section]
        if not _is_number(score) or not minimum <= float(score) <= maximum:
            raise PermissionError(f"evaluation section minimum or maximum failed: {section}")
    total_score = evaluation["total_score"]
    if not _is_number(total_score) or abs(float(total_score) - sum(float(value) for value in scores.values())) > 1e-9:
        raise PermissionError("evaluation total does not equal its section scores")
    if evaluation["verdict"] != "PASS" or float(total_score) < threshold:
        raise PermissionError("evaluation does not meet frozen threshold")
    gates = evaluation["mandatory_gates"]
    if not isinstance(gates, dict) or set(gates) != gates_required or any(result != "PASS" for result in gates.values()):
        raise PermissionError("the exact frozen mandatory gate set must all pass")
    if evaluation["evaluator_identity"] != "hermes-evaluator":
        raise PermissionError("independent evaluator identity required")
    if evaluation["task_id"] != expected_task_id or evaluation["contract_id"] != expected_contract_id:
        raise PermissionError("evaluation task or contract binding mismatch")
    if expected_artifact_id is not ... and evaluation["artifact_id"] != expected_artifact_id:
        raise PermissionError("evaluation artifact binding mismatch")
    if expected_claim_id is not ... and evaluation["claim_id"] != expected_claim_id:
        raise PermissionError("evaluation claim binding mismatch")
    if evaluation["rubric_sha256"] != expected_rubric_sha256:
        raise PermissionError("evaluation is not bound to the frozen rubric")
    if evaluation["evidence_manifest_sha256"] != sha256_file(evidence_manifest):
        raise PermissionError("evidence manifest hash mismatch")
    if expected_previous_ledger_hash is not ... and previous != expected_previous_ledger_hash:
        raise PermissionError("evaluation ledger predecessor mismatch")
    if evaluation["ledger_hash"] != evaluation_ledger_hash(evaluation):
        raise PermissionError("evaluation ledger hash mismatch")
    try:
        signature = base64.b64decode(evaluation["signature"], validate=True)
    except (binascii.Error, ValueError):
        raise PermissionError("evaluation signature is not canonical base64") from None
    subject = {name: value for name, value in evaluation.items() if name != "signature"}
    _verify_openssl_signature(canonical(subject), signature, public_key)


@dataclass(frozen=True)
class CandidateBundle:
    manifest_path: Path
    manifest_sha256: str
    bundle_path: Path
    bundle_sha256: str
    task_id: str
    attempt: int
    project_id: str
    base_sha: str
    candidate_sha: str
    contract_sha256: str


class ProjectIntegrator:
    def __init__(self, repo: Path, binding: Path, evaluator_public_key: Path,
                 rubric_path: Path, accepted_ref: str,
                 expected_binding_group: str | None = None,
                 publication_root: Path | None = None,
                 evaluation_policy: TaskEvaluationPolicy | None = None):
        self.repo = repo.resolve()
        self.binding = Path(os.path.abspath(binding))
        self.evaluator_public_key = Path(os.path.abspath(evaluator_public_key))
        if self.evaluator_public_key.is_symlink() or not self.evaluator_public_key.is_file():
            raise PermissionError("evaluator public key must be a regular non-symlink file")
        self._evaluator_public_key_sha256 = sha256_file(self.evaluator_public_key)
        self.rubric_path = Path(os.path.abspath(rubric_path))
        self.rubric_sha256 = sha256_file(self.rubric_path)
        self.evaluation_policy = evaluation_policy
        self.assert_verification_configuration()
        if not re.fullmatch(r"refs/ai-ops/accepted/[a-z]+", accepted_ref):
            raise ValueError("accepted ref is not canonical")
        self.accepted_ref = accepted_ref
        self.project = accepted_ref.rsplit("/", 1)[-1]
        self.expected_binding_group = expected_binding_group
        self.publications = PublicationStore(
            publication_root if publication_root is not None
            else self.binding.parent / "publications"
        )

    def assert_verification_configuration(self) -> None:
        """Refuse changed trusted key/rubric inputs before any checked effects."""
        if self.evaluator_public_key.is_symlink() or not self.evaluator_public_key.is_file():
            raise PermissionError("evaluator public key must be a regular non-symlink file")
        if sha256_file(self.evaluator_public_key) != self._evaluator_public_key_sha256:
            raise PermissionError("evaluator public key bytes changed after configuration")
        if self.rubric_path.is_symlink() or not self.rubric_path.is_file():
            raise PermissionError("frozen rubric must be a regular non-symlink file")
        if sha256_file(self.rubric_path) != self.rubric_sha256:
            raise PermissionError("frozen rubric bytes changed after configuration")
        if self.evaluation_policy is not None:
            validate_task_policy(self.evaluation_policy, self.rubric_sha256)

    @contextmanager
    def _binding_lock(self):
        lock_path = self.binding.with_suffix(self.binding.suffix + ".lock")
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def preflight_bundle(
        self,
        manifest_path: Path,
        evidence_root: Path,
        *,
        expected_project_id: str,
        expected_task_id: str,
        expected_base_sha: str,
        expected_candidate_sha: str,
    ) -> CandidateBundle:
        root = evidence_root.resolve(strict=True)
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise PermissionError("candidate manifest must be a regular non-symlink file")
        resolved_manifest = manifest_path.resolve(strict=True)
        if root not in resolved_manifest.parents:
            raise PermissionError("candidate manifest is outside the configured evidence root")
        if resolved_manifest.stat().st_nlink != 1:
            raise PermissionError("candidate manifest must be a single-link file")
        manifest_bytes = resolved_manifest.read_bytes()
        manifest = json.loads(manifest_bytes)
        validate_manifest_v4(
            manifest, resolved_manifest.parent,
            expected_task_id=expected_task_id,
            expected_project_id=expected_project_id,
            expected_base_sha=expected_base_sha,
        )
        if manifest["candidate_sha"] != expected_candidate_sha:
            raise PermissionError("candidate manifest candidate binding mismatch")
        bundle = manifest["bundle"]
        supplied_bundle = resolved_manifest.parent / safe_relative_artifact_path(bundle["path"])
        if supplied_bundle.is_symlink() or not supplied_bundle.is_file() or supplied_bundle.stat().st_nlink != 1:
            raise PermissionError("candidate bundle must be a regular non-symlink file")
        resolved_bundle = supplied_bundle.resolve(strict=True)
        if (resolved_manifest.parent not in resolved_bundle.parents
                or root not in resolved_bundle.parents
                or sha256_file(resolved_bundle) != bundle["sha256"]
                or resolved_bundle.stat().st_size != bundle["byte_length"]):
            raise PermissionError("candidate bundle hash or evidence-root binding is invalid")
        heads = subprocess.run(
            ["git", "bundle", "list-heads", str(resolved_bundle)], check=True,
            capture_output=True, text=True,
        ).stdout.splitlines()
        if f"{expected_candidate_sha} HEAD" not in heads:
            raise PermissionError("candidate bundle HEAD does not match the recorded candidate")
        subprocess.run(
            ["git", "-C", str(self.repo), "bundle", "verify", str(resolved_bundle)],
            check=True, capture_output=True, text=True,
        )
        return CandidateBundle(
            resolved_manifest, hashlib.sha256(manifest_bytes).hexdigest(), resolved_bundle,
            bundle["sha256"], manifest["task_id"], manifest["attempt"],
            manifest["project_id"], manifest["base_sha"], manifest["candidate_sha"],
            manifest["contract_sha256"],
        )

    def import_bundle(self, candidate: CandidateBundle) -> str:
        if sha256_file(candidate.manifest_path) != candidate.manifest_sha256:
            raise PermissionError("candidate manifest changed after preflight")
        if sha256_file(candidate.bundle_path) != candidate.bundle_sha256:
            raise PermissionError("candidate bundle changed after preflight")
        reference = f"refs/ai-ops/candidates/{candidate.task_id}/{candidate.candidate_sha}"
        subprocess.run(
            ["git", "-C", str(self.repo), "fetch", str(candidate.bundle_path), f"HEAD:{reference}"],
            check=True, capture_output=True, text=True,
        )
        if git(self.repo, "rev-parse", f"{reference}^{{commit}}") != candidate.candidate_sha:
            raise PermissionError("imported bundle does not match candidate SHA")
        return candidate.candidate_sha

    def promote(
        self,
        candidate_sha: str,
        expected_base_sha: str,
        allowed_paths: list[str],
        evaluation: dict[str, Any],
        evidence_manifest: Path,
        *,
        expected_task_id: str,
        expected_contract_id: str,
        fault_hook: FaultHook | None = None,
    ) -> dict[str, Any]:
        ProjectIntegrator.assert_verification_configuration(self)
        verify_evaluation(
            evaluation, self.evaluator_public_key, evidence_manifest, self.rubric_sha256,
            expected_task_id=expected_task_id, expected_contract_id=expected_contract_id,
            evaluation_policy=self.evaluation_policy,
        )
        if evaluation["evaluated_git_sha"] != candidate_sha:
            raise PermissionError("evaluation is not bound to candidate SHA")
        with self._binding_lock():
            return self._promote_locked(
                candidate_sha, expected_base_sha, allowed_paths, evaluation,
                evidence_manifest, fault_hook,
            )

    def _promote_locked(
        self,
        candidate_sha: str,
        expected_base_sha: str,
        allowed_paths: list[str],
        evaluation: dict[str, Any],
        evidence_manifest: Path,
        fault_hook: FaultHook | None,
    ) -> dict[str, Any]:
        current, metadata = self._read_binding()
        current_sha = current["base_sha"]
        accepted_sha = self._ref_sha(self.accepted_ref)
        if current_sha not in {expected_base_sha, candidate_sha}:
            raise RuntimeError("binding compare-and-swap conflict")
        if accepted_sha not in {None, expected_base_sha, candidate_sha}:
            raise RuntimeError("accepted ref compare-and-swap conflict")
        if not self._workspace_is_clean():
            raise RuntimeError("publication source is not a clean repository")
        self._validate_candidate(candidate_sha, expected_base_sha, allowed_paths)
        self.publications.ensure(self.repo, current["repo"], expected_base_sha, metadata)
        publication = self.publications.ensure(
            self.repo, current["repo"], candidate_sha, metadata
        )
        if fault_hook:
            fault_hook("after_publication")
        if fault_hook:
            fault_hook("before_ref")
        if accepted_sha is None:
            self._update_ref(self.accepted_ref, expected_base_sha, None)
            accepted_sha = expected_base_sha
        rollback_ref = self._rollback_ref(candidate_sha)
        rollback_sha = self._ref_sha(rollback_ref)
        if rollback_sha is None:
            self._update_ref(rollback_ref, expected_base_sha, None)
        elif rollback_sha != expected_base_sha:
            raise RuntimeError("rollback reference conflict")
        if accepted_sha == expected_base_sha:
            self._update_ref(self.accepted_ref, candidate_sha, expected_base_sha)
        if fault_hook:
            fault_hook("after_ref")
        # Retain the historical hook name for fault-injection compatibility.
        # No shared checkout is changed; the immutable generation was already
        # made durable before the accepted-ref compare-and-swap.
        if fault_hook:
            fault_hook("after_materialize")
        if current_sha == expected_base_sha:
            self._atomic_write({"repo": current["repo"], "base_sha": candidate_sha}, metadata)
        if fault_hook:
            fault_hook("after_binding")
        return {
            "repo": current["repo"], "base_sha": candidate_sha,
            "integration_sha": candidate_sha, "accepted_ref": self.accepted_ref,
            "publication_generation": publication.generation,
            "evaluation_sha256": hashlib.sha256(canonical(evaluation)).hexdigest(),
            "evidence_manifest_sha256": sha256_file(evidence_manifest),
        }

    def promotion_started(self, candidate_sha: str) -> bool:
        with self._binding_lock():
            binding, _ = self._read_binding()
            return binding["base_sha"] == candidate_sha or self._ref_sha(self.accepted_ref) == candidate_sha

    def reconcile_promotion(self, expected_base_sha: str, candidate_sha: str) -> str | None:
        """Finish publication -> ref -> binding ordering, or report no side effect."""
        ProjectIntegrator.assert_verification_configuration(self)
        with self._binding_lock():
            binding, metadata = self._read_binding()
            accepted_sha = self._ref_sha(self.accepted_ref)
            if accepted_sha != candidate_sha:
                if binding["base_sha"] == candidate_sha:
                    raise RuntimeError("binding advanced without the accepted Git ref")
                return None
            if binding["base_sha"] not in {expected_base_sha, candidate_sha}:
                raise RuntimeError("binding compare-and-swap conflict during recovery")
            if git(self.repo, "rev-parse", f"{candidate_sha}^{{commit}}") != candidate_sha:
                raise RuntimeError("accepted candidate object is absent during recovery")
            self.publications.ensure(self.repo, binding["repo"], candidate_sha, metadata)
            if binding["base_sha"] == expected_base_sha:
                self._atomic_write({"repo": binding["repo"], "base_sha": candidate_sha}, metadata)
            return candidate_sha

    def rollback(self, expected_current_sha: str, *, expected_previous_sha: str | None = None,
                 fault_hook: FaultHook | None = None) -> dict[str, Any]:
        """Idempotently move the accepted ref and selector to its saved predecessor."""
        ProjectIntegrator.assert_verification_configuration(self)
        return self.reconcile_rollback(
            expected_current_sha, expected_previous_sha=expected_previous_sha,
            require_started=False, fault_hook=fault_hook,
        )

    def reconcile_rollback(
        self, expected_current_sha: str, *, expected_previous_sha: str | None = None,
        require_started: bool = False, fault_hook: FaultHook | None = None,
    ) -> dict[str, Any]:
        ProjectIntegrator.assert_verification_configuration(self)
        with self._binding_lock():
            current, metadata = self._read_binding()
            previous_sha = self._ref_sha(self._rollback_ref(expected_current_sha))
            if previous_sha is None:
                raise RuntimeError("rollback reference is absent")
            if expected_previous_sha is not None and previous_sha != expected_previous_sha:
                raise RuntimeError("rollback predecessor does not match the journal")
            accepted_sha = self._ref_sha(self.accepted_ref)
            if accepted_sha not in {expected_current_sha, previous_sha}:
                raise RuntimeError("rollback accepted-ref compare-and-swap conflict")
            if current["base_sha"] not in {expected_current_sha, previous_sha}:
                raise RuntimeError("rollback binding compare-and-swap conflict")
            if accepted_sha == expected_current_sha and current["base_sha"] != expected_current_sha:
                raise RuntimeError("rollback binding moved before the accepted ref")
            if require_started and accepted_sha == expected_current_sha:
                raise RuntimeError("journal says rollback started but accepted ref did not move")
            publication = self.publications.ensure(
                self.repo, current["repo"], previous_sha, metadata
            )
            if fault_hook:
                fault_hook("before_rollback_ref")
            if accepted_sha == expected_current_sha:
                self._update_ref(self.accepted_ref, previous_sha, expected_current_sha)
            if fault_hook:
                fault_hook("after_rollback_ref")
            if current["base_sha"] == expected_current_sha:
                self._atomic_write(
                    {"repo": current["repo"], "base_sha": previous_sha}, metadata
                )
            if fault_hook:
                fault_hook("after_rollback_binding")
            return {
                "repo": current["repo"], "base_sha": previous_sha,
                "accepted_ref": self.accepted_ref,
                "publication_generation": publication.generation,
            }

    def ensure_bound_publication(self) -> PublicationPin:
        """Materialize the initial bound generation without changing the selector."""
        with self._binding_lock():
            binding, metadata = self._read_binding()
            accepted_sha = self._ref_sha(self.accepted_ref)
            if accepted_sha not in {None, binding["base_sha"]}:
                raise RuntimeError("accepted ref and worker binding disagree")
            return self.publications.ensure(
                self.repo, binding["repo"], binding["base_sha"], metadata
            )

    def _validate_candidate(self, candidate_sha: str, expected_base_sha: str, allowed_paths: list[str]) -> None:
        if not HEX40.fullmatch(candidate_sha) or not HEX40.fullmatch(expected_base_sha):
            raise ValueError("candidate or base SHA is invalid")
        if git(self.repo, "rev-parse", f"{candidate_sha}^{{commit}}") != candidate_sha:
            raise ValueError("candidate is not a commit")
        parents = git(self.repo, "rev-list", "--parents", "-n", "1", candidate_sha).split()
        if parents != [candidate_sha, expected_base_sha]:
            raise ValueError("candidate must be exactly one non-merge commit atop the expected base")
        # Disable rename detection so both sides of a delete/add (including a
        # high-similarity rename) are independently checked against the frozen
        # write set.  NUL framing preserves every Git-valid path byte except
        # NUL itself and avoids newline/quoting ambiguity.
        changed_output = subprocess.run(
            [
                "git", "-C", str(self.repo), "diff", "--no-renames",
                "--name-status", "-z", "--no-ext-diff",
                expected_base_sha, candidate_sha, "--",
            ],
            check=True, capture_output=True,
        ).stdout
        if not changed_output.endswith(b"\0"):
            raise RuntimeError("candidate diff did not use complete NUL framing")
        fields = changed_output.split(b"\0")[:-1]
        if len(fields) % 2:
            raise RuntimeError("candidate diff name-status record is incomplete")
        changed: list[str] = []
        for status_value, name in zip(fields[0::2], fields[1::2]):
            if status_value not in {b"A", b"M", b"D", b"T"} or not name:
                raise PermissionError("candidate diff contains an unsupported change type")
            changed.append(os.fsdecode(name))
        if not changed:
            raise ValueError("candidate has no changes")
        if not isinstance(allowed_paths, list) or not all(
            isinstance(value, str) and value and "\x00" not in value
            for value in allowed_paths
        ):
            raise PermissionError("allowed paths are invalid")
        prefixes = [Path(value) for value in allowed_paths]
        if not prefixes or any(
            prefix.is_absolute() or ".." in prefix.parts or prefix == Path(".")
            for prefix in prefixes
        ):
            raise PermissionError("allowed paths are invalid")
        for name in changed:
            item = Path(name)
            if item.is_absolute() or ".." in item.parts or not any(item == prefix or prefix in item.parents for prefix in prefixes):
                raise PermissionError(f"candidate changes forbidden path: {name}")

    def _read_binding(self) -> tuple[dict[str, str], os.stat_result]:
        if self.binding.is_symlink() or not self.binding.is_file():
            raise PermissionError("repository binding must be a regular non-symlink file")
        metadata = self.binding.stat()
        if stat.S_IMODE(metadata.st_mode) != 0o440 or metadata.st_uid != os.geteuid():
            raise PermissionError("repository binding owner or mode is unsafe")
        if (self.expected_binding_group is not None
                and metadata.st_gid != grp.getgrnam(self.expected_binding_group).gr_gid):
            raise PermissionError("repository binding is not readable by the configured worker group")
        value = json.loads(self.binding.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != {"repo", "base_sha"}:
            raise PermissionError("repository binding must keep the worker-readable {repo,base_sha} schema")
        if not isinstance(value["repo"], str) or not value["repo"] or not HEX40.fullmatch(str(value["base_sha"])):
            raise PermissionError("repository binding values are invalid")
        return {"repo": value["repo"], "base_sha": value["base_sha"]}, metadata

    def _atomic_write(self, value: dict[str, str], metadata: os.stat_result) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{self.binding.name}.", dir=self.binding.parent)
        try:
            os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
            current_metadata = os.fstat(descriptor)
            if (current_metadata.st_uid, current_metadata.st_gid) != (metadata.st_uid, metadata.st_gid):
                if os.geteuid() != 0:
                    raise PermissionError("cannot preserve repository binding ownership")
                os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(canonical(value) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.binding)
            directory = os.open(self.binding.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _ref_sha(self, reference: str) -> str | None:
        completed = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "--verify", f"{reference}^{{commit}}"],
            check=False, capture_output=True, text=True,
        )
        return completed.stdout.strip() if completed.returncode == 0 else None

    def _update_ref(self, reference: str, new_sha: str, old_sha: str | None) -> None:
        command = ["git", "-C", str(self.repo), "update-ref", reference, new_sha]
        command.append(old_sha if old_sha is not None else "0" * 40)
        subprocess.run(command, check=True, capture_output=True, text=True)

    def _rollback_ref(self, candidate_sha: str) -> str:
        return f"refs/ai-ops/rollback/{self.project}/{candidate_sha}"

    def _workspace_is_clean(self) -> bool:
        uncommitted = git(
            self.repo, "status", "--porcelain=v1", "--untracked-files=all"
        )
        ignored = git(
            self.repo, "ls-files", "--others", "--ignored", "--exclude-standard"
        )
        return not uncommitted and not ignored
