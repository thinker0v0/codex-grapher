"""Executable, persistent local task lifecycle for trusted developer work.

The sample uses real Git repositories, required tests, immutable ingress, a
separate deterministic evaluator process, signed task results, and the normal
coordinator. Processes share a UID: this is not an OS security sandbox. Its task
policy says nothing about the product release rubric or deployed operation.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Any, Sequence

from control_plane.artifact_builder import _run_bounded_test_command, build, produce_required_test_results
from control_plane.evaluation_policy import load_task_policy
from control_plane.evidence_ingress import EvidenceIngress, resolve_manifest, validate_manifest_v4
from control_plane.graph_bootstrap import apply_database
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_graph import ProjectGraph
from control_plane.project_integrator import ProjectIntegrator, canonical, evaluation_ledger_hash, sha256_file
from control_plane.workspace_guard import inventory, is_allowed, violations


TASK = "greeting-fix"
SUCCESSOR = "consume-greeting"
GOAL = "local-developer-lifecycle"
ATTEMPT = "greeting-promotion-v1"
ROLLBACK = "greeting-rollback-v1"
CONTRACT = "greeting-acceptance-v1"
OWNER = "hermes-oss"
POLICY = {
    "schema_version": 1, "name": "local-greeting-task-v1",
    "sections": {"correctness": {"minimum": 95, "maximum": 100}},
    "mandatory_gates": ["required_tests", "independent_assertions", "write_scope"],
    "threshold": 95,
}
BASE_SOURCE = 'def greet(name):\n    return "Hello, " + name + "!"\n'
FIXED_SOURCE = 'def greet(name):\n    return "Hello, " + (name.strip() or "world") + "!"\n'
REQUIRED_TEST = '''from pathlib import Path
import sys
sys.path.insert(0, str(Path.cwd() / "src"))
from greeting import greet
assert greet("Ada") == "Hello, Ada!"
assert greet("Grace Hopper") == "Hello, Grace Hopper!"
print("2 required greeting assertions passed")
'''
INDEPENDENT_TEST = '''from pathlib import Path
import sys
sys.path.insert(0, str(Path.cwd() / "src"))
from greeting import greet
cases = [("Ada", "Hello, Ada!"), ("  Ada  ", "Hello, Ada!"),
         ("", "Hello, world!"), (" \\t ", "Hello, world!"),
         ("홍길동", "Hello, 홍길동!"), ("Ada Lovelace", "Hello, Ada Lovelace!")]
for value, expected in cases:
    if greet(value) != expected:
        raise SystemExit("independent greeting assertion failed")
print("6 independent greeting assertions passed")
'''


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("workflow record must be a JSON object")
    return value


def _write_json(path: Path, value: Any) -> None:
    """Durably replace a private local progress record; evidence uses core APIs."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _environment() -> dict[str, str]:
    return {
        "PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
    }


def _run(command: Sequence[str], *, cwd: Path | None = None,
         timeout: int = 60, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(command), cwd=cwd, env=environment or _environment(),
        check=True, capture_output=True, text=True, timeout=timeout,
    )


def _git(repo: Path, *arguments: str) -> str:
    return _run(["git", "-C", str(repo), *arguments]).stdout.strip()


def _python_command(code: str) -> str:
    return shlex.join([sys.executable, "-I", "-B", "-c", code])


def produce_worker_artifact(
    workspace: Path, contract_path: Path, output_dir: Path, attempt_number: int,
    worker_command: Sequence[str],
) -> dict[str, Any]:
    """Explicitly run a trusted local worker, guard its paths, and build evidence.

    The caller must approve the command/repository and freeze a contract with
    task_id, project_id, base_sha, builder_identity, allowed_paths, required_tests,
    timeout_seconds, idempotency_key and a nonnegative integer budget map. Start
    with a clean checkout at base_sha. Worker output is limited to 256 KiB and
    all descendants must be reaped using the artifact runner's containment.
    This helper never evaluates or promotes its output. It is not a sandbox for
    hostile workers; use separately isolated identities for that deployment.
    """
    workspace = Path(workspace).resolve(strict=True)
    contract_path = Path(contract_path).resolve(strict=True)
    contract_bytes = contract_path.read_bytes()
    contract = _json(contract_path)
    allowed = contract.get("allowed_paths")
    def safe_scope(path: Any) -> bool:
        if not isinstance(path, str) or not path or "\x00" in path:
            return False
        parts = (path[:-1] if path.endswith("/") else path).split("/")
        return all(part not in {"", ".", ".."} for part in parts)

    if not isinstance(allowed, list) or not allowed or not all(map(safe_scope, allowed)):
        raise ValueError("worker contract needs scoped allowed_paths")
    for name in ("task_id", "project_id", "idempotency_key"):
        if not isinstance(contract.get(name), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", contract[name]):
            raise ValueError("worker contract requires safe task/project/idempotency identifiers")
    budget = contract.get("budget")
    if not isinstance(budget, dict) or not budget or any(
        not isinstance(name, str) or not name or type(value) is not int or value < 0
        for name, value in budget.items()
    ):
        raise ValueError("worker contract requires an explicit nonnegative integer budget")
    if contract.get("builder_identity") != "hermes-" + contract["project_id"]:
        raise ValueError("worker identity must match its producer project")
    timeout = contract.get("timeout_seconds")
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError("local worker timeout must be 1..300 seconds")
    if isinstance(worker_command, (str, bytes)) or not worker_command or any(
        not isinstance(part, str) or not part or "\x00" in part for part in worker_command
    ):
        raise ValueError("worker_command must be a nonempty argument sequence")
    if _git(workspace, "rev-parse", "HEAD") != contract["base_sha"] or _git(
        workspace, "status", "--porcelain", "--untracked-files=all",
    ):
        raise ValueError("worker must start clean at the frozen contract base")
    before = inventory(workspace)
    with tempfile.TemporaryDirectory(prefix="grapher-worker-home-") as home:
        return_code, output = _run_bounded_test_command(
            workspace, shlex.join(worker_command), {**_environment(), "HOME": home},
            timeout, 256 * 1024,
        )
    if return_code != 0:
        raise PermissionError("trusted local worker returned a nonzero exit status")
    if contract_path.read_bytes() != contract_bytes:
        raise PermissionError("worker changed its frozen contract")
    denied = violations(before, inventory(workspace), allowed)
    # Filesystem content inventory also covers untracked files. Git's diff
    # supplies tracked mode-only changes, which content hashes cannot see.
    changed_paths = _run([
        "git", "-C", str(workspace), "diff", "--no-renames", "--name-only", "-z", "HEAD",
    ]).stdout.split("\x00")
    denied.extend(path for path in changed_paths if path and not is_allowed(path, allowed))
    if denied:
        raise PermissionError("worker changed paths outside allowed_paths")
    with tempfile.TemporaryDirectory(prefix="grapher-path-check-") as temporary:
        path_check = Path(temporary) / "path-check.json"
        _write_json(path_check, {"valid": True, "violations": denied})
        result = build(workspace, contract_path, path_check, Path(output_dir), attempt_number)
        result["worker_execution"] = {
            "command_sha256": hashlib.sha256(canonical(list(worker_command))).hexdigest(),
            "exit_code": return_code, "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_bytes": len(output), "idempotency_key": contract["idempotency_key"],
            "budget": budget, "timeout_seconds": timeout,
        }
        return result


@contextmanager
def _workspace_lock(root: Path):
    if root.is_symlink():
        raise ValueError("workflow workspace must not be a symlink")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(root / ".workflow.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def _initialize(root: Path, failure: str | None) -> None:
    if any(path.name != ".workflow.lock" for path in root.iterdir()):
        raise ValueError("new workflow requires an empty dedicated workspace")
    repo = root / "canonical"
    repo.mkdir(mode=0o700)
    _git(repo, "init", "--quiet")
    _git(repo, "config", "core.hooksPath", os.devnull)
    _git(repo, "config", "user.name", "Local developer fixture")
    _git(repo, "config", "user.email", "local@example.invalid")
    (repo / "src").mkdir()
    (repo / "tests").mkdir()
    (repo / "src/greeting.py").write_text(BASE_SOURCE)
    (repo / "tests/check_greeting.py").write_text(REQUIRED_TEST)
    _git(repo, "add", ".")
    _git(repo, "commit", "--quiet", "-m", "Local greeting baseline")
    baseline = _git(repo, "rev-parse", "HEAD")
    _write_json(root / "task-policy.json", POLICY)
    policy = load_task_policy(root / "task-policy.json")
    private = root / ".evaluator-private"
    private.mkdir(mode=0o700)
    _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private / "key.pem")])
    os.chmod(private / "key.pem", 0o600)
    _run(["openssl", "pkey", "-in", str(private / "key.pem"), "-pubout",
          "-out", str(root / "evaluator-public.pem")])
    required = [_python_command('from pathlib import Path; exec(Path("tests/check_greeting.py").read_text())')]
    contract = {
        "task_id": TASK, "project_id": "oss", "base_sha": baseline,
        "builder_identity": OWNER, "allowed_paths": ["src/greeting.py"],
        "required_tests": required, "timeout_seconds": 30,
        "idempotency_key": "greeting-worker-v1", "budget": {"model_calls": 0},
    }
    _write_json(root / "task-contract.json", contract)
    _write_json(root / "binding.json", {"repo": "local-greeting", "base_sha": baseline})
    os.chmod(root / "binding.json", 0o440)
    (root / "evidence").mkdir(mode=0o700)
    apply_database(root / "graph.sqlite")
    graph = ProjectGraph(root / "graph.sqlite", root / "evaluator-public.pem",
                         policy.sha256, evaluation_policy=policy)
    try:
        graph.create_goal(GOAL, "opensource", "Normalize names in local greetings", baseline,
                          idempotency_key="local-developer-lifecycle-v1")
        graph.add_node(TASK, GOAL, "BUILD", {
            "acceptance": ["Preserve names, strip boundary whitespace, greet empty names as world"],
            "evaluator_contract_id": CONTRACT, "required_tests": required,
            "task_contract_sha256": sha256_file(root / "task-contract.json"),
            "timeout_seconds": 30, "budget": {"model_calls": 0},
        }, ["src/greeting.py"])
        graph.add_node(SUCCESSOR, GOAL, "TEST", {
            "acceptance": ["Read the accepted immutable generation"],
            "evaluator_contract_id": "consume-greeting-v1", "timeout_seconds": 30,
            "budget": {"model_calls": 0},
        }, ["reports/"], [TASK])
    finally:
        graph.connection.close()
    _write_json(root / "workflow.json", {
        "schema_version": 1, "baseline_sha": baseline,
        "policy_sha256": policy.sha256, "failure": failure,
    })


def _configuration(root: Path):
    record = _json(root / "workflow.json")
    if set(record) != {"schema_version", "baseline_sha", "policy_sha256", "failure"} or record["schema_version"] != 1:
        raise ValueError("unsupported local workflow configuration")
    policy = load_task_policy(root / "task-policy.json")
    if policy.sha256 != record["policy_sha256"] or _json(root / "task-policy.json") != POLICY:
        raise PermissionError("sample task policy changed")
    if record["failure"] not in {None, "required-test", "evaluator"}:
        raise ValueError("unknown sample failure mode")
    return record, policy


def _coordinator(root: Path, graph: ProjectGraph, policy) -> ProjectCoordinator:
    spec = json.loads(graph.get_node(TASK)["spec_json"])
    if spec["task_contract_sha256"] != sha256_file(root / "task-contract.json"):
        raise PermissionError("frozen worker contract changed")
    integrator = ProjectIntegrator(
        root / "canonical", root / "binding.json", root / "evaluator-public.pem",
        root / "task-policy.json", "refs/ai-ops/accepted/opensource", evaluation_policy=policy,
    )
    coordinator = ProjectCoordinator(graph, integrator, root / "evidence", "oss")
    coordinator.assert_publication_integrity()
    return coordinator


def _ingest(root: Path, graph: ProjectGraph) -> None:
    node = graph.get_node(TASK)
    contract = _json(root / "task-contract.json")
    artifact = EvidenceIngress(root / "worker-output", root / "evidence").ingest(
        expected_task_id=TASK, expected_attempt=node["attempt"],
        expected_project_id="oss", expected_base_sha=node["base_sha"],
        expected_contract_sha256=sha256_file(root / "task-contract.json"),
        expected_required_tests=contract["required_tests"],
    )
    graph.record_ingressed_evidence(TASK, node["version"], artifact)


def _build_sample(root: Path, graph: ProjectGraph, failure: str | None) -> None:
    row = graph.get_node(TASK)
    leased = graph.lease(TASK, row["version"], OWNER, ttl_seconds=600)
    graph.start(TASK, leased["version"], leased["lease_id"], OWNER)
    worker = root / "worker"
    _run(["git", "clone", "--quiet", "--no-hardlinks", str(root / "canonical"), str(worker)])
    _git(worker, "config", "core.hooksPath", os.devnull)
    source = FIXED_SOURCE
    if failure == "required-test":
        source = 'def greet(name):\n    return "broken"\n'
    elif failure == "evaluator":
        source = 'def greet(name):\n    return "Hello, " + name.strip() + "!"\n'
    worker_code = "from pathlib import Path; Path('src/greeting.py').write_text(" + repr(source) + ")"
    try:
        produced = produce_worker_artifact(worker, root / "task-contract.json", root / "worker-output",
                                          leased["attempt"], [sys.executable, "-I", "-B", "-c", worker_code])
        _write_json(root / "worker-execution.json", produced["worker_execution"])
        _ingest(root, graph)
    except (PermissionError, subprocess.SubprocessError, ValueError):
        row = graph.get_node(TASK)
        graph.transition(TASK, row["version"], "FAILED_GATE", "local artifact production failed")
        if failure != "required-test":
            raise


def _artifact(root: Path, graph: ProjectGraph) -> tuple[dict[str, Any], Path]:
    node = graph.get_node(TASK)
    raw = graph.connection.execute(
        "SELECT * FROM evidence_artifacts WHERE artifact_id=?", (node["active_artifact_id"],),
    ).fetchone()
    if raw is None:
        raise ValueError("task has no immutable artifact")
    artifact = dict(raw)
    manifest = resolve_manifest(root / "evidence", artifact["manifest_relative_path"], artifact["manifest_sha256"])
    value = _json(manifest)
    validate_manifest_v4(
        value, manifest.parent, expected_task_id=TASK, expected_attempt=artifact["attempt"],
        expected_project_id="oss", expected_base_sha=artifact["base_sha"],
        expected_contract_sha256=sha256_file(root / "task-contract.json"),
        expected_required_tests=_json(root / "task-contract.json")["required_tests"],
    )
    if value["candidate_sha"] != artifact["candidate_sha"]:
        raise PermissionError("artifact candidate differs from its recorded Git binding")
    return artifact, manifest


def _evaluate_sample(root: Path) -> None:
    """Evaluator process: independently reconstruct and test before signing."""
    record, policy = _configuration(root)
    request = _json(root / "evaluation-request.json")
    digest = request["artifact_id"].removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise PermissionError("invalid evaluation artifact ID")
    manifest_path = resolve_manifest(root / "evidence", f"sha256/{digest[:2]}/{digest}/manifest.json", digest)
    manifest = _json(manifest_path)
    contract = _json(root / "task-contract.json")
    validate_manifest_v4(
        manifest, manifest_path.parent, expected_task_id=TASK, expected_attempt=1,
        expected_project_id="oss", expected_base_sha=record["baseline_sha"],
        expected_contract_sha256=sha256_file(root / "task-contract.json"),
        expected_required_tests=contract["required_tests"],
    )
    with tempfile.TemporaryDirectory(prefix="grapher-independent-evaluation-") as temporary:
        temporary = Path(temporary)
        candidate = temporary / "candidate"
        _run(["git", "clone", "--quiet", "--no-hardlinks", str(root / "canonical"), str(candidate)])
        _git(candidate, "config", "core.hooksPath", os.devnull)
        _git(candidate, "fetch", "--quiet", str(manifest_path.parent / manifest["bundle"]["path"]), "HEAD")
        _git(candidate, "checkout", "--detach", "--quiet", manifest["candidate_sha"])
        if _git(candidate, "rev-list", "--parents", "-n", "1", "HEAD").split() != [manifest["candidate_sha"], record["baseline_sha"]]:
            raise PermissionError("evaluator candidate is not one commit above the baseline")
        changed = _git(candidate, "diff", "--no-renames", "--name-only", "-z", record["baseline_sha"], "HEAD").split("\x00")
        if not any(changed) or any(path and not is_allowed(path, ["src/greeting.py"]) for path in changed):
            raise PermissionError("evaluator rejected candidate write scope")
        checks = temporary / "checks"
        checks.mkdir()
        results = produce_required_test_results(candidate, [_python_command(INDEPENDENT_TEST)],
                                                manifest["candidate_sha"], checks, timeout_seconds=30)
        output = (checks / results[0]["output"]["path"]).read_text()
        if output != "6 independent greeting assertions passed\n":
            raise PermissionError("independent evaluator output was not the acceptance result")
        # Full points mean all six declared local assertions passed. No release
        # section or HG1-HG11 is fabricated by this task-specific evaluator.
        value = {
            "schema_version": 4, "policy_sha256": policy.sha256,
            "evaluation_id": "local-greeting-evaluation-v1", "task_id": TASK,
            "contract_id": CONTRACT, "artifact_id": request["artifact_id"],
            "claim_id": request["claim_id"], "evaluated_git_sha": manifest["candidate_sha"],
            "evidence_manifest_sha256": digest, "rubric_sha256": policy.sha256,
            "section_scores": {"correctness": 100},
            "mandatory_gates": {name: "PASS" for name in POLICY["mandatory_gates"]},
            "total_score": 100, "verdict": "PASS", "evaluator_identity": "hermes-evaluator",
            "previous_ledger_hash": request["previous_ledger_hash"],
        }
        value["ledger_hash"] = evaluation_ledger_hash(value)
        message = temporary / "message.json"
        message.write_bytes(canonical(value))
        signature = temporary / "signature.bin"
        _run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
              str(root / ".evaluator-private/key.pem"), "-in", str(message), "-out", str(signature)])
        value["signature"] = base64.b64encode(signature.read_bytes()).decode("ascii")
        _write_json(root / "evaluation.json", value)
        _write_json(root / "evaluator-checks.json", {
            "candidate_sha": manifest["candidate_sha"], "assertions": 6,
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            "process_id": os.getpid(), "scope": "local task acceptance only",
        })


def _evaluate(root: Path, graph: ProjectGraph) -> None:
    artifact, manifest = _artifact(root, graph)
    node = graph.get_node(TASK)
    if node["state"] == "EVIDENCE_PENDING":
        claimed = graph.claim_evidence(TASK, node["version"], artifact["artifact_id"], "hermes-evaluator", 600)
        node, artifact = claimed["node"], claimed["artifact"]
    elif node["state"] == "EVALUATING":
        claim = graph.connection.execute("SELECT expires_at FROM evaluation_claims WHERE claim_id=?", (artifact["claim_id"],)).fetchone()
        if claim is None:
            raise PermissionError("evaluating artifact has no active claim")
        if dt.datetime.fromisoformat(claim[0]) <= dt.datetime.now(dt.timezone.utc):
            claimed = graph.claim_evidence(TASK, node["version"], artifact["artifact_id"], "hermes-evaluator", 600)
            node, artifact = claimed["node"], claimed["artifact"]
        else:
            graph.heartbeat_evidence_claim(TASK, node["version"], artifact["artifact_id"], artifact["claim_id"], "hermes-evaluator", 600)
    previous = graph.connection.execute("SELECT ledger_hash FROM evaluation_ledger ORDER BY sequence DESC LIMIT 1").fetchone()
    request = {
        "artifact_id": artifact["artifact_id"], "claim_id": artifact["claim_id"],
        "previous_ledger_hash": previous[0] if previous else None,
    }
    result_path = root / "evaluation.json"
    if result_path.exists():
        result = _json(result_path)
        if all(result.get(name) == value for name, value in request.items()):
            # A completed evaluator response is replayed byte-for-byte. Core
            # signature verification detects tampering before graph admission.
            graph.record_evaluation(TASK, node["version"], artifact["artifact_id"], result, manifest)
            return
        # Only a verifiably expired older claim permits a fresh evaluation.
        old = graph.connection.execute("SELECT status FROM evaluation_claims WHERE claim_id=? AND artifact_id=?", (result.get("claim_id"), artifact["artifact_id"])).fetchone()
        if old is None or old[0] != "EXPIRED":
            raise PermissionError("saved evaluator result conflicts with the active claim")
        history = root / "expired-evaluations"
        history.mkdir(mode=0o700, exist_ok=True)
        historical = history / (sha256_file(result_path) + ".json")
        if historical.exists() and historical.read_bytes() != result_path.read_bytes():
            raise PermissionError("historical evaluator response changed")
        if not historical.exists():
            _write_json(historical, result)
        result_path.unlink()
    _write_json(root / "evaluation-request.json", request)
    environment = {**_environment(), "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    try:
        _run([sys.executable, "-B", "-m", "control_plane.local_workflow", "_evaluate", str(root)],
             environment=environment, timeout=90)
    except subprocess.CalledProcessError:
        graph.reject_evidence(TASK, node["version"], artifact["artifact_id"], "FAILED_GATE",
                              hashlib.sha256(b"independent local acceptance assertions failed").hexdigest(), "hermes-evaluator")
        return
    graph.record_evaluation(TASK, node["version"], artifact["artifact_id"], _json(root / "evaluation.json"), manifest)


def _integrate(root: Path, graph: ProjectGraph, coordinator: ProjectCoordinator, crash_at: str | None) -> None:
    artifact, manifest = _artifact(root, graph)
    outcome = graph.connection.execute("SELECT outcome_id FROM evaluation_outcomes WHERE node_id=?", (TASK,)).fetchone()
    if outcome is None:
        raise ValueError("task has no signed independent outcome")

    def crash_hook(point: str) -> None:
        if point == crash_at:
            os._exit(86)  # Intentional explicit fault injection; no Python cleanup.

    coordinator.integrate(ATTEMPT, TASK, outcome[0], artifact["artifact_id"], manifest,
                          "oss", root / "evidence", crash_hook=crash_hook)


def _consume(root: Path, graph: ProjectGraph, coordinator: ProjectCoordinator) -> dict[str, Any]:
    successor = graph.get_node(SUCCESSOR)
    if successor["state"] != "READY":
        raise RuntimeError("successor was not released by integration")
    pin = coordinator.integrator.publications.pin_binding(
        root / "binding.json", expected_repo="local-greeting", expected_base_sha=successor["base_sha"],
    )
    # Execute a distinct consumer against its graph-assigned accepted generation.
    result = _run([sys.executable, "-I", "-B", "-c",
                   'import sys; from pathlib import Path; sys.path.insert(0, str(Path.cwd()/"src")); '
                   'from greeting import greet; print(greet("  Ada  "))'], cwd=pin.path)
    if result.stdout != "Hello, Ada!\n":
        raise RuntimeError("successor could not consume the accepted candidate")
    return {"node_id": SUCCESSOR, "base_sha": pin.base_sha, "output": result.stdout.strip()}


def _summary(root: Path, graph: ProjectGraph, coordinator: ProjectCoordinator, record: dict) -> dict[str, Any]:
    coordinator.assert_publication_integrity()
    node = graph.get_node(TASK)
    artifact = _artifact(root, graph)[0] if node["active_artifact_id"] else None
    binding = _json(root / "binding.json")
    rollback = graph.connection.execute(
        "SELECT 1 FROM publication_journal WHERE operation_id=? AND phase='COMPLETED'", (ROLLBACK,),
    ).fetchone()
    pending = graph.connection.execute("SELECT status FROM integration_attempts WHERE attempt_id=?", (ATTEMPT,)).fetchone()
    states = {"EVIDENCE_PENDING": "built", "EVALUATING": "evaluating", "PASSED": "evaluated",
              "INTEGRATED": "promoted", "FAILED_GATE": "failed"}
    state = "rolled_back" if rollback else states.get(node["state"], node["state"].lower())
    if (pending and pending[0] != "COMPLETED") or coordinator.pending_rollbacks():
        state = "recovery_required"
    outcome = graph.connection.execute("SELECT outcome_id FROM evaluation_outcomes WHERE node_id=?", (TASK,)).fetchone()
    return {
        "workspace": str(root), "workflow_state": state, "task_state": node["state"],
        "task_verdict": "PASS" if outcome else "NOT_PASS" if state == "failed" else "PENDING",
        "release_verdict": "NOT_PASS", "scope": "trusted local development; same-UID roles are not an OS sandbox",
        "integrity_verified": True, "baseline_sha": record["baseline_sha"],
        "accepted_sha": binding["base_sha"],
        "candidate_sha": artifact["candidate_sha"] if artifact else node["result_sha"],
        "artifact_id": node["active_artifact_id"], "outcome_id": outcome[0] if outcome else None,
        "database": str(root / "graph.sqlite"), "task_policy": str(root / "task-policy.json"),
        "publication_journal_entries": graph.connection.execute("SELECT count(*) FROM publication_journal").fetchone()[0],
        "next_step": "inspect failure and use a new workspace" if state == "failed" else
                     "run recover" if state == "recovery_required" else
                     "run rollback or inspect status" if state == "promoted" else
                     "historical accepted generation retained" if state == "rolled_back" else "run to continue",
    }


def run_local_workflow(
    directory: Path | None = None, *, operation: str = "run", stop_after: str | None = None,
    failure: str | None = None, crash_at: str | None = None,
) -> dict[str, Any]:
    """Run/reopen the sample or explicitly recover, inspect, or roll it back.

    A supplied directory persists across invocations. Without one, run uses a
    temporary workspace which is removed after returning. Intentional crash
    injection requires persistent storage. Recovery never repeats a worker whose
    execution was interrupted before immutable artifact publication.
    """
    if operation not in {"run", "recover", "rollback", "status"}:
        raise ValueError("unknown lifecycle operation")
    if stop_after not in {None, "built", "evaluated", "promoted"}:
        raise ValueError("unknown lifecycle stop stage")
    if failure not in {None, "required-test", "evaluator"} or crash_at not in {None, "after_binding"}:
        raise ValueError("unknown lifecycle failure injection")
    if operation != "run" and (failure or stop_after or crash_at):
        raise ValueError("stage/failure options apply only to run")
    if directory is None:
        if operation != "run" or crash_at:
            raise ValueError("this operation requires a persistent --workspace")
        with tempfile.TemporaryDirectory(prefix="codex-grapher-lifecycle-") as temporary:
            result = run_local_workflow(Path(temporary), stop_after=stop_after, failure=failure)
            result["workspace_persistent"] = False
            result["next_step"] = "rerun with --workspace PATH to retain evidence and exercise recovery"
            return result
    root = Path(os.path.abspath(directory))
    if operation != "run" and not (root / "workflow.json").is_file():
        raise ValueError("workspace has no initialized workflow")
    if operation == "status":
        from control_plane.cli import read_only_graph
        record, policy = _configuration(root)
        with read_only_graph(root / "graph.sqlite", evaluator_public_key=root / "evaluator-public.pem",
                             rubric_sha256=policy.sha256, evaluation_policy=policy) as graph:
            result = _summary(root, graph, _coordinator(root, graph, policy), record)
            result["workspace_persistent"] = True
            return result
    with _workspace_lock(root):
        if not (root / "workflow.json").exists():
            if operation != "run":
                raise ValueError("workspace has no initialized workflow")
            _initialize(root, failure)
        record, policy = _configuration(root)
        if failure is not None and failure != record["failure"]:
            raise ValueError("failure scenario cannot change on replay")
        graph = ProjectGraph(root / "graph.sqlite", root / "evaluator-public.pem",
                             policy.sha256, evaluation_policy=policy)
        try:
            coordinator = _coordinator(root, graph, policy)
            if operation == "rollback":
                # Fixed operation identity also fixes the original head CAS for replay.
                coordinator.rollback(ROLLBACK, TASK, ATTEMPT, expected_head_version=1)
            else:
                for rollback_id in coordinator.pending_rollbacks():
                    coordinator.reconcile_rollback(rollback_id)
                node = graph.get_node(TASK)
                if node["state"] == "READY":
                    if operation == "recover":
                        raise ValueError("no interrupted operation to recover; use run")
                    _build_sample(root, graph, record["failure"])
                elif node["state"] in {"LEASED", "RUNNING"}:
                    manifest = root / "worker-output" / TASK / f"attempt-{node['attempt']}" / "manifest.json"
                    if node["state"] == "RUNNING" and manifest.is_file():
                        _ingest(root, graph)
                    else:
                        raise RuntimeError("worker interrupted before immutable evidence; inspect before retrying in a new workspace")
                node = graph.get_node(TASK)
                if stop_after != "built" and node["state"] in {"EVIDENCE_PENDING", "EVALUATING"}:
                    _evaluate(root, graph)
                node = graph.get_node(TASK)
                rolled_back = graph.connection.execute("SELECT 1 FROM publication_journal WHERE operation_id=?", (ROLLBACK,)).fetchone()
                if stop_after not in {"built", "evaluated"} and node["state"] in {"PASSED", "INTEGRATING", "INTEGRATED"} and not rolled_back:
                    _integrate(root, graph, coordinator, crash_at)
            result = _summary(root, graph, coordinator, record)
            if result["workflow_state"] == "promoted":
                result["successor_consumed"] = _consume(root, graph, coordinator)
            result["workspace_persistent"] = True
            return result
        finally:
            graph.connection.close()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) == 2 and arguments[0] == "_evaluate":
        _evaluate_sample(Path(arguments[1]))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--operation", choices=["run", "recover", "status", "rollback"], default="run")
    parser.add_argument("--stop-after", choices=["built", "evaluated", "promoted"])
    parser.add_argument("--failure", choices=["required-test", "evaluator"])
    parser.add_argument("--crash-at", choices=["after_binding"])
    args = parser.parse_args(arguments)
    result = run_local_workflow(args.workspace, operation=args.operation, stop_after=args.stop_after,
                                failure=args.failure, crash_at=args.crash_at)
    print(json.dumps(result, indent=2))
    return 3 if result["workflow_state"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
