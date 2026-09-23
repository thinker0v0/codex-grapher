"""Frozen own-repository tasks using the existing graph authority.

Candidate code runs only through the provider and test broker. This module owns
Git snapshots, launch reservations, graph admission and identifier-only promotion.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Callable

from control_plane.artifact_builder import build
from control_plane.evaluation_policy import load_task_policy
from control_plane.evidence_ingress import EvidenceIngress, resolve_manifest, validate_manifest_v4
from control_plane.graph_bootstrap import apply_database
from control_plane.project_coordinator import ProjectCoordinator
from control_plane.project_graph import ProjectGraph
from control_plane.project_integrator import ProjectIntegrator
from control_plane.repository_task import canonical, parse_task_bytes, parse_checks_bytes, read_regular, strict_json_bytes
from control_plane.workspace_guard import inventory, is_allowed, violations

OWNER = "hermes-oss"
WORKFLOW_FIELDS = {"kind", "version", "schema_version", "workspace", "workspace_id", "task_sha256",
    "profile_sha256", "checks_sha256", "policy_sha256", "producer_contract_sha256", "baseline_sha",
    "project_id", "task_id", "goal_id", "evaluator_contract_id", "source_inventory_sha256", "source", "files"}
FROZEN_FILES = {"frozen/task.json", "frozen/profile.json", "frozen/checks.json", "frozen/policy.json",
                "frozen/producer-contract.json", "frozen/public-key.pem"}
CRASH_POINTS = {"after_reservation", "after_artifact_admission", "after_evaluation", "after_binding", "rollback_after_binding"}


class RepositoryWorkflowError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _record(path: Path) -> dict:
    value = strict_json_bytes(read_regular(path))
    if not isinstance(value, dict):
        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "record must be an object")
    return value


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path: Path, data: bytes, *, exclusive: bool = False, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if exclusive:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    else:
        descriptor, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    _sync_directory(path.parent)


def _write_json(path: Path, value: Any, *, exclusive: bool = False) -> None:
    _write(path, canonical(value) + b"\n", exclusive=exclusive)


def _root(path: Path, *, exists: bool = True) -> Path:
    raw = Path(os.path.abspath(path))
    if any(part.is_symlink() for part in [raw, *raw.parents]):
        raise ValueError("workspace/source path has a symlink component")
    if exists and not raw.is_dir():
        raise ValueError("workspace/source must be an existing directory")
    return raw


@contextmanager
def workspace_lock(root: Path, *, create: bool = False):
    """One maintenance barrier used by every workflow mutator and backup."""
    root = _root(root, exists=not create)
    if create:
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        (root / "state").mkdir(exist_ok=True, mode=0o700)
    _root(root / "state")
    flags = os.O_RDWR if create else os.O_RDONLY
    if create:
        flags |= os.O_CREAT
    descriptor = os.open(root / "state/.workflow.lock", flags | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("unsafe workspace lock")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RepositoryWorkflowError("BACKUP_NOT_QUIESCENT", "workspace owner is active") from exc
        yield
    finally:
        os.close(descriptor)


def _environment() -> dict[str, str]:
    return {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file", "PYTHONDONTWRITEBYTECODE": "1"}


def _git(repo: Path, *args: str, executable: str = "git") -> str:
    result = subprocess.run([executable, "-c", "safe.directory=" + str(repo), "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false", "-c", "core.untrackedCache=false",
        "-C", str(repo), *args], env=_environment(), capture_output=True, text=True, check=True, timeout=60)
    return result.stdout.strip()


def _tree_inventory(root: Path) -> dict[str, Any]:
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            metadata = path.lstat()
            item = {"mode": stat.S_IMODE(metadata.st_mode), "type": stat.S_IFMT(metadata.st_mode)}
            if stat.S_ISLNK(metadata.st_mode):
                item["target"] = os.readlink(path)
            elif stat.S_ISREG(metadata.st_mode):
                item["sha256"] = _hash(path.read_bytes())
                item["bytes"] = metadata.st_size
            elif not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("repository contains a special filesystem entry")
            result[path.relative_to(root).as_posix()] = item
    return result


def _snapshot_repository(source: Path, target: Path, base: str, git: str) -> None:
    """Copy only object storage, then reconstruct tracked files with clean config.

    Source config, hooks, refs, index, remotes and reflogs are never imported.
    Source .git must be self-contained; no worktree/alternates/partial clone.
    """
    objects = source / ".git/objects"
    if objects.is_symlink() or not objects.is_dir() or (source / ".git/objects/info/alternates").exists():
        raise ValueError("source repository has external object storage")
    for path in objects.rglob("*"):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError("unsafe source object storage")
        if path.is_file() and path.name.endswith(".promisor"):
            raise ValueError("partial clone object storage is unsupported")
    target.mkdir(mode=0o700)
    _git(target, "-c", "init.templateDir=", "init", "--quiet", executable=git)
    shutil.copytree(objects, target / ".git/objects", dirs_exist_ok=True)
    _git(target, "config", "core.hooksPath", os.devnull, executable=git)
    _git(target, "fsck", "--full", "--no-reflogs", executable=git)
    _git(target, "checkout", "--quiet", "--detach", base, executable=git)
    if _git(target, "status", "--porcelain", "--untracked-files=all", executable=git):
        raise ValueError("owned snapshot is dirty")


def _profile(path: Path):
    from control_plane.execution_profile import load_execution_profile
    return load_execution_profile(path, verify_tools=True, require_private_key=False)


def _sqlite_options(profile) -> dict[str, Any]:
    config = profile.raw["sqlite"]
    return {"sqlite_profile": config["profile"], "sqlite_attestation": config["attestation"]}


def _producer_contract(task: dict) -> dict:
    return {"task_id": task["task_id"], "project_id": "oss", "base_sha": task["base_sha"],
        "builder_identity": OWNER, "allowed_paths": task["allowed_paths"], "required_tests": task["required_tests"],
        "timeout_seconds": task["limits"]["required_test_timeout_seconds"], "idempotency_key": task["idempotency_key"],
        "budget": {"model_calls": task["limits"]["worker_invocations"]}}


def _configuration(root: Path, *, original_root: Path | None = None):
    record = _record(root / "workflow.json")
    if set(record) != WORKFLOW_FIELDS or record["kind"] != "repository-workflow" or any(
        type(record[key]) is not int or record[key] != 1 for key in ("version", "schema_version")
    ):
        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "unknown repository workflow kind/version")
    if record["workspace"] != str(original_root or root):
        raise RepositoryWorkflowError("CONFIG_CHANGED", "workspace relocation is unsupported")
    if not isinstance(record["files"], dict) or set(record["files"]) != FROZEN_FILES:
        raise RepositoryWorkflowError("CONFIG_CHANGED", "frozen inventory differs")
    for relative, digest in record["files"].items():
        if _hash(read_regular(root / relative)) != digest:
            raise RepositoryWorkflowError("CONFIG_CHANGED", "frozen input changed: " + relative)
    task = parse_task_bytes(read_regular(root / "frozen/task.json"))
    if _record(root / "frozen/producer-contract.json") != _producer_contract(task):
        raise RepositoryWorkflowError("CONFIG_CHANGED", "producer contract differs from the frozen public task")
    checks = parse_checks_bytes(read_regular(root / "frozen/checks.json"))
    profile = _profile(root / "frozen/profile.json")
    policy = load_task_policy(root / "frozen/policy.json")
    identities = {"task_sha256": record["files"]["frozen/task.json"], "profile_sha256": profile.sha256,
        "checks_sha256": record["files"]["frozen/checks.json"], "policy_sha256": policy.sha256,
        "producer_contract_sha256": record["files"]["frozen/producer-contract.json"],
        "baseline_sha": task["base_sha"], "task_id": task["task_id"], "project_id": task["project_id"],
        "goal_id": "repository-" + task["task_id"], "evaluator_contract_id": task["task_id"] + "-acceptance-v1"}
    if any(record[key] != value for key, value in identities.items()):
        raise RepositoryWorkflowError("CONFIG_CHANGED", "workflow identity differs from frozen inputs")
    descriptor = {key: record[key] for key in ("workspace", "task_sha256", "profile_sha256", "checks_sha256", "policy_sha256")}
    if _hash(canonical(descriptor)) != record["workspace_id"]:
        raise RepositoryWorkflowError("CONFIG_CHANGED", "workspace identity differs")
    if _hash(read_regular(Path(profile.paths["signer_public_key"]))) != record["files"]["frozen/public-key.pem"]:
        raise RepositoryWorkflowError("CONFIG_CHANGED", "configured signer public key changed")
    return record, task, checks, profile, policy


def load_frozen_task(root: Path) -> dict:
    return _configuration(_root(root))[1]


def _coordinator(root: Path, graph: ProjectGraph, record: dict, policy, *, verification_owner_uid: int | None = None) -> ProjectCoordinator:
    spec = json.loads(graph.get_node(record["task_id"])["spec_json"])
    expected = {"task_contract_sha256": record["producer_contract_sha256"], "public_task_sha256": record["task_sha256"],
        "execution_profile_sha256": record["profile_sha256"], "checks_sha256": record["checks_sha256"]}
    if any(spec.get(key) != value for key, value in expected.items()):
        raise RepositoryWorkflowError("CONFIG_CHANGED", "graph node has different frozen authority")
    integrator = ProjectIntegrator(root / "canonical", root / "state/binding.json", root / "frozen/public-key.pem",
        root / "frozen/policy.json", "refs/ai-ops/accepted/opensource", evaluation_policy=policy,
        publication_root=root / "publications", verification_owner_uid=verification_owner_uid)
    coordinator = ProjectCoordinator(graph, integrator, root / "evidence", "oss")
    coordinator.assert_publication_integrity()
    return coordinator


def initialize_repository_workflow(source: Path, task_path: Path, root: Path, profile: Path) -> dict:
    source, root = _root(source), _root(root, exists=False)
    if source == root or source in root.parents or root in source.parents:
        raise ValueError("source and workspace must not overlap")
    task_path = Path(task_path).absolute()
    raw_task, raw_profile = read_regular(task_path), read_regular(Path(profile))
    task, execution = parse_task_bytes(raw_task), _profile(Path(profile))
    if execution.mode == "isolated-linux":
        from control_plane.isolated_runner import workspace_socket_paths
        workspace_socket_paths(root)
    policy_path = task_path.parent / task["evaluation"]["policy"]
    checks_path = task_path.parent / task["evaluation"]["checks"]
    raw_policy, raw_checks = read_regular(policy_path), read_regular(checks_path)
    policy, checks = load_task_policy(policy_path), parse_checks_bytes(raw_checks)
    public_key = read_regular(Path(execution.paths["signer_public_key"]))
    # Checks may execute only pinned tools. External scripts are not frozen by
    # an argv hash, so this first public contract requires inline Python checks.
    python = execution.tools["python"].path
    for check in checks["checks"]:
        argv = check["argv"]
        if argv[0] != python or "-c" not in argv or argv.index("-c") != len(argv) - 2:
            raise ValueError("independent checks require pinned Python with frozen inline -c code")
        if any(flag not in {"-I", "-B", "-S", "-E", "-s"} for flag in argv[1:-2]):
            raise ValueError("independent check interpreter flags are unsupported")
    if not (source / ".git").is_dir() or (source / ".git").is_symlink():
        raise ValueError("source requires self-contained .git directory")
    git = execution.tools["git"].path
    before = _tree_inventory(source)
    try:
        if _git(source, "rev-parse", "--show-toplevel", executable=git) != str(source):
            raise ValueError("source must be the repository root")
        if _git(source, "rev-parse", "HEAD", executable=git) != task["base_sha"]:
            raise ValueError("task base differs from source HEAD")
        # Source-local filters are executable authority. Run cleanliness checks
        # with newly created Git metadata, never the source's configuration.
        with tempfile.TemporaryDirectory(prefix="grapher-source-inspection-") as temporary:
            inspection = Path(temporary) / "repository"
            _snapshot_repository(source, inspection, task["base_sha"], git)
            source_index = source / ".git/index"
            if source_index.is_symlink() or not source_index.is_file():
                raise ValueError("source index must be a regular file")
            shutil.copyfile(source_index, inspection / ".git/index")
            if _git(inspection, "write-tree", executable=git) != _git(inspection, "rev-parse", task["base_sha"] + "^{tree}", executable=git):
                raise ValueError("source must be clean, including its staged index")
            # Never inherit assume-unchanged/skip-worktree bits or cached stat
            # data when proving the source worktree matches the exact commit.
            (inspection / ".git/index").unlink()
            _git(inspection, "read-tree", task["base_sha"], executable=git)
            dirty = _git(inspection, "--work-tree=" + str(source), "status", "--porcelain", "--untracked-files=all", executable=git)
            if dirty:
                raise ValueError("source must be clean, including untracked files")
            tree = _git(inspection, "ls-tree", "-r", "-z", task["base_sha"], executable=git)
        if any(item.startswith(("120000 ", "160000 ")) for item in tree.split("\x00")):
            raise ValueError("source symlinks and submodules are unsupported")
        with workspace_lock(root, create=True):
            if any(path.name != "state" for path in root.iterdir()) or any(path.name != ".workflow.lock" for path in (root / "state").iterdir()):
                raise ValueError("initialization requires an empty dedicated workspace")
            frozen = {"task.json": raw_task, "profile.json": raw_profile, "policy.json": raw_policy,
                "checks.json": raw_checks, "public-key.pem": public_key}
            contract = _producer_contract(task)
            frozen["producer-contract.json"] = canonical(contract) + b"\n"
            for name, data in frozen.items():
                _write(root / "frozen" / name, data, exclusive=True, mode=0o440)
            _snapshot_repository(source, root / "canonical", task["base_sha"], git)
            for name in ("evidence", "attempts", "worker-output", "publications"):
                (root / name).mkdir(mode=0o700)
            _write(root / "state/binding.json", canonical({"repo": task["project_id"], "base_sha": task["base_sha"]}) + b"\n", exclusive=True, mode=0o440)
            record = {"kind": "repository-workflow", "version": 1, "schema_version": 1, "workspace": str(root),
                "task_sha256": _hash(raw_task), "profile_sha256": execution.sha256, "checks_sha256": _hash(raw_checks),
                "policy_sha256": policy.sha256, "producer_contract_sha256": _hash(frozen["producer-contract.json"]),
                "baseline_sha": task["base_sha"], "project_id": task["project_id"], "task_id": task["task_id"],
                "goal_id": "repository-" + task["task_id"], "evaluator_contract_id": task["task_id"] + "-acceptance-v1",
                "source_inventory_sha256": _hash(canonical(before)), "source": str(source),
                "files": {"frozen/" + name: _hash(data) for name, data in frozen.items()}}
            descriptor = {key: record[key] for key in ("workspace", "task_sha256", "profile_sha256", "checks_sha256", "policy_sha256")}
            record["workspace_id"] = _hash(canonical(descriptor))
            apply_database(root / "state/graph.sqlite", **_sqlite_options(execution))
            graph = ProjectGraph(root / "state/graph.sqlite", root / "frozen/public-key.pem", policy.sha256,
                                 evaluation_policy=policy, **_sqlite_options(execution))
            try:
                graph.create_goal(record["goal_id"], "opensource", task["objective"], task["base_sha"], idempotency_key=task["idempotency_key"])
                graph.add_node(task["task_id"], record["goal_id"], "BUILD", {
                    "acceptance": task["acceptance_criteria"], "evaluator_contract_id": record["evaluator_contract_id"],
                    "required_tests": task["required_tests"], "task_contract_sha256": record["producer_contract_sha256"],
                    "public_task_sha256": record["task_sha256"], "execution_profile_sha256": record["profile_sha256"],
                    "checks_sha256": record["checks_sha256"], "timeout_seconds": task["limits"]["worker_timeout_seconds"],
                    "budget": contract["budget"], "retry_policy": {"max_attempts": task["limits"]["worker_invocations"]}}, task["allowed_paths"])
                # Initial publication materialization is trusted Git, never candidate execution.
                coordinator = _coordinator(root, graph, record, policy)
                coordinator.integrator.ensure_bound_publication()
                initialized = _summary(root, graph, coordinator, record, task)
            finally:
                graph.connection.close()
            _write_json(root / "workflow.json", record, exclusive=True)
    finally:
        if _tree_inventory(source) != before:
            raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "source repository changed during initialization")
    # Isolated bootstrap assigns the graph UID only after this root-only,
    # candidate-free initialization returns. Do not demand graph ownership early.
    return initialized


def _attempt_path(root: Path, task: dict, number: int = 1) -> Path:
    return root / "attempts" / f"{task['task_id']}-attempt-{number}"


def _worker_prompt(task: dict) -> str:
    """One fixed template reconstructed independently by the privileged broker."""
    return ("Implement this bounded repository task. Leave uncommitted edits only. Do not change Git metadata, "
        "commit, install dependencies, access other directories, or alter files outside the allowed paths.\n"
        + "Objective: " + task["objective"] + "\nAcceptance criteria: " + json.dumps(task["acceptance_criteria"], ensure_ascii=True)
        + "\nAllowed paths: " + json.dumps(task["allowed_paths"], ensure_ascii=True) + "\n")


@contextmanager
def _worker_control(root: Path, graph: ProjectGraph, task: dict, profile, attempt: Path, lease: dict, ttl: int):
    if profile.mode != "isolated-linux":
        yield
        return
    from control_plane.isolated_runner import ScopedWorkerControlServer, get_active_launcher, workspace_socket_paths
    def status():
        row = graph.get_node(task["task_id"])
        return {"task_id": task["task_id"], "attempt_id": attempt.name, "state": row["state"],
                "lease_expires_at": row["lease_expires_at"]}
    def heartbeat():
        graph.heartbeat(task["task_id"], lease["lease_id"], OWNER, ttl)
        return status()
    launcher = get_active_launcher()
    _launcher_path, control_path = workspace_socket_paths(root)
    server = ScopedWorkerControlServer(control_path,
        worker_uid=profile.roles["worker"].uid, project_id=task["project_id"], task_id=task["task_id"],
        attempt_id=attempt.name, status=status, heartbeat=heartbeat)
    prior = launcher.control_server
    launcher.control_server = server
    try:
        yield
    finally:
        launcher.control_server = prior
        server.close()


def _reservations(root: Path, record: dict) -> list[dict]:
    from control_plane.worker_provider import validate_worker_request, validate_worker_receipt
    task = parse_task_bytes(read_regular(root / "frozen/task.json"))
    profile = _profile(root / "frozen/profile.json")
    result = []
    for path in sorted((root / "attempts").glob("*/reservation.json")):
        value = _record(path)
        if set(value) != {"schema_version", "attempt_id", "attempt_number", "invocation_count", "request_sha256", "request", "reserved_at"}:
            raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "reservation fields differ")
        request = value["request"]
        if (type(value["schema_version"]) is not int or value["schema_version"] != 1
                or type(value["attempt_number"]) is not int or value["attempt_number"] != len(result) + 1
                or type(value["invocation_count"]) is not int or value["invocation_count"] != len(result) + 1
                or value["attempt_id"] != f"{record['task_id']}-attempt-{value['attempt_number']}"
                or path.parent.name != value["attempt_id"] or not isinstance(request, dict)
                or value["request_sha256"] != _hash(canonical(request))
                or request.get("attempt_id") != value["attempt_id"]
                or request.get("task_sha256") != record["task_sha256"]
                or request.get("profile_sha256") != record["profile_sha256"]
                or request.get("checkout") != str(Path(record["workspace"]) / "attempts" / value["attempt_id"] / "checkout")):
            raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "reservation identity differs")
        expected = {"schema_version": 1, "project_id": task["project_id"], "task_id": task["task_id"],
            "idempotency_key": task["idempotency_key"], "attempt_id": value["attempt_id"], "attempt_number": value["attempt_number"],
            "base_sha": task["base_sha"], "checkout": str(Path(record["workspace"]) / "attempts" / value["attempt_id"] / "checkout"),
            "task_sha256": record["task_sha256"], "profile_sha256": record["profile_sha256"], "prompt": _worker_prompt(task),
            "prompt_sha256": _hash(_worker_prompt(task).encode()),
            "limits": {key: task["limits"][key] for key in ("worker_invocations", "worker_timeout_seconds", "max_output_bytes")}}
        if request != expected:
            raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "reservation differs from frozen authority")
        # Offline backup verification may inspect a validated copy at a private
        # temporary root. Verify its local checkout without changing the frozen
        # request, its original absolute path, or its launch identity.
        checkout = _root(path.parent / "checkout")
        if not (checkout / ".git").is_dir() or (checkout / ".git").is_symlink():
            raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "reservation checkout is not self-contained")
        validate_worker_request({**request, "checkout": str(checkout)})
        receipt_path = path.parent / "worker-receipt.json"
        if receipt_path.exists():
            validate_worker_receipt(_record(receipt_path), request, profile)
        result.append(value)
    return result


def _artifact(root: Path, graph: ProjectGraph, record: dict, task: dict) -> tuple[dict, Path]:
    node = graph.get_node(task["task_id"])
    row = graph.connection.execute("SELECT * FROM evidence_artifacts WHERE artifact_id=?", (node["active_artifact_id"],)).fetchone()
    if row is None:
        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "task has no admitted artifact")
    artifact = dict(row)
    manifest = resolve_manifest(root / "evidence", artifact["manifest_relative_path"], artifact["manifest_sha256"])
    value = _record(manifest)
    validate_manifest_v4(value, manifest.parent, expected_task_id=task["task_id"], expected_attempt=artifact["attempt"],
        expected_project_id="oss", expected_base_sha=record["baseline_sha"],
        expected_contract_sha256=record["producer_contract_sha256"], expected_required_tests=task["required_tests"])
    if value["candidate_sha"] != artifact["candidate_sha"]:
        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "artifact candidate binding differs")
    return artifact, manifest


def _required_runner(root: Path, task: dict, record: dict, profile, attempt: Path):
    from control_plane.evaluation_broker import run_candidate_tests, fetch_receipt_output

    def runner(workspace: Path, commands: list[str], candidate_sha: str, artifact_root: Path,
               timeout_seconds: int, max_output_bytes: int) -> list[dict]:
        if commands != task["required_tests"] or timeout_seconds != task["limits"]["required_test_timeout_seconds"]:
            raise RepositoryWorkflowError("CONFIG_CHANGED", "producer required tests differ")
        request = {"schema_version": 1, "run_id": attempt.name + "-required", "kind": "required",
            "candidate_sha": candidate_sha, "candidate_root": str(workspace), "task_sha256": record["task_sha256"],
            "profile_sha256": record["profile_sha256"], "commands_sha256": _hash(canonical(commands)),
            "commands": commands, "checks": [], "timeout_seconds": timeout_seconds,
            "max_output_bytes": min(max_output_bytes, task["limits"]["max_output_bytes"])}
        receipt = run_candidate_tests(request, profile)
        receipt_hash = _hash(canonical({key: value for key, value in receipt.items() if key != "receipt_id"}))
        expected = {"schema_version": 1, "receipt_id": receipt_hash, "request_sha256": _hash(canonical(request)),
            "run_id": request["run_id"], "kind": "required", "workspace_id": record["workspace_id"],
            "task_sha256": record["task_sha256"], "profile_sha256": record["profile_sha256"],
            "candidate_sha": candidate_sha, "commands_sha256": request["commands_sha256"], "replayed": False}
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise RepositoryWorkflowError("TEST_FAILED", "sealed required-test bindings differ")
        if receipt.get("pre_tree_sha256") != receipt.get("post_tree_sha256") or receipt.get("descendants") != {"reaped": True, "survivors": 0}:
            raise RepositoryWorkflowError("TEST_FAILED", "test candidate changed or descendants survived")
        if receipt.get("actual_uid") != profile.roles["test_runner"].uid:
            raise RepositoryWorkflowError("TEST_FAILED", "test receipt identity differs")
        results = receipt.get("results")
        if not isinstance(results, list) or len(results) != len(commands):
            raise RepositoryWorkflowError("TEST_FAILED", "test receipt result count differs")
        output_dir = artifact_root / "required-tests"
        output_dir.mkdir(mode=0o700)
        translated, total = [], 0
        for sequence, (result, command) in enumerate(zip(results, commands)):
            if (result.get("sequence") != sequence or result.get("id") != f"required-{sequence:04d}"
                    or result.get("command_sha256") != _hash(canonical(command))
                    or type(result.get("exit_code")) is not int or result["exit_code"] != 0):
                raise RepositoryWorkflowError("TEST_FAILED", "required test failed or result binding differs")
            combined = bytearray()
            for name in ("stdout", "stderr"):
                output = result[name]
                data = fetch_receipt_output(receipt_hash, output["relative_path"], profile)
                if type(data) is not bytes or _hash(data) != output["sha256"] or len(data) != output["bytes"]:
                    raise RepositoryWorkflowError("TEST_FAILED", "sealed output bytes differ")
                combined.extend(data)
            total += len(combined)
            if total > request["max_output_bytes"]:
                raise RepositoryWorkflowError("TEST_FAILED", "test output limit exceeded")
            relative = f"required-tests/{sequence:04d}.output"
            _write(artifact_root / relative, bytes(combined), exclusive=True, mode=0o400)
            translated.append({"sequence": sequence, "command": command, "candidate_sha": candidate_sha,
                "exit_code": 0, "output": {"path": relative, "sha256": _hash(combined), "byte_length": len(combined)}})
        _write_json(attempt / "required-receipt.json", receipt, exclusive=True)
        return translated
    return runner


def _build(root: Path, graph: ProjectGraph, record: dict, task: dict, profile, point: Callable[[str], None]) -> None:
    from control_plane.worker_provider import launch_worker, provider_preflight
    from control_plane.evaluation_broker import broker_workspace
    if _reservations(root, record):
        raise RepositoryWorkflowError("WORKER_INTERRUPTED_UNSEALED", "existing reservation cannot launch again")
    with broker_workspace(root, profile=profile, graph=graph):
        provider_preflight(profile)
    node = graph.get_node(task["task_id"])
    ttl = min(3600, max(10, task["limits"]["worker_timeout_seconds"] + task["limits"]["required_test_timeout_seconds"] + 120))
    leased = graph.lease(task["task_id"], node["version"], OWNER, ttl_seconds=ttl)
    graph.start(task["task_id"], leased["version"], leased["lease_id"], OWNER)
    attempt = _attempt_path(root, task, leased["attempt"])
    attempt.mkdir(mode=0o700)
    _sync_directory(attempt.parent)
    checkout = attempt / "checkout"
    _snapshot_repository(root / "canonical", checkout, record["baseline_sha"], profile.tools["git"].path)
    before, git_before = inventory(checkout), _tree_inventory(checkout / ".git")
    prompt = _worker_prompt(task)
    request = {"schema_version": 1, "project_id": task["project_id"], "task_id": task["task_id"],
        "idempotency_key": task["idempotency_key"], "attempt_id": attempt.name, "attempt_number": leased["attempt"],
        "base_sha": record["baseline_sha"], "checkout": str(checkout), "task_sha256": record["task_sha256"],
        "profile_sha256": record["profile_sha256"], "prompt": prompt, "prompt_sha256": _hash(prompt.encode()),
        "limits": {key: task["limits"][key] for key in ("worker_invocations", "worker_timeout_seconds", "max_output_bytes")}}
    reservation = {"schema_version": 1, "attempt_id": attempt.name, "attempt_number": leased["attempt"],
        "invocation_count": 1, "request_sha256": _hash(canonical(request)), "request": request,
        "reserved_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    _write_json(attempt / "reservation.json", reservation, exclusive=True)
    point("after_reservation")
    try:
        with broker_workspace(root, profile=profile, graph=graph), _worker_control(root, graph, task, profile, attempt, leased, ttl):
            receipt = launch_worker(request, profile)
        expected = {"schema_version": 1, "attempt_id": attempt.name, "request_sha256": reservation["request_sha256"],
            "task_sha256": record["task_sha256"], "profile_sha256": record["profile_sha256"],
            "prompt_sha256": request["prompt_sha256"], "completion": "COMPLETED", "exit_code": 0,
            "signal": None, "descendants_reaped": True}
        _write_json(attempt / "worker-receipt.json", receipt, exclusive=True)
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise RepositoryWorkflowError("TEST_FAILED", "worker protocol did not complete successfully")
        if _tree_inventory(checkout / ".git") != git_before:
            raise RepositoryWorkflowError("TEST_FAILED", "worker altered Git metadata")
        after = inventory(checkout)
        denied = violations(before, after, task["allowed_paths"])
        changed = _git(checkout, "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", "HEAD", executable=profile.tools["git"].path).split("\x00")
        denied.extend(path for path in changed if path and not is_allowed(path, task["allowed_paths"]))
        for path in checkout.rglob("*"):
            if ".git" in path.relative_to(checkout).parts:
                continue
            metadata = path.lstat()
            if path.is_symlink() or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)) or (path.is_file() and metadata.st_nlink != 1):
                denied.append(path.relative_to(checkout).as_posix())
        if denied:
            raise RepositoryWorkflowError("TEST_FAILED", "candidate escaped allowed paths or file types")
        # Freeze checks again before the only pre-admission candidate execution.
        _configuration(root)
        _write_json(attempt / "path-check.json", {"valid": True, "violations": []}, exclusive=True)
        with broker_workspace(root, profile=profile, graph=graph):
            build(checkout, root / "frozen/producer-contract.json", attempt / "path-check.json", root / "worker-output",
                  leased["attempt"], test_runner=_required_runner(root, task, record, profile, attempt))
        current = graph.get_node(task["task_id"])
        artifact = EvidenceIngress(root / "worker-output", root / "evidence").ingest(
            expected_task_id=task["task_id"], expected_attempt=leased["attempt"], expected_project_id="oss",
            expected_base_sha=record["baseline_sha"], expected_contract_sha256=record["producer_contract_sha256"],
            expected_required_tests=task["required_tests"])
        graph.record_ingressed_evidence(task["task_id"], current["version"], artifact)
        point("after_artifact_admission")
    except Exception:
        node = graph.get_node(task["task_id"])
        if node["state"] in {"LEASED", "RUNNING"}:
            graph.transition(task["task_id"], node["version"], "FAILED_GATE", "repository artifact production failed")
        raise


def _evaluate(root: Path, graph: ProjectGraph, record: dict, task: dict, profile) -> None:
    from control_plane.evaluation_broker import broker_workspace, evaluate_artifact
    artifact, manifest = _artifact(root, graph, record, task)
    node = graph.get_node(task["task_id"])
    ttl = max(10, min(3600, task["limits"]["evaluation_timeout_seconds"] + 120))
    active = graph.connection.execute("SELECT expires_at FROM evaluation_claims WHERE claim_id=?", (artifact["claim_id"],)).fetchone() if node["state"] == "EVALUATING" else None
    if active and dt.datetime.fromisoformat(active[0]) > dt.datetime.now(dt.timezone.utc):
        graph.heartbeat_evidence_claim(task["task_id"], node["version"], artifact["artifact_id"], artifact["claim_id"], "hermes-evaluator", ttl)
    else:
        claim = graph.claim_evidence(task["task_id"], node["version"], artifact["artifact_id"], "hermes-evaluator", ttl)
        node, artifact = claim["node"], claim["artifact"]
    previous = graph.connection.execute("SELECT ledger_hash FROM evaluation_ledger ORDER BY sequence DESC LIMIT 1").fetchone()
    required = _record(_attempt_path(root, task, artifact["attempt"]) / "required-receipt.json")
    request = {"schema_version": 1, "workspace_id": record["workspace_id"], "task_sha256": record["task_sha256"],
        "profile_sha256": record["profile_sha256"], "policy_sha256": record["policy_sha256"], "checks_sha256": record["checks_sha256"],
        "producer_contract_sha256": record["producer_contract_sha256"], "artifact_id": artifact["artifact_id"],
        "manifest_sha256": artifact["manifest_sha256"], "evaluation_id": task["task_id"] + "-evaluation-v1",
        "evaluator_contract_id": record["evaluator_contract_id"], "claim_id": artifact["claim_id"],
        "previous_ledger_hash": previous[0] if previous else None, "required_receipt_id": required["receipt_id"]}
    with broker_workspace(root, profile=profile, graph=graph):
        response = evaluate_artifact(request, profile)
    if "rejection_id" in response:
        expected = _hash(canonical({key: value for key, value in response.items() if key != "rejection_id"}))
        if response.get("rejection_id") != expected or response.get("evaluation_request_sha256") != _hash(canonical(request)) or response.get("artifact_id") != artifact["artifact_id"] or response.get("claim_id") != artifact["claim_id"]:
            raise RepositoryWorkflowError("EVALUATION_REJECTED", "invalid sealed rejection")
        graph.reject_evidence(task["task_id"], node["version"], artifact["artifact_id"], "FAILED_GATE", expected, "hermes-evaluator")
        return
    graph.record_evaluation(task["task_id"], node["version"], artifact["artifact_id"], response, manifest)


def _summary(root: Path, graph: ProjectGraph, coordinator: ProjectCoordinator, record: dict, task: dict) -> dict:
    coordinator.assert_publication_integrity()
    node = graph.get_node(task["task_id"])
    artifact = _artifact(root, graph, record, task)[0] if node["active_artifact_id"] else None
    reservations = _reservations(root, record)
    if len(reservations) > task["limits"]["worker_invocations"]:
        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "invocation limit exceeded")
    if artifact and len(reservations) != node["attempt"]:
        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "admitted artifact lacks its invocation reservation")
    if artifact:
        receipt = _record(_attempt_path(root, task, artifact["attempt"]) / "worker-receipt.json")
        if receipt["completion"] != "COMPLETED" or receipt["exit_code"] != 0 or receipt["signal"] is not None or receipt["descendants_reaped"] is not True:
            raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "admitted artifact lacks successful worker completion")
    binding = _record(root / "state/binding.json")
    outcome = graph.connection.execute("SELECT outcome_id FROM evaluation_outcomes WHERE node_id=?", (task["task_id"],)).fetchone()
    rollback = graph.connection.execute("SELECT phase FROM publication_journal WHERE operation_id=? AND phase='COMPLETED'", (task["task_id"] + "-rollback-v1",)).fetchone()
    pending = graph.connection.execute("SELECT status FROM integration_attempts WHERE attempt_id=?", (task["task_id"] + "-promotion-v1",)).fetchone()
    state = {"READY": "ready", "EVIDENCE_PENDING": "built", "EVALUATING": "evaluating", "PASSED": "evaluated", "INTEGRATED": "promoted", "FAILED_GATE": "failed"}.get(node["state"], node["state"].lower())
    classification = None
    if node["state"] in {"LEASED", "RUNNING"}:
        state, classification = "interrupted", "WORKER_INTERRUPTED_UNSEALED"
    if rollback and rollback[0] == "COMPLETED":
        state = "rolled_back"
    if (pending and pending[0] != "COMPLETED") or coordinator.pending_rollbacks():
        state = "recovery_required"
    return {"workflow_id": record["workspace_id"], "workflow_kind": "repository-workflow", "workspace": str(root),
        "project_id": task["project_id"], "task_id": task["task_id"], "task_sha256": record["task_sha256"],
        "workflow_state": state, "task_state": node["state"], "attempts": len(reservations),
        "baseline_sha": record["baseline_sha"], "candidate_sha": artifact["candidate_sha"] if artifact else None,
        "accepted_sha": binding["base_sha"], "accepted_generation": str(root / "publications" / binding["base_sha"]),
        "artifact_id": node["active_artifact_id"], "outcome_id": outcome[0] if outcome else None,
        "task_verdict": "PASS" if outcome else "NOT_PASS" if state == "failed" else "PENDING",
        "release_verdict": "NOT_PASS", "classification": classification, "integrity_verified": True,
        "evidence_scope": "trusted-local; no hostile-code OS separation" if _record(root / "frozen/profile.json")["mode"] == "trusted-local" else "isolated-linux; inspect sealed role evidence for proven boundaries",
        "publication_journal_entries": graph.connection.execute("SELECT count(*) FROM publication_journal").fetchone()[0],
        "publication_operations": graph.connection.execute("SELECT count(DISTINCT operation_id) FROM publication_journal").fetchone()[0],
        "next_safe_action": "inspect interrupted attempt; no automatic relaunch" if state == "interrupted" else
            "inspect rejection and initialize a new task" if state == "failed" else "recover" if state == "recovery_required" else
            "inspect accepted generation or rollback" if state == "promoted" else "inspect historical generation" if state == "rolled_back" else "run"}


def verify_workspace(root: Path, *, require_quiescent: bool = False, original_root: Path | None = None,
                     _snapshot=None) -> dict:
    """Offline closure check. Caller holds workspace_lock; never writes source DB."""
    from control_plane.cli import read_only_graph
    root = _root(root)
    record, task, checks, profile, policy = _configuration(root, original_root=original_root)
    verification_owner = profile.roles["graph"].uid if profile.mode == "isolated-linux" else os.geteuid()
    if _snapshot is not None:
        from control_plane._verification_snapshot import snapshot_owner_uid
        verification_owner = snapshot_owner_uid(_snapshot, root, original_root)
    with read_only_graph(root / "state/graph.sqlite", evaluator_public_key=root / "frozen/public-key.pem",
                         rubric_sha256=policy.sha256, evaluation_policy=policy,
                         **_sqlite_options(profile),
                         original_database=Path(original_root) / "state/graph.sqlite" if original_root else None) as graph:
        coordinator = _coordinator(root, graph, record, policy,
            verification_owner_uid=verification_owner)
        result = _summary(root, graph, coordinator, record, task)
        if require_quiescent:
            if graph.connection.execute("SELECT 1 FROM nodes WHERE state IN ('LEASED','RUNNING','EVALUATING','INTEGRATING')").fetchone() or graph.connection.execute("SELECT 1 FROM evaluation_claims WHERE status='ACTIVE'").fetchone() or coordinator.pending_rollbacks() or graph.connection.execute("SELECT 1 FROM integration_attempts WHERE status!='COMPLETED'").fetchone():
                raise RepositoryWorkflowError("BACKUP_NOT_QUIESCENT", "active lease, claim or publication operation")
        return result


def run_repository_workflow(root: Path, operation: str = "run", stop_after: str | None = None, *,
                            crash_at: str | None = None, barrier: Callable[[str], None] | None = None) -> dict:
    if operation not in {"run", "recover", "status", "rollback"} or stop_after not in {None, "built", "evaluated", "promoted"}:
        raise ValueError("unknown repository workflow operation/stage")
    if crash_at not in CRASH_POINTS | {None}:
        raise ValueError("unknown repository workflow fault boundary")
    if operation != "run" and stop_after is not None:
        raise ValueError("stop_after applies only to run")
    root = _root(root)
    if (root / ".restore-incomplete").exists():
        raise RepositoryWorkflowError("RESTORE_INVALID", "restore has not completed verification")
    def point(name: str):
        if barrier is not None:
            barrier(name)
        if name == crash_at:
            os._exit(86)
    with workspace_lock(root):
        if operation == "status":
            return verify_workspace(root)
        record, task, checks, profile, policy = _configuration(root)
        _reservations(root, record)
        if profile.mode == "isolated-linux" and os.geteuid() != profile.roles["graph"].uid:
            raise RepositoryWorkflowError("ISOLATION_UNAVAILABLE", "operation requires the configured dropped graph role")
        graph = ProjectGraph(root / "state/graph.sqlite", root / "frozen/public-key.pem", policy.sha256,
                             evaluation_policy=policy, **_sqlite_options(profile))
        try:
            coordinator = _coordinator(root, graph, record, policy)
            for rollback_id in coordinator.pending_rollbacks():
                coordinator.reconcile_rollback(rollback_id)
            if operation == "rollback":
                coordinator.rollback(task["task_id"] + "-rollback-v1", task["task_id"], task["task_id"] + "-promotion-v1",
                    expected_head_version=1, crash_hook=lambda name: point("rollback_after_binding") if name == "after_rollback_binding" else None)
            else:
                node = graph.get_node(task["task_id"])
                if node["state"] == "READY":
                    if operation == "recover":
                        return _summary(root, graph, coordinator, record, task)
                    _build(root, graph, record, task, profile, point)
                elif node["state"] in {"LEASED", "RUNNING"}:
                    # Even a complete worker manifest cannot grant graph admission
                    # after restart. Only a live producer may cross this boundary.
                    return _summary(root, graph, coordinator, record, task)
                node = graph.get_node(task["task_id"])
                if stop_after != "built" and node["state"] in {"EVIDENCE_PENDING", "EVALUATING"}:
                    _evaluate(root, graph, record, task, profile)
                    if graph.get_node(task["task_id"])["state"] == "PASSED":
                        point("after_evaluation")
                node = graph.get_node(task["task_id"])
                rolled_back = graph.connection.execute("SELECT 1 FROM publication_journal WHERE operation_id=?", (task["task_id"] + "-rollback-v1",)).fetchone()
                if stop_after not in {"built", "evaluated"} and node["state"] in {"PASSED", "INTEGRATING", "INTEGRATED"} and not rolled_back:
                    artifact, manifest = _artifact(root, graph, record, task)
                    outcome = graph.connection.execute("SELECT outcome_id FROM evaluation_outcomes WHERE node_id=?", (task["task_id"],)).fetchone()
                    if outcome is None:
                        raise RepositoryWorkflowError("DURABLE_STATE_INVALID", "promotion lacks signed outcome")
                    coordinator.integrate(task["task_id"] + "-promotion-v1", task["task_id"], outcome[0], artifact["artifact_id"],
                        manifest, "oss", root / "evidence", crash_hook=point)
            return _summary(root, graph, coordinator, record, task)
        finally:
            graph.connection.close()
