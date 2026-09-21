"""Strict offline whole-workspace backups and original-root restores.

The archive is never opened as a runtime workspace. Both creation and restoration
verify disposable extracted state before publishing it. The workflow admission
lock is shared with run/recover/rollback; this is deliberately not an online
SQLite snapshot API.
"""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import asdict, dataclass
import configparser
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
from typing import Any, Iterator

from control_plane.evidence_store import resolve_artifact
from control_plane.publication_store import PublicationStore, _rename_noreplace

FORMAT = "codex-grapher-offline-workspace"
VERSION = 1
RUNTIME_ENTRIES = frozenset({
    ".workflow.lock", ".bootstrap.lock", ".launcher.sock", ".worker-control.sock",
    "binding.json.lock", "graph.sqlite.owner.lock",
    "state/.workflow.lock", "state/.worker-control.sock", "state/binding.json.lock", "state/graph.sqlite.owner.lock",
    ".broker-receipts/.lock", ".broker-receipts/.private",
})
HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")


class WorkspaceBackupError(ValueError):
    def __init__(self, message: str, code: str = "RESTORE_INVALID"):
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class BackupReceipt:
    backup: str
    sha256: str
    bytes: int
    original_root: str
    workspace_id: str
    entries: int
    usable: bool = True
    scope: str = "offline-complete-workspace; original absolute root only"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RestoreReceipt:
    workspace: str
    workspace_id: str
    backup_sha256: str
    verify_only: bool
    closure: dict[str, Any]
    next_action: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _json(path: Path) -> dict[str, Any]:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise WorkspaceBackupError("duplicate metadata key")
            result[key] = value
        return result
    value = json.loads(path.read_bytes(), object_pairs_hook=pairs,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    if not isinstance(value, dict):
        raise WorkspaceBackupError("metadata must be an object")
    return value


def _path(path: Path, *, must_exist: bool = True) -> Path:
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise WorkspaceBackupError("symlink roots or ancestors are unsupported")
    if must_exist and not path.is_dir():
        raise WorkspaceBackupError("workspace must be an existing directory")
    return path


def _no_overlap(first: Path, second: Path) -> None:
    if first == second or first in second.parents or second in first.parents:
        raise WorkspaceBackupError("source, destination and backup paths must not overlap")


def _state_root(root: Path) -> Path:
    # The whole-workspace public APIs first require the generic workflow's
    # exact kind/schema. The low-level inventory auditor also serves legacy
    # local-fixture tests, whose original on-disk layout remains unchanged.
    return root / "state" if _json(root / "workflow.json").get("kind") == "repository-workflow" else root


def _no_sidecars(root: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        if os.path.lexists(str(_state_root(root) / "graph.sqlite") + suffix):
            raise WorkspaceBackupError(
                "close every database writer cleanly; WAL/SHM/journal sidecars are not removed",
                "BACKUP_NOT_QUIESCENT",
            )


@contextmanager
def _database_barrier(root: Path) -> Iterator[None]:
    """Exclude even a direct runtime DB writer that skipped workflow admission."""
    from control_plane.cli import offline_database_guard
    with ExitStack() as stack:
        try:
            stack.enter_context(offline_database_guard(_state_root(root) / "graph.sqlite"))
        except ValueError as error:
            raise WorkspaceBackupError("database writer is still open or its owner lock is unsafe",
                                       "BACKUP_NOT_QUIESCENT") from error
        yield


@contextmanager
def _bootstrap_barrier(root: Path) -> Iterator[None]:
    """A still-running root launcher is not an offline backup source."""
    lock = root / ".bootstrap.lock"
    if not os.path.lexists(lock):
        yield
        return
    descriptor = os.open(lock, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise WorkspaceBackupError("bootstrap owner lock is unsafe")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise WorkspaceBackupError("bootstrap launcher is still active", "BACKUP_NOT_QUIESCENT") from error
        yield
    finally:
        os.close(descriptor)


@contextmanager
def _closed_database(root: Path) -> Iterator[sqlite3.Connection]:
    _no_sidecars(root)
    path = _state_root(root) / "graph.sqlite"
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise WorkspaceBackupError("graph database is not a single-link regular file")
    before = _sha(path)
    connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if [tuple(row) for row in connection.execute("PRAGMA integrity_check")] != [("ok",)]:
            raise WorkspaceBackupError("graph SQLite integrity check failed")
        yield connection
    finally:
        connection.close()
    _no_sidecars(root)
    if _sha(path) != before:
        raise WorkspaceBackupError("graph changed while backup admission was closed")


def _git(repo: Path, *arguments: str, executable: str = "/usr/bin/git") -> str:
    result = subprocess.run(
        [executable, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
         "-C", str(repo), *arguments],
        env={"PATH": os.defpath, "HOME": "/nonexistent", "LC_ALL": "C",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
             "GIT_OPTIONAL_LOCKS": "0", "GIT_ALLOW_PROTOCOL": "file",
             "GIT_TERMINAL_PROMPT": "0"},
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode:
        raise WorkspaceBackupError("Git object/ref/bundle closure failed")
    return result.stdout.strip()


def _self_contained_git(repo: Path) -> None:
    git = repo / ".git"
    if not git.is_dir() or git.is_symlink():
        raise WorkspaceBackupError("linked or external Git worktrees are unsupported")
    for name in ("commondir", "gitdir", "objects/info/alternates", "objects/info/http-alternates", "shallow", "worktrees"):
        if os.path.lexists(git / name):
            raise WorkspaceBackupError("Git must be complete and independent of external object stores")
    # No object replacement, external include, lazy object fetch, filter or helper
    # can stand in for the immutable objects inspected by fsck and bundle verify.
    configuration = _git(repo, "config", "--local", "--list").splitlines()
    for entry in configuration:
        name = entry.partition("=")[0].lower()
        if (name.startswith(("include.", "includeif.", "filter.", "credential.", "remote."))
                or name in {"core.alternaterefscommand", "core.sshcommand", "core.worktree"}
                or name.endswith((".promisor", ".partialclonefilter"))):
            raise WorkspaceBackupError("Git configuration requires external or executable authority")
    if _git(repo, "for-each-ref", "refs/replace"):
        raise WorkspaceBackupError("Git replacement refs are unsupported")
    _git(repo, "fsck", "--full", "--strict", "--no-reflogs")


def _audit_git_configs(root: Path) -> None:
    """Parse owned Git configuration as data before any privileged Git call.

    These repositories are initialized by the controller, which never imports
    source remotes, includes, hooks, filters, fsmonitor or executable helpers.
    Privileged verification must not activate configuration written by a role
    whose authority is narrower than the verifying root process.
    """
    allowed_core = {
        "repositoryformatversion": {"0"}, "filemode": {"true", "false"},
        "bare": {"false"}, "logallrefupdates": {"true", "false"},
        "hookspath": {"/dev/null"}, "ignorecase": {"true", "false"},
        "symlinks": {"true", "false"}, "quotepath": {"true", "false"},
        "fsmonitor": {"false"},
    }
    for path in root.rglob("config"):
        if path.parent.name != ".git":
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise WorkspaceBackupError("unsafe Git configuration file")
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(path.read_text(encoding="utf-8"))
        except (UnicodeError, configparser.Error) as error:
            raise WorkspaceBackupError("Git configuration is not controller-owned data") from error
        if parser.defaults() or set(parser.sections()) - {"core", "user"}:
            raise WorkspaceBackupError("Git configuration contains external or executable authority")
        for section in parser.sections():
            for key, value in parser.items(section):
                if any(ord(character) < 32 for character in value):
                    raise WorkspaceBackupError("multiline Git configuration is unsupported")
                if section == "core" and (key not in allowed_core or value not in allowed_core[key]):
                    raise WorkspaceBackupError("Git core configuration is outside the fixed verification policy")
                if section == "user" and key not in {"name", "email"}:
                    raise WorkspaceBackupError("Git user configuration is outside the fixed verification policy")


def _candidate_provenance(repo: Path, bundle: Path, base: str, candidate: str,
                          allowed: list[str]) -> None:
    """Decode candidate objects in private scratch, never import into source."""
    with tempfile.TemporaryDirectory(prefix="grapher-backup-candidate-") as temporary:
        scratch = Path(temporary) / "candidate"
        _git(repo, "clone", "--quiet", "--no-local", "--no-hardlinks", "--no-checkout",
             str(repo), str(scratch))
        _git(scratch, "fetch", "--quiet", str(bundle), "HEAD:refs/backup/candidate")
        if (_git(scratch, "rev-parse", "refs/backup/candidate") != candidate
                or _git(scratch, "show", "-s", "--format=%P", candidate) != base):
            raise WorkspaceBackupError("artifact candidate must have exactly its recorded baseline parent")
        changed = _git(scratch, "diff", "--no-renames", "--name-only", "-z", base, candidate).split("\x00")
        changed = [name for name in changed if name]
        if not changed:
            raise WorkspaceBackupError("artifact candidate has no changed paths")
        for name in changed:
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or not any(
                    path == Path(prefix) or Path(prefix) in path.parents for prefix in allowed):
                raise WorkspaceBackupError("artifact candidate escaped its graph write scope")


def verify_complete_inventory(root: Path) -> dict[str, Any]:
    """Read every artifact row and every retained generation, including history.

    Caller owns the exclusive workflow barrier and has verified graph static and
    signed/coordinator closure. This supplements those checks, not replaces them.
    """
    root = _path(root)
    _self_contained_git(root / "canonical")
    binding = _json(_state_root(root) / "binding.json")
    if set(binding) != {"repo", "base_sha"} or not HEX40.fullmatch(str(binding["base_sha"])):
        raise WorkspaceBackupError("invalid publication binding")
    artifacts = []
    with _closed_database(root) as connection:
        if connection.execute("SELECT 1 FROM nodes WHERE lease_id IS NOT NULL LIMIT 1").fetchone():
            raise WorkspaceBackupError("worker lease is still recorded", "BACKUP_NOT_QUIESCENT")
        if connection.execute("SELECT 1 FROM evaluation_claims WHERE status='ACTIVE' LIMIT 1").fetchone():
            raise WorkspaceBackupError("evaluator claim is active", "BACKUP_NOT_QUIESCENT")
        if connection.execute("SELECT 1 FROM integration_attempts WHERE status!='COMPLETED' LIMIT 1").fetchone():
            raise WorkspaceBackupError("promotion is unfinished", "BACKUP_NOT_QUIESCENT")
        if connection.execute("SELECT operation_id FROM publication_journal GROUP BY operation_id HAVING SUM(phase='COMPLETED')=0 LIMIT 1").fetchone():
            raise WorkspaceBackupError("publication/rollback is unfinished", "BACKUP_NOT_QUIESCENT")
        for row in connection.execute("SELECT artifact_id FROM evidence_artifacts ORDER BY artifact_id"):
            record, path = resolve_artifact(connection, row["artifact_id"], root / "evidence")
            manifest = _json(path)
            bundle = path.parent / manifest["bundle"]["path"]
            heads = _git(root / "canonical", "bundle", "list-heads", str(bundle)).splitlines()
            if f'{record["candidate_sha"]} HEAD' not in heads:
                raise WorkspaceBackupError("artifact candidate provenance is missing")
            _git(root / "canonical", "bundle", "verify", str(bundle))
            if _git(root / "canonical", "rev-parse", record["base_sha"] + "^{commit}") != record["base_sha"]:
                raise WorkspaceBackupError("artifact baseline history is absent")
            node = connection.execute("SELECT write_set_json FROM nodes WHERE node_id=?",
                                      (record["node_id"],)).fetchone()
            _candidate_provenance(root / "canonical", bundle, record["base_sha"],
                                  record["candidate_sha"], json.loads(node["write_set_json"]))
            artifacts.append({key: record[key] for key in (
                "artifact_id", "node_id", "attempt", "manifest_sha256", "base_sha", "candidate_sha", "contract_sha256",
            )})
        journal = [dict(row) for row in connection.execute("SELECT * FROM publication_journal ORDER BY sequence")]
    generations = []
    store = PublicationStore(root / "publications")
    if not store.root.is_dir() or store.root.is_symlink():
        raise WorkspaceBackupError("publication store is absent")
    for generation in sorted(store.root.iterdir()):
        if not HEX40.fullmatch(generation.name):
            raise WorkspaceBackupError("unfinished or unknown retained publication generation")
        _self_contained_git(generation)
        pin = store.verify(binding["repo"], generation.name)
        generations.append({"sha": pin.base_sha, "tree_sha": pin.tree_sha})
    if binding["base_sha"] not in {item["sha"] for item in generations}:
        raise WorkspaceBackupError("bound publication generation is absent")
    refs = _git(root / "canonical", "for-each-ref", "--format=%(refname) %(objectname)").splitlines()
    return {"artifacts": artifacts, "generations": generations, "refs": refs,
            "database_sha256": _sha(_state_root(root) / "graph.sqlite"),
            "publication_journal_sha256": hashlib.sha256(_canonical(journal)).hexdigest(),
            "binding": binding}


def _role_names(relative: str, _metadata=None) -> tuple[str, str]:
    parts = Path(relative).parts
    if parts[0] in {".broker-receipts", "frozen", "workflow.json"}:
        return "bootstrap", "bootstrap"
    if parts[0] == "publications" or relative in {"state", "binding.json", "state/binding.json"}:
        return "graph", "worker"
    # Bootstrap hands the entire checkout back after worker completion. Live
    # worker-owned checkouts cannot pass the quiescent backup contract.
    return "graph", "graph"


def _excluded(relative: str) -> bool:
    return (any(relative == name or relative.startswith(name + "/") for name in RUNTIME_ENTRIES)
            or re.fullmatch(r"state/[A-Za-z0-9][A-Za-z0-9_.-]{0,255}\.control\.sock", relative) is not None)


def _runtime_excludes(root: Path) -> frozenset[str]:
    names = set(RUNTIME_ENTRIES)
    if (root / "state").is_dir():
        names.update(path.relative_to(root).as_posix() for path in (root / "state").iterdir()
                     if _excluded(path.relative_to(root).as_posix()))
    return frozenset(names)


def _profile(root: Path, supplied: Any = None):
    from control_plane.execution_profile import load_execution_profile
    frozen = load_execution_profile(root / "frozen/profile.json", require_private_key=False)
    if supplied is not None:
        if isinstance(supplied, (Path, str)):
            supplied = load_execution_profile(Path(supplied), require_private_key=False)
        if supplied.sha256 != frozen.sha256:
            raise WorkspaceBackupError("restore profile differs from the frozen execution profile")
    return frozen


def _profile_mode(profile) -> str:
    return profile.mode


def _role_ids(profile, role: str) -> tuple[int, int]:
    if role == "bootstrap":
        return (0, 0) if _profile_mode(profile) == "isolated-linux" else (os.geteuid(), os.getegid())
    item = profile.roles[role]
    return item.uid, item.gid


def _check_private_paths(root: Path, profile) -> None:
    if profile.auth_home == root or root in profile.auth_home.parents:
        raise WorkspaceBackupError("provider authentication home must be outside the workspace")
    for name, value in profile.paths.items():
        if value and ("private" in name or "auth" in name):
            path = Path(value)
            if path == root or root in path.parents:
                raise WorkspaceBackupError("private keys and authentication stores must live outside the workspace")


def _matching_key(root: Path, profile) -> bool:
    """Return signing availability; a present wrong key always rejects."""
    public = Path(profile.paths["signer_public_key"])
    if _sha(public) != _sha(root / "frozen/public-key.pem"):
        raise WorkspaceBackupError("provisioned public key differs from the frozen key")
    private = Path(profile.paths["signer_private_key"])
    if not private.exists():
        return False
    executable = profile.tools["openssl"].path
    outputs = []
    for arguments in (("pkey", "-in", str(private), "-pubout", "-outform", "DER"),
                      ("pkey", "-pubin", "-in", str(public), "-outform", "DER")):
        result = subprocess.run([executable, *arguments], capture_output=True,
                                env={"PATH": os.defpath}, timeout=15)
        if result.returncode or not result.stdout or len(result.stdout) > 65536:
            raise WorkspaceBackupError("cannot verify provisioned signing key")
        outputs.append(result.stdout)
    if outputs[0] != outputs[1]:
        raise WorkspaceBackupError("provisioned private key does not match the frozen public key")
    return True


def _attempt_provenance(root: Path, profile, closure: dict[str, Any]) -> list[dict[str, str]]:
    """Keep every admitted attempt joined to its sealed public execution proof."""
    from control_plane.repository_workflow import _reservations
    from control_plane.worker_provider import validate_worker_receipt
    from control_plane.evaluation_broker import BrokerStore
    record = _json(root / "workflow.json")
    reservations = _reservations(root, record)
    artifacts = {(item["node_id"], item["attempt"]): item for item in closure["artifacts"]}
    if len(reservations) != len(artifacts):
        raise WorkspaceBackupError("every reserved invocation must have admitted artifact closure", "BACKUP_NOT_QUIESCENT")
    if not reservations:
        return []
    store = BrokerStore(root, require_root=profile.mode == "isolated-linux", create=False)
    proofs = []
    try:
        task = _json(root / "frozen/task.json")
        for reservation in reservations:
            artifact = artifacts.get((record["task_id"], reservation["attempt_number"]))
            if artifact is None:
                raise WorkspaceBackupError("invocation is unsealed or has no matching admitted attempt", "BACKUP_NOT_QUIESCENT")
            attempt = root / "attempts" / reservation["attempt_id"]
            worker = validate_worker_receipt(_json(attempt / "worker-receipt.json"), reservation["request"], profile)
            if worker["completion"] != "COMPLETED":
                raise WorkspaceBackupError("admitted artifact has no completed worker receipt")
            required = _json(attempt / "required-receipt.json")
            sealed = store.fetch(required["receipt_id"])
            if required != sealed or any(required.get(key) != value for key, value in {
                    "kind": "required", "workspace_id": record["workspace_id"],
                    "task_sha256": record["task_sha256"], "profile_sha256": record["profile_sha256"],
                    "candidate_sha": artifact["candidate_sha"],
                    "actual_uid": profile.roles["test_runner"].uid,
                    "commands_sha256": hashlib.sha256(_canonical(task["required_tests"])).hexdigest(),
            }.items()):
                raise WorkspaceBackupError("required test receipt differs from frozen attempt/artifact authority")
            digest = artifact["manifest_sha256"]
            manifest_path = root / "evidence/sha256" / digest[:2] / digest / "manifest.json"
            manifest = _json(manifest_path)
            if len(sealed["results"]) != len(manifest["required_tests"]):
                raise WorkspaceBackupError("required receipt/manifest result inventory differs")
            for result, test in zip(sealed["results"], manifest["required_tests"]):
                if (result["sequence"] != test["sequence"] or result["exit_code"] != 0
                        or result["command_sha256"] != hashlib.sha256(_canonical(test["command"])).hexdigest()):
                    raise WorkspaceBackupError("sealed required result differs from ingressed result")
                output = b"".join(store.output(sealed["receipt_id"], result[name]["relative_path"])
                                  for name in ("stdout", "stderr"))
                if (hashlib.sha256(output).hexdigest() != test["output"]["sha256"]
                        or len(output) != test["output"]["byte_length"]):
                    raise WorkspaceBackupError("sealed output differs from ingressed required-test bytes")
            proofs.append({"attempt_id": reservation["attempt_id"], "worker_receipt_sha256": _sha(attempt / "worker-receipt.json"),
                           "required_receipt_id": sealed["receipt_id"]})
    finally:
        store.close()
    return proofs


def _check_tree(root: Path, profile) -> None:
    _check_private_paths(root, profile)
    isolated = _profile_mode(profile) == "isolated-linux"
    if isolated and (os.geteuid() != 0 or root.stat().st_uid != 0):
        raise WorkspaceBackupError("isolated backup/restore requires root bootstrap ownership")
    if isolated:
        for name, mode in (("state", 0o2700), ("publications", 0o2750)):
            if stat.S_IMODE((root / name).stat().st_mode) != mode:
                raise WorkspaceBackupError(f"isolated {name} directory must retain mode {mode:04o}")
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in list(names) + files:
            path = base / name
            relative = path.relative_to(root).as_posix()
            if _excluded(relative):
                if name in names:
                    names.remove(name)
                continue
            metadata = path.lstat()
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise WorkspaceBackupError("links and special workspace files are unsupported")
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                raise WorkspaceBackupError("hard-linked workspace files are unsupported")
            if metadata.st_mode & 0o7000:
                allowed_mode = {"state": 0o2700, "publications": 0o2750}.get(relative)
                if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != allowed_mode:
                    raise WorkspaceBackupError("special permission bits are unsupported outside exact SGID authority roots")
            if path.name in {"auth.json", ".netrc", "credentials.json"}:
                raise WorkspaceBackupError("authentication stores are excluded from backups")
            if isolated:
                owner, group = _role_names(relative)
                if (metadata.st_uid, metadata.st_gid) != (_role_ids(profile, owner)[0], _role_ids(profile, group)[1]):
                    raise WorkspaceBackupError(f"workspace semantic ownership mismatch: {relative}")
                if owner == "bootstrap" and metadata.st_mode & 0o022:
                    raise WorkspaceBackupError("bootstrap-owned frozen inputs and receipts must not be group/world writable")
                if owner == "graph" and metadata.st_mode & 0o022:
                    raise WorkspaceBackupError("graph authority must not be group/world writable")
            if stat.S_ISREG(metadata.st_mode):
                previous = b""
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        data = previous + block
                        if re.search(rb"-----BEGIN [A-Z ]*PRIVATE" + rb" KEY-----", data):
                            raise WorkspaceBackupError("private signing material cannot enter a backup")
                        previous = data[-128:]


def _verify(root: Path, *, original_root: Path, profile=None) -> tuple[Any, dict[str, Any]]:
    _no_sidecars(root)
    profile = _profile(root, profile)
    _check_tree(root, profile)
    _matching_key(root, profile)
    if profile.mode == "isolated-linux":
        from control_plane._verification_snapshot import verification_snapshot, verify_backup_snapshot
        with verification_snapshot(root, profile, original_root=original_root,
                                   excludes=_runtime_excludes(root), role_for_path=_role_names) as snapshot:
            # The helper seals before/after source identities around its copy
            # and this context. Bind the role audit to that stable interval,
            # rather than trusting an audit completed before copying began.
            _check_tree(root, profile)
            closure = verify_backup_snapshot(snapshot)
    else:
        closure = _verify_all(root, original_root=original_root, profile=profile)
    _no_sidecars(root)
    return profile, closure


def _verify_all(root: Path, *, original_root: Path, profile, _snapshot=None) -> dict[str, Any]:
    """Full public closure after original ownership audit or sealed projection.

    The isolated subprocess receives only the active helper's sealed readonly
    snapshot token. Original frozen profile/key/task bytes retain their identity;
    source-role ownership is audited before any projected-root Git execution.
    """
    from control_plane.repository_workflow import verify_workspace
    _audit_git_configs(root)
    arguments = {} if _snapshot is None else {"_snapshot": _snapshot}
    verify_workspace(root, require_quiescent=True, original_root=original_root, **arguments)
    closure = verify_complete_inventory(root)
    if (root / ".broker-receipts").exists():
        from control_plane.evaluation_broker import verify_public_receipt_store
        closure["broker_receipts"] = verify_public_receipt_store(root, profile)
    else:
        closure["broker_receipts"] = None
    closure["attempt_provenance"] = _attempt_provenance(root, profile, closure)
    _no_sidecars(root)
    return closure


def _apply_ownership(root: Path, manifest: dict[str, Any], profile) -> None:
    isolated = _profile_mode(profile) == "isolated-linux"
    if isolated and os.geteuid() != 0:
        raise WorkspaceBackupError("restoring isolated role ownership requires root bootstrap")
    for entry in manifest["entries"]:
        expected = _role_names(entry["path"])
        if (entry["owner_role"], entry["group_role"]) != expected:
            raise WorkspaceBackupError("archive role mapping differs from trusted path semantics")
        owner, group = expected
        uid, gid = _role_ids(profile, owner)[0], _role_ids(profile, group)[1]
        path = root / entry["path"]
        if os.geteuid() == 0:
            os.chown(path, uid, gid, follow_symlinks=False)
        elif (path.stat().st_uid, path.stat().st_gid) != (uid, gid):
            raise WorkspaceBackupError("cannot recreate validated role ownership")
        # chown can clear SGID. Reapply only archive modes already admitted by
        # the exact path/type/role policy, after assigning the trusted group.
        os.chmod(path, entry["mode"], follow_symlinks=False)
    # Retain a private root-owned staging ancestor until every byte and graph
    # binding is verified; restored worker-owned descendants must stay hidden.
    os.chmod(root, 0o700)


def _metadata(manifest: dict[str, Any]) -> dict[str, Any]:
    metadata = manifest["metadata"]
    expected = {"format", "version", "original_root", "workspace_id", "profile_sha256",
                "public_key_sha256", "root_mode", "closure"}
    if (set(metadata) != expected or metadata["format"] != FORMAT
            or type(metadata["version"]) is not int or metadata["version"] != VERSION
            or not isinstance(metadata["original_root"], str)
            or not Path(metadata["original_root"]).is_absolute()
            or str(Path(metadata["original_root"])) != metadata["original_root"]
            or any(not isinstance(metadata[name], str) or not HEX64.fullmatch(metadata[name])
                   for name in ("workspace_id", "profile_sha256", "public_key_sha256"))
            or type(metadata["root_mode"]) is not int or metadata["root_mode"] & ~0o777):
        raise WorkspaceBackupError("backup metadata is invalid")
    return metadata


def _validate_extracted(root: Path, manifest: dict[str, Any], supplied=None) -> tuple[Any, dict[str, Any]]:
    metadata = _metadata(manifest)
    if any(_excluded(entry["path"]) for entry in manifest["entries"]):
        raise WorkspaceBackupError("archive contains excluded credentials or runtime state")
    profile = _profile(root, supplied)
    if _profile_mode(profile) == "isolated-linux" and metadata["root_mode"] != 0o755:
        raise WorkspaceBackupError("isolated workspace root must retain bootstrap mode 0755")
    if (profile.sha256 != metadata["profile_sha256"]
            or _sha(root / "frozen/public-key.pem") != metadata["public_key_sha256"]
            or _json(root / "workflow.json")["workspace_id"] != metadata["workspace_id"]):
        raise WorkspaceBackupError("workspace/profile/public key does not match backup identity")
    _apply_ownership(root, manifest, profile)
    profile, closure = _verify(root, original_root=Path(metadata["original_root"]), profile=profile)
    if closure != metadata["closure"]:
        raise WorkspaceBackupError("restored external closure differs from the complete source inventory")
    return profile, closure


def backup_workspace(root: Path, destination: Path) -> BackupReceipt:
    """Publish one offline archive only after a disposable restore succeeds."""
    from control_plane.backup_archive import create_archive, extract_archive
    from control_plane.repository_workflow import workspace_lock
    root = _path(root)
    destination = _path(destination, must_exist=False)
    _no_overlap(root, destination)
    if os.path.lexists(destination):
        raise WorkspaceBackupError("backup destination already exists")
    if not destination.parent.is_dir():
        raise WorkspaceBackupError("backup destination parent must exist")
    with _bootstrap_barrier(root), workspace_lock(root), _database_barrier(root):
        profile, closure = _verify(root, original_root=root)
        record = _json(root / "workflow.json")
        metadata = {"format": FORMAT, "version": VERSION, "original_root": str(root),
                    "workspace_id": record["workspace_id"], "profile_sha256": profile.sha256,
                    "public_key_sha256": _sha(root / "frozen/public-key.pem"),
                    "root_mode": stat.S_IMODE(root.stat().st_mode), "closure": closure}
        with tempfile.TemporaryDirectory(prefix=".grapher-backup-", dir=destination.parent) as work:
            staged = Path(work) / "archive.tar"
            manifest = create_archive(root, staged, excludes=_runtime_excludes(root),
                                      metadata=metadata, role_for_path=_role_names)
            restored = Path(work) / "restored"
            restored.mkdir(mode=0o700)
            extracted = extract_archive(staged, restored)
            if extracted != manifest:
                raise WorkspaceBackupError("archive inventory changed between creation and extraction")
            _validate_extracted(restored, extracted, profile)
            # The source must still close exactly over the same authority bytes.
            _, current = _verify(root, original_root=root, profile=profile)
            if current != closure:
                raise WorkspaceBackupError("workspace changed during the exclusive backup")
            _rename_noreplace(staged, destination)
            _fsync_directory(destination.parent)
    return BackupReceipt(str(destination), _sha(destination), destination.stat().st_size,
                         str(root), record["workspace_id"], len(manifest["entries"]))


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def restore_workspace(backup: Path, destination: Path, profile: Any) -> RestoreReceipt:
    """Restore verified state atomically to its empty original absolute root.

    Failed staging directories remain for diagnosis. No private key is created,
    historical response signed, runtime schema migrated, or operation dispatched.
    """
    from control_plane.backup_archive import inspect_archive, extract_archive
    backup = _path(backup, must_exist=False)
    destination = _path(destination, must_exist=False)
    _no_overlap(backup, destination)
    manifest = inspect_archive(backup)
    metadata = _metadata(manifest)
    if str(destination) != metadata["original_root"]:
        raise WorkspaceBackupError("relocation is unsupported; restore the original absolute root")
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise WorkspaceBackupError("restore destination must be absent or empty")
    if not destination.parent.is_dir():
        raise WorkspaceBackupError("restore destination parent must exist")
    before = _sha(backup)
    staging_parent = Path(tempfile.mkdtemp(prefix=".grapher-restore-", dir=destination.parent))
    staged = staging_parent / "workspace"
    staged.mkdir(mode=0o700)
    try:
        restored_manifest = extract_archive(backup, staged)
        if restored_manifest != manifest:
            raise WorkspaceBackupError("archive changed during restore")
        restored_profile, closure = _validate_extracted(staged, manifest, profile)
        verify_only = not _matching_key(staged, restored_profile)
        if _sha(backup) != before:
            raise WorkspaceBackupError("immutable backup changed during restore")
        # Recreate only the shared admission lock; no archived socket or stale
        # owner lock is reused. Its actual owner is derived from trusted profile.
        for name in (".workflow.lock", "graph.sqlite.owner.lock"):
            lock = staged / "state" / name
            descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                uid, gid = _role_ids(restored_profile, "graph")
                if os.geteuid() == 0:
                    os.fchown(descriptor, uid, gid)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        uid, gid = _role_ids(restored_profile, "bootstrap")
        if os.geteuid() == 0:
            os.chown(staged, uid, gid)
        os.chmod(staged, metadata["root_mode"])
        _fsync_directory(staged)
        if destination.exists():
            destination.rmdir()  # Atomic failure if raced content appeared.
        _rename_noreplace(staged, destination)
        _fsync_directory(destination.parent)
        staging_parent.rmdir()
    except Exception as error:
        raise WorkspaceBackupError(f"restore rejected; diagnostic state retained at {staged}: {error}") from error
    return RestoreReceipt(str(destination), metadata["workspace_id"], before, verify_only,
                          closure, "provision matching signing key" if verify_only else "recover")
