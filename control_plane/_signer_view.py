"""Root-created public evidence view for a signer mounted at the original root.

This is a temporary read-only signing input, not a backup or relocated workspace.
The caller must keep graph mutation paused until signing completes and mount the
returned tree at the original workspace path. Private broker records, credentials
and runtime endpoints are never copied. Source bytes and permissions are untouched.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
from urllib.parse import quote

from .execution_profile import _path


MAX_FILES = 100000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
COPY_TIMEOUT_SECONDS = 60
FROZEN = {"task.json", "profile.json", "checks.json", "policy.json",
          "producer-contract.json", "public-key.pem"}
ROOT_ENTRIES = {"workflow.json", "frozen", "state", "canonical", "evidence",
                "publications", ".broker-receipts"}
_OPEN_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OPEN_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


class SignerViewError(PermissionError):
    """The public signing input could not be copied and verified stably."""


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _names(fd):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            names.append(entry.name)
            if len(names) > MAX_FILES:
                raise SignerViewError("signer directory exceeds the entry bound")
    return sorted(names)


def _selection(relative, names):
    names = set(names)
    if relative == ".":
        required = ROOT_ENTRIES
    elif relative == "frozen":
        if names != FROZEN:
            raise SignerViewError("frozen signing input inventory differs")
        required = FROZEN
    elif relative == "state":
        if names & {"graph.sqlite-wal", "graph.sqlite-shm", "graph.sqlite-journal"}:
            raise SignerViewError("signer view requires a sidecar-free graph snapshot")
        required = {"graph.sqlite", "binding.json"}
    elif relative == ".broker-receipts":
        required = {"receipts", "rejections"}
    else:
        required = {name for name in names if name != ".private"
                    and name != ".lock" and not name.endswith(".lock")}
    if not required <= names:
        raise SignerViewError("public signer input is incomplete")
    return sorted(required)


def _copy_file(source_fd, name, destination, relative, budget, graph_uid, signer_gid):
    before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise SignerViewError("signer input must be a single-link regular file")
    if before.st_size > MAX_FILE_BYTES:
        raise SignerViewError("signer input file exceeds its bound")
    budget["bytes"] += before.st_size
    if budget["bytes"] > MAX_TOTAL_BYTES:
        raise SignerViewError("signer input exceeds the total byte bound")
    fd = os.open(name, _OPEN_FILE, dir_fd=source_fd)
    output = None
    digest = hashlib.sha256()
    length = 0
    try:
        if _fingerprint(os.fstat(fd)) != _fingerprint(before):
            raise SignerViewError("signer input changed during open")
        if destination is not None:
            output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        while True:
            data = os.read(fd, 1024 * 1024)
            if not data:
                break
            length += len(data)
            if length > before.st_size or time.monotonic() > budget["deadline"]:
                raise SignerViewError("signer input changed or copy deadline expired")
            digest.update(data)
            if output is not None:
                pending = memoryview(data)
                while pending:
                    pending = pending[os.write(output, pending):]
        if (length != before.st_size or _fingerprint(os.fstat(fd)) != _fingerprint(before)
                or _fingerprint(os.stat(name, dir_fd=source_fd, follow_symlinks=False)) != _fingerprint(before)):
            raise SignerViewError("signer input changed while copying")
        mode = 0o440 if relative == "state/binding.json" else 0o555 if before.st_mode & 0o111 else 0o444
        owner = (graph_uid, signer_gid) if relative == "state/binding.json" else (0, 0)
        if output is not None:
            os.fchown(output, *owner)
            os.fchmod(output, mode)
            os.fsync(output)
        return {"path": relative, "type": "file", "source_stat": _fingerprint(before),
                "bytes": length, "sha256": digest.hexdigest(),
                "view_mode": mode, "view_uid": owner[0], "view_gid": owner[1]}
    finally:
        os.close(fd)
        if output is not None:
            os.close(output)


def _inventory(source_fd, destination, graph_uid, signer_gid, *, forbidden, deadline):
    inventory = []
    budget = {"bytes": 0, "entries": 0, "deadline": deadline}

    def walk(fd, target, relative):
        before = os.fstat(fd)
        names = _names(fd)
        if not stat.S_ISDIR(before.st_mode):
            raise SignerViewError("signer input ancestor is not a directory")
        inventory.append({"path": relative, "type": "directory", "source_stat": _fingerprint(before),
                          "source_names": names, "view_mode": 0o755, "view_uid": 0, "view_gid": 0})
        if target is not None:
            target.mkdir(mode=0o755)
            os.chown(target, 0, 0)
            os.chmod(target, 0o755)
        for name in _selection(relative, names):
            path = name if relative == "." else relative + "/" + name
            if any(path == item or path.startswith(item + "/") for item in forbidden):
                raise SignerViewError("configured credential path occurs inside public signing inputs")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISSOCK(info.st_mode):
                continue
            budget["entries"] += 1
            if budget["entries"] > MAX_FILES or time.monotonic() > deadline:
                raise SignerViewError("signer inventory exceeds its count or time bound")
            child_target = target / name if target is not None else None
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, _OPEN_DIR, dir_fd=fd)
                try:
                    if _fingerprint(os.fstat(child)) != _fingerprint(info):
                        raise SignerViewError("signer directory changed during open")
                    walk(child, child_target, path)
                    if _fingerprint(os.stat(name, dir_fd=fd, follow_symlinks=False)) != _fingerprint(info):
                        raise SignerViewError("signer directory was replaced during copy")
                finally:
                    os.close(child)
            else:
                inventory.append(_copy_file(fd, name, child_target, path, budget, graph_uid, signer_gid))
        if _names(fd) != names or _fingerprint(os.fstat(fd)) != _fingerprint(before):
            raise SignerViewError("signer directory inventory changed during copy")
        if target is not None:
            output = os.open(target, _OPEN_DIR)
            try:
                os.fsync(output)
            finally:
                os.close(output)

    walk(source_fd, destination, ".")
    return sorted(inventory, key=lambda item: item["path"])


def _verify_snapshot(view, original, profile):
    from .evaluation_broker import validate_git_repository_metadata
    from .evaluation_policy import load_task_policy
    from .graph_schema import inspect_schema
    from .project_graph import ProjectGraph
    from .sealed_protocol import load_json

    # Pure Python parsing precedes every graph/coordinator operation that could
    # consult Git. Never ask Git to parse graph-writable filters or includes.
    for metadata in view.rglob(".git"):
        validate_git_repository_metadata(metadata.parent)
    record = load_json((view / "workflow.json").read_bytes(), require_canonical=False)
    expected = {"frozen/" + name for name in FROZEN}
    if (type(record) is not dict or record.get("workspace") != str(original)
            or type(record.get("files")) is not dict or set(record["files"]) != expected):
        raise SignerViewError("signer view does not preserve the original frozen descriptor")
    for relative, expected_hash in record["files"].items():
        if hashlib.sha256((view / relative).read_bytes()).hexdigest() != expected_hash:
            raise SignerViewError("signer view frozen content hash mismatch")
    if (record.get("profile_sha256") != profile.sha256
            or record["files"]["frozen/profile.json"] != profile.sha256):
        raise SignerViewError("signer view profile differs from bootstrap authority")
    policy = load_task_policy(view / "frozen/policy.json")
    if policy.sha256 != record.get("policy_sha256"):
        raise SignerViewError("signer view policy differs from frozen authority")
    database = view / "state/graph.sqlite"
    connection = sqlite3.connect("file:" + quote(str(database)) + "?mode=ro&immutable=1", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        rows = connection.execute("PRAGMA quick_check").fetchall()
        if len(rows) != 1 or rows[0][0] != "ok":
            raise SignerViewError("signer graph copy is not a valid SQLite database")
        if inspect_schema(connection).action != "none":
            raise SignerViewError("signer graph copy has an unsupported schema")
        graph = object.__new__(ProjectGraph)
        graph.connection, graph.database = connection, database
        graph.evaluator_public_key = view / "frozen/public-key.pem"
        graph.evaluation_policy, graph.rubric_sha256 = policy, policy.sha256
        graph.assert_static_integrity()
    finally:
        connection.close()


@contextmanager
def signer_view(workspace: Path, profile):
    """Yield a protected public snapshot to mount at unchanged ``workspace``."""
    if os.geteuid() != 0:
        raise SignerViewError("only bootstrap root may construct a signer view")
    root = _path(os.fspath(workspace), "signer source workspace")
    graph_uid, signer_gid = profile.roles["graph"].uid, profile.roles["signer"].gid
    forbidden = []
    for path in (Path(profile.paths["signer_private_key"]), Path(profile.auth_home) / ".codex"):
        if path == root:
            raise SignerViewError("workspace is a configured credential root")
        if root in path.parents:
            forbidden.append(path.relative_to(root).as_posix())
    source = os.open(root, _OPEN_DIR)
    identity = _fingerprint(os.fstat(source))
    try:
        with tempfile.TemporaryDirectory(prefix="grapher-signer-view-") as temporary:
            outer = Path(temporary)
            os.chmod(outer, 0o700)
            view = outer / "workspace"
            deadline = time.monotonic() + COPY_TIMEOUT_SECONDS
            first = _inventory(source, view, graph_uid, signer_gid, forbidden=forbidden, deadline=deadline)
            _verify_snapshot(view, root, profile)
            second = _inventory(source, None, graph_uid, signer_gid, forbidden=forbidden, deadline=deadline)
            if first != second or _fingerprint(root.lstat()) != identity:
                raise SignerViewError("public source changed while preparing signer view")
            public = [{key: value for key, value in item.items() if key not in {"source_stat", "source_names"}}
                      for item in first]
            manifest = {"schema_version": 1, "kind": "temporary-signer-view", "workspace": str(root),
                        "source_inventory_sha256": hashlib.sha256(_canonical(first)).hexdigest(),
                        "view_inventory_sha256": hashlib.sha256(_canonical(public)).hexdigest(),
                        "source_inventory": first, "view_inventory": public,
                        "profile_sha256": profile.sha256}
            proof = outer / "view-manifest.json"
            proof.write_bytes(_canonical(manifest))
            proof.chmod(0o400)
            with proof.open("rb") as stream:
                os.fsync(stream.fileno())
            yield view
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
        if isinstance(exc, SignerViewError):
            raise
        raise SignerViewError("public signer view could not be verified") from exc
    finally:
        os.close(source)
