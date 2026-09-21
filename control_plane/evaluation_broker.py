"""Finite evaluation authority and immutable root-sealed public evidence.

The graph selects names; this broker reconstructs their authority from frozen
startup files. No launcher operation accepts commands, signing bytes, roles,
keys, or caller-selected output paths.
"""
from __future__ import annotations

import base64
import contextvars
import configparser
import datetime as dt
import fcntl
import json
import os
import secrets
import sqlite3
import stat
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

from control_plane.sealed_protocol import (
    MAX_OUTPUT_BYTES, ProtocolError, canonical, digest, hex64, identifier,
    load_json, relative_path, sha256, validate_candidate_test_request,
    validate_evaluation_rejection, validate_evaluation_request,
    validate_sealed_test_receipt, validate_signing_request,
)

_ACTIVE_CLIENT = contextvars.ContextVar("grapher_broker_client", default=None)
_ACTIVE_WORKSPACE = contextvars.ContextVar("grapher_broker_workspace", default=None)


def _profile(profile: Any) -> dict[str, Any]:
    if type(profile) is dict:
        return profile
    for name in ("raw", "value", "data"):
        value = getattr(profile, name, None)
        if type(value) is dict:
            return value
    source = getattr(profile, "source_bytes", None)
    if type(source) is bytes:
        return load_json(source, require_canonical=False)
    raise TypeError("validated execution profile required")


def _safe_path(path: Path, *, owner: int | None = None, parents: bool = False) -> None:
    if not path.is_absolute() or Path(os.path.abspath(path)) != path:
        raise PermissionError("path must be absolute and canonical")
    # Every ancestor is checked for links, including graph-owned state paths.
    # Ownership applies to the leaf, or the entire chain for protected roots.
    for entry in [path, *path.parents]:
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise PermissionError("symlink in trusted path")
        sticky_ancestor = (entry != path and stat.S_ISDIR(info.st_mode)
                           and bool(info.st_mode & stat.S_ISVTX) and info.st_uid == 0)
        if owner is not None and (entry == path or parents) and (
                info.st_uid != owner or (info.st_mode & 0o022 and not sticky_ancestor)):
            raise PermissionError("trusted path is writable by another authority")


def _stable_stat(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(path: Path, *, maximum: int = 1024 * 1024, owner: int | None = None) -> bytes:
    _safe_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise PermissionError("unsafe or oversized regular file")
        if owner is not None and (info.st_uid != owner or info.st_mode & 0o022):
            raise PermissionError("frozen file is not root protected")
        result = b""
        while len(result) <= maximum:
            part = os.read(fd, min(65536, maximum + 1 - len(result)))
            if not part:
                break
            result += part
        if len(result) > maximum or _stable_stat(os.fstat(fd)) != _stable_stat(info):
            raise PermissionError("input changed during read")
        return result
    finally:
        os.close(fd)


class BrokerStore:
    """Pinned no-follow directories, root-only writes, exclusive durable records."""

    def __init__(self, workspace: Path | str, *, require_root: bool = True, create: bool = True):
        self.workspace = Path(os.path.abspath(workspace))
        self.owner = 0 if require_root else os.geteuid()
        self.require_root = require_root
        _safe_path(self.workspace, owner=self.owner, parents=require_root)
        self.root = self.workspace / ".broker-receipts"
        if create:
            self._writer()
            try:
                self.root.mkdir(mode=0o755)
                os.chmod(self.root, 0o755)
            except FileExistsError:
                pass
        _safe_path(self.root, owner=self.owner)
        self.fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.identity = os.fstat(self.fd)
        self.workspace_identity = self.workspace.stat()
        if create:
            for name, mode in (("receipts", 0o755), ("rejections", 0o755), (".private", 0o700)):
                try:
                    os.mkdir(name, mode=mode, dir_fd=self.fd)
                    os.chmod(name, mode, dir_fd=self.fd, follow_symlinks=False)
                except FileExistsError:
                    pass
                info = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != self.owner or info.st_mode & 0o022:
                    raise PermissionError("unsafe broker store child")
            os.fsync(self.fd)
            workspace_fd = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(workspace_fd)
            finally:
                os.close(workspace_fd)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def _writer(self) -> None:
        if os.geteuid() != self.owner:
            raise PermissionError("only the receipt authority may seal evidence")

    def _pinned(self) -> None:
        for path, expected in ((self.workspace, self.workspace_identity), (self.root, self.identity)):
            actual = path.lstat()
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise PermissionError("broker directory was replaced")
            if actual.st_uid != self.owner or actual.st_mode & 0o022 or not stat.S_ISDIR(actual.st_mode):
                raise PermissionError("broker directory ownership changed")

    def _dir(self, name: str, base: int | None = None) -> int:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.fd if base is None else base)
        info = os.fstat(fd)
        if (info.st_uid != self.owner or info.st_mode & 0o022
                or (name == ".private" and stat.S_IMODE(info.st_mode) != 0o700)):
            os.close(fd)
            raise PermissionError("untrusted store directory")
        return fd

    @contextmanager
    def lock(self):
        self._writer()
        self._pinned()
        fd = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != self.owner or info.st_nlink != 1 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise PermissionError("unsafe broker lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _new(self, fd: int, name: str, data: bytes, mode: int = 0o444) -> None:
        descriptor = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=fd)
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _read(self, fd: int, name: str, maximum: int) -> bytes:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.owner
                    or info.st_mode & 0o222 or info.st_size > maximum):
                raise PermissionError("sealed file metadata is invalid")
            chunks = []
            remaining = maximum + 1
            while remaining:
                data = os.read(descriptor, min(65536, remaining))
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
            result = b"".join(chunks)
            if len(result) > maximum or _stable_stat(os.fstat(descriptor)) != _stable_stat(info):
                raise PermissionError("sealed bytes changed or exceed bounds")
            return result
        finally:
            os.close(descriptor)

    def private_record(self, name: str) -> dict[str, Any] | None:
        identifier(name)
        fd = self._dir(".private")
        try:
            try:
                return load_json(self._read(fd, name, 1024 * 1024))
            except FileNotFoundError:
                return None
        finally:
            os.close(fd)

    def reserve(self, name: str, value: dict[str, Any]) -> None:
        self._writer()
        identifier(name)
        fd = self._dir(".private")
        try:
            self._new(fd, name, canonical(value), 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)

    def seal_receipt(self, value: dict[str, Any], outputs: dict[str, bytes]) -> dict[str, Any]:
        self._writer()
        self._pinned()
        v = validate_sealed_test_receipt(value)
        expected = {result[stream]["relative_path"]: result[stream]
                    for result in v["results"] for stream in ("stdout", "stderr")}
        if type(outputs) is not dict or set(outputs) != set(expected):
            raise PermissionError("sealed output inventory differs from receipt")
        for path, metadata in expected.items():
            data = outputs[path]
            if type(data) is not bytes or len(data) != metadata["bytes"] or sha256(data) != metadata["sha256"]:
                raise PermissionError("sealed output bytes differ from receipt")
        parent = self._dir("receipts")
        staging = ".staging-" + secrets.token_hex(16)
        try:
            try:
                old = self.fetch(v["receipt_id"])
            except FileNotFoundError:
                old = None
            if old is not None:
                if old != v:
                    raise PermissionError("receipt ID collision")
                return old
            os.mkdir(staging, mode=0o700, dir_fd=parent)
            fd = self._dir(staging, parent)
            try:
                os.mkdir("outputs", mode=0o755, dir_fd=fd)
                output_fd = self._dir("outputs", fd)
                try:
                    os.fchmod(output_fd, 0o755)
                    for path, data in outputs.items():
                        self._new(output_fd, path.split("/")[1], data)
                    os.fsync(output_fd)
                finally:
                    os.close(output_fd)
                self._new(fd, "receipt.json", canonical(v))
                os.fchmod(fd, 0o755)
                os.fsync(fd)
            finally:
                os.close(fd)
            # Parent is writable only by this authority. The process-wide store
            # lock covers admission and publication; rename never overwrites a
            # receipt because a published destination directory is nonempty.
            os.rename(staging, v["receipt_id"], src_dir_fd=parent, dst_dir_fd=parent)
            os.fsync(parent)
            return v
        finally:
            os.close(parent)

    def fetch(self, receipt_id: str) -> dict[str, Any]:
        hex64(receipt_id)
        self._pinned()
        parent = self._dir("receipts")
        try:
            fd = self._dir(receipt_id, parent)
            try:
                v = validate_sealed_test_receipt(self._read(fd, "receipt.json", 1024 * 1024))
                if v["receipt_id"] != receipt_id or set(os.listdir(fd)) != {"receipt.json", "outputs"}:
                    raise PermissionError("sealed receipt directory inventory mismatch")
                outfd = self._dir("outputs", fd)
                try:
                    expected = {result[stream]["relative_path"].split("/")[1]: result[stream]
                                for result in v["results"] for stream in ("stdout", "stderr")}
                    if set(os.listdir(outfd)) != set(expected):
                        raise PermissionError("sealed output inventory mismatch")
                    for name, metadata in expected.items():
                        data = self._read(outfd, name, v["limits"]["max_output_bytes"])
                        if len(data) != metadata["bytes"] or sha256(data) != metadata["sha256"]:
                            raise PermissionError("sealed output hash mismatch")
                finally:
                    os.close(outfd)
                return v
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def output(self, receipt_id: str, path: str) -> bytes:
        relative_path(path)
        receipt = self.fetch(receipt_id)
        if path not in {r[s]["relative_path"] for r in receipt["results"] for s in ("stdout", "stderr")}:
            raise PermissionError("output is not in sealed inventory")
        parent = self._dir("receipts")
        fd = self._dir(receipt_id, parent)
        outfd = self._dir("outputs", fd)
        try:
            data = self._read(outfd, path.split("/")[1], receipt["limits"]["max_output_bytes"])
            metadata = next(r[s] for r in receipt["results"] for s in ("stdout", "stderr") if r[s]["relative_path"] == path)
            if len(data) != metadata["bytes"] or sha256(data) != metadata["sha256"]:
                raise PermissionError("sealed output changed after verification")
            return data
        finally:
            os.close(outfd)
            os.close(fd)
            os.close(parent)

    def fetch_rejection(self, rejection_id: str) -> dict[str, Any]:
        hex64(rejection_id)
        self._pinned()
        fd = self._dir("rejections")
        try:
            value = validate_evaluation_rejection(self._read(fd, rejection_id + ".json", 1024 * 1024))
            if value["rejection_id"] != rejection_id:
                raise PermissionError("rejection identity mismatch")
            return value
        finally:
            os.close(fd)

    def seal_rejection(self, value: dict[str, Any]) -> dict[str, Any]:
        self._writer()
        v = validate_evaluation_rejection(value)
        fd = self._dir("rejections")
        try:
            try:
                self._new(fd, v["rejection_id"] + ".json", canonical(v))
                os.fsync(fd)
            except FileExistsError:
                if self._read(fd, v["rejection_id"] + ".json", 1024 * 1024) != canonical(v):
                    raise PermissionError("rejection collision")
            return v
        finally:
            os.close(fd)


class FrozenWorkspace:
    """Revalidate bytes and reconstruct values from the immutable startup seal."""

    def __init__(self, workspace: Path | str, profile: Any):
        self.root = Path(os.path.abspath(workspace))
        self.profile = profile
        self.isolated = _profile(profile)["mode"] == "isolated-linux"
        _safe_path(self.root, owner=0 if self.isolated else None, parents=self.isolated)
        self.startup = _read_file(self.root / "workflow.json", owner=0 if self.isolated else None)
        self.reload()

    def reload(self) -> None:
        from control_plane.repository_workflow import _configuration
        if _read_file(self.root / "workflow.json", owner=0 if self.isolated else None) != self.startup:
            raise PermissionError("workspace descriptor changed since bootstrap")
        manifest = load_json(self.startup, require_canonical=False)
        if type(manifest.get("files")) is not dict:
            raise PermissionError("frozen input inventory missing")
        for path in manifest["files"]:
            relative_path(path)
            _safe_path(self.root / path, owner=0 if self.isolated else None)
            _safe_path((self.root / path).parent, owner=0 if self.isolated else None)
        self.record, self.task, self.checks, loaded, self.policy = _configuration(self.root)
        if loaded.sha256 != self.profile.sha256 or loaded.raw != self.profile.raw:
            raise PermissionError("profile differs from pinned workspace profile")
        self.contract = load_json(_read_file(self.root / "frozen/producer-contract.json"), require_canonical=False)

    @property
    def workspace_id(self) -> str:
        return self.record["workspace_id"]

    def reservation(self, attempt_id: str, *, require_fresh: bool = False) -> dict[str, Any]:
        from control_plane.worker_provider import validate_worker_request
        self.reload()
        identifier(attempt_id)
        prefix = self.task["task_id"] + "-attempt-"
        if not attempt_id.startswith(prefix):
            raise PermissionError("attempt belongs to another task")
        try:
            number = int(attempt_id[len(prefix):])
        except ValueError as exc:
            raise PermissionError("attempt number is invalid") from exc
        if attempt_id != prefix + str(number) or not 1 <= number <= self.task["limits"]["worker_invocations"]:
            raise PermissionError("attempt is outside frozen invocation budget")
        directory = self.root / "attempts" / attempt_id
        _safe_path(directory)
        path = directory / "reservation.json"
        data = _read_file(path)
        value = load_json(data, require_canonical=False)
        if (type(value) is not dict or set(value) != {"schema_version", "attempt_id", "attempt_number", "invocation_count", "request_sha256", "request", "reserved_at"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["attempt_id"] != attempt_id or type(value["attempt_number"]) is not int or value["attempt_number"] != number
                or type(value["invocation_count"]) is not int or value["invocation_count"] != 1):
            raise PermissionError("reservation does not match exact attempt")
        request = validate_worker_request(value["request"])
        expected = {
            "task_id": self.task["task_id"], "project_id": self.task["project_id"],
            "idempotency_key": self.task["idempotency_key"], "attempt_id": attempt_id,
            "attempt_number": number, "base_sha": self.task["base_sha"],
            "checkout": str(directory / "checkout"), "task_sha256": self.record["task_sha256"],
            "profile_sha256": self.record["profile_sha256"],
            "limits": {key: self.task["limits"][key] for key in ("worker_invocations", "worker_timeout_seconds", "max_output_bytes")},
        }
        from control_plane.repository_workflow import _worker_prompt
        prompt = _worker_prompt(self.task)
        expected.update(prompt=prompt, prompt_sha256=sha256(prompt.encode("utf-8")))
        if any(request.get(key) != val for key, val in expected.items()) or value["request_sha256"] != digest(request):
            raise PermissionError("reservation differs from reconstructed frozen worker request")
        try:
            stamp = dt.datetime.fromisoformat(value["reserved_at"])
        except (TypeError, ValueError) as exc:
            raise PermissionError("reservation time invalid") from exc
        if stamp.tzinfo is None or stamp > dt.datetime.now(dt.timezone.utc):
            raise PermissionError("reservation timestamp is not timezone-bound")
        if require_fresh and stamp + dt.timedelta(seconds=request["limits"]["worker_timeout_seconds"]) <= dt.datetime.now(dt.timezone.utc):
            raise PermissionError("reservation deadline has expired")
        # fsync the already-validated proposal before admitting the privileged
        # launch; the private registry then records its canonical bytes.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return request

    def _verify_node_spec(self, node: dict[str, Any]) -> None:
        spec = load_json(node["spec_json"], require_canonical=False)
        expected = {"task_contract_sha256": self.record["producer_contract_sha256"],
            "public_task_sha256": self.record["task_sha256"],
            "execution_profile_sha256": self.record["profile_sha256"],
            "checks_sha256": self.record["checks_sha256"],
            "evaluation_policy_sha256": self.record["policy_sha256"],
            "evaluator_contract_id": self.record["evaluator_contract_id"]}
        if (any(spec.get(key) != value for key, value in expected.items())
                or node["base_sha"] != self.task["base_sha"]
                or node["goal_id"] != self.record["goal_id"]):
            raise PermissionError("graph node differs from pinned task authority")

    def verify_worker_lease(self, attempt_id: str) -> None:
        from control_plane.repository_workflow import _coordinator
        from control_plane.project_coordinator import ProjectCoordinator
        from control_plane.project_graph import ProjectGraph
        from control_plane.graph_schema import inspect_schema
        database = self.root / "state/graph.sqlite"
        _safe_path(database)
        connection = sqlite3.connect("file:" + quote(str(database)) + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            if inspect_schema(connection).action != "none":
                raise PermissionError("launch graph schema is not current")
            graph = object.__new__(ProjectGraph)
            graph.connection, graph.database = connection, database
            graph.evaluator_public_key = self.root / "frozen/public-key.pem"
            graph.evaluation_policy, graph.rubric_sha256 = self.policy, self.policy.sha256
            ProjectGraph.assert_static_integrity(graph)
            node = graph.get_node(self.task["task_id"])
            self._verify_node_spec(node)
            # Root admission never asks Git to inspect mutable graph-owned
            # config. The signer closes physical publication/signature state in
            # its immutable, allowlisted public snapshot before signing.
            if not self.isolated or os.geteuid() == self.profile.roles["signer"].uid:
                coordinator = _coordinator(self.root, graph, self.record, self.policy,
                    verification_owner_uid=self.profile.roles["graph"].uid if self.isolated else os.geteuid())
                ProjectCoordinator.require_external_integrity(graph, {"opensource": coordinator})
            graph._assert_no_human_gate(node)
            graph._assert_node_has_no_pending_publication(node)
            if (node["state"] != "RUNNING" or node["lease_owner"] != "hermes-oss"
                    or not graph._lease_is_live(node)
                    or attempt_id != f"{self.task['task_id']}-attempt-{node['attempt']}"):
                raise PermissionError("named launch lacks its current active graph lease")
        finally:
            connection.close()

    def required_request(self, run_id: str) -> dict[str, Any]:
        identifier(run_id)
        if not run_id.endswith("-required"):
            raise PermissionError("only registered required runs can be selected")
        worker = self.reservation(run_id[:-len("-required")])
        checkout = Path(worker["checkout"])
        _safe_path(checkout)
        candidate = _git(self.profile, checkout, "rev-parse", "HEAD").decode().strip()
        verify_candidate_scope(self.profile, checkout, candidate, self.task["base_sha"], self.task["allowed_paths"])
        return validate_candidate_test_request({
            "schema_version": 1, "run_id": run_id, "kind": "required", "candidate_sha": candidate,
            "candidate_root": str(checkout), "task_sha256": self.record["task_sha256"],
            "profile_sha256": self.record["profile_sha256"], "commands_sha256": digest(self.task["required_tests"]),
            "commands": self.task["required_tests"], "checks": [],
            "timeout_seconds": self.task["limits"]["required_test_timeout_seconds"],
            "max_output_bytes": self.task["limits"]["max_output_bytes"],
        })

    @contextmanager
    def verify_evaluation(self, request: dict[str, Any]):
        from control_plane.evidence_ingress import validate_manifest_v4
        from control_plane.evidence_store import get_active_claim, resolve_artifact
        from control_plane.graph_schema import inspect_schema
        from control_plane.project_graph import ProjectGraph
        from control_plane.project_coordinator import ProjectCoordinator
        from control_plane.repository_workflow import _coordinator
        self.reload()
        v = validate_evaluation_request(request)
        for field in ("workspace_id", "task_sha256", "profile_sha256", "policy_sha256", "checks_sha256", "producer_contract_sha256", "evaluator_contract_id"):
            if v[field] != self.record[field]:
                raise PermissionError("evaluation differs from frozen authority: " + field)
        if v["evaluation_id"] != self.task["task_id"] + "-evaluation-v1":
            raise PermissionError("evaluation ID differs from registered task evaluation")
        database = self.root / "state/graph.sqlite"
        _safe_path(database)
        connection = sqlite3.connect("file:" + quote(str(database)) + "?mode=ro", uri=True)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            if inspect_schema(connection).action != "none":
                raise PermissionError("graph schema is not current")
            graph = object.__new__(ProjectGraph)
            graph.connection, graph.database = connection, database
            graph.evaluator_public_key = self.root / "frozen/public-key.pem"
            graph.evaluation_policy, graph.rubric_sha256 = self.policy, self.policy.sha256
            ProjectGraph.assert_static_integrity(graph)
            # Root admission never asks Git to inspect mutable graph-owned
            # config. The signer closes physical publication/signature state in
            # its immutable, allowlisted public snapshot before signing.
            if not self.isolated or os.geteuid() == self.profile.roles["signer"].uid:
                coordinator = _coordinator(self.root, graph, self.record, self.policy,
                    verification_owner_uid=self.profile.roles["graph"].uid if self.isolated else os.geteuid())
                ProjectCoordinator.require_external_integrity(graph, {"opensource": coordinator})
            node = graph.get_node(self.task["task_id"])
            self._verify_node_spec(node)
            graph._assert_no_human_gate(node)
            graph._assert_node_has_no_pending_publication(node)
            artifact, manifest_path = resolve_artifact(connection, v["artifact_id"], self.root / "evidence",
                expected_node_id=self.task["task_id"], expected_project="opensource")
            claim = get_active_claim(connection, v["artifact_id"], expected_node_id=self.task["task_id"], expected_claimant="hermes-evaluator")
            spec = json.loads(node["spec_json"])
            if (node["state"] != "EVALUATING" or node["active_artifact_id"] != v["artifact_id"]
                    or node["evidence_hash"] != v["manifest_sha256"] or node["attempt"] != artifact["attempt"]
                    or node["base_sha"] != self.task["base_sha"] or claim["claim_id"] != v["claim_id"]
                    or claim["claim_version"] != node["version"] - 1
                    or spec["evaluator_contract_id"] != v["evaluator_contract_id"]
                    or spec.get("evaluation_policy_sha256") != v["policy_sha256"]):
                raise PermissionError("active evaluation claim differs from request")
            tail = connection.execute("SELECT ledger_hash FROM evaluation_ledger ORDER BY sequence DESC LIMIT 1").fetchone()
            if (tail[0] if tail else None) != v["previous_ledger_hash"]:
                raise PermissionError("evaluation ledger predecessor is stale")
            manifest = load_json(_read_file(manifest_path), require_canonical=False)
            validate_manifest_v4(manifest, manifest_path.parent, expected_task_id=self.task["task_id"],
                expected_attempt=artifact["attempt"], expected_project_id="oss", expected_base_sha=self.task["base_sha"],
                expected_contract_sha256=self.record["producer_contract_sha256"], expected_required_tests=self.task["required_tests"])
            if manifest["candidate_sha"] != artifact["candidate_sha"]:
                raise PermissionError("admitted candidate SHA mismatch")
            yield {"request": v, "artifact": artifact, "manifest": manifest, "manifest_path": manifest_path, "node": node}
        finally:
            connection.close()


def validate_git_repository_metadata(repository: Path | str) -> None:
    """Admit only inert, self-contained Git configuration using Python reads.

    Call this on a root-owned snapshot before existing Git verification helpers.
    It deliberately rejects filter, include, extension and filesystem monitor
    configuration instead of executing Git to ask which config is effective.
    """
    repository = Path(repository)
    metadata = repository / ".git"
    _safe_path(metadata)
    if not metadata.is_dir():
        raise PermissionError("trusted verification requires a self-contained Git directory")
    for name in ("commondir", "gitdir", "config.worktree", "objects/info/alternates", "objects/info/http-alternates", "shallow"):
        if (metadata / name).exists() or (metadata / name).is_symlink():
            raise PermissionError("external or partial Git metadata is unsupported")
    parser = configparser.RawConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(_read_file(metadata / "config", maximum=65536).decode("utf-8"))
    except (configparser.Error, UnicodeError) as exc:
        raise PermissionError("Git config is not the admitted inert format") from exc
    if parser.defaults():
        raise PermissionError("Git configuration defaults are unsupported")
    allowed_core = {"repositoryformatversion": {"0"}, "filemode": {"true", "false"},
        "bare": {"false"}, "logallrefupdates": {"true", "false"},
        "hookspath": {"/dev/null"}, "fsmonitor": {"false"}, "untrackedcache": {"false"},
        "ignorecase": {"true", "false"}, "precomposeunicode": {"true", "false"}}
    for section in parser.sections():
        for name, value in parser.items(section, raw=True):
            if section == "core":
                if name not in allowed_core or value.strip() not in allowed_core[name]:
                    raise PermissionError("Git core configuration can alter trusted verification")
            elif section == "user" and name in {"name", "email"}:
                if not value or "\n" in value or "\0" in value:
                    raise PermissionError("invalid Git author metadata")
            elif section == 'remote "origin"' and name in {"url", "fetch"}:
                if not value or "\n" in value or "\0" in value:
                    raise PermissionError("invalid inert remote metadata")
            else:
                raise PermissionError("Git configuration contains an executable or unsupported section")


def _git(profile: Any, repository: Path, *args: str) -> bytes:
    validate_git_repository_metadata(repository)
    executable = _profile(profile)["tools"]["git"]["path"]
    argv = [executable, "-c", "safe.directory=" + str(repository), "-c", "core.hooksPath=/dev/null",
            "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "submodule.recurse=false", "-C", str(repository), *args]
    result = subprocess.run(argv, check=True, capture_output=True, timeout=60, env={
        "PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "file",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"})
    if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
        raise PermissionError("Git verification output exceeds bounds")
    return result.stdout


def verify_candidate_scope(profile: Any, candidate: Path, sha: str, base: str, allowed: list[str]) -> None:
    from control_plane.workspace_guard import is_allowed
    if _git(profile, candidate, "rev-list", "--parents", "-n", "1", sha).decode().split() != [sha, base]:
        raise PermissionError("candidate must be one non-merge commit above the frozen base")
    diff = _git(profile, candidate, "diff", "--no-renames", "--no-ext-diff", "--name-status", "-z", base, sha, "--")
    fields = diff.split(b"\0")
    if not diff or fields[-1] != b"" or len(fields[:-1]) % 2:
        raise PermissionError("invalid candidate diff framing")
    for status_value, path in zip(fields[0:-1:2], fields[1:-1:2]):
        if status_value not in {b"A", b"M", b"D", b"T"} or not path or not is_allowed(os.fsdecode(path), allowed):
            raise PermissionError("candidate changed outside frozen scope")


def candidate_tree_sha256(candidate: Path | str, profile: Any, expected_sha: str) -> str:
    """Bind clean tracked path/mode/content bytes, including symlink targets."""
    candidate = Path(candidate)
    if _git(profile, candidate, "rev-parse", "HEAD").decode().strip() != expected_sha:
        raise PermissionError("candidate HEAD changed")
    # Do not use `git status`: candidate .gitattributes/config can configure
    # clean filters. Compare committed objects, index and filesystem directly.
    result = []
    expected_index = {}
    for record in _git(profile, candidate, "ls-tree", "-rz", "--full-tree", expected_sha).split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, object_id = metadata.split(b" ")
        path = os.fsdecode(raw_path)
        relative_path(path)
        expected_index[raw_path] = (mode, object_id, b"0")
        if kind != b"blob" or mode not in {b"100644", b"100755", b"120000"}:
            raise PermissionError("candidate contains unsupported tracked entry")
        file = candidate / path
        for parent in file.parents:
            if parent == candidate:
                break
            if parent.is_symlink():
                raise PermissionError("tracked path traverses symlink")
        if mode == b"120000":
            raise PermissionError("candidate symlinks are unsupported by the isolated snapshot copier")
        else:
            content = _read_file(file, maximum=64 * 1024 * 1024)
            actual_mode = b"100755" if file.stat().st_mode & 0o111 else b"100644"
            if actual_mode != mode:
                raise PermissionError("tracked executable mode changed")
        if _git(profile, candidate, "cat-file", "blob", object_id.decode()) != content:
            raise PermissionError("tracked file differs from committed bytes")
        result.append({"path": path, "mode": mode.decode(), "sha256": sha256(content)})
    actual_index = {}
    for record in _git(profile, candidate, "ls-files", "--stage", "-z").split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            fields = tuple(metadata.split(b" "))
            if path in actual_index or len(fields) != 3:
                raise PermissionError("candidate index has duplicate or unmerged entries")
            actual_index[path] = fields
    if actual_index != expected_index:
        raise PermissionError("candidate index differs from committed tree")
    tracked = {entry["path"] for entry in result}
    observed = set()
    for directory, directories, files in os.walk(candidate, followlinks=False):
        if Path(directory) == candidate:
            directories[:] = [name for name in directories if name != ".git"]
        for name in directories + files:
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise PermissionError("candidate contains an unsupported filesystem entry")
            if stat.S_ISREG(info.st_mode):
                observed.add(path.relative_to(candidate).as_posix())
    if observed != tracked:
        raise PermissionError("candidate contains missing or untracked files, including ignored files")
    return digest(sorted(result, key=lambda entry: entry["path"]))


def _receipt_matches(receipt: dict[str, Any], request: dict[str, Any], workspace: FrozenWorkspace, *, passing: bool = True) -> None:
    receipt = validate_sealed_test_receipt(receipt)
    if (receipt["workspace_id"] != workspace.workspace_id or receipt["request_sha256"] != digest(request)
            or receipt["request_id"] != request["run_id"]):
        raise PermissionError("receipt request/workspace binding mismatch")
    for key in ("run_id", "kind", "candidate_sha", "task_sha256", "profile_sha256", "commands_sha256"):
        if receipt[key] != request[key]:
            raise PermissionError("receipt differs from reconstructed request: " + key)
    if receipt["limits"] != {key: request[key] for key in ("timeout_seconds", "max_output_bytes")}:
        raise PermissionError("receipt limits differ from frozen task")
    role = _profile(workspace.profile)["roles"]["test_runner"]
    if receipt["actual_uid"] != role["uid"] or receipt["actual_gid"] != role["gid"]:
        raise PermissionError("candidate did not run under configured test identity")
    if workspace.isolated and any(int(mask, 16) for mask in receipt["capabilities"].values()):
        raise PermissionError("candidate retained a capability")
    if receipt["pre_tree_sha256"] != receipt["post_tree_sha256"] or receipt["descendants"] != {"reaped": True, "survivors": 0}:
        raise PermissionError("candidate changed or descendants remain")
    commands = request["commands"] if request["kind"] == "required" else request["checks"]
    if len(receipt["results"]) != len(commands):
        raise PermissionError("receipt omitted declared tests")
    for index, (result, command) in enumerate(zip(receipt["results"], commands)):
        expected_id = f"required-{index:04d}" if request["kind"] == "required" else command["id"]
        if result["command_sha256"] != digest(command) or result["id"] != expected_id:
            raise PermissionError("receipt changed declared command")
        if passing and result["exit_code"] != 0:
            raise PermissionError("candidate check did not pass")
    if receipt["elapsed_ms"] > request["timeout_seconds"] * 1000:
        raise PermissionError("candidate suite exceeded deadline")


class EvaluationBroker:
    """Root-private registration and finite launch/evaluation actions."""

    def __init__(self, workspace: Path | str, profile: Any):
        self.frozen = FrozenWorkspace(workspace, profile)
        self.profile = profile
        self.store = BrokerStore(self.frozen.root, require_root=self.frozen.isolated)

    def close(self) -> None:
        self.store.close()

    def _existing_run(self, name: str, request_hash: str) -> dict[str, Any] | None:
        result = self.store.private_record("result-" + digest(name))
        if result is not None:
            if result["request_sha256"] != request_hash:
                raise PermissionError("registered request ID reused for different data")
            return result["result"]
        # Restored quiescent stores contain public sealed receipts without the
        # ephemeral private registry. Only an exact completed receipt replays.
        receipt_root = self.store.root / "receipts"
        for entry in receipt_root.iterdir():
            if entry.name.startswith(".staging-"):
                continue
            receipt = self.store.fetch(entry.name)
            if receipt["request_id"] == name:
                if receipt["request_sha256"] != request_hash:
                    raise PermissionError("receipt request ID reused for different data")
                return receipt
        return None

    def _run_tests(self, request: dict[str, Any]) -> dict[str, Any]:
        from control_plane.isolated_runner import execute_candidate_tests
        request = validate_candidate_test_request(request)
        request_hash, name = digest(request), request["run_id"]
        old = self._existing_run(name, request_hash)
        if old is not None:
            _receipt_matches(self.store.fetch(old["receipt_id"]), request, self.frozen, passing=False)
            return old
        registration = "request-" + digest(name)
        if self.store.private_record(registration) is not None:
            raise PermissionError("WORKER_INTERRUPTED_UNSEALED: a reserved run cannot be restarted")
        before = candidate_tree_sha256(request["candidate_root"], self.profile, request["candidate_sha"])
        self.store.reserve(registration, {"request_sha256": request_hash, "request": request})
        fields, outputs = execute_candidate_tests(request, self.profile)
        expected_fields = {"pre_tree_sha256", "post_tree_sha256", "actual_uid", "actual_gid", "namespaces", "capabilities", "no_new_privs", "results", "elapsed_ms", "descendants"}
        if type(fields) is not dict or set(fields) != expected_fields:
            raise PermissionError("runner returned noncanonical observations")
        after = candidate_tree_sha256(request["candidate_root"], self.profile, request["candidate_sha"])
        if before != after or fields["pre_tree_sha256"] != before or fields["post_tree_sha256"] != before:
            raise PermissionError("runner candidate differs from trusted clean inventory")
        value = {**fields, "schema_version": 1, "request_id": name, "request_sha256": request_hash,
                 "workspace_id": self.frozen.workspace_id, "replayed": False,
                 **{key: request[key] for key in ("run_id", "kind", "candidate_sha", "task_sha256", "profile_sha256", "commands_sha256")},
                 "limits": {key: request[key] for key in ("timeout_seconds", "max_output_bytes")}}
        value["receipt_id"] = digest(value)
        _receipt_matches(value, request, self.frozen, passing=False)
        receipt = self.store.seal_receipt(value, outputs)
        self.store.reserve("result-" + digest(name), {"request_sha256": request_hash, "result": receipt})
        return receipt

    def _required(self, run_id: str) -> dict[str, Any]:
        request = self.frozen.required_request(run_id)
        if self._existing_run(run_id, digest(request)) is None:
            self.frozen.verify_worker_lease(run_id[:-len("-required")])
        return self._run_tests(request)

    def _rejection(self, request: dict[str, Any], reason: str, failed_receipt: str | None = None) -> dict[str, Any]:
        rejection = {"schema_version": 1, "evaluation_request_sha256": digest(request),
                     "artifact_id": request["artifact_id"], "claim_id": request["claim_id"],
                     "failed_receipt_id": failed_receipt, "reason": reason}
        rejection["rejection_id"] = digest(rejection)
        return self.store.seal_rejection(rejection)

    def _evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        from control_plane.repository_workflow import _snapshot_repository
        from control_plane.isolated_runner import run_signer_process
        request = validate_evaluation_request(request)
        result_key = "evaluation-" + digest(request)
        previous = self.store.private_record(result_key)
        if previous is not None:
            # A stale claim must never trigger effects. Exact completed replay is
            # a durable result; normal graph acceptance still owns state changes.
            return previous["result"]
        receipt_id = None
        with self.frozen.verify_evaluation(request) as verified:
            required = self.store.fetch(request["required_receipt_id"])
            required_request = self.frozen.required_request(required["run_id"])
            _receipt_matches(required, required_request, self.frozen)
            if required["candidate_sha"] != verified["artifact"]["candidate_sha"]:
                raise PermissionError("required receipt belongs to another artifact candidate")
            # Required output in the admitted manifest must be the exact combined
            # stdout/stderr bytes that the root sealed, not graph-made reports.
            for result, admitted in zip(required["results"], verified["manifest"]["required_tests"]):
                data = self.store.output(required["receipt_id"], result["stdout"]["relative_path"]) + self.store.output(required["receipt_id"], result["stderr"]["relative_path"])
                if admitted["output"]["sha256"] != sha256(data) or admitted["output"]["byte_length"] != len(data):
                    raise PermissionError("admitted required output differs from sealed receipt")
            temporary_root = self.store.root / ".private" / ("candidate-" + digest(request))
            if temporary_root.exists():
                raise PermissionError("WORKER_INTERRUPTED_UNSEALED: independent candidate already reserved")
            candidate_sha = verified["artifact"]["candidate_sha"]
            _snapshot_repository(self.frozen.root / "canonical", temporary_root, self.frozen.task["base_sha"], self.profile.tools["git"].path)
            _git(self.profile, temporary_root, "fetch", "--quiet", str(verified["manifest_path"].parent / verified["manifest"]["bundle"]["path"]), "HEAD")
            _git(self.profile, temporary_root, "checkout", "--quiet", "--detach", candidate_sha)
            verify_candidate_scope(self.profile, temporary_root, candidate_sha, self.frozen.task["base_sha"], self.frozen.task["allowed_paths"])
            test_request = validate_candidate_test_request({
                "schema_version": 1, "run_id": "independent-" + digest(request), "kind": "independent",
                "candidate_root": str(temporary_root), "candidate_sha": candidate_sha,
                "task_sha256": request["task_sha256"], "profile_sha256": request["profile_sha256"],
                "commands": [], "checks": self.frozen.checks["checks"], "commands_sha256": digest(self.frozen.checks["checks"]),
                "timeout_seconds": self.frozen.task["limits"]["evaluation_timeout_seconds"],
                "max_output_bytes": self.frozen.task["limits"]["max_output_bytes"],
            })
        try:
            independent = self._run_tests(test_request)
            receipt_id = independent["receipt_id"]
            if any(result["exit_code"] != 0 for result in independent["results"]):
                result = self._rejection(request, "CHECK_FAILED", receipt_id)
            else:
                signing = validate_signing_request({"schema_version": 1, "evaluation": request,
                    "evaluation_request_sha256": digest(request), "independent_receipt_id": receipt_id,
                    "candidate_sha": candidate_sha})
                with self.frozen.verify_evaluation(request) as current:
                    if current["artifact"]["candidate_sha"] != candidate_sha:
                        raise PermissionError("candidate changed after independent checks")
                    if self.frozen.isolated:
                        result = run_signer_process(signing, self.profile, self.frozen.root)
                    else:
                        result = signer_main(signing, self.profile, self.frozen.root)
        except (PermissionError, ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
            message = str(exc).lower()
            reason = ("LIMIT_EXCEEDED" if "limit" in message or "timeout" in message else
                      "STATE_INVALID" if any(word in message for word in ("claim", "ledger", "artifact", "frozen", "candidate", "state")) else "ISOLATION_FAILED")
            result = self._rejection(request, reason, receipt_id)
        self.store.reserve(result_key, {"result": result})
        return result

    def handle(self, action: str, payload: dict[str, Any]) -> Any:
        """The only bootstrap-facing dispatcher; executable authority is finite."""
        from control_plane.sealed_protocol import validate_launcher_request
        # Reuse complete wire validation, including nested exact key sets, even
        # when called directly from the in-process local adapter.
        envelope = {"schema_version": 1, "action": action, "workspace_id": self.frozen.workspace_id,
                    "request_id": "internal-dispatch", "payload": payload}
        envelope["request_sha256"] = digest(envelope)
        validate_launcher_request(envelope)
        with self.store.lock():
            self.frozen.reload()
            if action == "candidate-tests":
                return self._required(payload["registered_request_id"])
            if action == "sign-evaluation":
                return self._evaluate(payload)
            if action == "immutable-receipt-fetch":
                try:
                    receipt = self.store.fetch(payload["receipt_id"])
                except FileNotFoundError:
                    return self.store.fetch_rejection(payload["receipt_id"])
                return receipt
            if action == "provider-preflight":
                from control_plane.worker_provider import execute_provider_preflight
                if self.frozen.isolated:
                    from ._provider_admission import provider_dispatch
                    with provider_dispatch(self, None):
                        return execute_provider_preflight(self.profile)
                return execute_provider_preflight(self.profile)
            if action == "worker-launch":
                from control_plane.worker_provider import execute_worker
                name = payload["registered_request_id"]
                worker = self.frozen.reservation(name)
                old = self._existing_run(name, digest(worker))
                if old is not None:
                    return old
                key = "request-" + digest(name)
                if self.store.private_record(key) is not None:
                    raise PermissionError("WORKER_INTERRUPTED_UNSEALED: worker cannot be relaunched")
                worker = self.frozen.reservation(name, require_fresh=True)
                self.frozen.verify_worker_lease(name)
                self.store.reserve(key, {"request_sha256": digest(worker), "request": worker})
                if self.frozen.isolated:
                    from ._provider_admission import provider_dispatch
                    with provider_dispatch(self, worker):
                        result = execute_worker(worker, self.profile)
                else:
                    result = execute_worker(worker, self.profile)
                if result.get("descendants_reaped") is True:
                    from control_plane.isolated_runner import finish_worker_checkout
                    finish_worker_checkout(worker, self.profile)
                self.store.reserve("result-" + digest(name), {"request_sha256": digest(worker), "result": result})
                return result
            if action == "shutdown":
                return {"shutdown": True}
            raise PermissionError("unreachable launcher action")


def _receipt_request(receipt: dict[str, Any], frozen: FrozenWorkspace, evaluation: dict[str, Any] | None = None) -> dict[str, Any]:
    if receipt["kind"] == "required":
        suffix = "-required"
        if not receipt["run_id"].endswith(suffix):
            raise PermissionError("required run name is invalid")
        attempt_id = receipt["run_id"][:-len(suffix)]
        prefix = frozen.task["task_id"] + "-attempt-"
        if not attempt_id.startswith(prefix) or not attempt_id[len(prefix):].isdigit():
            raise PermissionError("required run belongs to another task")
        number = int(attempt_id[len(prefix):])
        if not 1 <= number <= frozen.task["limits"]["worker_invocations"] or attempt_id != prefix + str(number):
            raise PermissionError("required attempt is outside frozen limits")
        candidate = frozen.root / "attempts" / attempt_id / "checkout"
        commands, checks = frozen.task["required_tests"], []
        timeout = frozen.task["limits"]["required_test_timeout_seconds"]
    else:
        if evaluation is None or receipt["run_id"] != "independent-" + digest(evaluation):
            raise PermissionError("independent receipt belongs to another evaluation")
        candidate = frozen.root / ".broker-receipts" / ".private" / ("candidate-" + digest(evaluation))
        commands, checks = [], frozen.checks["checks"]
        timeout = frozen.task["limits"]["evaluation_timeout_seconds"]
    return validate_candidate_test_request({"schema_version": 1, "run_id": receipt["run_id"], "kind": receipt["kind"],
        "candidate_sha": receipt["candidate_sha"], "candidate_root": str(candidate),
        "task_sha256": frozen.record["task_sha256"], "profile_sha256": frozen.record["profile_sha256"],
        "commands_sha256": digest(commands if commands else checks), "commands": commands, "checks": checks,
        "timeout_seconds": timeout, "max_output_bytes": frozen.task["limits"]["max_output_bytes"]})


def signer_main(signing_request: dict[str, Any], profile: Any, workspace: Path | str) -> dict[str, Any]:
    """Derive one v4 acceptance outcome. Never execute/import candidate code."""
    from control_plane.project_integrator import canonical as outcome_canonical, evaluation_ledger_hash
    signing = validate_signing_request(signing_request)
    expected = _profile(profile)["roles"]["signer"]
    if os.geteuid() != expected["uid"] or os.getegid() != expected["gid"]:
        raise PermissionError("signing requires the configured signer identity")
    frozen = FrozenWorkspace(workspace, profile)
    store = BrokerStore(workspace, require_root=frozen.isolated, create=False)
    try:
        # The signer reads only the sealed public inventory and trusted graph
        # state. Paths to candidate trees are reconstructed as hash input only.
        required = store.fetch(signing["evaluation"]["required_receipt_id"])
        independent = store.fetch(signing["independent_receipt_id"])
        if required["kind"] != "required" or independent["kind"] != "independent":
            raise PermissionError("signing requires both distinct receipt kinds")
        for receipt in (required, independent):
            _receipt_matches(receipt, _receipt_request(receipt, frozen, signing["evaluation"]), frozen)
            if receipt["candidate_sha"] != signing["candidate_sha"]:
                raise PermissionError("receipt candidate differs from signing subject")
        if required["pre_tree_sha256"] != independent["pre_tree_sha256"]:
            raise PermissionError("required and independent tests used different candidate bytes")
        with frozen.verify_evaluation(signing["evaluation"]) as verified:
            if verified["artifact"]["candidate_sha"] != signing["candidate_sha"]:
                raise PermissionError("admitted candidate differs from signing subject")
            if required["run_id"] != f"{frozen.task['task_id']}-attempt-{verified['artifact']['attempt']}-required":
                raise PermissionError("required receipt belongs to another attempt")
            for sealed, admitted in zip(required["results"], verified["manifest"]["required_tests"]):
                data = store.output(required["receipt_id"], sealed["stdout"]["relative_path"]) + store.output(required["receipt_id"], sealed["stderr"]["relative_path"])
                if sha256(data) != admitted["output"]["sha256"] or len(data) != admitted["output"]["byte_length"]:
                    raise PermissionError("manifest output differs from root-sealed required output")
            request = signing["evaluation"]
            scores = {name: maximum for name, _minimum, maximum in frozen.policy.sections}
            value = {"schema_version": 4, "policy_sha256": frozen.policy.sha256,
                "evaluation_id": request["evaluation_id"], "task_id": frozen.task["task_id"],
                "contract_id": request["evaluator_contract_id"], "artifact_id": request["artifact_id"],
                "claim_id": request["claim_id"], "evaluated_git_sha": signing["candidate_sha"],
                "evidence_manifest_sha256": request["manifest_sha256"], "rubric_sha256": frozen.policy.sha256,
                "section_scores": scores, "mandatory_gates": {name: "PASS" for name in sorted(frozen.policy.mandatory_gates)},
                "total_score": sum(scores.values()), "verdict": "PASS", "evaluator_identity": "hermes-evaluator",
                "previous_ledger_hash": request["previous_ledger_hash"]}
            value["ledger_hash"] = evaluation_ledger_hash(value)
            key = Path(_profile(profile)["paths"]["signer_private_key"])
            _safe_path(key)
            info = key.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PermissionError("private signing key is not an unlinked regular file")
            if frozen.isolated:
                if info.st_uid != 0 or info.st_gid != expected["gid"] or stat.S_IMODE(info.st_mode) not in {0o440, 0o640}:
                    raise PermissionError("private key must be root-owned and readable only by signer group")
            elif info.st_uid != expected["uid"] or info.st_mode & 0o077:
                raise PermissionError("private signing key permissions are not signer-only")
            if frozen.root == key or frozen.root in key.parents:
                raise PermissionError("private signing key cannot be in workspace")
            with tempfile.TemporaryDirectory(prefix="grapher-sign-") as temporary:
                message, signature = Path(temporary) / "message", Path(temporary) / "signature"
                message.write_bytes(outcome_canonical(value))
                subprocess.run([_profile(profile)["tools"]["openssl"]["path"], "pkeyutl", "-sign", "-rawin",
                    "-inkey", str(key), "-in", str(message), "-out", str(signature)], check=True, capture_output=True,
                    timeout=15, env={"PATH": os.defpath, "LANG": "C", "HOME": str(temporary)})
                signature_bytes = _read_file(signature, maximum=4096)
                if len(signature_bytes) != 64:
                    raise PermissionError("signer did not produce an Ed25519 signature")
                value["signature"] = base64.b64encode(signature_bytes).decode("ascii")
                return value
    finally:
        store.close()


@contextmanager
def broker_client(client):
    """Bind an already authenticated bootstrap client for this graph context."""
    if not callable(getattr(client, "request", None)):
        raise TypeError("broker client must expose finite request(action,payload)")
    token = _ACTIVE_CLIENT.set(client)
    try:
        yield client
    finally:
        _ACTIVE_CLIENT.reset(token)


@contextmanager
def broker_workspace(root: Path | str, profile: Any = None, graph: Any = None):
    """Explicit trusted-local context; isolated mode uses its active root client."""
    if profile is None:
        from control_plane.execution_profile import load_execution_profile
        profile = load_execution_profile(Path(root) / "frozen/profile.json", require_private_key=False)
    if _profile(profile)["mode"] == "isolated-linux":
        yield None
        return
    broker = EvaluationBroker(root, profile)
    token = _ACTIVE_WORKSPACE.set(broker)
    try:
        yield broker
    finally:
        _ACTIVE_WORKSPACE.reset(token)
        broker.close()


def _client(profile: Any):
    client = _ACTIVE_CLIENT.get()
    if client is not None:
        return client
    if _profile(profile)["mode"] == "trusted-local":
        broker = _ACTIVE_WORKSPACE.get()
        if broker is None:
            raise PermissionError("trusted-local evaluation requires explicit broker_workspace")
        if broker.profile.sha256 != profile.sha256:
            raise PermissionError("active broker has a different frozen profile")
        class LocalClient:
            workspace = broker.frozen.root

            def request(self, action, payload):
                return broker.handle(action, payload)
        return LocalClient()
    from control_plane.isolated_runner import get_active_launcher
    return get_active_launcher()


def run_candidate_tests(request: dict[str, Any], profile: Any) -> dict[str, Any]:
    request = validate_candidate_test_request(request)
    if request["kind"] != "required":
        raise PermissionError("independent runs are constructed only by the root evaluation broker")
    receipt = validate_sealed_test_receipt(_client(profile).request("candidate-tests", {"registered_request_id": request["run_id"]}))
    if receipt["request_sha256"] != digest(request):
        raise PermissionError("broker reconstructed different test authority")
    return receipt


def evaluate_artifact(request: dict[str, Any], profile: Any) -> dict[str, Any]:
    request = validate_evaluation_request(request)
    result = _client(profile).request("sign-evaluation", request)
    if type(result) is not dict:
        raise PermissionError("broker returned invalid evaluation")
    if "rejection_id" in result:
        result = validate_evaluation_rejection(result)
        if result["evaluation_request_sha256"] != digest(request):
            raise PermissionError("rejection belongs to a different evaluation")
    elif (result.get("schema_version") != 4 or result.get("artifact_id") != request["artifact_id"]
          or result.get("claim_id") != request["claim_id"] or result.get("evaluation_id") != request["evaluation_id"]):
        raise PermissionError("signed result belongs to a different evaluation")
    return result


def fetch_receipt_output(receipt_id: str, path: str, profile: Any) -> bytes:
    hex64(receipt_id)
    relative_path(path)
    client = _client(profile)
    receipt = validate_sealed_test_receipt(client.request("immutable-receipt-fetch", {"receipt_id": receipt_id}))
    if receipt["receipt_id"] != receipt_id:
        raise PermissionError("fetched receipt identity mismatch")
    workspace = getattr(client, "workspace", None)
    if workspace is None:
        socket_path = getattr(client, "path", None)
        if not isinstance(socket_path, (str, Path)):
            raise PermissionError("authenticated launcher has no workspace binding")
        workspace = Path(socket_path).parent
    store = BrokerStore(workspace, require_root=_profile(profile)["mode"] == "isolated-linux", create=False)
    try:
        if store.fetch(receipt_id) != receipt:
            raise PermissionError("root-sealed bytes differ from launcher response")
        return store.output(receipt_id, path)
    finally:
        store.close()


def verify_public_receipt_store(workspace: Path | str, profile: Any) -> dict[str, Any]:
    """Read-only archive admission; never creates or repairs store metadata."""
    store = BrokerStore(workspace, require_root=_profile(profile)["mode"] == "isolated-linux", create=False)
    try:
        receipts, rejections = [], []
        allowed = {"receipts", "rejections", ".private", ".lock"}
        if set(os.listdir(store.fd)) - allowed:
            raise PermissionError("unexpected broker store entry")
        directory = store._dir("receipts")
        try:
            for name in sorted(os.listdir(directory)):
                receipt = store.fetch(name)
                receipts.append(receipt["receipt_id"])
        finally:
            os.close(directory)
        directory = store._dir("rejections")
        try:
            for name in sorted(os.listdir(directory)):
                if not name.endswith(".json"):
                    raise PermissionError("invalid rejection inventory")
                value = validate_evaluation_rejection(store._read(directory, name, 1024 * 1024))
                if name != value["rejection_id"] + ".json":
                    raise PermissionError("rejection filename mismatch")
                if value["failed_receipt_id"] is not None and value["failed_receipt_id"] not in receipts:
                    raise PermissionError("rejection references absent receipt")
                rejections.append(value["rejection_id"])
        finally:
            os.close(directory)
        return {"receipt_ids": receipts, "rejection_ids": rejections}
    finally:
        store.close()
