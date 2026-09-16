"""Fail-closed publication of worker evidence into an immutable evaluator store."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from control_plane.artifact_builder import (
    FILE_RECORD_FIELDS,
    HEX40,
    HEX64,
    MAX_ATTEMPT_NUMBER,
    SAFE_ID,
    safe_relative_artifact_path,
    validate_required_test_results,
)


MANIFEST_V4_FIELDS = {
    "schema_version", "task_id", "attempt", "project_id", "base_sha", "candidate_sha",
    "producer_identity", "created_at", "contract_sha256", "path_check",
    "bundle", "required_tests",
}
ARTIFACT_ID = re.compile(r"^sha256:[a-f0-9]{64}$")
RENAME_NOREPLACE = 1
AT_FDCWD = -100


@dataclass(frozen=True)
class IngressArtifact:
    artifact_id: str
    manifest_sha256: str
    manifest_relative_path: str
    task_id: str
    attempt: int
    project_id: str
    base_sha: str
    candidate_sha: str
    contract_sha256: str

    def as_record(self) -> dict[str, Any]:
        return asdict(self)


def _metadata_fingerprint(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_uid, metadata.st_gid, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _open_relative(root: Path, relative: Path) -> int:
    """Open a path without following a symlink in any component."""
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in relative.parts[:-1]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        result = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        os.close(descriptor)
        return result
    except Exception:
        os.close(descriptor)
        raise


def _check_source(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PermissionError("ingress source must be a regular single-link file")


def _read_stable(root: Path, relative: Path, maximum: int | None = None) -> bytes:
    descriptor = _open_relative(root, relative)
    try:
        before = os.fstat(descriptor)
        _check_source(before)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum is not None and total > maximum:
                raise PermissionError("ingress source exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        _check_source(after)
        if _metadata_fingerprint(before) != _metadata_fingerprint(after) or total != after.st_size:
            raise PermissionError("ingress source changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _hash_stable(root: Path, relative: Path) -> tuple[str, int]:
    descriptor = _open_relative(root, relative)
    try:
        before = os.fstat(descriptor)
        _check_source(before)
        digest = hashlib.sha256()
        length = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
        after = os.fstat(descriptor)
        _check_source(after)
        if _metadata_fingerprint(before) != _metadata_fingerprint(after) or length != after.st_size:
            raise PermissionError("stored artifact changed while being hashed")
        return digest.hexdigest(), length
    finally:
        os.close(descriptor)


def _copy_stable(
    source_root: Path,
    relative: Path,
    destination: Path,
    expected_sha256: str,
    expected_length: int,
    group_id: int,
) -> None:
    source = _open_relative(source_root, relative)
    target = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o440)
    try:
        before = os.fstat(source)
        _check_source(before)
        digest = hashlib.sha256()
        length = 0
        while True:
            chunk = os.read(source, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            length += len(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target, view)
                view = view[written:]
        after = os.fstat(source)
        _check_source(after)
        if _metadata_fingerprint(before) != _metadata_fingerprint(after) or length != after.st_size:
            raise PermissionError("ingress source changed while being copied")
        if (digest.hexdigest(), length) != (expected_sha256, expected_length):
            raise PermissionError("ingress source bytes differ from the manifest")
        os.fchmod(target, 0o440)
        if os.fstat(target).st_gid != group_id:
            os.fchown(target, -1, group_id)
        os.fsync(target)
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        os.close(source)
        os.close(target)


def _rename_noreplace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for no-overwrite ingress")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(destination), RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def _validate_file_record(record: Any, *, allow_empty: bool) -> Path:
    if not isinstance(record, dict) or set(record) != FILE_RECORD_FIELDS:
        raise PermissionError("manifest file record is invalid")
    path = safe_relative_artifact_path(record["path"])
    if not isinstance(record["sha256"], str) or not HEX64.fullmatch(record["sha256"]):
        raise PermissionError("manifest file hash is invalid")
    if type(record["byte_length"]) is not int or record["byte_length"] < int(not allow_empty):
        raise PermissionError("manifest file byte length is invalid")
    return path


def validate_manifest_v4(
    manifest: Any,
    manifest_directory: Path,
    *,
    expected_task_id: str | None = None,
    expected_attempt: int | None = None,
    expected_project_id: str | None = None,
    expected_base_sha: str | None = None,
    expected_contract_sha256: str | None = None,
    expected_required_tests: list[str] | None = None,
) -> list[tuple[Path, dict[str, Any]]]:
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_V4_FIELDS:
        raise PermissionError("candidate manifest does not match the exact v4 schema")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 4:
        raise PermissionError("candidate manifest is not version 4")
    if not isinstance(manifest["task_id"], str) or not SAFE_ID.fullmatch(manifest["task_id"]):
        raise PermissionError("candidate manifest task ID is unsafe")
    if type(manifest["attempt"]) is not int or not 1 <= manifest["attempt"] <= MAX_ATTEMPT_NUMBER:
        raise PermissionError("candidate manifest attempt is invalid")
    for field in ("base_sha", "candidate_sha"):
        if not isinstance(manifest[field], str) or not HEX40.fullmatch(manifest[field]):
            raise PermissionError(f"candidate manifest {field} is invalid")
    if not isinstance(manifest["contract_sha256"], str) or not HEX64.fullmatch(
        manifest["contract_sha256"]
    ):
        raise PermissionError("candidate manifest contract_sha256 is invalid")
    for field in ("project_id", "producer_identity", "created_at"):
        if not isinstance(manifest[field], str) or not manifest[field]:
            raise PermissionError(f"candidate manifest {field} is invalid")
    if manifest["producer_identity"] != f"hermes-{manifest['project_id']}":
        raise PermissionError("candidate manifest producer identity mismatch")
    if expected_task_id is not None and manifest["task_id"] != expected_task_id:
        raise PermissionError("candidate manifest task binding mismatch")
    if expected_attempt is not None and manifest["attempt"] != expected_attempt:
        raise PermissionError("candidate manifest attempt binding mismatch")
    if expected_project_id is not None and manifest["project_id"] != expected_project_id:
        raise PermissionError("candidate manifest project binding mismatch")
    if expected_base_sha is not None and manifest["base_sha"] != expected_base_sha:
        raise PermissionError("candidate manifest base binding mismatch")
    if (
        expected_contract_sha256 is not None
        and manifest["contract_sha256"] != expected_contract_sha256
    ):
        raise PermissionError("candidate manifest contract hash differs from the root-owned contract")

    bundle_path = _validate_file_record(manifest["bundle"], allow_empty=False)
    path_check_path = _validate_file_record(manifest["path_check"], allow_empty=False)
    path_check_bytes = _read_stable(manifest_directory, path_check_path, maximum=1024 * 1024)
    if (
        hashlib.sha256(path_check_bytes).hexdigest(), len(path_check_bytes)
    ) != (
        manifest["path_check"]["sha256"], manifest["path_check"]["byte_length"],
    ):
        raise PermissionError("candidate path-check bytes differ from the manifest")
    try:
        path_check_value = json.loads(path_check_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PermissionError("candidate path-check evidence is invalid JSON") from None
    if (
        not isinstance(path_check_value, dict)
        or set(path_check_value) != {"valid", "violations"}
        or path_check_value["valid"] is not True
        or path_check_value["violations"] != []
    ):
        raise PermissionError("candidate path-check evidence did not pass")
    contract_commands = expected_required_tests
    if contract_commands is None:
        results = manifest["required_tests"]
        if not isinstance(results, list):
            raise PermissionError("candidate manifest required tests are invalid")
        contract_commands = [
            result.get("command") if isinstance(result, dict) else None for result in results
        ]
    output_paths = validate_required_test_results(
        manifest["required_tests"], contract_commands, manifest["candidate_sha"], manifest_directory,
    )
    records = [
        (bundle_path, manifest["bundle"]),
        (path_check_path, manifest["path_check"]),
    ]
    for result, output_path in zip(manifest["required_tests"], output_paths):
        records.append((safe_relative_artifact_path(result["output"]["path"]), result["output"]))
    relative_paths = [path for path, _ in records]
    if len(set(relative_paths)) != len(relative_paths):
        raise PermissionError("candidate manifest artifact paths must be unique")
    return records


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_store_directory(path: Path, group_id: int) -> None:
    try:
        path.mkdir(mode=0o750)
    except FileExistsError:
        pass
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PermissionError("content-addressed artifact bucket is unsafe")
    if metadata.st_gid != group_id:
        os.chown(path, -1, group_id)
    os.chmod(path, 0o750)


def validate_destination_inventory(
    target: Path,
    manifest_bytes: bytes,
    records: list[tuple[Path, dict[str, Any]]],
) -> None:
    """Verify the exact stored manifest/file inventory and every bound byte."""
    if target.is_symlink() or not target.is_dir():
        raise PermissionError("content-addressed artifact target is not a safe directory")
    if _read_stable(target, Path("manifest.json"), maximum=1024 * 1024) != manifest_bytes:
        raise PermissionError("content-addressed artifact replay differs from stored manifest")
    expected = {Path("manifest.json"), *(path for path, _ in records)}
    expected_directories = {
        parent
        for relative in expected
        for parent in relative.parents
        if parent != Path(".")
    }
    actual: set[Path] = set()
    actual_directories: set[Path] = set()
    for directory, directories, files in os.walk(target, followlinks=False):
        root = Path(directory)
        for name in directories:
            item = root / name
            metadata = item.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise PermissionError("stored artifact contains an unsafe directory")
            actual_directories.add(item.relative_to(target))
        for name in files:
            item = root / name
            relative = item.relative_to(target)
            metadata = item.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise PermissionError("stored artifact is not a regular single-link file")
            actual.add(relative)
    if actual != expected or actual_directories != expected_directories:
        raise PermissionError(
            "stored content-addressed artifact has unexpected files or directories"
        )
    for relative, record in records:
        if _hash_stable(target, relative) != (record["sha256"], record["byte_length"]):
            raise PermissionError("stored content-addressed artifact bytes are invalid")


class EvidenceIngress:
    """Copy a v4 manifest closure into a no-overwrite content-addressed store."""

    def __init__(self, source_root: Path, target_root: Path):
        self.source_root = Path(os.path.abspath(source_root))
        self.target_root = Path(os.path.abspath(target_root))

    def ingest(
        self,
        *,
        expected_task_id: str,
        expected_attempt: int,
        expected_project_id: str,
        expected_base_sha: str,
        expected_contract_sha256: str,
        expected_required_tests: list[str],
    ) -> IngressArtifact:
        if not isinstance(expected_task_id, str) or not SAFE_ID.fullmatch(expected_task_id):
            raise PermissionError("server-derived manifest task ID is unsafe")
        if type(expected_attempt) is not int or not 1 <= expected_attempt <= MAX_ATTEMPT_NUMBER:
            raise PermissionError("server-derived manifest attempt is invalid")
        relative_manifest = (
            Path(expected_task_id) / f"attempt-{expected_attempt}" / "manifest.json"
        )
        if self.source_root.is_symlink() or not self.source_root.is_dir():
            raise PermissionError("worker evidence root is unsafe")
        if self.target_root.is_symlink() or not self.target_root.is_dir():
            raise PermissionError("evaluator artifact root is unsafe")
        manifest_bytes = _read_stable(self.source_root, relative_manifest, maximum=1024 * 1024)
        try:
            manifest = json.loads(manifest_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise PermissionError("candidate manifest is not canonical JSON data") from None
        source_manifest_directory = self.source_root / relative_manifest.parent
        records = validate_manifest_v4(
            manifest, source_manifest_directory,
            expected_task_id=expected_task_id,
            expected_attempt=expected_attempt,
            expected_project_id=expected_project_id,
            expected_base_sha=expected_base_sha,
            expected_contract_sha256=expected_contract_sha256,
            expected_required_tests=expected_required_tests,
        )
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        artifact_id = f"sha256:{manifest_sha256}"
        relative_target = Path("sha256") / manifest_sha256[:2] / manifest_sha256
        target = self.target_root / relative_target
        record = IngressArtifact(
            artifact_id=artifact_id,
            manifest_sha256=manifest_sha256,
            manifest_relative_path=str(relative_target / "manifest.json"),
            task_id=manifest["task_id"],
            attempt=manifest["attempt"],
            project_id=manifest["project_id"],
            base_sha=manifest["base_sha"],
            candidate_sha=manifest["candidate_sha"],
            contract_sha256=manifest["contract_sha256"],
        )
        if target.exists() or target.is_symlink():
            validate_destination_inventory(target, manifest_bytes, records)
            return record

        group_id = self.target_root.stat().st_gid
        hash_root = self.target_root / "sha256"
        bucket = target.parent
        # The publisher needs owner-write on hash buckets; published artifact
        # directories themselves become read-only before the atomic rename.
        _ensure_store_directory(hash_root, group_id)
        _ensure_store_directory(bucket, group_id)
        _fsync_directory(hash_root)
        _fsync_directory(self.target_root)
        staging = Path(tempfile.mkdtemp(prefix=f".{manifest_sha256}.", dir=bucket))
        try:
            for relative, file_record in records:
                destination = staging / relative
                destination.parent.mkdir(parents=True, mode=0o750, exist_ok=True)
                source_relative = relative_manifest.parent / relative
                _copy_stable(
                    self.source_root, source_relative, destination,
                    file_record["sha256"], file_record["byte_length"], group_id,
                )
            manifest_destination = staging / "manifest.json"
            manifest_destination.parent.mkdir(parents=True, mode=0o750, exist_ok=True)
            _copy_stable(
                self.source_root, relative_manifest, manifest_destination,
                manifest_sha256, len(manifest_bytes), group_id,
            )
            for directory, directories, _ in os.walk(staging, topdown=False):
                for name in directories:
                    child = Path(directory) / name
                    os.chmod(child, 0o550)
                    if child.stat().st_gid != group_id:
                        os.chown(child, -1, group_id)
                    _fsync_directory(child)
            os.chmod(staging, 0o550)
            if staging.stat().st_gid != group_id:
                os.chown(staging, -1, group_id)
            _fsync_directory(staging)
            try:
                _rename_noreplace(staging, target)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                validate_destination_inventory(target, manifest_bytes, records)
            _fsync_directory(bucket)
        finally:
            if staging.exists():
                shutil.rmtree(staging)
        validate_destination_inventory(target, manifest_bytes, records)
        return record


def resolve_manifest(target_root: Path, manifest_relative_path: str, expected_sha256: str) -> Path:
    """Resolve and revalidate a server-recorded immutable artifact closure."""
    if not isinstance(expected_sha256, str) or not HEX64.fullmatch(expected_sha256):
        raise PermissionError("recorded manifest hash is invalid")
    root = Path(os.path.abspath(target_root))
    relative = safe_relative_artifact_path(manifest_relative_path)
    data = _read_stable(root, relative, maximum=1024 * 1024)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise PermissionError("recorded immutable manifest was modified")
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PermissionError("recorded immutable manifest is invalid JSON") from None
    manifest_path = root / relative
    records = validate_manifest_v4(manifest, manifest_path.parent)
    validate_destination_inventory(manifest_path.parent, data, records)
    return manifest_path
