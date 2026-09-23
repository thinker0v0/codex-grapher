"""Private complete-state projection for root's read-only backup verification.

The original role ownership is audited by the backup caller. The protected copy
projects file owners to root solely to let existing Git readers inspect it without
safe.directory exceptions. No operational workflow accepts this owner override.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

# A fixed installed script is the only subprocess entry; -I excludes cwd/site
# injection. This path derives from that trusted script, never candidate input.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    # G imports this private module when validating the capability. Keep that
    # import bound to this exact module instead of creating a second token/type.
    sys.modules["control_plane._verification_snapshot"] = sys.modules[__name__]

from control_plane import backup_archive
from control_plane.repository_task import canonical, read_regular, strict_json_bytes

_TOKEN = object()
MAX_RECORD_BYTES = 64 * 1024 * 1024


@dataclass
class VerificationSnapshot:
    root: Path
    original_root: Path
    manifest: Path
    profile_sha256: str
    _token: Any
    _active: bool = True


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_manifest(path: Path) -> dict:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o077 or info.st_size > MAX_RECORD_BYTES):
        raise PermissionError("verification projection descriptor is not private root authority")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = bytearray()
        while len(raw) <= MAX_RECORD_BYTES:
            block = os.read(descriptor, min(1024 * 1024, MAX_RECORD_BYTES + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(descriptor)
        if backup_archive._fingerprint(info) != backup_archive._fingerprint(after) or len(raw) != info.st_size:
            raise PermissionError("verification projection descriptor changed")
    finally:
        os.close(descriptor)
    # The ordinary public-input parser deliberately caps documents at 1 MiB.
    # This internal inventory has its separate 64 MiB cap and duplicate parser.
    value = json.loads(raw, object_pairs_hook=backup_archive._unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite descriptor")))
    if type(value) is not dict:
        raise ValueError("invalid verification projection descriptor")
    return value


def _inventory(root: Path, excludes, role_for_path):
    descriptor = backup_archive._directory(root)
    try:
        entries, identities = backup_archive._inventory(descriptor, None, tuple(sorted(excludes)),
                                                         role_for_path, backup_archive.ArchiveLimits())
        identity = backup_archive._fingerprint(os.fstat(descriptor))
        return {"entries": entries, "identities": {name: list(value) for name, value in identities.items()},
                "root_identity": list(identity)}
    finally:
        os.close(descriptor)


def _verify_projection(snapshot: VerificationSnapshot) -> dict:
    if (os.geteuid() != 0 or type(snapshot) is not VerificationSnapshot
            or snapshot._token is not _TOKEN or snapshot._active is not True):
        raise PermissionError("sealed verification projection requires its active root-only context")
    outer = snapshot.manifest.parent
    if (outer.is_symlink() or outer.stat().st_uid != 0
            or stat.S_IMODE(outer.stat().st_mode) != 0o700
            or snapshot.root != outer / "workspace" or snapshot.root.is_symlink()
            or snapshot.root.stat().st_uid != 0
            or stat.S_IMODE(snapshot.root.stat().st_mode) != 0o700):
        raise PermissionError("verification projection has no private root ancestor")
    value = _read_manifest(snapshot.manifest)
    fields = {"schema_version", "kind", "root", "original_root", "profile_sha256",
              "source_inventory_sha256", "source_inventory", "projection_inventory_sha256",
              "projection_inventory", "excludes"}
    if (set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["kind"] != "root-readonly-verification-projection"
            or value["root"] != str(snapshot.root) or value["original_root"] != str(snapshot.original_root)
            or value["profile_sha256"] != snapshot.profile_sha256
            or _digest(value["source_inventory"]) != value["source_inventory_sha256"]
            or _digest(value["projection_inventory"]) != value["projection_inventory_sha256"]):
        raise PermissionError("verification projection descriptor binding differs")
    expected = value["projection_inventory"]
    found = []
    for directory, dirs, files in os.walk(snapshot.root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            if info.st_uid != 0 or (not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
                raise PermissionError("verification projection is not root-owned regular state")
            relative = path.relative_to(snapshot.root).as_posix()
            found.append({"path": relative, "type": "directory" if path.is_dir() else "file",
                "mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                "bytes": 0 if path.is_dir() else info.st_size,
                "sha256": None if path.is_dir() else _file_digest(path)})
    if sorted(found, key=lambda item: item["path"]) != expected:
        raise PermissionError("verification projection bytes, modes or ownership changed")
    record = strict_json_bytes(read_regular(snapshot.root / "workflow.json"))
    if record["workspace"] != str(snapshot.original_root) or record["profile_sha256"] != snapshot.profile_sha256:
        raise PermissionError("verification projection changed frozen workspace authority")
    # This is pure Python admission. Existing privileged Git readers run only
    # after every metadata directory passes, never against graph-writable bytes.
    from control_plane.evaluation_broker import validate_git_repository_metadata
    from control_plane.workspace_backup import _audit_git_configs
    _audit_git_configs(snapshot.root)
    for path in snapshot.root.rglob(".git"):
        validate_git_repository_metadata(path.parent)
        for relative in ("info/grafts", "refs/replace", "worktrees"):
            if (path / relative).exists():
                raise PermissionError("verification projection contains alternate Git history")
        packed = path / "packed-refs"
        if packed.exists():
            with packed.open("rt", encoding="utf-8") as stream:
                while line := stream.readline(4097):
                    if len(line) > 4096 or line.rstrip().rsplit(" ", 1)[-1].startswith("refs/replace/"):
                        raise PermissionError("verification projection contains invalid or replacement refs")
    return value


def snapshot_owner_uid(snapshot: VerificationSnapshot, root: Path, original_root: Path | None) -> int:
    """Internal read-only owner projection; never called by a mutation path."""
    _verify_projection(snapshot)
    if Path(root) != snapshot.root or Path(original_root or root) != snapshot.original_root:
        raise PermissionError("owner projection belongs to another verification root")
    return 0


@contextmanager
def verification_snapshot(root: Path, profile, *, original_root: Path, excludes, role_for_path):
    """Copy a caller-audited quiescent public closure with source/copy evidence."""
    if os.geteuid() != 0:
        raise PermissionError("only root may construct a read-only owner projection")
    root, original_root = Path(root), Path(original_root)
    if root.resolve(strict=True) != root or not original_root.is_absolute():
        raise ValueError("verification projection requires canonical paths")
    from control_plane.evaluation_broker import _safe_path
    _safe_path(root.parent, owner=0, parents=True)
    before = _inventory(root, excludes, role_for_path)
    with tempfile.TemporaryDirectory(prefix=".grapher-verification-projection-", dir=root.parent) as temporary:
        outer = Path(temporary)
        os.chmod(outer, 0o700)
        archive, view = outer / "public-state.tar", outer / "workspace"
        manifest = backup_archive.create_archive(root, archive, excludes=tuple(sorted(excludes)),
            metadata={"purpose": "private-readonly-owner-projection"}, role_for_path=role_for_path)
        view.mkdir(mode=0o700)
        if backup_archive.extract_archive(archive, view) != manifest:
            raise PermissionError("verification projection changed during extraction")
        projection = []
        for entry in manifest["entries"]:
            path = view / entry["path"]
            group = entry["group_role"]
            gid = 0 if group == "bootstrap" else profile.roles[group if group != "test" else "test_runner"].gid
            os.chown(path, 0, gid, follow_symlinks=False)
            os.chmod(path, entry["mode"], follow_symlinks=False)
            projection.append({"path": entry["path"], "type": entry["type"], "mode": entry["mode"],
                "uid": 0, "gid": gid, "bytes": entry["size"], "sha256": entry["sha256"]})
        after = _inventory(root, excludes, role_for_path)
        if before != after:
            raise PermissionError("source changed while constructing verification projection")
        descriptor = {"schema_version": 1, "kind": "root-readonly-verification-projection", "root": str(view),
            "original_root": str(original_root), "profile_sha256": profile.sha256,
            "source_inventory_sha256": _digest(before), "source_inventory": before,
            "projection_inventory_sha256": _digest(projection), "projection_inventory": projection,
            "excludes": sorted(excludes)}
        path = outer / "projection.json"
        with path.open("xb") as stream:
            stream.write(canonical(descriptor)); stream.flush(); os.fsync(stream.fileno())
        path.chmod(0o400)
        snapshot = VerificationSnapshot(view, original_root, path, profile.sha256, _TOKEN)
        _verify_projection(snapshot)
        try:
            yield snapshot
            if _inventory(root, excludes, role_for_path) != before:
                raise PermissionError("source changed during read-only closure verification")
        finally:
            snapshot._active = False


def _run_verifier(argv: list[str], *, environment: dict[str, str], cwd: Path,
                  timeout_seconds: float = 300, max_output_bytes: int = MAX_RECORD_BYTES):
    """Bound the fixed trusted reader and every Git child in its process group."""
    from control_plane.process_supervisor import terminate_group
    process = subprocess.Popen(argv, env=environment, cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout_seconds
    try:
        with selectors.DefaultSelector() as ready:
            for name in buffers:
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                ready.register(stream, selectors.EVENT_READ, name)
            while ready.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("snapshot verifier exceeded its execution deadline")
                for event, _ in ready.select(min(remaining, 0.1)):
                    block = os.read(event.fileobj.fileno(), min(65536, max_output_bytes - total + 1))
                    if not block:
                        ready.unregister(event.fileobj)
                        continue
                    total += len(block)
                    if total > max_output_bytes:
                        raise PermissionError("snapshot verifier output exceeds its bound")
                    buffers[event.data].extend(block)
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        return subprocess.CompletedProcess(argv, process.returncode,
            bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    finally:
        try:
            # This reader runs only fixed Python/Git/OpenSSL commands after
            # executable Git metadata is denied. None can detach a new session.
            terminate_group(process)
        finally:
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


def verify_backup_snapshot(snapshot: VerificationSnapshot) -> dict:
    """Run one fixed verifier action with no ambient Git/Python configuration."""
    _verify_projection(snapshot)
    from control_plane.execution_profile import load_execution_profile
    profile = load_execution_profile(snapshot.root / "frozen/profile.json", require_private_key=False)
    script = Path(profile.paths["trusted_code_root"]) / "control_plane/_verification_snapshot.py"
    if not script.is_file() or script.is_symlink():
        raise PermissionError("trusted installed projection verifier is unavailable")
    # Existing readonly readers use these fixed system commands. Refuse a
    # differing profile rather than silently substitute an unpinned executable.
    for name in ("git", "openssl"):
        resolved = shutil.which(name, path=os.defpath)
        if resolved is None or Path(resolved).resolve() != Path(profile.tools[name].path):
            raise PermissionError("snapshot verifier requires the pinned system " + name)
    environment = {"PATH": os.defpath, "HOME": "/nonexistent", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file", "GIT_TEMPLATE_DIR": "/nonexistent"}
    result = _run_verifier([profile.tools["python"].path, "-I", "-B", str(script), "--verify-backup", str(snapshot.manifest)],
        environment=environment, cwd=snapshot.manifest.parent)
    if result.returncode:
        raise PermissionError("root-owned snapshot closure verification failed: " + result.stderr.decode("utf-8", "replace")[-4096:])
    if len(result.stdout) > MAX_RECORD_BYTES:
        raise PermissionError("snapshot verifier output exceeds its bound")
    value = json.loads(result.stdout, object_pairs_hook=backup_archive._unique)
    if type(value) is not dict:
        raise PermissionError("snapshot verifier returned invalid closure")
    return value


def _main(arguments: list[str]) -> int:
    if len(arguments) != 2 or arguments[0] != "--verify-backup" or os.geteuid() != 0:
        raise PermissionError("invalid internal snapshot verifier action")
    manifest = Path(arguments[1])
    value = _read_manifest(manifest)
    snapshot = VerificationSnapshot(Path(value["root"]), Path(value["original_root"]), manifest, value["profile_sha256"], _TOKEN)
    _verify_projection(snapshot)
    from control_plane.execution_profile import load_execution_profile
    from control_plane.workspace_backup import _verify_all
    profile = load_execution_profile(snapshot.root / "frozen/profile.json", require_private_key=False)
    if profile.sha256 != snapshot.profile_sha256:
        raise PermissionError("snapshot verification profile differs")
    result = _verify_all(snapshot.root, original_root=snapshot.original_root, profile=profile, _snapshot=snapshot)
    _verify_projection(snapshot)
    sys.stdout.buffer.write(canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
