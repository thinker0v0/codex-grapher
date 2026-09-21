"""Deterministic, bounded workspace archives; policy and ownership stay with callers.

Only the uncompressed USTAR subset is accepted. No archive UID/GID is restored.
The caller must quiesce the source, choose exclusions, and apply trusted semantic
ownership after extraction into its private, empty staging directory.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from typing import Callable, Iterable


class ArchiveError(ValueError):
    """Invalid, unsafe, changed, or over-limit archive/source."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_entries: int = 200_000
    max_manifest_bytes: int = 64 * 1024 * 1024
    max_file_bytes: int = 1024 * 1024 * 1024
    max_total_bytes: int = 8 * 1024 * 1024 * 1024


ROLES = frozenset({"bootstrap", "graph", "worker", "test", "signer"})
MANIFEST_NAME = "__backup_manifest__.json"
_BLOCK = 512
_CHUNK = 1024 * 1024
_ENTRY_KEYS = {"path", "type", "mode", "size", "sha256", "owner_role", "group_role"}
_SGID_DIRECTORY_MODES = {"state": 0o2700, "publications": 0o2750}


def _allowed_mode(relative: str, kind: str, mode: int) -> bool:
    if type(mode) is not int or mode < 0:
        return False
    return mode <= 0o777 or (
        kind == "directory" and _SGID_DIRECTORY_MODES.get(relative) == mode
    )


def _allowed_entry_mode(entry: dict) -> bool:
    return _allowed_mode(entry["path"], entry["type"], entry["mode"]) and (
        entry["mode"] <= 0o777
        or (entry["owner_role"], entry["group_role"]) == ("graph", "worker")
    )


def _limits(limits: ArchiveLimits) -> None:
    if not isinstance(limits, ArchiveLimits) or any(
        type(value) is not int or value < 1 for value in vars(limits).values()
    ):
        raise ArchiveError("archive limits must be positive integers")


def _relative(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ArchiveError("invalid relative archive path")
    if "\\" in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ArchiveError("invalid character in archive path")
    if any(part in {"", ".", ".."} for part in value.split("/")):
        raise ArchiveError("archive path must be canonical and relative")
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError) as exc:
        raise ArchiveError("manifest is not bounded JSON data") from exc


def _unique(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArchiveError("duplicate manifest JSON key")
        result[key] = value
    return result


def _fingerprint(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_uid, info.st_gid)


def _directory(path: Path) -> int:
    """Pin every absolute path component without following symlinks."""
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except OSError as exc:
        os.close(fd)
        raise ArchiveError("directory path is missing, linked, or inaccessible") from exc


def _source_open(root_fd: int, relative: str, directory: bool = False) -> int:
    parts = relative.split("/")
    parent_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        return os.open(parts[-1], flags, dir_fd=parent_fd)
    except OSError as exc:
        raise ArchiveError("source path changed or is inaccessible") from exc
    finally:
        os.close(parent_fd)


def _hash_fd(fd: int, expected_size: int) -> str:
    digest = hashlib.sha256()
    remaining = expected_size
    while remaining:
        data = os.read(fd, min(_CHUNK, remaining))
        if not data:
            raise ArchiveError("source shortened while reading")
        remaining -= len(data)
        digest.update(data)
    if os.read(fd, 1):
        raise ArchiveError("source grew while reading")
    return digest.hexdigest()


def _header(name: str, kind: str, mode: int, size: int) -> tarfile.TarInfo:
    member = tarfile.TarInfo(name)
    member.type = tarfile.DIRTYPE if kind == "directory" else tarfile.REGTYPE
    member.mode = mode
    member.size = size
    # The archive deliberately carries no numeric ownership authority.
    member.uid = member.gid = member.mtime = 0
    member.uname = member.gname = ""
    return member


def _inventory(root_fd: int, includes: tuple[str, ...] | None,
               excludes: tuple[str, ...], role_for_path: Callable | None,
               limits: ArchiveLimits) -> tuple[list[dict], dict[str, tuple]]:
    entries: list[dict] = []
    fingerprints: dict[str, tuple] = {}
    seen_includes: set[str] = set()
    total = 0

    def walk(parent_fd: int, prefix: str) -> None:
        nonlocal total
        with os.scandir(parent_fd) as listing:
            names = []
            for item in listing:
                if len(names) >= limits.max_entries:
                    raise ArchiveError("source directory entry limit exceeded")
                names.append(item.name)
            names.sort()
        for name in names:
            relative = _relative(f"{prefix}/{name}" if prefix else name)
            if any(relative == item or relative.startswith(item + "/") for item in excludes):
                continue
            if includes is not None and not any(
                relative == item or relative.startswith(item + "/") or item.startswith(relative + "/")
                for item in includes
            ):
                continue
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            is_dir = stat.S_ISDIR(info.st_mode)
            if not is_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                raise ArchiveError("source contains a link or special file")
            mode = stat.S_IMODE(info.st_mode)
            if len(entries) >= limits.max_entries:
                raise ArchiveError("source entry limit exceeded")
            size = 0 if is_dir else info.st_size
            if size > limits.max_file_bytes or total + size > limits.max_total_bytes:
                raise ArchiveError("source byte limit exceeded")
            total += size
            roles = ("graph", "graph") if role_for_path is None else role_for_path(relative, info)
            if not isinstance(roles, (tuple, list)) or len(roles) != 2 or any(
                type(role) is not str or role not in ROLES for role in roles
            ):
                raise ArchiveError("unknown semantic ownership role")
            entry = {"path": relative, "type": "directory" if is_dir else "file",
                     "mode": mode, "size": size, "sha256": None,
                     "owner_role": roles[0], "group_role": roles[1]}
            if not _allowed_entry_mode(entry):
                raise ArchiveError("unsupported source permission mode or inheritance role")
            _header("payload/" + relative, entry["type"], mode, size).tobuf(
                format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict")
            child_fd = _source_open(root_fd, relative, is_dir)
            try:
                if _fingerprint(os.fstat(child_fd)) != _fingerprint(info):
                    raise ArchiveError("source changed before reading")
                if not is_dir:
                    entry["sha256"] = _hash_fd(child_fd, size)
                entries.append(entry)
                fingerprints[relative] = _fingerprint(info)
                seen_includes.add(relative)
                if is_dir:
                    walk(child_fd, relative)
                if _fingerprint(os.fstat(child_fd)) != _fingerprint(info):
                    raise ArchiveError("source changed while reading")
            finally:
                os.close(child_fd)

    walk(root_fd, "")
    if includes is not None and any(item not in seen_includes for item in includes):
        raise ArchiveError("included source path is missing or excluded")
    entries.sort(key=lambda entry: entry["path"])
    return entries, fingerprints


class _HashReader:
    def __init__(self, file):
        self.file = file
        self.digest = hashlib.sha256()

    def read(self, size: int) -> bytes:
        data = self.file.read(size)
        self.digest.update(data)
        return data


def create_archive(source_root: str | Path, archive_path: str | Path, *,
                   includes: Iterable[str] | None = None, excludes: Iterable[str] = (),
                   metadata: dict | None = None, role_for_path: Callable | None = None,
                   limits: ArchiveLimits = ArchiveLimits()) -> dict:
    """Hash, copy, verify, fsync and exclusively publish a deterministic archive.

    Includes select descendants and retain all ancestor directories. Exclusions
    are exact relative paths and recursively omit their descendants. The role
    callback receives (relative_path, lstat_result), returning (owner, group).
    USTAR-unrepresentable names and privileged modes fail closed, except the
    graph/worker-owned state (02700) and publications (02750) directories.
    """
    _limits(limits)
    selected = None if includes is None else tuple(_relative(item) for item in includes)
    omitted = tuple(_relative(item) for item in excludes)
    if metadata is not None and not isinstance(metadata, dict):
        raise ArchiveError("archive metadata must be an object")
    source = Path(source_root)
    output = Path(archive_path)
    root_fd = _directory(source)
    output_fd = None
    temporary = None
    try:
        output_fd = _directory(output.parent)
        if output.name in {"", ".", ".."}:
            raise ArchiveError("invalid archive output path")
        try:
            os.stat(output.name, dir_fd=output_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ArchiveError("archive destination already exists")
        # Never permit output within the source, even if excluded by the caller.
        source_path = Path(os.path.realpath(f"/proc/self/fd/{root_fd}"))
        output_parent = Path(os.path.realpath(f"/proc/self/fd/{output_fd}"))
        if output_parent == source_path or source_path in output_parent.parents:
            raise ArchiveError("archive output must be outside source")
        root_fingerprint = _fingerprint(os.fstat(root_fd))
        entries, fingerprints = _inventory(root_fd, selected, omitted, role_for_path, limits)
        manifest = {"schema_version": 1, "metadata": metadata or {}, "entries": entries}
        raw = _canonical(manifest)
        if len(raw) > limits.max_manifest_bytes:
            raise ArchiveError("manifest byte limit exceeded")
        fd, temporary = tempfile.mkstemp(prefix=".backup-", suffix=".tar", dir=output_parent)
        with os.fdopen(fd, "wb") as output_file:
            with tarfile.open(fileobj=output_file, mode="w", format=tarfile.USTAR_FORMAT,
                              encoding="utf-8", errors="strict") as archive:
                archive.addfile(_header(MANIFEST_NAME, "file", 0o600, len(raw)), io.BytesIO(raw))
                for entry in entries:
                    relative = entry["path"]
                    is_dir = entry["type"] == "directory"
                    member = _header("payload/" + relative, entry["type"], entry["mode"], entry["size"])
                    child_fd = _source_open(root_fd, relative, is_dir)
                    try:
                        if _fingerprint(os.fstat(child_fd)) != fingerprints[relative]:
                            raise ArchiveError("source changed after inventory")
                        if is_dir:
                            archive.addfile(member)
                        else:
                            with os.fdopen(os.dup(child_fd), "rb") as input_file:
                                reader = _HashReader(input_file)
                                archive.addfile(member, reader)
                                if reader.digest.hexdigest() != entry["sha256"] or input_file.read(1):
                                    raise ArchiveError("source content changed after inventory")
                        if _fingerprint(os.fstat(child_fd)) != fingerprints[relative]:
                            raise ArchiveError("source changed during archive creation")
                    finally:
                        os.close(child_fd)
            output_file.flush()
            os.fsync(output_file.fileno())
        inspect_archive(temporary, limits=limits)
        if _fingerprint(os.fstat(root_fd)) != root_fingerprint:
            raise ArchiveError("source root changed during archive creation")
        for entry in entries:
            child_fd = _source_open(root_fd, entry["path"], entry["type"] == "directory")
            try:
                if _fingerprint(os.fstat(child_fd)) != fingerprints[entry["path"]]:
                    raise ArchiveError("source changed before archive publication")
            finally:
                os.close(child_fd)
        # link() is an atomic, no-replace publication; the temporary name is private.
        os.link(temporary, output.name, dst_dir_fd=output_fd, follow_symlinks=False)
        os.unlink(temporary)
        temporary = None
        os.fsync(output_fd)
        return manifest
    except (OSError, tarfile.TarError, UnicodeError, ValueError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("archive creation failed") from exc
    finally:
        os.close(root_fd)
        if output_fd is not None:
            os.close(output_fd)
        if temporary is not None:
            os.unlink(temporary)


def _validate_manifest(raw: bytes, limits: ArchiveLimits) -> dict:
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique,
                              parse_constant=lambda value: (_ for _ in ()).throw(ArchiveError("nonfinite JSON")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ArchiveError("invalid archive manifest JSON") from exc
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "metadata", "entries"}:
        raise ArchiveError("invalid manifest fields")
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ArchiveError("unsupported archive schema")
    if not isinstance(manifest["metadata"], dict) or not isinstance(manifest["entries"], list):
        raise ArchiveError("invalid manifest metadata or entries")
    if _canonical(manifest) != raw:
        raise ArchiveError("manifest is not canonical JSON")
    entries = manifest["entries"]
    if len(entries) > limits.max_entries:
        raise ArchiveError("archive entry limit exceeded")
    known: dict[str, str] = {}
    previous = ""
    total = 0
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
            raise ArchiveError("invalid inventory fields")
        relative = _relative(entry["path"])
        if relative <= previous:
            raise ArchiveError("duplicate or unordered inventory path")
        previous = relative
        if type(entry["type"]) is not str or entry["type"] not in {"file", "directory"}:
            raise ArchiveError("unsupported inventory type")
        if not _allowed_entry_mode(entry):
            raise ArchiveError("invalid inventory permission mode or inheritance role")
        if type(entry["size"]) is not int or not 0 <= entry["size"] <= limits.max_file_bytes:
            raise ArchiveError("invalid inventory file size")
        if any(type(entry[field]) is not str or entry[field] not in ROLES
               for field in ("owner_role", "group_role")):
            raise ArchiveError("unknown semantic ownership role")
        if entry["type"] == "directory":
            if entry["size"] != 0 or entry["sha256"] is not None:
                raise ArchiveError("invalid directory inventory")
        elif (not isinstance(entry["sha256"], str) or len(entry["sha256"]) != 64
              or any(char not in "0123456789abcdef" for char in entry["sha256"])):
            raise ArchiveError("invalid inventory digest")
        parent = relative.rpartition("/")[0]
        if parent and known.get(parent) != "directory":
            raise ArchiveError("inventory parent directory is missing")
        known[relative] = entry["type"]
        total += entry["size"]
        if total > limits.max_total_bytes:
            raise ArchiveError("archive total byte limit exceeded")
    return manifest


def _read_exact(file, size: int) -> bytes:
    value = file.read(size)
    if len(value) != size:
        raise ArchiveError("truncated archive")
    return value


def _read_header(file) -> tarfile.TarInfo:
    raw = _read_exact(file, _BLOCK)
    try:
        member = tarfile.TarInfo.frombuf(raw, "utf-8", "strict")
        if member.type not in {tarfile.REGTYPE, tarfile.DIRTYPE}:
            raise ArchiveError("archive links, extensions and special files are forbidden")
        relative = member.name[len("payload/"):] if member.name.startswith("payload/") else ""
        kind = "directory" if member.type == tarfile.DIRTYPE else "file"
        if (member.uid != 0 or member.gid != 0 or member.uname or member.gname
                or member.mtime != 0 or member.linkname or member.devmajor or member.devminor
                or not _allowed_mode(relative, kind, member.mode) or member.size < 0):
            raise ArchiveError("unsupported archive header metadata")
        if member.tobuf(format=tarfile.USTAR_FORMAT, encoding="utf-8", errors="strict") != raw:
            raise ArchiveError("noncanonical archive header")
        return member
    except (tarfile.TarError, ValueError, UnicodeError) as exc:
        if isinstance(exc, ArchiveError):
            raise
        raise ArchiveError("invalid archive header") from exc


def _set_mode(descriptor: int, mode: int) -> None:
    os.fchmod(descriptor, mode)
    if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode:
        raise ArchiveError("filesystem did not preserve the requested archive mode")


def _padding(file, size: int) -> None:
    if any(_read_exact(file, (-size) % _BLOCK)):
        raise ArchiveError("nonzero archive member padding")


def _scan(file, limits: ArchiveLimits, destination_fd: int | None = None) -> dict:
    first = _read_header(file)
    if (first.name != MANIFEST_NAME or first.type != tarfile.REGTYPE or first.mode != 0o600
            or first.size > limits.max_manifest_bytes):
        raise ArchiveError("missing or over-limit archive manifest")
    manifest = _validate_manifest(_read_exact(file, first.size), limits)
    _padding(file, first.size)
    directories = []
    for entry in manifest["entries"]:
        member = _read_header(file)
        expected_type = tarfile.DIRTYPE if entry["type"] == "directory" else tarfile.REGTYPE
        if (member.name != "payload/" + entry["path"] or member.type != expected_type
                or member.mode != entry["mode"] or member.size != entry["size"]):
            raise ArchiveError("archive member differs from exact inventory")
        target = None
        if destination_fd is not None:
            parent, _, leaf = entry["path"].rpartition("/")
            parent_fd = _source_open(destination_fd, parent, True) if parent else os.dup(destination_fd)
            try:
                if entry["type"] == "directory":
                    os.mkdir(leaf, 0o700, dir_fd=parent_fd)
                    directories.append(entry)
                else:
                    target = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=parent_fd)
            finally:
                os.close(parent_fd)
        digest = hashlib.sha256()
        remaining = member.size
        try:
            while remaining:
                chunk = _read_exact(file, min(_CHUNK, remaining))
                remaining -= len(chunk)
                digest.update(chunk)
                if target is not None:
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target, view)
                        if written <= 0:
                            raise ArchiveError("archive extraction write failed")
                        view = view[written:]
            if entry["type"] == "file" and digest.hexdigest() != entry["sha256"]:
                raise ArchiveError("archive content hash mismatch")
            if target is not None:
                _set_mode(target, entry["mode"])
                os.fsync(target)
        finally:
            if target is not None:
                os.close(target)
        _padding(file, member.size)
    # Reject missing terminators, concatenated tars, hidden members, and trailing data.
    offset = file.tell()
    expected_tail = ((offset + 1024 + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE - offset
    if any(_read_exact(file, expected_tail)) or file.read(1):
        raise ArchiveError("archive has extra entries or invalid termination")
    if destination_fd is not None:
        for entry in reversed(directories):
            directory_fd = _source_open(destination_fd, entry["path"], True)
            try:
                _set_mode(directory_fd, entry["mode"])
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        os.fsync(destination_fd)
    return manifest


def _archive_file(path: str | Path, limits: ArchiveLimits):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        maximum = (limits.max_total_bytes + limits.max_manifest_bytes
                   + (limits.max_entries + 1) * 1024 + tarfile.RECORDSIZE + 1024)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            os.close(fd)
            raise ArchiveError("archive is not a bounded regular file")
        return os.fdopen(fd, "rb")
    except OSError as exc:
        raise ArchiveError("archive is missing, linked, or inaccessible") from exc


def inspect_archive(archive_path: str | Path, *, limits: ArchiveLimits = ArchiveLimits()) -> dict:
    """Read and validate every byte without changing archive content or modes."""
    _limits(limits)
    with _archive_file(archive_path, limits) as file:
        before = _fingerprint(os.fstat(file.fileno()))
        manifest = _scan(file, limits)
        if _fingerprint(os.fstat(file.fileno())) != before:
            raise ArchiveError("archive changed during validation")
        return manifest


def extract_archive(archive_path: str | Path, empty_destination: str | Path, *,
                    limits: ArchiveLimits = ArchiveLimits()) -> dict:
    """Validate then stream files to an existing private empty staging directory.

    Extracted entries belong to the extracting process; semantic ownership must
    be applied by the wrapper using its trusted profile. Failure preserves staging
    bytes for diagnosis, and never changes the source archive.
    """
    _limits(limits)
    destination_fd = _directory(Path(empty_destination))
    try:
        if os.listdir(destination_fd):
            raise ArchiveError("archive extraction destination must be empty")
        destination_info = os.fstat(destination_fd)
        if (stat.S_IMODE(destination_info.st_mode) & 0o077
                or destination_info.st_uid != os.geteuid()):
            raise ArchiveError("archive extraction destination must be private and owned by extractor")
        with _archive_file(archive_path, limits) as file:
            before = _fingerprint(os.fstat(file.fileno()))
            _scan(file, limits)
            if _fingerprint(os.fstat(file.fileno())) != before:
                raise ArchiveError("archive changed during validation")
            file.seek(0)
            manifest = _scan(file, limits, destination_fd)
            if _fingerprint(os.fstat(file.fileno())) != before:
                raise ArchiveError("archive changed during extraction")
            return manifest
    except OSError as exc:
        raise ArchiveError("archive extraction failed") from exc
    finally:
        os.close(destination_fd)
