"""Verified SQLite durability profiles and a process-lifetime writer owner.

The default avoids the WAL-reset defect; it does not claim to patch SQLite.
All supported writers must use this module. Advisory locks cannot constrain
arbitrary programs which deliberately bypass the application protocol.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import threading
from pathlib import Path
from typing import Any
from urllib.parse import quote

import _sqlite3


FIXED_VERSION = "3.53.4"
FIXED_SOURCE_ID = "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"
ARCHIVE_SHA256 = "0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c"
ARCHIVE_SHA3 = "454e45f61c6bd75b7420e7190732dea03ce6639c63ada47bbc592f67fc340338"
SOURCE_SHA256 = "b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189"
UNPATCHED_LIBRARY_SHA256 = "85265a9d4afca6f4b325ceb078b669c754fb881abed4cafe91ccebe9d625d975"
PROFILES = {"delete-extra": ("delete", 3), "wal-full": ("wal", 2)}
BUILD_FLAGS = ["-O2", "-fPIC", "-shared", "-DSQLITE_THREADSAFE=1",
               "-DSQLITE_ENABLE_FTS5", "-DSQLITE_ENABLE_COLUMN_METADATA",
               "-ldl", "-lpthread", "-lm", "-Wl,-soname,libsqlite3.so.0"]
MAINTENANCE_GUIDANCE = (
    "existing journal mode requires explicit offline maintenance and backup with "
    "the verified fixed runtime; use python -m control_plane.sqlite_runtime maintain; "
    "never delete journal/WAL/SHM sidecars"
)


class SQLiteRuntimeError(RuntimeError):
    """The observed runtime or database does not satisfy its support policy."""


def _sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _regular(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SQLiteRuntimeError("SQLite policy files must be regular single-link files")
    return metadata


def _database_path(database: Path, *, create: bool = False) -> Path:
    path = Path(os.path.abspath(database))
    # Canonicalize the parent so aliases cannot acquire independent owner locks.
    path = path.parent.resolve(strict=True) / path.name
    if path.is_symlink():
        raise SQLiteRuntimeError("SQLite database must not be a symlink")
    if path.exists():
        _regular(path)
    elif not create:
        raise SQLiteRuntimeError("SQLite database must be explicitly bootstrapped")
    return path


def _header_mode(database: Path) -> str | None:
    if not database.exists() or database.stat().st_size == 0:
        return None
    with database.open("rb") as stream:
        header = stream.read(100)
    if len(header) < 100 or header[:16] != b"SQLite format 3\0":
        raise SQLiteRuntimeError("invalid SQLite database header")
    if header[18:20] == b"\x02\x02":
        return "wal"
    if header[18:20] == b"\x01\x01":
        return "delete"
    raise SQLiteRuntimeError("unsupported SQLite database format")


def runtime_identity() -> dict[str, Any]:
    """Observe the SQLite library actually resolving Python's SQLite symbols."""
    connection = sqlite3.connect(":memory:")
    try:
        version, source_id = connection.execute(
            "SELECT sqlite_version(), sqlite_source_id()"
        ).fetchone()
        options = sorted(row[0] for row in connection.execute("PRAGMA compile_options"))
    finally:
        connection.close()
    result: dict[str, Any] = {
        "version": version, "source_id": source_id, "compile_options": options,
        "python_sqlite_extension_sha256": _sha256(Path(_sqlite3.__file__)),
        "library_path": None, "library_sha256": None, "library_mapping_verified": False,
    }
    try:
        class DlInfo(ctypes.Structure):
            _fields_ = [("name", ctypes.c_char_p), ("base", ctypes.c_void_p),
                        ("symbol", ctypes.c_char_p), ("address", ctypes.c_void_p)]

        extension = ctypes.CDLL(_sqlite3.__file__)
        symbol = ctypes.cast(extension.sqlite3_libversion, ctypes.c_void_p)
        dladdr = ctypes.CDLL(None).dladdr
        dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
        dladdr.restype = ctypes.c_int
        info = DlInfo()
        if not dladdr(symbol, ctypes.byref(info)) or not info.name:
            raise SQLiteRuntimeError("actual SQLite library symbol is not identifiable")
        library = Path(os.fsdecode(info.name)).resolve(strict=True)
        metadata = _regular(library)
        mappings = Path("/proc/self/maps").read_text().splitlines()
        matched = False
        for row in mappings:
            fields = row.split(maxsplit=5)
            lower, upper = (int(part, 16) for part in fields[0].split("-"))
            if lower <= symbol.value < upper and len(fields) == 6:
                major, minor = (int(part, 16) for part in fields[3].split(":"))
                matched = (
                    int(fields[4]) == metadata.st_ino
                    and os.makedev(major, minor) == metadata.st_dev
                    and Path(fields[5]).resolve(strict=True) == library
                )
        if not matched:
            raise SQLiteRuntimeError("loaded SQLite mapping differs from library bytes on disk")
        result.update(library_path=str(library), library_sha256=_sha256(library),
                      library_mapping_verified=True)
    except (OSError, ValueError, AttributeError, SQLiteRuntimeError) as exc:
        result["mapping_error"] = str(exc)
    return result


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SQLiteRuntimeError("duplicate SQLite attestation field")
        result[key] = value
    return result


def _verify_attestation(attestation: Path, observed: dict[str, Any]) -> None:
    path = Path(attestation)
    if not path.is_absolute():
        raise SQLiteRuntimeError("SQLite attestation must be an absolute trusted path")
    metadata = _regular(path)
    if metadata.st_mode & 0o022:
        raise SQLiteRuntimeError("SQLite attestation must not be group/world writable")
    if metadata.st_size > 65536:
        raise SQLiteRuntimeError("SQLite attestation is too large")
    data = json.loads(path.read_text(), object_pairs_hook=_strict_object)
    keys = {
        "schema_version", "kind", "version", "source_id", "archive_sha256",
        "source_sha256", "library_sha256", "library_path", "compiler_path",
        "compiler_sha256", "compiler_version", "compiler_flags", "compile_options",
        "python_sqlite_extension_sha256",
    }
    if not isinstance(data, dict) or set(data) != keys:
        raise SQLiteRuntimeError("unsupported SQLite build attestation schema")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise SQLiteRuntimeError("unsupported SQLite build attestation version")
    expected = {
        "kind": "codex-grapher-sqlite-build", "version": FIXED_VERSION,
        "source_id": FIXED_SOURCE_ID, "archive_sha256": ARCHIVE_SHA256,
        "source_sha256": SOURCE_SHA256,
    }
    if any(data[key] != value for key, value in expected.items()):
        raise SQLiteRuntimeError("SQLite source is not the pinned verified fixed release")
    if not observed["library_mapping_verified"]:
        raise SQLiteRuntimeError("actual loaded SQLite library identity is unproven")
    for key in ("version", "source_id", "library_sha256", "library_path",
                "compile_options", "python_sqlite_extension_sha256"):
        if data[key] != observed[key]:
            raise SQLiteRuntimeError(f"SQLite attestation mismatch: {key}")
    prefix = path.parent
    source = prefix / "source" / "sqlite3.c"
    archive = prefix / "source" / "sqlite-autoconf-3530400.tar.gz"
    for item in (source, archive, Path(data["library_path"])):
        item_meta = _regular(item)
        if item_meta.st_mode & 0o022:
            raise SQLiteRuntimeError("SQLite build evidence is writable by another role")
    if _sha256(source) != SOURCE_SHA256 or _sha256(archive) != ARCHIVE_SHA256:
        raise SQLiteRuntimeError("SQLite build source/archive evidence changed")
    if data["compiler_flags"] != BUILD_FLAGS:
        raise SQLiteRuntimeError("SQLite compiler flags differ from the supported build recipe")
    if "THREADSAFE=1" not in data["compile_options"]:
        raise SQLiteRuntimeError("SQLite runtime must enable thread safety")
    for key in ("compiler_path", "compiler_version", "compiler_sha256"):
        if type(data[key]) is not str or not data[key]:
            raise SQLiteRuntimeError("SQLite compiler provenance is missing")
    if len(data["compiler_sha256"]) != 64 or any(
        value not in "0123456789abcdef" for value in data["compiler_sha256"]
    ):
        raise SQLiteRuntimeError("SQLite compiler digest is invalid")


def runtime_status(attestation: Path | str | None = None) -> dict[str, Any]:
    result = runtime_identity()
    result["patch_status"] = "UNPROVEN"
    if (result["library_mapping_verified"]
            and result["library_sha256"] == UNPATCHED_LIBRARY_SHA256):
        result["patch_status"] = "UNPATCHED"
    if attestation is not None:
        try:
            _verify_attestation(Path(attestation), result)
        except (OSError, ValueError, TypeError, SQLiteRuntimeError) as exc:
            result["attestation_error"] = str(exc)
        else:
            result["patch_status"] = "FIXED"
    return result


def validate_attestation(attestation: Path | str) -> dict[str, Any]:
    """Validate operator-owned provenance against this process's loaded runtime."""
    result = runtime_status(attestation)
    if result["patch_status"] != "FIXED":
        raise SQLiteRuntimeError(result.get("attestation_error", "fixed SQLite runtime is unproven"))
    return result


def _receipt_path(database: Path) -> Path:
    return Path(f"{database}.sqlite-runtime.json")


def _runtime_binding(runtime: dict[str, Any], attestation: Path | str) -> dict[str, str]:
    return {"version": runtime["version"], "source_id": runtime["source_id"],
            "library_sha256": runtime["library_sha256"],
            "attestation_sha256": _sha256(Path(attestation))}


def _write_runtime_receipt(
    database: Path, runtime: dict[str, Any], attestation: Path | str,
    *, kind: str, profile: str, backup_manifest_sha256: str | None,
) -> None:
    receipt = {"schema_version": 1, "database_path": str(database),
               "kind": kind, "profile": profile,
               "runtime": _runtime_binding(runtime, attestation),
               "backup_manifest_sha256": backup_manifest_sha256}
    target = _receipt_path(database)
    # A successful explicit maintenance may replace this public provenance
    # receipt; its old bytes remain in the fsynced maintenance backup.
    temporary = target.with_name(f"{target.name}.tmp-{os.getpid()}")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as output:
            json.dump(receipt, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
        fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary.exists():
            temporary.unlink()


def _verify_runtime_receipt(
    database: Path, runtime: dict[str, Any], attestation: Path | str,
    *, original_database: Path | None = None,
) -> None:
    path = _receipt_path(database)
    try:
        metadata = _regular(path)
        if metadata.st_mode & 0o022 or metadata.st_size > 8192:
            raise SQLiteRuntimeError("unsafe SQLite maintenance receipt")
        value = json.loads(path.read_text(), object_pairs_hook=_strict_object)
        keys = {"schema_version", "database_path", "kind", "profile", "runtime", "backup_manifest_sha256"}
        if not isinstance(value, dict) or set(value) != keys:
            raise SQLiteRuntimeError("invalid SQLite maintenance receipt schema")
        expected_database = database if original_database is None else original_database
        if (type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["database_path"] != str(expected_database) or value["profile"] != "wal-full"
                or value["runtime"] != _runtime_binding(runtime, attestation)):
            raise SQLiteRuntimeError("SQLite maintenance receipt binding mismatch")
        backup_hash = value["backup_manifest_sha256"]
        if value["kind"] == "fresh-wal":
            if backup_hash is not None:
                raise SQLiteRuntimeError("invalid fresh SQLite runtime receipt")
        elif value["kind"] == "offline-maintenance":
            if (type(backup_hash) is not str or len(backup_hash) != 64
                    or any(character not in "0123456789abcdef" for character in backup_hash)):
                raise SQLiteRuntimeError("SQLite maintenance backup binding is missing")
        else:
            raise SQLiteRuntimeError("unknown SQLite maintenance receipt kind")
    except (OSError, ValueError, TypeError) as exc:
        raise SQLiteRuntimeError(MAINTENANCE_GUIDANCE) from exc


_owners: dict[Path, "DatabaseOwner"] = {}
_owners_guard = threading.RLock()


class DatabaseOwner:
    """One kernel flock held until every connection in its owning PID closes."""

    def __init__(self, database: Path):
        self.database = database
        self.pid = os.getpid()
        self.references = 0
        self.maintenance = False
        self.lock_path = Path(f"{database}.owner.lock")
        self.fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(self.fd)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
                raise SQLiteRuntimeError("unsafe SQLite owner lock")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_owned()
        except BaseException as exc:
            os.close(self.fd)
            self.fd = -1
            if isinstance(exc, BlockingIOError):
                raise SQLiteRuntimeError("SQLite database has another process owner") from exc
            raise

    def assert_owned(self) -> None:
        if self.pid != os.getpid() or self.fd < 0:
            raise SQLiteRuntimeError("SQLite owner belongs to another or closed process")
        opened = os.fstat(self.fd)
        named = self.lock_path.lstat()
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise SQLiteRuntimeError("SQLite owner lock was replaced")

    def release(self) -> None:
        with _owners_guard:
            self.references -= 1
            if self.references == 0 and self.fd >= 0:
                # close, rather than LOCK_UN, also keeps fork semantics safe.
                os.close(self.fd)
                self.fd = -1
                if _owners.get(self.database) is self:
                    del _owners[self.database]


def _acquire_owner(database: Path, owner: DatabaseOwner | None, *, exclusive: bool = False) -> DatabaseOwner:
    with _owners_guard:
        existing = _owners.get(database)
        if exclusive and existing is not None:
            raise SQLiteRuntimeError("offline SQLite operation requires all application writers closed")
        if owner is not None and (owner is not existing or owner.database != database):
            raise SQLiteRuntimeError("auxiliary SQLite connection has a different owner")
        if existing is None:
            existing = DatabaseOwner(database)
            _owners[database] = existing
        existing.assert_owned()
        if existing.maintenance:
            raise SQLiteRuntimeError("SQLite database is under exclusive offline maintenance")
        existing.references += 1
        if exclusive:
            existing.maintenance = True
        return existing


def _after_fork() -> None:
    global _owners_guard
    for owner in _owners.values():
        if owner.fd >= 0:
            os.close(owner.fd)
            owner.fd = -1
    _owners.clear()
    _owners_guard = threading.RLock()


os.register_at_fork(after_in_child=_after_fork)


class OwnedCursor(sqlite3.Cursor):
    def execute(self, *args, **kwargs):
        self.connection._assert_owner()
        return super().execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        self.connection._assert_owner()
        return super().executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        self.connection._assert_owner()
        return super().executescript(*args, **kwargs)

    def fetchone(self):
        self.connection._assert_owner()
        return super().fetchone()

    def fetchmany(self, *args, **kwargs):
        self.connection._assert_owner()
        return super().fetchmany(*args, **kwargs)

    def fetchall(self):
        self.connection._assert_owner()
        return super().fetchall()

    def __next__(self):
        self.connection._assert_owner()
        return super().__next__()


class OwnedConnection(sqlite3.Connection):
    owner: DatabaseOwner | None = None
    sqlite_profile: str
    sqlite_attestation: Path | str | None
    runtime_report: dict[str, Any]

    def _assert_owner(self) -> None:
        if self.owner is None:
            raise SQLiteRuntimeError("SQLite owner connection is closed")
        self.owner.assert_owned()

    def execute(self, *args, **kwargs):
        return self.cursor().execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self.cursor().executemany(*args, **kwargs)

    def executescript(self, *args, **kwargs):
        return self.cursor().executescript(*args, **kwargs)

    def cursor(self, factory=OwnedCursor):
        self._assert_owner()
        if factory is not OwnedCursor:
            raise SQLiteRuntimeError("custom SQLite cursor bypasses owner policy")
        return super().cursor(factory)

    def commit(self):
        self._assert_owner()
        return super().commit()

    def rollback(self):
        self._assert_owner()
        return super().rollback()

    def __enter__(self):
        self._assert_owner()
        return super().__enter__()

    def __exit__(self, *args):
        self._assert_owner()
        return super().__exit__(*args)

    def close(self) -> None:
        if getattr(self, "_connection_pid", os.getpid()) != os.getpid():
            self.owner = None
            raise SQLiteRuntimeError("cannot close an inherited SQLite connection")
        super().close()
        if self.owner is not None:
            owner, self.owner = self.owner, None
            owner.release()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            # SQLite enforces thread checks on explicit close. Its C destructor
            # closes an unreachable connection; release the corresponding lock.
            if self.owner is not None:
                owner, self.owner = self.owner, None
                owner.release()


def connect_database(
    database: Path, *, profile: str = "delete-extra", attestation: Path | str | None = None,
    owner: DatabaseOwner | None = None, create: bool = False,
    check_same_thread: bool = True, exclusive_owner: bool = False,
) -> OwnedConnection:
    """Open a supported writer without silently changing an existing journal mode."""
    if profile not in PROFILES:
        raise SQLiteRuntimeError("unsupported SQLite durability profile")
    runtime = runtime_status(attestation)
    if profile == "wal-full" and runtime["patch_status"] != "FIXED":
        raise SQLiteRuntimeError("WAL requires a verified fixed loaded SQLite runtime")
    path = _database_path(database, create=create)
    acquired = _acquire_owner(path, owner, exclusive=exclusive_owner)
    connection = None
    try:
        journal, synchronous = PROFILES[profile]
        header = _header_mode(path)
        if header is None and not create:
            raise SQLiteRuntimeError("SQLite database must be explicitly bootstrapped")
        if header is not None and header != journal:
            raise SQLiteRuntimeError(MAINTENANCE_GUIDANCE)
        if header == "wal":
            _verify_runtime_receipt(path, runtime, attestation)
        if journal != "wal" and any(Path(f"{path}{suffix}").exists() for suffix in ("-wal", "-shm")):
            raise SQLiteRuntimeError(MAINTENANCE_GUIDANCE)
        uri = f"file:{quote(str(path), safe='/')}?mode={'rwc' if create else 'rw'}"
        connection = sqlite3.connect(uri, uri=True, check_same_thread=check_same_thread,
                                     factory=OwnedConnection)
        connection.owner = acquired
        connection._connection_pid = os.getpid()
        connection.sqlite_profile = profile
        connection.sqlite_attestation = attestation
        if header is None:
            connection.execute(f"PRAGMA journal_mode={journal}")
        connection.execute(f"PRAGMA synchronous={synchronous}")
        actual_journal = connection.execute("PRAGMA journal_mode").fetchone()[0].lower()
        actual_sync = connection.execute("PRAGMA synchronous").fetchone()[0]
        acquired.assert_owned()
        if (actual_journal, actual_sync) != (journal, synchronous):
            raise SQLiteRuntimeError("SQLite durability PRAGMA readback failed")
        if header is None and journal == "wal":
            _write_runtime_receipt(path, runtime, attestation, kind="fresh-wal", profile=profile,
                                   backup_manifest_sha256=None)
        connection.runtime_report = {
            **runtime, "profile": profile, "journal_mode": actual_journal,
            "synchronous": actual_sync, "owner_lock": True,
            "support_status": "SUPPORTED_AVOIDANCE" if journal == "delete" else "SUPPORTED_FIXED_WAL",
        }
        return connection
    except BaseException:
        if connection is not None:
            connection.close()
        else:
            acquired.release()
        raise


def sqlite_doctor(
    *, profile: str = "delete-extra", attestation: Path | str | None = None,
    database: Path | str | None = None,
) -> dict[str, Any]:
    """Read-only diagnosis; missing live policy observations remain UNPROVEN."""
    report = runtime_status(attestation)
    report.update(profile=profile, support_status="UNPROVEN", owner_lock=False,
                  journal_mode=None, synchronous=None)
    if profile not in PROFILES:
        report["error"] = "unsupported SQLite durability profile"
    elif profile == "wal-full" and report["patch_status"] != "FIXED":
        report["error"] = "WAL requires a verified fixed loaded SQLite runtime"
    if database is not None:
        try:
            path = _database_path(Path(database))
            report["journal_mode"] = _header_mode(path)
            with _owners_guard:
                owner = _owners.get(path)
                if owner is not None:
                    owner.assert_owned()
                    report["owner_lock"] = True
            if report["journal_mode"] != PROFILES.get(profile, (None,))[0]:
                report["error"] = MAINTENANCE_GUIDANCE
        except (OSError, SQLiteRuntimeError) as exc:
            report["error"] = str(exc)
    report["observation_limit"] = (
        "Doctor does not create an owner lock or open a writer. Effective synchronous "
        "and support are certified on each live connection's runtime_report."
    )
    return report


def verify_database_policy(
    database: Path, *, profile: str = "delete-extra", attestation: Path | str | None = None,
    original_database: Path | None = None,
) -> dict[str, Any]:
    """Validate an offline source's mode/provenance without opening SQLite.

    Used before copying a database for read-only inspection. The caller retains
    its workspace barrier and verifies stable source/copy bytes. The optional
    original_database is for an independently verified offline copy/restore whose
    manifest binds the original canonical path and exact DB/receipt bytes. It
    changes only this read-only receipt identity check; connect_database never
    accepts this override. The original host/path need not still be accessible.
    This observes
    neither a live connection's synchronous setting nor an acquired owner lock.
    """
    if profile not in PROFILES:
        raise SQLiteRuntimeError("unsupported SQLite durability profile")
    if original_database is not None:
        original_database = Path(original_database)
        if not original_database.is_absolute() or ".." in original_database.parts:
            raise SQLiteRuntimeError("original database identity must be an absolute canonical path")
    path = _database_path(database)
    if any(os.path.lexists(f"{path}{suffix}") for suffix in ("-wal", "-shm", "-journal")):
        raise SQLiteRuntimeError("offline policy verification requires no journal/WAL sidecars")
    runtime = runtime_status(attestation)
    if profile == "wal-full" and runtime["patch_status"] != "FIXED":
        raise SQLiteRuntimeError("WAL requires a verified fixed loaded SQLite runtime")
    mode = _header_mode(path)
    if mode != PROFILES[profile][0]:
        raise SQLiteRuntimeError(MAINTENANCE_GUIDANCE)
    if mode == "wal":
        _verify_runtime_receipt(path, runtime, attestation, original_database=original_database)
    return {"profile": profile, "journal_mode": mode, "runtime": runtime,
            "receipt_sha256": _sha256(_receipt_path(path)) if mode == "wal" else None,
            "receipt_bound_database": str(original_database or path),
            "support_status": "UNPROVEN", "scope": "offline-mode-and-provenance-only"}


def maintain_journal_mode(
    database: Path, backup_dir: Path, *, target_profile: str = "delete-extra",
    attestation: Path | str,
) -> dict[str, Any]:
    """Explicit offline, byte-backed-up journal maintenance using the fixed runtime.

    This is a database maintenance backup, not a complete workspace backup. Stop
    the application and make its full workspace backup first. Raw DB/sidecars are
    copied and fsynced before SQLite is opened; no sidecar is manually removed.
    """
    if target_profile not in PROFILES:
        raise SQLiteRuntimeError("unsupported SQLite durability profile")
    runtime = runtime_status(attestation)
    if runtime["patch_status"] != "FIXED":
        raise SQLiteRuntimeError("offline maintenance requires verified fixed SQLite")
    path = _database_path(database)
    with _owners_guard:
        if path in _owners:
            raise SQLiteRuntimeError("offline maintenance requires all application writers closed")
        owner = _acquire_owner(path, None)
        owner.maintenance = True
    connection = None
    try:
        destination = Path(os.path.abspath(backup_dir))
        if destination.exists():
            raise SQLiteRuntimeError("maintenance backup destination must not exist")
        destination.mkdir(mode=0o700, parents=False)
        inventory = []
        for item in (path, *(Path(f"{path}{suffix}") for suffix in ("-wal", "-shm", "-journal")),
                     _receipt_path(path)):
            if item.exists() or item.is_symlink():
                metadata = _regular(item)
                target = destination / item.name
                with item.open("rb") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                    output.flush()
                    os.fsync(output.fileno())
                digest = _sha256(target)
                if _sha256(item) != digest or item.stat().st_size != metadata.st_size:
                    raise SQLiteRuntimeError("database changed during offline maintenance backup")
                inventory.append({"name": item.name, "bytes": metadata.st_size, "sha256": digest})
        record = {"schema_version": 1, "scope": "offline-database-and-sidecars",
                  "target_profile": target_profile, "inventory": inventory, "runtime": runtime}
        with (destination / "maintenance-backup.json").open("x") as output:
            json.dump(record, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        for directory in (destination, destination.parent):
            fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        owner.assert_owned()
        connection = sqlite3.connect(f"file:{quote(str(path), safe='/')}?mode=rw", uri=True)
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise SQLiteRuntimeError("maintenance database integrity check failed")
        if connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal":
            checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if checkpoint[0] != 0:
                raise SQLiteRuntimeError("maintenance cannot checkpoint a busy WAL database")
        journal, synchronous = PROFILES[target_profile]
        actual = connection.execute(f"PRAGMA journal_mode={journal}").fetchone()[0]
        connection.execute(f"PRAGMA synchronous={synchronous}")
        if actual != journal or connection.execute("PRAGMA synchronous").fetchone()[0] != synchronous:
            raise SQLiteRuntimeError("maintenance durability PRAGMA readback failed")
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise SQLiteRuntimeError("maintained database integrity check failed")
        _write_runtime_receipt(path, runtime, attestation, kind="offline-maintenance",
                               profile=target_profile,
                               backup_manifest_sha256=_sha256(destination / "maintenance-backup.json"))
        return {"status": "MAINTAINED", "profile": target_profile, "backup": str(destination),
                "inventory": inventory, "runtime": runtime}
    finally:
        if connection is not None:
            connection.close()
        owner.release()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="read-only runtime diagnosis")
    doctor.add_argument("--profile", choices=PROFILES, default="delete-extra")
    doctor.add_argument("--attestation", type=Path)
    doctor.add_argument("--database", type=Path)
    maintain = commands.add_parser("maintain", help="offline maintenance; stop application and back up workspace first")
    maintain.add_argument("--database", type=Path, required=True)
    maintain.add_argument("--backup-dir", type=Path, required=True)
    maintain.add_argument("--profile", choices=PROFILES, default="delete-extra")
    maintain.add_argument("--attestation", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = sqlite_doctor(profile=args.profile, attestation=args.attestation, database=args.database)
        else:
            result = maintain_journal_mode(args.database, args.backup_dir, target_profile=args.profile,
                                           attestation=args.attestation)
    except (OSError, ValueError, SQLiteRuntimeError, sqlite3.Error) as exc:
        print(json.dumps({"status": "DENIED", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 1 if "error" in result else 0


if __name__ == "__main__":
    raise SystemExit(main())
