"""Strict, operator-owned execution profiles; never execute candidate code.

The profile hash binds the original UTF-8 bytes, not a normalized spelling. Tree
hashes bind a sorted inventory of every directory and regular file, including
permission bits, file lengths and content hashes. There are no ignored entries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
from types import MappingProxyType
from typing import Any, Mapping


MAX_PROFILE_BYTES = 64 * 1024
MAX_ID = 2**32 - 2
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}\Z")
_TOOLS = {"python", "git", "provider", "openssl", "bwrap", "setpriv"}
_ROLES = {"worker", "test_runner", "signer", "graph"}


class ExecutionProfileError(PermissionError):
    """A profile cannot establish the requested execution authority."""


@dataclass(frozen=True)
class Tool:
    path: str
    sha256: str
    version: str


@dataclass(frozen=True)
class Role:
    uid: int
    gid: int


@dataclass(frozen=True)
class ExecutionProfile:
    mode: str
    tools: Mapping[str, Tool | None]
    provider: Mapping[str, str]
    roles: Mapping[str, Role]
    auth_account: str
    auth_home: Path
    paths: Mapping[str, str]
    sqlite: Mapping[str, str | None]
    sha256: str
    _json: bytes = field(repr=False)
    schema_version: int = 1

    @property
    def raw(self) -> dict[str, Any]:
        """Return an independent dictionary, never mutable validation state."""
        return json.loads(self._json)

    def to_dict(self) -> dict[str, Any]:
        return self.raw


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _object(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ExecutionProfileError(f"{label} has an invalid field set")
    return value


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ExecutionProfileError(f"{label} must be a bounded nonempty string")
    return value


def _hash(value: Any, label: str) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        raise ExecutionProfileError(f"{label} must be a lowercase SHA-256")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_ID:
        raise ExecutionProfileError(f"{label} is outside its integer bounds")
    return value


def _path(value: Any, label: str, *, missing: bool = False) -> Path:
    value = _text(value, label, maximum=4096)
    path = Path(value)
    if value == "/" or not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ExecutionProfileError(f"{label} must be a canonical absolute path")
    try:
        for part in reversed((path, *path.parents)):
            try:
                metadata = part.lstat()
            except FileNotFoundError:
                if missing and part == path:
                    continue
                raise
            if stat.S_ISLNK(metadata.st_mode):
                raise ExecutionProfileError(f"{label} contains a symlink")
            if part != path and not stat.S_ISDIR(metadata.st_mode):
                raise ExecutionProfileError(f"{label} has a non-directory ancestor")
    except OSError as exc:
        if isinstance(exc, ExecutionProfileError):
            raise
        raise ExecutionProfileError(f"{label} is unavailable") from exc
    return path


def _no_acl(path: Path, label: str) -> None:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise ExecutionProfileError(f"cannot verify {label} permissions") from exc
    if any(name in {"system.posix_acl_access", "system.posix_acl_default", "security.capability"}
           for name in names):
        raise ExecutionProfileError(f"{label} has unsupported extended access permissions")


def _protected(path: Path, label: str, *, isolated: bool,
               missing: bool = False) -> None:
    """Verify every ancestor; sticky root-owned ancestors protect root children."""
    if not isolated:
        return
    for part in (path, *path.parents):
        try:
            metadata = part.lstat()
        except FileNotFoundError:
            if missing and part == path:
                continue
            raise ExecutionProfileError(f"{label} is unavailable") from None
        if metadata.st_uid != 0 or stat.S_ISLNK(metadata.st_mode):
            raise ExecutionProfileError(f"{label} and its ancestors must be root-owned")
        sticky_ancestor = (part != path and stat.S_ISDIR(metadata.st_mode)
                           and bool(metadata.st_mode & stat.S_ISVTX))
        if metadata.st_mode & 0o022 and not sticky_ancestor:
            raise ExecutionProfileError(f"{label} or its ancestor is role-writable")
        _no_acl(part, label)


def _read_regular(path: Path, label: str, *, maximum: int | None = None) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ExecutionProfileError(f"{label} must be a regular file")
            if maximum is not None and before.st_size > maximum:
                raise ExecutionProfileError(f"{label} exceeds its size bound")
            data = stream.read(-1 if maximum is None else maximum + 1)
            after = os.fstat(stream.fileno())
            if maximum is not None and len(data) > maximum:
                raise ExecutionProfileError(f"{label} exceeds its size bound")
            if _identity(before) != _identity(after) or len(data) != after.st_size:
                raise ExecutionProfileError(f"{label} changed while being read")
            if _identity(path.lstat()) != _identity(after):
                raise ExecutionProfileError(f"{label} was replaced while being read")
            return data
    except OSError as exc:
        if isinstance(exc, ExecutionProfileError):
            raise
        raise ExecutionProfileError(f"cannot read {label}") from exc


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_size, metadata.st_mtime_ns,
            metadata.st_ctime_ns)


def _tree_inventory(root: Path, *, protected: bool = False) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    observed: list[tuple[Path, tuple[int, ...]]] = []
    directory_names: list[tuple[Path, tuple[str, ...]]] = []
    pending = [root]
    while pending:
        path = pending.pop()
        try:
            before = path.lstat()
            observed.append((path, _identity(before)))
            if protected:
                _protected(path, "trusted code", isolated=True)
            name = "." if path == root else path.relative_to(root).as_posix()
            if stat.S_ISDIR(before.st_mode):
                names = sorted(path.iterdir(), key=lambda child: child.name)
                directory_names.append((path, tuple(child.name for child in names)))
                pending.extend(reversed(names))
                entries.append({"path": name, "type": "directory",
                                "mode": stat.S_IMODE(before.st_mode)})
                if _identity(path.lstat()) != _identity(before):
                    raise ExecutionProfileError("trusted code directory changed during hashing")
            elif stat.S_ISREG(before.st_mode):
                if before.st_nlink != 1:
                    raise ExecutionProfileError("trusted code must not contain hardlinks")
                data = _read_regular(path, "trusted code file")
                entries.append({"path": name, "type": "file",
                                "mode": stat.S_IMODE(before.st_mode),
                                "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
            else:
                raise ExecutionProfileError("trusted code must contain only directories and regular files")
        except OSError as exc:
            if isinstance(exc, ExecutionProfileError):
                raise
            raise ExecutionProfileError("cannot inventory trusted code") from exc
    try:
        for path, identity in observed:
            if _identity(path.lstat()) != identity:
                raise ExecutionProfileError("trusted code changed during inventory")
        for path, names in directory_names:
            if tuple(sorted(child.name for child in path.iterdir())) != names:
                raise ExecutionProfileError("trusted code directory inventory changed")
    except OSError as exc:
        if isinstance(exc, ExecutionProfileError):
            raise
        raise ExecutionProfileError("trusted code disappeared during inventory") from exc
    return sorted(entries, key=lambda item: item["path"])


def trusted_code_digest(root: str | Path, *, isolated: bool = True) -> str:
    """Hash exact code/venv bytes; explicit local mode permits user-owned metadata.

    The default retains isolated venv protection. Profile validation separately
    checks the complete code ownership; ownership never changes digest bytes.
    """
    if type(isolated) is not bool:
        raise ExecutionProfileError("venv isolation mode must be a boolean")
    path = _path(os.fspath(root), "trusted_code_root")
    if not path.is_dir():
        raise ExecutionProfileError("trusted_code_root must be a directory")
    return hashlib.sha256(_canonical(_trusted_inventory(path, venv_isolated=isolated))).hexdigest()


def _venv_code_prefix(root: Path) -> tuple[Path, str] | None:
    if (root.name == "site-packages" and root.parent.parent.name == "lib"
            and re.fullmatch(r"python[0-9]+\.[0-9]+", root.parent.name)):
        return root.parents[2], root.parent.name.removeprefix("python")
    return None


def _present(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _read_venv_config(path: Path, minor_version: str, *, isolated: bool = True) -> tuple[dict[str, str], bytes]:
    if type(isolated) is not bool:
        raise ExecutionProfileError("venv isolation mode must be a boolean")
    path = _path(str(path), "venv runtime metadata")
    _protected(path, "venv runtime metadata", isolated=isolated)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ExecutionProfileError("venv metadata must be a single-link regular file")
    raw = _read_regular(path, "venv runtime metadata", maximum=16384)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ExecutionProfileError("venv runtime metadata must be UTF-8") from exc
    if any(ord(char) < 32 and char not in "\n\r\t" or ord(char) == 127 for char in text):
        raise ExecutionProfileError("venv runtime metadata contains control characters")
    fields = {}
    allowed = {"home", "include-system-site-packages", "version", "executable", "command"}
    for line in text.splitlines():
        if not line.strip():
            continue
        if "=" not in line:
            raise ExecutionProfileError("venv runtime metadata has an invalid entry")
        key, value = (part.strip() for part in line.split("=", 1))
        if key not in allowed or key in fields:
            raise ExecutionProfileError("venv runtime metadata has duplicate or unsupported keys")
        fields[key] = _text(value, "venv metadata value", maximum=4096)
    if not {"home", "include-system-site-packages", "version"} <= set(fields):
        raise ExecutionProfileError("venv runtime metadata is incomplete")
    if fields["include-system-site-packages"] != "false":
        raise ExecutionProfileError("venv must not import unpinned system site-packages")
    if (not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", fields["version"])
            or ".".join(fields["version"].split(".")[:2]) != minor_version):
        raise ExecutionProfileError("venv version differs from the trusted code topology")
    home = _path(fields["home"], "venv interpreter home")
    if home not in (Path("/usr/bin"), Path("/usr/local/bin")) or not home.is_dir():
        raise ExecutionProfileError("venv interpreter home must be a protected system bin directory")
    _protected(home, "venv interpreter home", isolated=True)
    if "executable" in fields:
        executable = _path(fields["executable"], "venv base executable")
        _protected(executable, "venv base executable", isolated=True)
        info = executable.lstat()
        if (executable.parent != home or not stat.S_ISREG(info.st_mode)
                or not info.st_mode & 0o111 or info.st_mode & (stat.S_ISUID | stat.S_ISGID)):
            raise ExecutionProfileError("venv base executable differs from its protected home")
    if _identity(path.lstat()) != _identity(before):
        raise ExecutionProfileError("venv metadata changed during validation")
    return fields, raw


def venv_runtime_metadata(python_path: str | Path, code_root: str | Path, *, isolated: bool = True) -> tuple[Path, ...]:
    """Return cfg for a matching copied venv, with strict isolated defaults.

    This performs no execution and supplies only explicit metadata mount inputs.
    A genuine non-venv returns an empty tuple; a detected mismatched or unsafe
    venv fails closed. The frozen profile schema gains no additional fields.
    """
    if type(isolated) is not bool:
        raise ExecutionProfileError("venv isolation mode must be a boolean")
    python = _path(os.fspath(python_path), "venv Python executable")
    root = _path(os.fspath(code_root), "venv trusted code root")
    topology = _venv_code_prefix(root)
    code_cfg = topology[0] / "pyvenv.cfg" if topology else None
    python_prefix = python.parent.parent if python.parent.name == "bin" else None
    python_cfg = python_prefix / "pyvenv.cfg" if python_prefix else None
    if not ((code_cfg is not None and _present(code_cfg))
            or (python_cfg is not None and _present(python_cfg))):
        return ()
    if topology is None or python_prefix != topology[0] or code_cfg != python_cfg:
        raise ExecutionProfileError("venv Python and trusted code must share one standard prefix")
    if python.name not in {"python", "python3", "python" + topology[1]}:
        raise ExecutionProfileError("venv Python executable differs from the code version")
    _protected(python, "venv Python executable", isolated=isolated)
    _protected(root, "venv trusted code root", isolated=isolated)
    if not python.is_file() or not root.is_dir():
        raise ExecutionProfileError("venv executable and trusted code topology is invalid")
    _read_venv_config(code_cfg, topology[1], isolated=isolated)
    return (code_cfg,)


def _trusted_inventory(root: Path, *, protected: bool = False,
                       venv_isolated: bool = True) -> list[dict[str, Any]]:
    if type(protected) is not bool or type(venv_isolated) is not bool or (protected and not venv_isolated):
        raise ExecutionProfileError("trusted inventory isolation mode is inconsistent")
    inventory = _tree_inventory(root, protected=protected)
    topology = _venv_code_prefix(root)
    if topology is not None:
        metadata = topology[0] / "pyvenv.cfg"
        if _present(metadata):
            _fields, raw = _read_venv_config(metadata, topology[1], isolated=venv_isolated)
            inventory.append({"path": "@venv/pyvenv.cfg", "type": "external-metadata",
                              "mode": stat.S_IMODE(metadata.stat().st_mode),
                              "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return sorted(inventory, key=lambda item: (item["path"], item["type"]))


def executable_digest(path: str | Path) -> str:
    """Hash a canonical regular executable without executing it."""
    target = _path(os.fspath(path), "executable")
    metadata = target.stat()
    if (not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)):
        raise ExecutionProfileError("executable must be a regular file without set-id bits")
    return hashlib.sha256(_read_regular(target, "executable")).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExecutionProfileError("duplicate execution profile field")
        result[key] = value
    return result


def _decode(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes or not data or len(data) > MAX_PROFILE_BYTES:
        raise ExecutionProfileError("execution profile bytes exceed their bounds")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda value: _reject_constant())
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ExecutionProfileError("execution profile is not strict UTF-8 JSON") from exc


def _reject_constant() -> None:
    raise ExecutionProfileError("nonfinite numbers are forbidden")


def _verify_tool(tool: Tool, name: str) -> None:
    if executable_digest(tool.path) != tool.sha256:
        raise ExecutionProfileError(f"tools.{name} executable hash mismatch")


def validate_execution_profile(value: dict[str, Any], *, raw_bytes: bytes | None = None,
                               verify_tools: bool = True,
                               require_private_key: bool = False) -> ExecutionProfile:
    """Validate configuration without executing any tool or candidate code.

    ``verify_tools=False`` skips only executable hash checks. Account,
    filesystem protection and trusted code integrity are always checked. A caller
    that will execute or sign must set ``require_private_key=True``.
    """
    try:
        return _validate(value, raw_bytes=raw_bytes, verify_tools=verify_tools,
                         require_private_key=require_private_key)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        if isinstance(exc, ExecutionProfileError):
            raise
        raise ExecutionProfileError("execution profile validation failed") from exc


def _validate(value: dict[str, Any], *, raw_bytes: bytes | None,
              verify_tools: bool, require_private_key: bool) -> ExecutionProfile:
    if type(verify_tools) is not bool or type(require_private_key) is not bool:
        raise ExecutionProfileError("validation switches must be booleans")
    source = _object(value, {"schema_version", "mode", "tools", "provider", "roles",
                             "auth", "paths", "sqlite"}, "execution profile")
    if type(source["schema_version"]) is not int or source["schema_version"] != 1:
        raise ExecutionProfileError("execution profile schema_version must be integer 1")
    if type(source["mode"]) is not str or source["mode"] not in {"trusted-local", "isolated-linux"}:
        raise ExecutionProfileError("unsupported execution profile mode")
    isolated = source["mode"] == "isolated-linux"
    roles = {}
    for name, item in _object(source["roles"], _ROLES, "roles").items():
        _object(item, {"uid", "gid"}, f"roles.{name}")
        roles[name] = Role(_integer(item["uid"], f"roles.{name}.uid", int(isolated)),
                           _integer(item["gid"], f"roles.{name}.gid"))
    if isolated and len({role.uid for role in roles.values()}) != 4:
        raise ExecutionProfileError("isolated roles require four distinct non-root UIDs")
    if isolated:
        try:
            uid_map = [tuple(map(int, line.split()))
                       for line in Path("/proc/self/uid_map").read_text().splitlines()]
        except (OSError, ValueError):
            raise ExecutionProfileError("cannot establish the kernel UID mapping") from None
        for role in roles.values():
            matches = [outside + role.uid - inside for inside, outside, count in uid_map
                       if inside <= role.uid < inside + count]
            if len(matches) != 1 or matches[0] == 0:
                raise ExecutionProfileError("isolated roles must have mapped non-root kernel UIDs")
    provider = _object(source["provider"], {"backend", "model", "reasoning_effort", "service_tier"}, "provider")
    if provider["backend"] != "codex":
        raise ExecutionProfileError("unsupported provider backend")
    for name, item in provider.items():
        if type(item) is not str or not _TOKEN.fullmatch(item):
            raise ExecutionProfileError(f"provider.{name} must be a bounded explicit token")
    auth = _object(source["auth"], {"kind", "account"}, "auth")
    if auth["kind"] != "existing-cli-login":
        raise ExecutionProfileError("unsupported authentication kind")
    account_name = _text(auth["account"], "auth.account", maximum=256)
    try:
        account = pwd.getpwnam(account_name)
    except KeyError:
        raise ExecutionProfileError("configured authentication account does not exist") from None
    if (account.pw_name != account_name or account.pw_uid != roles["worker"].uid
            or account.pw_gid != roles["worker"].gid):
        raise ExecutionProfileError("authentication account must match the worker UID and primary GID")
    auth_home = _path(account.pw_dir, "authentication account home")
    if not auth_home.is_dir() or auth_home.stat().st_uid != account.pw_uid:
        raise ExecutionProfileError("authentication home must be owned by the actual account")

    tools: dict[str, Tool | None] = {}
    for name, item in _object(source["tools"], _TOOLS, "tools").items():
        if item is None and name in {"bwrap", "setpriv"} and not isolated:
            tools[name] = None
            continue
        _object(item, {"path", "sha256", "version"}, f"tools.{name}")
        path = _path(item["path"], f"tools.{name}.path")
        _protected(path, f"tools.{name}", isolated=isolated)
        metadata = path.stat()
        if (not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111
                or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)):
            raise ExecutionProfileError(f"tools.{name} must be a regular executable without set-id bits")
        tools[name] = Tool(str(path), _hash(item["sha256"], f"tools.{name}.sha256"),
                           _text(item["version"], f"tools.{name}.version", maximum=1024))

    paths = _object(source["paths"], {"trusted_code_root", "trusted_code_sha256",
                                    "signer_private_key", "signer_public_key"}, "paths")
    code = _path(paths["trusted_code_root"], "trusted_code_root")
    if not code.is_dir():
        raise ExecutionProfileError("trusted_code_root must be a directory")
    _protected(code, "trusted_code_root", isolated=isolated)
    expected_code = _hash(paths["trusted_code_sha256"], "trusted_code_sha256")
    python_metadata = venv_runtime_metadata(tools["python"].path, code, isolated=isolated)
    if python_metadata:
        topology = _venv_code_prefix(code)
        fields, _raw = _read_venv_config(python_metadata[0], topology[1], isolated=isolated)
        declared_version = re.fullmatch(r"Python ([0-9]+\.[0-9]+\.[0-9]+)", tools["python"].version)
        if declared_version and declared_version[1] != fields["version"]:
            raise ExecutionProfileError("pinned Python version differs from venv metadata")
    if hashlib.sha256(_canonical(_trusted_inventory(code, protected=isolated, venv_isolated=isolated))).hexdigest() != expected_code:
        raise ExecutionProfileError("trusted code tree hash mismatch")
    key_paths = {}
    for name in ("signer_private_key", "signer_public_key"):
        private = name == "signer_private_key"
        path = _path(paths[name], name, missing=private and not require_private_key)
        if path == code or code in path.parents:
            raise ExecutionProfileError("signing keys must live outside trusted code")
        _protected(path, name, isolated=isolated, missing=private and not require_private_key)
        key_paths[name] = path
        if not path.exists():
            continue
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size == 0:
            raise ExecutionProfileError(f"{name} must be a nonempty unlinked regular file")
        if private:
            if metadata.st_mode & 0o007 or metadata.st_mode & 0o020:
                raise ExecutionProfileError("private signing key permissions are too broad")
            if isolated and metadata.st_mode & 0o040:
                if (metadata.st_gid != roles["signer"].gid
                        or any(role.gid == metadata.st_gid for name, role in roles.items() if name != "signer")):
                    raise ExecutionProfileError("private signing key group must belong exclusively to signer")
    if key_paths["signer_private_key"] == key_paths["signer_public_key"]:
        raise ExecutionProfileError("private and public signing key paths must differ")

    sqlite = _object(source["sqlite"], {"profile", "attestation"}, "sqlite")
    if sqlite["profile"] not in ("delete-extra", "wal-full"):
        raise ExecutionProfileError("unsupported SQLite profile")
    if sqlite["profile"] == "delete-extra":
        if sqlite["attestation"] is not None:
            raise ExecutionProfileError("delete-extra must not assert a patched runtime attestation")
    else:
        attestation = _path(sqlite["attestation"], "SQLite attestation")
        _protected(attestation, "SQLite attestation", isolated=isolated)
        _read_regular(attestation, "SQLite attestation", maximum=MAX_PROFILE_BYTES)
        # Exact loaded-library proof belongs to the SQLite runtime policy; the
        # profile never treats mere presence of a document as proof of a patch.
        try:
            from .sqlite_runtime import validate_attestation
        except ImportError as exc:
            raise ExecutionProfileError("SQLite attestation verification is unavailable") from exc
        try:
            validate_attestation(attestation)
        except (RuntimeError, ValueError, OSError) as exc:
            raise ExecutionProfileError("SQLite loaded-runtime attestation did not verify") from exc

    encoded = _canonical(source)
    if raw_bytes is None:
        raw_bytes = encoded
    elif _canonical(_decode(raw_bytes)) != encoded:
        raise ExecutionProfileError("profile dictionary does not match its exact raw bytes")
    if len(raw_bytes) > MAX_PROFILE_BYTES:
        raise ExecutionProfileError("execution profile exceeds its size bound")
    if verify_tools:
        for name in sorted(tools):
            if tools[name] is not None:
                _verify_tool(tools[name], name)
    return ExecutionProfile(
        source["mode"], MappingProxyType(tools), MappingProxyType(dict(provider)),
        MappingProxyType(roles), account_name, auth_home, MappingProxyType(dict(paths)),
        MappingProxyType(dict(sqlite)), hashlib.sha256(raw_bytes).hexdigest(), encoded,
    )


def load_execution_profile(path: str | Path, *, verify_tools: bool = True,
                           require_private_key: bool = False) -> ExecutionProfile:
    """Read an exact, nonsymlink profile, checking root provenance when isolated."""
    source = _path(os.fspath(path), "execution profile")
    raw = _read_regular(source, "execution profile", maximum=MAX_PROFILE_BYTES)
    value = _decode(raw)
    if type(value) is dict and value.get("mode") == "isolated-linux":
        _protected(source, "execution profile", isolated=True)
    return validate_execution_profile(value, raw_bytes=raw, verify_tools=verify_tools,
                                      require_private_key=require_private_key)
