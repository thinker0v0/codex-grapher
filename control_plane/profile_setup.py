"""Create explicit operator profiles without launching or installing any tool.

Versions are operator observations, not results invented by this helper. The
provider's later role-scoped preflight must verify them before an invocation.
Only a new profile file is written; keys, accounts and tools are never changed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Mapping

from .execution_profile import (
    ExecutionProfile,
    ExecutionProfileError,
    executable_digest,
    trusted_code_digest,
    validate_execution_profile,
)


def _destination(path: str | Path, *, isolated: bool) -> Path:
    """Check the new output and its ancestry before creating a temporary file."""
    text = os.fspath(path)
    result = Path(text)
    if not result.is_absolute() or str(result) != text or ".." in result.parts:
        raise ExecutionProfileError("profile output must be a canonical absolute path")
    for parent in reversed(result.parents):
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ExecutionProfileError("profile output ancestors must be real directories")
        if isolated:
            sticky = bool(metadata.st_mode & stat.S_ISVTX)
            if metadata.st_uid != 0 or (metadata.st_mode & 0o022 and not sticky):
                raise ExecutionProfileError("isolated profile output requires protected root-owned ancestry")
            if any(name in {"system.posix_acl_access", "system.posix_acl_default"}
                   for name in os.listxattr(parent, follow_symlinks=False)):
                raise ExecutionProfileError("profile output has unsupported extended access permissions")
    if os.path.lexists(result):
        raise ExecutionProfileError("profile output already exists; choose a new path")
    if isolated and os.geteuid() != 0:
        raise ExecutionProfileError("creating an isolated profile requires the root operator")
    return result


def _publish_new(path: Path, data: bytes) -> None:
    """Publish complete bytes without ever replacing an operator's existing file."""
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".profile-", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # link() is exclusive, unlike replace(): a concurrent output is retained.
        os.link(temporary, path.name, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(temporary)
        temporary = None
        os.fsync(directory_fd)
    finally:
        if temporary is not None:
            os.unlink(temporary)
        os.close(directory_fd)


def create_execution_profile(
    output_path: str | Path,
    *,
    mode: str,
    worker_account: str,
    model: str,
    reasoning_effort: str,
    service_tier: str,
    python_path: str | Path,
    git_path: str | Path,
    provider_path: str | Path,
    openssl_path: str | Path,
    trusted_code_root: str | Path,
    signer_public_key: str | Path,
    signer_private_key: str | Path,
    roles: Mapping[str, Mapping[str, int]],
    observed_versions: Mapping[str, str],
    sqlite_profile: str = "delete-extra",
    sqlite_attestation: str | Path | None = None,
    bwrap_path: str | Path | None = None,
    setpriv_path: str | Path | None = None,
    require_private_key: bool = True,
) -> ExecutionProfile:
    """Hash explicit files, validate the strict profile, and exclusively create it.

    All paths must already be absolute, canonical and free of symlink components.
    ``observed_versions`` has exactly one nonempty version for each enabled tool:
    python, git, provider, openssl, and any specified bwrap/setpriv. Gather those
    observations as the intended non-root role. This function never executes a
    binary or reads ambient API keys, provider configuration or credential data.

    The private key must be separately provisioned outside code and workspace.
    ``require_private_key=False`` is exclusively for a verify-only profile; it
    does not authorize running without the matching private key. The strict
    profile loader remains the authority for roles, tool protection and runtime.
    """
    try:
        output = _destination(output_path, isolated=mode == "isolated-linux")
        code = Path(trusted_code_root)
        if output == code or code in output.parents:
            raise ExecutionProfileError("profile output must live outside the pinned code tree")
        tool_paths = {
            "python": python_path, "git": git_path, "provider": provider_path,
            "openssl": openssl_path, "bwrap": bwrap_path, "setpriv": setpriv_path,
        }
        enabled = {name for name, path in tool_paths.items() if path is not None}
        if not isinstance(observed_versions, Mapping) or set(observed_versions) != enabled:
            raise ExecutionProfileError("observed versions must exactly name the enabled tools")
        tools = {
            name: None if path is None else {
                "path": os.fspath(path), "sha256": executable_digest(path),
                "version": observed_versions[name],
            }
            for name, path in tool_paths.items()
        }
        value = {
            "schema_version": 1,
            "mode": mode,
            "tools": tools,
            "provider": {"backend": "codex", "model": model,
                         "reasoning_effort": reasoning_effort, "service_tier": service_tier},
            "roles": {name: dict(role) for name, role in roles.items()},
            "auth": {"kind": "existing-cli-login", "account": worker_account},
            "paths": {"trusted_code_root": os.fspath(trusted_code_root),
                      "trusted_code_sha256": trusted_code_digest(trusted_code_root),
                      "signer_private_key": os.fspath(signer_private_key),
                      "signer_public_key": os.fspath(signer_public_key)},
            "sqlite": {"profile": sqlite_profile,
                       "attestation": None if sqlite_attestation is None else os.fspath(sqlite_attestation)},
        }
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("utf-8")
        profile = validate_execution_profile(value, raw_bytes=raw, verify_tools=True,
                                             require_private_key=require_private_key)
        _publish_new(output, raw)
        return profile
    except (OSError, TypeError, ValueError, AttributeError) as exc:
        if isinstance(exc, ExecutionProfileError):
            raise
        # Private key paths and account information are not echoed in diagnostics.
        raise ExecutionProfileError("execution profile setup failed without replacing existing files") from exc
