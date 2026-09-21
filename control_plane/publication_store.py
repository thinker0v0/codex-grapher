#!/usr/bin/env python3
"""Immutable, SHA-addressed local Git publications selected by a worker binding.

The worker-readable binding deliberately remains exactly ``{repo,base_sha}``.
``base_sha`` is also the publication generation name, so replacing that one
regular file atomically selects a generation that already exists.  A reader
which opened the old binding can continue using the old generation because
published directories are never replaced or removed by this module.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HEX40 = re.compile(r"^[a-f0-9]{40}$")
SAFE_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
MARKER = "ai-ops-publication.json"
MARKER_FIELDS = {"format", "generation", "repo", "base_sha", "tree_sha"}
AT_FDCWD = -100
RENAME_NOREPLACE = 1


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _git_environment() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
        env=_git_environment(),
    ).stdout.strip()


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish one directory without replacing any raced inode."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for atomic publication")
    renameat2.argtypes = [
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        AT_FDCWD, os.fsencode(source), AT_FDCWD, os.fsencode(destination),
        RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


@dataclass(frozen=True)
class PublicationPin:
    repo: str
    base_sha: str
    generation: str
    path: Path
    tree_sha: str


class PublicationStore:
    """Create and verify immutable generations beneath one non-symlink root."""

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(root))

    def ensure(self, source_repo: Path, repo: str, base_sha: str,
               metadata: os.stat_result | None = None) -> PublicationPin:
        """Return an existing verified generation or atomically publish one."""
        self._validate_identity(repo, base_sha)
        source_repo = Path(source_repo).resolve(strict=True)
        if not (source_repo / ".git").exists():
            raise ValueError("publication source must be a local Git repository")
        if _git(source_repo, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
            raise ValueError("publication SHA is not a source commit")
        self._ensure_root(metadata)
        destination = self.root / base_sha
        if destination.exists() or destination.is_symlink():
            return self.verify(repo, base_sha)

        temporary = Path(tempfile.mkdtemp(prefix=".building-", dir=self.root))
        try:
            subprocess.run(
                ["git", "-C", str(temporary), "init", "--quiet"],
                check=True, capture_output=True, text=True, env=_git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(temporary), "config", "core.hooksPath", os.devnull],
                check=True, capture_output=True, text=True, env=_git_environment(),
            )
            # Fetch only the selected commit and its history.  This avoids both
            # an alternate object store and disclosure of unrelated candidate
            # objects that happen to exist in the integrator repository.
            subprocess.run(
                ["git", "-C", str(temporary), "fetch", "--quiet", "--no-tags",
                 str(source_repo), base_sha],
                check=True, capture_output=True, text=True, env=_git_environment(),
            )
            subprocess.run(
                ["git", "-C", str(temporary), "checkout", "--detach", "--force", base_sha],
                check=True, capture_output=True, text=True, env=_git_environment(),
            )
            (temporary / ".git/FETCH_HEAD").unlink(missing_ok=True)
            alternates = temporary / ".git/objects/info/alternates"
            if alternates.exists() or alternates.is_symlink():
                raise RuntimeError("publication clone must not borrow source objects")
            tree_sha = _git(temporary, "rev-parse", f"{base_sha}^{{tree}}")
            marker = temporary / ".git" / MARKER
            marker.write_bytes(_canonical({
                "format": 1,
                "generation": base_sha,
                "repo": repo,
                "base_sha": base_sha,
                "tree_sha": tree_sha,
            }) + b"\n")
            self._validate_symlinks(temporary)
            self._set_reader_permissions(temporary, metadata)
            self._fsync_tree(temporary)
            try:
                _rename_noreplace(temporary, destination)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                # Another root-owned publisher won the identical generation.
                # Never replace it; verify its complete immutable contract.
                shutil.rmtree(temporary)
            self._fsync_directory(self.root)
        except Exception:
            if temporary.exists():
                shutil.rmtree(temporary)
            raise
        return self.verify(repo, base_sha)

    def verify(self, repo: str, base_sha: str) -> PublicationPin:
        """Fail closed unless the generation is a clean, self-contained clone."""
        self._validate_identity(repo, base_sha)
        self._require_root()
        generation = self.root / base_sha
        if generation.is_symlink() or not generation.is_dir():
            raise FileNotFoundError("publication generation is absent or unsafe")
        if generation.resolve(strict=True).parent != self.root.resolve(strict=True):
            raise PermissionError("publication generation escaped its configured root")
        self._validate_symlinks(generation)
        self._verify_reader_permissions(generation)
        git_directory = generation / ".git"
        if git_directory.is_symlink() or not git_directory.is_dir():
            raise PermissionError("publication Git directory is absent or unsafe")
        marker = git_directory / MARKER
        if marker.is_symlink() or not marker.is_file():
            raise PermissionError("publication marker is absent or unsafe")
        value = json.loads(marker.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != MARKER_FIELDS:
            raise PermissionError("publication marker has an invalid field set")
        expected = {
            "format": 1,
            "generation": base_sha,
            "repo": repo,
            "base_sha": base_sha,
            "tree_sha": _git(generation, "rev-parse", f"{base_sha}^{{tree}}"),
        }
        if value != expected:
            raise PermissionError("publication marker does not match the selected binding")
        if _git(generation, "rev-parse", "HEAD") != base_sha:
            raise PermissionError("publication HEAD does not match its generation")
        alternates = generation / ".git/objects/info/alternates"
        if alternates.exists() or alternates.is_symlink():
            raise PermissionError("publication depends on an external object store")
        uncommitted = _git(generation, "status", "--porcelain=v1", "--untracked-files=all")
        ignored = _git(generation, "ls-files", "--others", "--ignored", "--exclude-standard")
        if uncommitted or ignored:
            raise PermissionError("publication working tree is not immutable commit content")
        return PublicationPin(repo, base_sha, base_sha, generation, value["tree_sha"])

    def pin_binding(self, binding: Path, *, expected_repo: str | None = None,
                    expected_base_sha: str | None = None) -> PublicationPin:
        """Read one binding inode once and pin the selected immutable generation."""
        binding = Path(os.path.abspath(binding))
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(binding, flags)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PermissionError("publication binding must be a regular file")
            chunks = []
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(map(len, chunks)) > 65536:
                    raise PermissionError("publication binding is unexpectedly large")
        finally:
            os.close(descriptor)
        value = json.loads(b"".join(chunks))
        if not isinstance(value, dict) or set(value) != {"repo", "base_sha"}:
            raise PermissionError("publication binding must remain exactly {repo,base_sha}")
        repo, base_sha = value["repo"], value["base_sha"]
        self._validate_identity(repo, base_sha)
        if expected_repo is not None and repo != expected_repo:
            raise PermissionError("publication binding repository mismatch")
        if expected_base_sha is not None and base_sha != expected_base_sha:
            raise PermissionError("publication binding generation is stale")
        return self.verify(repo, base_sha)

    def _ensure_root(self, metadata: os.stat_result | None) -> None:
        if self.root.exists() or self.root.is_symlink():
            self._require_root()
        else:
            self.root.mkdir(parents=True, mode=0o750)
        if metadata is not None:
            current_mode = stat.S_IMODE(self.root.stat().st_mode)
            expected_mode = 0o750 | (current_mode & stat.S_ISGID)
            if current_mode & stat.S_ISGID and current_mode != expected_mode:
                raise PermissionError("setgid publication root must be provisioned with mode 2750")
            self._set_owner(self.root, metadata.st_uid, metadata.st_gid)
            # A graph publisher outside the reader group cannot restore SGID:
            # even chmod(path, 02750) can silently clear it without CAP_FSETID.
            # Leave an operator-provisioned 02750 root untouched so subsequent
            # generation trees inherit the binding's reader group at creation.
            if stat.S_IMODE(self.root.stat().st_mode) != expected_mode:
                os.chmod(self.root, expected_mode)
            observed = self.root.stat()
            if (observed.st_uid, observed.st_gid, stat.S_IMODE(observed.st_mode)) != (
                metadata.st_uid, metadata.st_gid, expected_mode,
            ):
                raise PermissionError("publication root ownership or permissions changed")

    def _require_root(self) -> None:
        if self.root.is_symlink() or not self.root.is_dir():
            raise PermissionError("publication root must be a non-symlink directory")
        if self.root.stat().st_mode & 0o022:
            raise PermissionError("publication root must not be group- or world-writable")

    @staticmethod
    def _validate_identity(repo: Any, base_sha: Any) -> None:
        if not isinstance(repo, str) or not SAFE_REPO.fullmatch(repo):
            raise ValueError("publication repository name is invalid")
        if not isinstance(base_sha, str) or not HEX40.fullmatch(base_sha):
            raise ValueError("publication generation SHA is invalid")

    def _set_reader_permissions(self, root: Path, metadata: os.stat_result | None) -> None:
        uid = metadata.st_uid if metadata is not None else os.geteuid()
        gid = metadata.st_gid if metadata is not None else os.getegid()
        for directory, names, files in os.walk(root, topdown=False, followlinks=False):
            directory_path = Path(directory)
            for name in files:
                item = directory_path / name
                if item.is_symlink():
                    continue
                mode = stat.S_IMODE(item.stat().st_mode)
                os.chmod(item, 0o750 if mode & 0o111 else 0o640)
                self._set_owner(item, uid, gid)
            for name in names:
                item = directory_path / name
                if item.is_symlink():
                    continue
                os.chmod(item, 0o750)
                self._set_owner(item, uid, gid)
            os.chmod(directory_path, 0o750)
            self._set_owner(directory_path, uid, gid)

    @staticmethod
    def _verify_reader_permissions(root: Path) -> None:
        for directory, names, files in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            if directory_path.stat().st_mode & 0o022:
                raise PermissionError("publication directory is writable by a reader")
            for name in (*names, *files):
                item = directory_path / name
                if item.is_symlink():
                    continue
                if item.stat().st_mode & 0o022:
                    raise PermissionError("publication bytes are writable by a reader")

    @staticmethod
    def _validate_symlinks(root: Path) -> None:
        """Allow only fully resolved relative worktree links to in-tree files.

        Directory links are rejected because even individually in-tree targets can
        form recursive traversal cycles.  Git-internal links are never part of the
        published worktree contract.
        """
        resolved_root = root.resolve(strict=True)
        for directory, directories, files in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            for name in (*directories, *files):
                item = directory_path / name
                metadata = item.lstat()
                if not stat.S_ISLNK(metadata.st_mode):
                    continue
                relative_item = item.relative_to(root)
                if relative_item.parts[0] == ".git":
                    raise PermissionError("publication Git metadata contains a symlink")
                target = os.readlink(item)
                if os.path.isabs(target):
                    raise PermissionError("publication contains an absolute symlink")
                lexical_target = Path(os.path.normpath(
                    os.path.join(str(relative_item.parent), target)
                ))
                if (
                    lexical_target.is_absolute()
                    or not lexical_target.parts
                    or lexical_target.parts[0] == ".."
                    or lexical_target.parts[0] == ".git"
                ):
                    raise PermissionError("publication symlink escapes or targets Git metadata")
                try:
                    resolved_target = item.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise PermissionError("publication contains a broken or cyclic symlink") from None
                if resolved_root not in resolved_target.parents:
                    raise PermissionError("publication symlink resolves outside its generation")
                resolved_relative = resolved_target.relative_to(resolved_root)
                if resolved_relative.parts[0] == ".git":
                    raise PermissionError("publication symlink resolves into Git metadata")
                if not resolved_target.is_file():
                    raise PermissionError("publication symlink must resolve to an in-tree file")

    @staticmethod
    def _set_owner(path: Path, uid: int, gid: int) -> None:
        current = path.stat()
        if (current.st_uid, current.st_gid) == (uid, gid):
            return
        if os.geteuid() != 0:
            raise PermissionError("cannot set publication ownership")
        os.chown(path, uid, gid, follow_symlinks=False)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _fsync_tree(self, root: Path) -> None:
        for directory, _, files in os.walk(root, topdown=False, followlinks=False):
            directory_path = Path(directory)
            for name in files:
                item = directory_path / name
                if item.is_symlink():
                    continue
                descriptor = os.open(item, os.O_RDONLY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            self._fsync_directory(directory_path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--expected-repo", required=True)
    parser.add_argument("--expected-base-sha", required=True)
    args = parser.parse_args()
    pin = PublicationStore(args.root).pin_binding(
        args.binding, expected_repo=args.expected_repo,
        expected_base_sha=args.expected_base_sha,
    )
    print(pin.path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
