#!/usr/bin/env python3
"""Create a portable candidate bundle with deterministic required-test evidence."""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


HEX40 = re.compile(r"^[a-f0-9]{40}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,199}$")
TEST_RESULT_FIELDS = {"sequence", "command", "candidate_sha", "exit_code", "output"}
FILE_RECORD_FIELDS = {"path", "sha256", "byte_length"}
MINIMAL_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
DEFAULT_REQUIRED_TEST_OUTPUT_LIMIT = 8 * 1024 * 1024
MAX_ATTEMPT_NUMBER = 1_000_000
AT_FDCWD = -100
RENAME_NOREPLACE = 1
PR_SET_CHILD_SUBREAPER = 36
INTERNAL_SUPERVISOR_FLAG = "--internal-required-test-supervisor"
SUPERVISOR_CLEANUP_SECONDS = 5.0


class RequiredTestOutputLimitExceeded(PermissionError):
    """A required test emitted more evidence bytes than the fixed local bound."""

    def __init__(self, limit: int, output: bytes):
        super().__init__(f"required test combined output exceeded {limit} bytes")
        self.limit = limit
        self.output = output


class RequiredTestContainmentFailure(RuntimeError):
    """The trusted supervisor could not prove descendant quiescence in time."""


def sha256(path: Path) -> str:
    return sha256_and_length(path)[0]


def sha256_and_length(path: Path) -> tuple[str, int]:
    value = hashlib.sha256()
    length = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
            length += len(chunk)
    return value.hexdigest(), length


def safe_relative_artifact_path(value: Any) -> Path:
    """Return a normalized portable relative path or fail closed."""
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise PermissionError("artifact path must be a non-empty portable string")
    path = Path(value)
    if path.is_absolute() or path == Path(".") or ".." in path.parts or "." in path.parts:
        raise PermissionError("artifact path must be normalized and relative")
    if str(path) != value or any(not part for part in path.parts):
        raise PermissionError("artifact path must be normalized and relative")
    return path


def _regular_single_link(path: Path, root: Path) -> Path:
    if path.is_symlink():
        raise PermissionError("artifact must not be a symlink")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise PermissionError("artifact must be a regular single-link file")
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved_root != resolved.parent and resolved_root not in resolved.parents:
        raise PermissionError("artifact escapes its manifest directory")
    return resolved


def _write_new_file(path: Path, data: bytes, mode: int = 0o400) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _file_record(relative_path: str, absolute_path: Path) -> dict[str, Any]:
    file_hash, byte_length = sha256_and_length(absolute_path)
    return {"path": relative_path, "sha256": file_hash, "byte_length": byte_length}


def _read_stable_input(path: Path, maximum: int = 1024 * 1024) -> bytes:
    """Read one regular single-link input without following a final symlink."""
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
            raise PermissionError("artifact input must be a bounded regular single-link file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise PermissionError("artifact input exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        fingerprint = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if fingerprint(before) != fingerprint(after) or total != after.st_size:
            raise PermissionError("artifact input changed while being read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _minimal_environment(home: Path) -> dict[str, str]:
    """Return a deterministic subprocess environment with no inherited secrets."""
    return {
        "HOME": str(home),
        "PATH": MINIMAL_PATH,
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "PYTHONDONTWRITEBYTECODE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically publish one completed attempt without replacing a raced inode."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is required for immutable artifact publication")
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


def _validate_attempt_number(value: Any) -> int:
    if type(value) is not int or not 1 <= value <= MAX_ATTEMPT_NUMBER:
        raise ValueError(f"attempt number must be 1..{MAX_ATTEMPT_NUMBER}")
    return value


def _git_probe(workspace: Path, environment: dict[str, str], *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.fsmonitor=false", "-C", str(workspace), *arguments],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=environment, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise PermissionError("required-test candidate Git state could not be verified") from None
    return completed.stdout


def _assert_clean_candidate(
    workspace: Path, candidate_sha: str, environment: dict[str, str],
) -> None:
    """Bind every command boundary to one clean candidate checkout."""
    head = _git_probe(workspace, environment, "rev-parse", "--verify", "HEAD^{commit}").strip()
    if head != candidate_sha:
        raise PermissionError("required-test workspace HEAD differs from the candidate")
    status = _git_probe(
        workspace, environment, "status", "--porcelain=v1", "--untracked-files=all",
    )
    ignored = _git_probe(
        workspace, environment, "ls-files", "--others", "--ignored", "--exclude-standard",
    )
    if status or ignored:
        raise PermissionError("required-test workspace is not exactly clean")


def _parse_proc_stat(value: str) -> tuple[int, str, int, int, int]:
    """Parse PID/state/PPID/PGRP/start-time without splitting the comm field."""
    opening = value.find("(")
    closing = value.rfind(")")
    if opening <= 0 or closing <= opening:
        raise ValueError("malformed /proc stat record")
    pid = int(value[:opening].strip())
    suffix = value[closing + 1:].strip().split()
    # Fields after comm begin at proc(5) field 3. starttime is field 22.
    if len(suffix) < 20 or len(suffix[0]) != 1:
        raise ValueError("truncated /proc stat record")
    return pid, suffix[0], int(suffix[1]), int(suffix[2]), int(suffix[19])


def _read_proc_identity(pid: int) -> tuple[int, str, int, int, int]:
    try:
        return _parse_proc_stat(
            (Path("/proc") / str(pid) / "stat").read_text(
                encoding="utf-8", errors="surrogateescape",
            )
        )
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessLookupError(pid) from None


def _signal_process(pid: int, requested_signal: int) -> None:
    """Signal one exact process through pidfd; PID-only fallback is forbidden."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux pidfd signaling is unavailable")
    try:
        before = _read_proc_identity(pid)
        descriptor = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return
    try:
        after = _read_proc_identity(pid)
        if before[0] != pid or after[0] != pid or before[4] != after[4]:
            raise RuntimeError("required-test child identity changed during pidfd acquisition")
        signal.pidfd_send_signal(descriptor, requested_signal)
    except ProcessLookupError:
        pass
    finally:
        os.close(descriptor)


def _signal_pidfd(descriptor: int, requested_signal: int) -> None:
    if not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux pidfd signaling is unavailable")
    try:
        signal.pidfd_send_signal(descriptor, requested_signal)
    except ProcessLookupError:
        pass


def _direct_child_pids() -> set[int]:
    """Read the calling helper thread's kernel-maintained direct-child set."""
    children_path = Path("/proc/self/task") / str(os.getpid()) / "children"
    try:
        value = children_path.read_text(encoding="ascii")
    except (FileNotFoundError, PermissionError, UnicodeDecodeError) as exc:
        raise RuntimeError("Linux direct-child accounting is unavailable") from exc
    try:
        return {int(item) for item in value.split()}
    except ValueError:
        raise RuntimeError("Linux direct-child accounting is malformed") from None


def _reap_adopted_children() -> bool:
    """Reap every waitable child; return true only when waitpid proves ECHILD."""
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            return False


def _terminate_supervised_descendants(
    supervisor_pid: int, command_process: subprocess.Popen[bytes],
) -> set[int]:
    """Freeze, kill, adopt, and reap until waitpid proves no child exists."""
    if supervisor_pid != os.getpid():
        raise RuntimeError("descendant cleanup must run inside the dedicated supervisor")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux pidfd signaling is required for descendant containment")
    observed: set[int] = set()
    deadline = time.monotonic() + SUPERVISOR_CLEANUP_SECONDS
    deadline_exceeded = False
    cleanup_errors: list[str] = []

    def signal_children(children: set[int], requested_signal: int) -> None:
        for pid in children:
            try:
                _signal_process(pid, requested_signal)
            except BaseException as exc:
                message = f"{type(exc).__name__}: {exc}"
                if message not in cleanup_errors:
                    cleanup_errors.append(message)

    while True:
        if time.monotonic() >= deadline:
            deadline_exceeded = True
        children = _direct_child_pids()
        observed.update(children)
        # SIGSTOP is uncatchable and closes the fork/setsid race before the
        # second snapshot. Killing one generation reparents its descendants to
        # this subreaper, where the next kernel children read captures them.
        signal_children(children, signal.SIGSTOP)
        if children:
            time.sleep(0.01)
        children = _direct_child_pids()
        observed.update(children)
        signal_children(children, signal.SIGKILL)
        if command_process.returncode is None:
            try:
                command_process.wait(timeout=0.05)
            except subprocess.TimeoutExpired:
                pass
        no_children = _reap_adopted_children()
        if no_children:
            if _direct_child_pids():
                raise RuntimeError("waitpid and Linux child accounting disagree")
            if deadline_exceeded or cleanup_errors:
                detail = "; ".join(cleanup_errors) or "deadline exceeded"
                raise RequiredTestContainmentFailure(
                    f"required-test descendant cleanup proof failed: {detail}"
                )
            return observed
        time.sleep(0.01)


def _write_supervisor_status(descriptor: int, status: dict[str, Any]) -> None:
    data = json.dumps(status, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    while data:
        written = os.write(descriptor, data)
        data = data[written:]


def _required_test_supervisor(
    status_descriptor: int, start_descriptor: int, command: str,
) -> int:
    """Trusted Linux subreaper wrapper; command descendants never own its status FD."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Linux pidfd signaling is required for required-test containment")
    _direct_child_pids()
    stop_requested = False

    def request_stop(_signal: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        start_token = os.read(start_descriptor, 1)
    finally:
        os.close(start_descriptor)
    if start_token != b"1":
        _write_supervisor_status(status_descriptor, {
            "cancelled": True,
            "cleanup_error": "supervisor start handshake was not authorized",
            "command_returncode": None,
            "leaked_descendants": False,
        })
        os.close(status_descriptor)
        return 70
    process = subprocess.Popen(
        ["/bin/sh", "-c", command], stdin=subprocess.DEVNULL,
        stdout=None, stderr=subprocess.STDOUT, close_fds=True,
    )
    while not stop_requested and process.poll() is None:
        time.sleep(0.01)

    command_returncode = process.returncode
    children = _direct_child_pids()
    no_children = _reap_adopted_children()
    children.update(_direct_child_pids())
    leaked = not stop_requested and (bool(children) or not no_children)
    cleanup_error = None
    if stop_requested or children or not no_children:
        try:
            _terminate_supervised_descendants(os.getpid(), process)
        except BaseException as exc:
            cleanup_error = f"{type(exc).__name__}: {exc}"
        command_returncode = process.returncode
    else:
        if not _reap_adopted_children():
            cleanup_error = "waitpid did not prove ECHILD after command completion"
    status = {
        "cancelled": stop_requested,
        "cleanup_error": cleanup_error,
        "command_returncode": command_returncode,
        "leaked_descendants": leaked,
    }
    try:
        _write_supervisor_status(status_descriptor, status)
    finally:
        os.close(status_descriptor)
    return 0 if cleanup_error is None else 70


def _read_supervisor_status(descriptor: int) -> dict[str, Any]:
    data = bytearray()
    try:
        while True:
            chunk = os.read(descriptor, 4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 65536:
                raise RequiredTestContainmentFailure(
                    "required-test supervisor status exceeded its bound"
                )
    finally:
        os.close(descriptor)
    try:
        status = json.loads(bytes(data))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RequiredTestContainmentFailure(
            "required-test supervisor returned invalid status"
        ) from None
    if not isinstance(status, dict) or set(status) != {
        "cancelled", "cleanup_error", "command_returncode", "leaked_descendants",
    }:
        raise RequiredTestContainmentFailure(
            "required-test supervisor status shape is invalid"
        )
    if (
        type(status["cancelled"]) is not bool
        or type(status["leaked_descendants"]) is not bool
        or status["cleanup_error"] is not None
        and not isinstance(status["cleanup_error"], str)
        or status["command_returncode"] is not None
        and type(status["command_returncode"]) is not int
    ):
        raise RequiredTestContainmentFailure(
            "required-test supervisor status values are invalid"
        )
    return status


def _run_bounded_test_command(
    workspace: Path,
    command: str,
    environment: dict[str, str],
    timeout_seconds: float,
    output_limit: int,
) -> tuple[int, bytes]:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RequiredTestContainmentFailure(
            "Linux pidfd supervision is unavailable"
        )
    status_read, status_write = os.pipe()
    start_read, start_write = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable, str(Path(__file__).resolve()), INTERNAL_SUPERVISOR_FLAG,
            str(status_write), str(start_read), command,
        ],
        cwd=workspace, env=environment,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
        bufsize=0, pass_fds=(status_write, start_read),
    )
    os.close(status_write)
    os.close(start_read)
    try:
        supervisor_pidfd = os.pidfd_open(process.pid, 0)
    except OSError as exc:
        os.close(start_write)
        process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS)
        os.close(status_read)
        raise RequiredTestContainmentFailure(
            "required-test supervisor pidfd could not be opened"
        ) from exc
    try:
        os.write(start_write, b"1")
    except OSError as exc:
        os.close(start_write)
        process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS)
        os.close(status_read)
        if process.stdout is not None:
            process.stdout.close()
        os.close(supervisor_pidfd)
        raise RequiredTestContainmentFailure(
            "required-test supervisor rejected its start handshake"
        ) from exc
    else:
        os.close(start_write)
    status_consumed = False
    if process.stdout is None:
        os.close(status_read)
        status_consumed = True
        _signal_pidfd(supervisor_pidfd, signal.SIGTERM)
        process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS)
        os.close(supervisor_pidfd)
        raise RuntimeError("required-test output pipe was not created")
    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    failure: BaseException | None = None
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = subprocess.TimeoutExpired(command, timeout_seconds, output=bytes(output))
                break
            events = selector.select(remaining)
            if not events:
                failure = subprocess.TimeoutExpired(command, timeout_seconds, output=bytes(output))
                break
            chunk = os.read(process.stdout.fileno(), min(65536, output_limit - len(output) + 1))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > output_limit:
                failure = RequiredTestOutputLimitExceeded(output_limit, bytes(output))
                break
        if failure is not None:
            _signal_pidfd(supervisor_pidfd, signal.SIGTERM)
            selector.unregister(process.stdout)
            try:
                process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS + 1)
            except subprocess.TimeoutExpired:
                os.close(status_read)
                status_consumed = True
                raise RequiredTestContainmentFailure(
                    "required-test supervisor did not prove quiescence by its deadline"
                ) from failure
            remaining_capacity = max(0, output_limit + 1 - len(output))
            if remaining_capacity:
                output.extend(os.read(process.stdout.fileno(), remaining_capacity))
            status_consumed = True
            status = _read_supervisor_status(status_read)
            if process.returncode != 0 or status["cleanup_error"] is not None:
                raise RequiredTestContainmentFailure(
                    "required-test supervisor could not prove containment"
                ) from failure
            failure.output = bytes(output)
            raise failure
        return_code = process.poll()
        if return_code is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _signal_pidfd(supervisor_pidfd, signal.SIGTERM)
                process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS + 1)
                status_consumed = True
                status = _read_supervisor_status(status_read)
                if process.returncode != 0 or status["cleanup_error"] is not None:
                    raise RequiredTestContainmentFailure(
                        "required-test supervisor could not prove containment"
                    )
                raise subprocess.TimeoutExpired(
                    command, timeout_seconds, output=bytes(output),
                )
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                _signal_pidfd(supervisor_pidfd, signal.SIGTERM)
                process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS + 1)
                status_consumed = True
                status = _read_supervisor_status(status_read)
                if process.returncode != 0 or status["cleanup_error"] is not None:
                    raise RequiredTestContainmentFailure(
                        "required-test supervisor could not prove containment"
                    )
                raise subprocess.TimeoutExpired(
                    command, timeout_seconds, output=bytes(output),
                ) from None
        status_consumed = True
        status = _read_supervisor_status(status_read)
        if process.returncode != 0 or status["cleanup_error"] is not None:
            raise RequiredTestContainmentFailure(
                "required-test supervisor could not prove containment"
            )
        if status["cancelled"]:
            raise PermissionError("required-test supervisor was interrupted")
        if status["leaked_descendants"]:
            raise PermissionError("required test left a detached descendant")
        if status["command_returncode"] is None:
            raise RuntimeError("required-test supervisor lost the command exit status")
        return int(status["command_returncode"]), bytes(output)
    except BaseException as caught:
        if isinstance(caught, RequiredTestContainmentFailure):
            raise
        if process.poll() is None:
            try:
                _signal_pidfd(supervisor_pidfd, signal.SIGTERM)
                process.wait(timeout=SUPERVISOR_CLEANUP_SECONDS + 1)
            except subprocess.TimeoutExpired as exc:
                raise RequiredTestContainmentFailure(
                    "required-test supervisor cleanup proof timed out"
                ) from exc
        raise
    finally:
        selector.close()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()
        if not status_consumed:
            try:
                os.close(status_read)
            except OSError:
                pass
        os.close(supervisor_pidfd)


def produce_required_test_results(
    workspace: Path,
    commands: list[str],
    candidate_sha: str,
    artifact_root: Path,
    timeout_seconds: int = 300,
    max_output_bytes: int = DEFAULT_REQUIRED_TEST_OUTPUT_LIMIT,
    *,
    test_runner=None,
) -> list[dict[str, Any]]:
    """Run commands against one unchanged candidate with bounded exact output."""
    if not HEX40.fullmatch(candidate_sha):
        raise ValueError("required tests need a full candidate SHA")
    if not isinstance(commands, list) or not commands or not all(
        isinstance(command, str) and command and "\x00" not in command for command in commands
    ):
        raise ValueError("required test commands must be a non-empty string list")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 21600:
        raise ValueError("required test timeout must be 1..21600 seconds")
    if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 64 * 1024 * 1024:
        raise ValueError("required test output limit must be 1..67108864 bytes")
    workspace = workspace.resolve(strict=True)
    if test_runner is not None:
        # The generic workflow supplies a broker adapter. The adapter executes
        # candidate code in the test role and copies only verified sealed output.
        results = test_runner(workspace, commands, candidate_sha, artifact_root,
                              timeout_seconds, max_output_bytes)
        validate_required_test_results(results, commands, candidate_sha, artifact_root)
        if sum(item["output"]["byte_length"] for item in results) > max_output_bytes:
            raise PermissionError("required test output exceeds the suite limit")
        return results
    output_dir = artifact_root / "required-tests"
    output_dir.mkdir(mode=0o700)
    results: list[dict[str, Any]] = []
    total_output = 0
    deadline = time.monotonic() + timeout_seconds
    with tempfile.TemporaryDirectory(prefix="artifact-test-home-") as temporary_home:
        for sequence, command in enumerate(commands):
            home = Path(temporary_home) / f"home-{sequence:04d}"
            home.mkdir(mode=0o700)
            environment = _minimal_environment(home)
            _assert_clean_candidate(workspace, candidate_sha, environment)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            failure: BaseException | None = None
            try:
                return_code, output = _run_bounded_test_command(
                    workspace, command, environment, remaining,
                    max_output_bytes - total_output,
                )
            except BaseException as exc:
                failure = exc
            try:
                _assert_clean_candidate(workspace, candidate_sha, environment)
            except BaseException as state_error:
                if failure is not None:
                    raise state_error from failure
                raise
            if failure is not None:
                raise failure
            total_output += len(output)
            relative = f"required-tests/{sequence:04d}.output"
            output_path = artifact_root / relative
            _write_new_file(output_path, output)
            if return_code != 0:
                raise PermissionError("required test command returned a nonzero exit status")
            results.append({
                "sequence": sequence,
                "command": command,
                "candidate_sha": candidate_sha,
                "exit_code": return_code,
                "output": _file_record(relative, output_path),
            })
    return results


def validate_required_test_results(
    results: Any,
    contract_commands: Any,
    candidate_sha: str,
    artifact_root: Path,
) -> list[Path]:
    """Validate exact order/command/SHA/exit/output bindings for required tests."""
    if not isinstance(contract_commands, list) or not contract_commands:
        raise PermissionError("contract required tests are absent")
    if not isinstance(results, list) or len(results) != len(contract_commands):
        raise PermissionError("required test result count differs from the contract")
    paths: list[Path] = []
    seen: set[Path] = set()
    for sequence, (result, command) in enumerate(zip(results, contract_commands)):
        if not isinstance(command, str) or not command:
            raise PermissionError("contract required test command is invalid")
        if not isinstance(result, dict) or set(result) != TEST_RESULT_FIELDS:
            raise PermissionError("required test result has an unexpected field set")
        if type(result["sequence"]) is not int or result["sequence"] != sequence:
            raise PermissionError("required test result order differs from the contract")
        if result["command"] != command:
            raise PermissionError("required test command differs from the contract")
        if result["candidate_sha"] != candidate_sha:
            raise PermissionError("required test result is bound to a different candidate")
        if type(result["exit_code"]) is not int or result["exit_code"] != 0:
            raise PermissionError("required test did not record an integer zero exit code")
        output = result["output"]
        if not isinstance(output, dict) or set(output) != FILE_RECORD_FIELDS:
            raise PermissionError("required test output record is invalid")
        relative = safe_relative_artifact_path(output["path"])
        if relative in seen:
            raise PermissionError("required test output paths must be unique")
        seen.add(relative)
        if not isinstance(output["sha256"], str) or not HEX64.fullmatch(output["sha256"]):
            raise PermissionError("required test output hash is invalid")
        if type(output["byte_length"]) is not int or output["byte_length"] < 0:
            raise PermissionError("required test output byte length is invalid")
        path = _regular_single_link(artifact_root / relative, artifact_root)
        actual_hash, actual_length = sha256_and_length(path)
        if (actual_hash, actual_length) != (output["sha256"], output["byte_length"]):
            raise PermissionError("required test output bytes do not match the manifest")
        paths.append(path)
    return paths


def run(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True,
        text=True, env=env,
    ).stdout.strip()


def build(
    attempt: Path,
    contract_path: Path,
    path_check: Path,
    output_dir: Path,
    attempt_number: int,
    *,
    test_runner=None,
) -> dict:
    attempt_number = _validate_attempt_number(attempt_number)
    contract_bytes = _read_stable_input(contract_path)
    path_check_bytes = _read_stable_input(path_check)
    contract = json.loads(contract_bytes)
    try:
        path_check_value = json.loads(path_check_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise PermissionError("path-check evidence is invalid JSON") from None
    if (
        not isinstance(path_check_value, dict)
        or set(path_check_value) != {"valid", "violations"}
        or path_check_value["valid"] is not True
        or path_check_value["violations"] != []
    ):
        raise PermissionError("path-check evidence did not pass")
    task_id = contract["task_id"]
    if not isinstance(task_id, str) or not SAFE_ID.fullmatch(task_id):
        raise ValueError("contract task ID is unsafe")
    base_sha = contract["base_sha"]
    if not isinstance(base_sha, str) or not HEX40.fullmatch(base_sha):
        raise ValueError("contract base SHA is invalid")
    if run(attempt, "rev-parse", f"{base_sha}^{{commit}}") != base_sha:
        raise ValueError("contract base SHA is absent from attempt")
    if run(attempt, "rev-parse", "HEAD") != base_sha:
        raise ValueError("attempt must start exactly at the contract base SHA")
    changed = [value for value in run(attempt, "status", "--porcelain").splitlines() if value]
    if not changed:
        raise ValueError("worker produced no candidate changes")
    run(attempt, "add", "-A")
    with tempfile.TemporaryDirectory(prefix="artifact-git-home-") as temporary_home:
        environment = {
            **_minimal_environment(Path(temporary_home)),
            "GIT_AUTHOR_NAME": "Codex isolated builder",
            "GIT_AUTHOR_EMAIL": "builder@localhost",
            "GIT_COMMITTER_NAME": "Codex isolated builder",
            "GIT_COMMITTER_EMAIL": "builder@localhost",
        }
        run(
            attempt, "commit", "-m", f"Candidate {task_id} attempt {attempt_number}",
            env=environment,
        )
    candidate_sha = run(attempt, "rev-parse", "HEAD")
    if run(attempt, "rev-list", "--parents", "-n", "1", candidate_sha).split() != [candidate_sha, base_sha]:
        raise ValueError("artifact candidate must be one non-merge commit atop the contract base")

    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_dir.is_symlink() or not output_dir.is_dir():
        raise PermissionError("artifact output root is unsafe")
    task_root = output_dir / task_id
    task_root.mkdir(mode=0o700, exist_ok=True)
    if task_root.is_symlink() or not task_root.is_dir():
        raise PermissionError("artifact task namespace is unsafe")
    _fsync_directory(output_dir)
    final_dir = task_root / f"attempt-{attempt_number}"
    if final_dir.exists() or final_dir.is_symlink():
        raise FileExistsError("task attempt artifact directory already exists")
    staging = Path(tempfile.mkdtemp(prefix=f".attempt-{attempt_number}.", dir=task_root))
    try:
        bundle = staging / "candidate.bundle"
        subprocess.run(
            ["git", "-C", str(attempt), "bundle", "create", str(bundle), "HEAD", f"^{base_sha}"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(attempt), "bundle", "verify", str(bundle)],
            check=True, capture_output=True,
        )
        os.chmod(bundle, 0o400)
        bundle_descriptor = os.open(bundle, os.O_RDONLY)
        try:
            os.fsync(bundle_descriptor)
        finally:
            os.close(bundle_descriptor)

        path_check_copy = staging / "path-check.json"
        _write_new_file(path_check_copy, path_check_bytes)

        required_tests = produce_required_test_results(
            attempt, contract["required_tests"], candidate_sha, staging,
            contract.get("timeout_seconds", 300),
            test_runner=test_runner,
        )
        validate_required_test_results(
            required_tests, contract["required_tests"], candidate_sha, staging,
        )
        manifest = {
            "schema_version": 4,
            "task_id": task_id,
            "attempt": attempt_number,
            "project_id": contract["project_id"],
            "base_sha": base_sha,
            "candidate_sha": candidate_sha,
            "producer_identity": contract["builder_identity"],
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "contract_sha256": hashlib.sha256(contract_bytes).hexdigest(),
            "path_check": _file_record("path-check.json", path_check_copy),
            "bundle": _file_record("candidate.bundle", bundle),
            "required_tests": required_tests,
        }
        manifest_path = staging / "manifest.json"
        _write_new_file(
            manifest_path,
            (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(),
        )
        _fsync_directory(staging)
        try:
            _rename_noreplace(staging, final_dir)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                raise FileExistsError("task attempt artifact directory already exists") from exc
            raise
        _fsync_directory(task_root)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    manifest_path = final_dir / "manifest.json"
    return {
        **manifest,
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256(manifest_path),
    }


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == INTERNAL_SUPERVISOR_FLAG:
        if len(sys.argv) != 5:
            raise SystemExit("invalid required-test supervisor invocation")
        return _required_test_supervisor(
            int(sys.argv[2]), int(sys.argv[3]), sys.argv[4],
        )
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempt", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--path-check", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--attempt-number", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(build(
        args.attempt, args.contract, args.path_check, args.output_dir,
        args.attempt_number,
    ), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
