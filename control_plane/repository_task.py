"""Strict, side-effect-free public repository task and check contracts.

Parsing returns independent dictionaries with all task limit defaults filled.
Callers must hash and freeze the original bytes separately: canonical(normalized
task) is a semantic identity, not the identity of the submitted file. This module
does not authorize tools, resolve evaluation inputs, or execute check programs.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import stat
from pathlib import Path
from types import MappingProxyType
from typing import Any


MAX_DOCUMENT_BYTES = 1024 * 1024
MAX_ARRAY_ITEMS = 256
MAX_TEXT_LENGTH = 65536
MAX_PATH_LENGTH = 4096
MAX_JSON_DEPTH = 64
# Required-test run IDs append "-attempt-N-required" and must fit the existing
# sealed protocol's 192-character identifier. Every supported attempt is 1..3.
MAX_TASK_IDENTIFIER_LENGTH = 173
MAX_CHECK_IDENTIFIER_LENGTH = 192
DEFAULT_LIMITS = MappingProxyType({
    "worker_invocations": 1,
    "worker_timeout_seconds": 900,
    "required_test_timeout_seconds": 300,
    "evaluation_timeout_seconds": 300,
    "max_output_bytes": 8 * 1024 * 1024,
})
MAX_LIMITS = MappingProxyType({
    "worker_invocations": 3,
    "worker_timeout_seconds": 3600,
    "required_test_timeout_seconds": 900,
    "evaluation_timeout_seconds": 900,
    "max_output_bytes": 8 * 1024 * 1024,
})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_TASK_REQUIRED = {
    "schema_version", "project_id", "task_id", "idempotency_key", "base_sha",
    "objective", "acceptance_criteria", "allowed_paths", "required_tests",
    "worker", "evaluation",
}


class RepositoryTaskError(ValueError):
    """Public admission failure with a machine-readable result classification."""

    def __init__(self, message: str, *, code: str = "INVALID_TASK") -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


def _fail(message: str) -> None:
    raise RepositoryTaskError(message)


def _json_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        _fail("JSON nesting exceeds the supported depth")
    if value is None or type(value) in (bool, int):
        return
    if type(value) is float:
        if not math.isfinite(value):
            _fail("nonfinite JSON numbers are forbidden")
    elif type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            _fail("JSON strings must contain valid Unicode scalar values")
    elif type(value) is list:
        for item in value:
            _json_value(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                _fail("JSON object keys must be strings")
            _json_value(key, depth + 1)
            _json_value(item, depth + 1)
    else:
        _fail("value is not a JSON value")


def canonical(value: Any) -> bytes:
    """Return canonical UTF-8 JSON: sorted, compact, ASCII escaped, no newline."""
    _json_value(value)
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError) as exc:
        raise RepositoryTaskError("cannot encode canonical JSON") from exc


def strict_json_bytes(raw: bytes) -> Any:
    """Decode bounded UTF-8 JSON, rejecting duplicate keys and nonfinite values."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_DOCUMENT_BYTES:
        _fail(f"JSON must be 1..{MAX_DOCUMENT_BYTES} bytes")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                _fail("duplicate JSON object key")
            result[key] = value
        return result

    def invalid_constant(_: str) -> Any:
        _fail("nonfinite JSON numbers are forbidden")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=invalid_constant)
        _json_value(value)
        return value
    except RepositoryTaskError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RepositoryTaskError("invalid UTF-8 JSON document") from exc


def read_regular(path: str | os.PathLike[str]) -> bytes:
    """Read a bounded stable regular file without following any path symlink.

    Directory descriptors pin each component; O_NONBLOCK prevents a FIFO from
    blocking before the regular-file check. This creates or modifies no files.
    """
    descriptors: list[int] = []
    try:
        supplied = os.fspath(path)
        if not isinstance(supplied, str) or not supplied or "\x00" in supplied:
            _fail("input path is invalid")
        candidate = Path(supplied)
        parts = candidate.parts
        if ".." in parts:
            _fail("input path cannot traverse a parent directory")
        if candidate.is_absolute():
            parts = parts[1:]
        if not parts:
            _fail("input must name a regular file")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open("/" if candidate.is_absolute() else ".", directory_flags)
        descriptors.append(directory)
        for part in parts[:-1]:
            directory = os.open(part, directory_flags, dir_fd=directory)
            descriptors.append(directory)
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK, dir_fd=directory)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_DOCUMENT_BYTES:
            _fail(f"input must be a regular file of 1..{MAX_DOCUMENT_BYTES} bytes")
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_DOCUMENT_BYTES:
            chunk = os.read(descriptor, min(65536, MAX_DOCUMENT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                                 item.st_mtime_ns, item.st_ctime_ns)
        if total > MAX_DOCUMENT_BYTES or total != before.st_size or identity(before) != identity(after):
            _fail("input changed during reading or exceeds the byte limit")
        return b"".join(chunks)
    except RepositoryTaskError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise RepositoryTaskError("input must be a readable regular file with no symlink components") from exc
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _object(value: Any, required: set[str], optional: set[str], name: str) -> None:
    if type(value) is not dict:
        _fail(f"{name} must be an object")
    if set(value) - required - optional:
        _fail(f"{name} has unknown fields")
    if required - set(value):
        _fail(f"{name} has missing fields")


def _text(value: Any, name: str, maximum: int = MAX_TEXT_LENGTH) -> None:
    if type(value) is not str or not value.strip() or len(value) > maximum or "\x00" in value:
        _fail(f"{name} must be a nonempty bounded string without NUL")
    _json_value(value)


def _identifier(value: Any, name: str, maximum: int = 200) -> None:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value) or len(value) > maximum:
        _fail(f"{name} must be a safe identifier of at most {maximum} characters")


def _array(value: Any, name: str) -> None:
    if type(value) is not list or not 1 <= len(value) <= MAX_ARRAY_ITEMS:
        _fail(f"{name} must be an array of 1..{MAX_ARRAY_ITEMS} items")


def _relative_path(value: Any, name: str, *, directory: bool = False) -> None:
    _text(value, name, MAX_PATH_LENGTH)
    if value.startswith("/") or "\\" in value or re.match(r"^[A-Za-z]:", value):
        _fail(f"{name} must be a relative Git path")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail(f"{name} cannot contain control characters")
    normalized = value[:-1] if directory and value.endswith("/") else value
    if any(part in {"", ".", ".."} or part.lower() == ".git" for part in normalized.split("/")):
        _fail(f"{name} cannot escape its root or reference .git")


def _unsupported_budget(value: Any) -> None:
    if type(value) is not dict:
        return
    for key, item in value.items():
        if type(key) is str and any(marker in key.lower() for marker in ("token", "dollar", "usd", "cost")):
            raise RepositoryTaskError("hard token or dollar limits are not supported by the CLI",
                                      code="BUDGET_UNSUPPORTED")
        if key == "budget":
            _unsupported_budget(item)


def validate_task(value: Any) -> dict[str, Any]:
    """Validate a task and return a copy with all five explicit limit values."""
    _json_value(value)
    _unsupported_budget(value)
    if type(value) is dict:
        _unsupported_budget(value.get("limits"))
    _object(value, _TASK_REQUIRED, {"limits"}, "task")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _fail("task schema_version must be integer 1")
    for name in ("project_id", "task_id", "idempotency_key"):
        _identifier(value[name], name, MAX_TASK_IDENTIFIER_LENGTH if name == "task_id" else 200)
    # The unchanged integrator embeds this exact value as an intermediate
    # component of refs/ai-ops/candidates/<task_id>/<candidate_sha>.
    if ".." in value["task_id"] or value["task_id"].endswith(".lock"):
        _fail("task_id cannot contain '..' or end with '.lock' in its candidate Git ref")
    if type(value["base_sha"]) is not str or not _COMMIT.fullmatch(value["base_sha"]):
        _fail("base_sha must be an exact lowercase 40-hex commit")
    _text(value["objective"], "objective")
    for name in ("acceptance_criteria", "required_tests", "allowed_paths"):
        _array(value[name], name)
        for item in value[name]:
            if name == "allowed_paths":
                _relative_path(item, name, directory=True)
            else:
                _text(item, name)
    _object(value["worker"], {"backend"}, set(), "worker")
    if type(value["worker"]["backend"]) is not str or value["worker"]["backend"] != "codex":
        _fail("worker backend must be codex")
    _object(value["evaluation"], {"policy", "checks"}, set(), "evaluation")
    for name, path in value["evaluation"].items():
        _relative_path(path, f"evaluation.{name}")
    supplied_limits = value.get("limits", {})
    _object(supplied_limits, set(), set(DEFAULT_LIMITS), "limits")
    for name, limit in supplied_limits.items():
        if type(limit) is not int or not 1 <= limit <= MAX_LIMITS[name]:
            _fail(f"limits.{name} must be an integer in 1..{MAX_LIMITS[name]}")
    result = copy.deepcopy(value)
    result["limits"] = {**DEFAULT_LIMITS, **supplied_limits}
    return result


def validate_checks(value: Any) -> dict[str, Any]:
    """Validate the checks-v1 envelope without authorizing or executing argv."""
    _json_value(value)
    _object(value, {"schema_version", "checks"}, set(), "checks document")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _fail("checks schema_version must be integer 1")
    _array(value["checks"], "checks")
    ids: set[str] = set()
    for check in value["checks"]:
        _object(check, {"id", "argv"}, set(), "check")
        _identifier(check["id"], "check.id", MAX_CHECK_IDENTIFIER_LENGTH)
        if check["id"] in ids:
            _fail("check IDs must be unique")
        ids.add(check["id"])
        _array(check["argv"], "check.argv")
        for argument in check["argv"]:
            _text(argument, "check.argv argument")
    return copy.deepcopy(value)


def parse_task_bytes(raw: bytes) -> dict[str, Any]:
    return validate_task(strict_json_bytes(raw))


def parse_checks_bytes(raw: bytes) -> dict[str, Any]:
    return validate_checks(strict_json_bytes(raw))


def load_repository_task(path: str | os.PathLike[str]) -> dict[str, Any]:
    return parse_task_bytes(read_regular(path))
