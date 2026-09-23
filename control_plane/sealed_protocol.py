"""Private, strict wire contracts for the privileged evaluation broker.

No request in this module grants authority. The launcher resolves a registered
name against its frozen startup inputs before any executable action.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any

MAX_WIRE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_COMMANDS = 256
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")


class ProtocolError(ValueError):
    """A noncanonical, malformed, or unbound broker message."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON key")
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProtocolError("invalid canonical JSON value") from exc


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(value: Any) -> str:
    return sha256(canonical(value))


def load_json(data: bytes | str, *, require_canonical: bool = True) -> Any:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if type(data) is not bytes or len(data) > MAX_WIRE_BYTES:
        raise ProtocolError("JSON exceeds transport limit")
    try:
        value = json.loads(data, object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ProtocolError("nonfinite JSON number")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if require_canonical and canonical(value) != data:
        raise ProtocolError("JSON bytes are not canonical")
    return value


def _input(value: Any) -> dict[str, Any]:
    if isinstance(value, (bytes, str)):
        value = load_json(value)
    if type(value) is not dict:
        raise ProtocolError("expected JSON object")
    data = canonical(value)
    if len(data) > MAX_WIRE_BYTES:
        raise ProtocolError("JSON exceeds transport limit")
    return load_json(data)


def _keys(value: Any, names: str) -> None:
    if type(value) is not dict or set(value) != set(names.split()):
        raise ProtocolError("object does not match exact schema")


def _int(value: Any, low: int, high: int = 2**63 - 1) -> None:
    if type(value) is not int or not low <= value <= high:
        raise ProtocolError("integer outside bounds")


def _str(value: Any, maximum: int = 65536) -> None:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum or "\0" in value:
        raise ProtocolError("invalid bounded string")


def identifier(value: Any) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ProtocolError("invalid identifier")


def hex64(value: Any) -> None:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ProtocolError("invalid lowercase SHA-256")


def hex40(value: Any) -> None:
    if type(value) is not str or _HEX40.fullmatch(value) is None:
        raise ProtocolError("invalid lowercase commit SHA")


def relative_path(value: Any) -> None:
    _str(value, 512)
    path = PurePosixPath(value)
    if (path.is_absolute() or str(path) != value or any(p in {".", ".."} for p in path.parts)
            or "\\" in value or any(ord(c) < 32 for c in value)):
        raise ProtocolError("unsafe relative path")


def absolute_path(value: Any) -> None:
    _str(value, 4096)
    path = PurePosixPath(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts or "\\" in value:
        raise ProtocolError("unsafe absolute path")


def _version(value: Any) -> None:
    _int(value, 1, 1)


def _checks(value: Any) -> None:
    if type(value) is not list or not 1 <= len(value) <= MAX_COMMANDS:
        raise ProtocolError("invalid checks array")
    names = set()
    for check in value:
        _keys(check, "id argv")
        identifier(check["id"])
        if check["id"] in names:
            raise ProtocolError("duplicate check ID")
        names.add(check["id"])
        argv = check["argv"]
        if type(argv) is not list or not 1 <= len(argv) <= 256:
            raise ProtocolError("invalid check argv")
        for arg in argv:
            _str(arg)


def validate_candidate_test_request(value: Any) -> dict[str, Any]:
    v = _input(value)
    _keys(v, "schema_version run_id kind candidate_sha candidate_root task_sha256 profile_sha256 commands_sha256 commands checks timeout_seconds max_output_bytes")
    _version(v["schema_version"])
    identifier(v["run_id"])
    hex40(v["candidate_sha"])
    absolute_path(v["candidate_root"])
    for key in ("task_sha256", "profile_sha256", "commands_sha256"):
        hex64(v[key])
    _int(v["timeout_seconds"], 1, 900)
    _int(v["max_output_bytes"], 1, MAX_OUTPUT_BYTES)
    if v["kind"] == "required":
        commands = v["commands"]
        if type(commands) is not list or not 1 <= len(commands) <= MAX_COMMANDS or v["checks"] != []:
            raise ProtocolError("required run must contain only required commands")
        for command in commands:
            _str(command)
        bound = commands
    elif v["kind"] == "independent":
        if v["commands"] != []:
            raise ProtocolError("independent run cannot contain required commands")
        _checks(v["checks"])
        bound = v["checks"]
    else:
        raise ProtocolError("invalid candidate run kind")
    if v["commands_sha256"] != digest(bound):
        raise ProtocolError("ordered commands hash mismatch")
    return v


def validate_evaluation_request(value: Any) -> dict[str, Any]:
    v = _input(value)
    _keys(v, "schema_version workspace_id task_sha256 profile_sha256 policy_sha256 checks_sha256 producer_contract_sha256 artifact_id manifest_sha256 evaluation_id evaluator_contract_id claim_id previous_ledger_hash required_receipt_id")
    _version(v["schema_version"])
    for key in ("workspace_id", "task_sha256", "profile_sha256", "policy_sha256", "checks_sha256", "producer_contract_sha256", "manifest_sha256", "required_receipt_id"):
        hex64(v[key])
    for key in ("evaluation_id", "evaluator_contract_id"):
        identifier(v[key])
    if v["artifact_id"] != "sha256:" + v["manifest_sha256"]:
        raise ProtocolError("artifact ID is not manifest-derived")
    if type(v["claim_id"]) is not str or not v["claim_id"].startswith("claim:"):
        raise ProtocolError("invalid claim ID")
    hex64(v["claim_id"][6:])
    if v["previous_ledger_hash"] is not None:
        hex64(v["previous_ledger_hash"])
    return v


def validate_signing_request(value: Any) -> dict[str, Any]:
    v = _input(value)
    _keys(v, "schema_version evaluation evaluation_request_sha256 independent_receipt_id candidate_sha")
    _version(v["schema_version"])
    v["evaluation"] = validate_evaluation_request(v["evaluation"])
    hex64(v["evaluation_request_sha256"])
    hex64(v["independent_receipt_id"])
    hex40(v["candidate_sha"])
    if v["evaluation_request_sha256"] != digest(v["evaluation"]):
        raise ProtocolError("evaluation request hash mismatch")
    return v


def _hash_id(v: dict[str, Any], field: str) -> None:
    hex64(v[field])
    if v[field] != digest({k: x for k, x in v.items() if k != field}):
        raise ProtocolError("content-derived ID mismatch")


def validate_launcher_request(value: Any) -> dict[str, Any]:
    v = _input(value)
    _keys(v, "schema_version action workspace_id request_id request_sha256 payload")
    _version(v["schema_version"])
    hex64(v["workspace_id"])
    identifier(v["request_id"])
    if type(v["action"]) is not str:
        raise ProtocolError("launcher action must be a string")
    if v["action"] in {"provider-preflight", "shutdown"}:
        _keys(v["payload"], "")
    elif v["action"] in {"worker-launch", "candidate-tests"}:
        _keys(v["payload"], "registered_request_id")
        identifier(v["payload"]["registered_request_id"])
    elif v["action"] == "sign-evaluation":
        v["payload"] = validate_evaluation_request(v["payload"])
        if v["payload"]["workspace_id"] != v["workspace_id"]:
            raise ProtocolError("workspace mismatch")
    elif v["action"] == "immutable-receipt-fetch":
        _keys(v["payload"], "receipt_id")
        hex64(v["payload"]["receipt_id"])
    else:
        raise ProtocolError("unknown launcher action")
    _hash_id(v, "request_sha256")
    return v


def validate_sealed_test_receipt(value: Any) -> dict[str, Any]:
    v = _input(value)
    _keys(v, "schema_version receipt_id request_id request_sha256 run_id kind workspace_id task_sha256 profile_sha256 commands_sha256 candidate_sha pre_tree_sha256 post_tree_sha256 actual_uid actual_gid namespaces capabilities no_new_privs results elapsed_ms limits descendants replayed")
    _version(v["schema_version"])
    for key in ("request_id", "run_id"):
        identifier(v[key])
    for key in ("receipt_id", "request_sha256", "workspace_id", "task_sha256", "profile_sha256", "commands_sha256", "pre_tree_sha256", "post_tree_sha256"):
        hex64(v[key])
    hex40(v["candidate_sha"])
    if type(v["kind"]) is not str or v["kind"] not in {"required", "independent"} or v["no_new_privs"] is not True or v["replayed"] is not False:
        raise ProtocolError("invalid receipt isolation/replay fields")
    _int(v["actual_uid"], 0, 2**32 - 2)
    _int(v["actual_gid"], 0, 2**32 - 2)
    _keys(v["namespaces"], "user mount pid ipc net")
    for inode in v["namespaces"].values():
        _int(inode, 1)
    _keys(v["capabilities"], "inheritable permitted effective bounding ambient")
    for mask in v["capabilities"].values():
        if type(mask) is not str or re.fullmatch(r"[0-9a-f]{1,16}", mask) is None:
            raise ProtocolError("invalid capability mask")
    _int(v["elapsed_ms"], 0, 1000000)
    _keys(v["limits"], "timeout_seconds max_output_bytes")
    _int(v["limits"]["timeout_seconds"], 1, 900)
    _int(v["limits"]["max_output_bytes"], 1, MAX_OUTPUT_BYTES)
    _keys(v["descendants"], "reaped survivors")
    if type(v["descendants"]["reaped"]) is not bool:
        raise ProtocolError("invalid descendant cleanup flag")
    _int(v["descendants"]["survivors"], 0, 2**31 - 1)
    results = v["results"]
    if type(results) is not list or not 1 <= len(results) <= MAX_COMMANDS:
        raise ProtocolError("invalid receipt results")
    names, paths, total = set(), set(), 0
    for sequence, result in enumerate(results):
        _keys(result, "sequence id command_sha256 exit_code stdout stderr")
        _int(result["sequence"], sequence, sequence)
        identifier(result["id"])
        if result["id"] in names or (v["kind"] == "required" and result["id"] != f"required-{sequence:04d}"):
            raise ProtocolError("invalid or repeated receipt result ID")
        names.add(result["id"])
        hex64(result["command_sha256"])
        _int(result["exit_code"], -255, 255)
        for stream in ("stdout", "stderr"):
            output = result[stream]
            _keys(output, "sha256 bytes relative_path")
            hex64(output["sha256"])
            _int(output["bytes"], 0, v["limits"]["max_output_bytes"])
            relative_path(output["relative_path"])
            if output["relative_path"] != f"outputs/{sequence:04d}.{stream}" or output["relative_path"] in paths:
                raise ProtocolError("output path is not broker-derived")
            paths.add(output["relative_path"])
            total += output["bytes"]
    if total > v["limits"]["max_output_bytes"]:
        raise ProtocolError("combined output limit exceeded")
    _hash_id(v, "receipt_id")
    return v


def validate_evaluation_rejection(value: Any) -> dict[str, Any]:
    v = _input(value)
    _keys(v, "schema_version rejection_id evaluation_request_sha256 artifact_id claim_id failed_receipt_id reason")
    _version(v["schema_version"])
    hex64(v["evaluation_request_sha256"])
    for key, prefix in (("artifact_id", "sha256:"), ("claim_id", "claim:")):
        if type(v[key]) is not str or not v[key].startswith(prefix):
            raise ProtocolError("invalid rejection subject")
        hex64(v[key][len(prefix):])
    if v["failed_receipt_id"] is not None:
        hex64(v["failed_receipt_id"])
    if type(v["reason"]) is not str or v["reason"] not in {"CHECK_FAILED", "ISOLATION_FAILED", "LIMIT_EXCEEDED", "STATE_INVALID"}:
        raise ProtocolError("invalid rejection reason")
    _hash_id(v, "rejection_id")
    return v


# Private transport spelling used by the fixed launcher.
strict_json_loads = load_json
