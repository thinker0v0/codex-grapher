"""Strict, bounded Codex CLI protocol adapter.

This module never starts a subprocess. The trusted isolation launcher owns the
actual worker identity, environment, reservation and descendant supervision.
A COMPLETED receipt is transport evidence, never task acceptance.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import stat
from pathlib import Path
from typing import Any


CLI_VERSION = "codex-cli 0.155.1"
MODEL = "gpt-5.6-sol"
MAX_PROMPT_BYTES = 262_144
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_PROTOCOL_EVENTS = 65_536
CLEANUP_GRACE_SECONDS = 5.0
SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
REQUEST_FIELDS = {
    "schema_version", "project_id", "task_id", "idempotency_key", "attempt_id",
    "attempt_number", "base_sha", "checkout", "task_sha256", "profile_sha256",
    "prompt", "prompt_sha256", "limits",
}
RECEIPT_FIELDS = {
    "schema_version", "attempt_id", "request_sha256", "task_sha256",
    "profile_sha256", "prompt_sha256", "provider", "cli_version",
    "executable_sha256", "model", "session_id", "completion", "usage_observed",
    "exit_code", "signal", "elapsed_seconds", "stdout_sha256", "stderr_sha256",
    "stdout_bytes", "stderr_bytes", "descendants_reaped",
}
COMPLETIONS = frozenset({
    "COMPLETED", "PROTOCOL_INVALID", "PROVIDER_FAILED", "REFUSED", "BLOCKED",
    "TIMEOUT", "OUTPUT_LIMIT", "CLEANUP_FAILED", "HEAD_CHANGED",
})
RESULT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "schema_version": {"type": "integer", "const": 1},
        "status": {"type": "string", "enum": ["completed", "refused", "blocked", "failed"]},
        "summary": {"type": "string", "minLength": 1, "maxLength": 4096},
    },
    "required": ["schema_version", "status", "summary"],
}
RESULT_SCHEMA_SHA256 = "4bced1d017090ce630f2b3cf8eafcbd6cf4215228ab2345829d3d1f6569823d8"


class WorkerProviderError(ValueError):
    """An admission failure; the code is safe for public diagnostics."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def request_sha256(request: dict) -> str:
    return _sha(canonical_bytes(request))


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def strict_loads(value: bytes | str) -> Any:
    def reject_constant(_: str) -> None:
        raise ValueError("nonfinite JSON number")
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="strict")
    return json.loads(value, object_pairs_hook=_pairs, parse_constant=reject_constant)


def _exact(value: Any, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise WorkerProviderError("INVALID_TASK", f"invalid {label} fields")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise WorkerProviderError("INVALID_TASK", f"invalid {label}")
    return value


def _hash(value: Any, pattern: re.Pattern, label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise WorkerProviderError("INVALID_TASK", f"invalid {label}")
    return value


def validate_worker_request(request: dict) -> dict:
    """Validate before any launcher call; return an independent canonical copy."""
    _exact(request, REQUEST_FIELDS, "worker request")
    _integer(request["schema_version"], 1, 1, "schema version")
    for field in ("project_id", "task_id", "idempotency_key", "attempt_id"):
        _hash(request[field], SAFE_ID, field)
    _integer(request["attempt_number"], 1, 1_000_000, "attempt number")
    _hash(request["base_sha"], HEX40, "base SHA")
    for field in ("task_sha256", "profile_sha256", "prompt_sha256"):
        _hash(request[field], HEX64, field)
    prompt = request["prompt"]
    if not isinstance(prompt, str) or not prompt.strip() or "\x00" in prompt:
        raise WorkerProviderError("INVALID_TASK", "invalid prompt")
    try:
        prompt_bytes = prompt.encode("utf-8")
    except UnicodeError:
        raise WorkerProviderError("INVALID_TASK", "invalid prompt encoding") from None
    if len(prompt_bytes) > MAX_PROMPT_BYTES or _sha(prompt_bytes) != request["prompt_sha256"]:
        raise WorkerProviderError("INVALID_TASK", "prompt bound or hash mismatch")
    checkout = request["checkout"]
    if not isinstance(checkout, str) or "\x00" in checkout or not Path(checkout).is_absolute():
        raise WorkerProviderError("INVALID_TASK", "checkout must be an absolute path")
    try:
        path = Path(checkout)
        if str(path) != checkout or path.resolve(strict=True) != path or not path.is_dir():
            raise ValueError()
        if not (path / ".git").is_dir() or (path / ".git").is_symlink():
            raise ValueError()
    except (OSError, ValueError):
        raise WorkerProviderError("INVALID_TASK", "checkout must be a canonical owned repository") from None
    limits = request["limits"]
    if isinstance(limits, dict) and any(key in limits for key in ("max_tokens", "max_cost_usd", "max_usd", "token_budget", "dollar_budget")):
        raise WorkerProviderError("BUDGET_UNSUPPORTED", "Codex CLI cannot enforce hard token or dollar ceilings")
    _exact(limits, {"worker_invocations", "worker_timeout_seconds", "max_output_bytes"}, "worker limits")
    _integer(limits["worker_invocations"], 1, 3, "invocation limit")
    _integer(limits["worker_timeout_seconds"], 1, 3600, "worker timeout")
    _integer(limits["max_output_bytes"], 1, MAX_OUTPUT_BYTES, "output limit")
    if request["attempt_number"] > limits["worker_invocations"]:
        raise WorkerProviderError("INVALID_TASK", "invocation limit exceeded")
    return strict_loads(canonical_bytes(request))


def _profile(profile: Any) -> None:
    # Deliberately require the trusted loader's object, never a caller dictionary.
    from .execution_profile import ExecutionProfile
    if not isinstance(profile, ExecutionProfile):
        raise WorkerProviderError("CONFIG_CHANGED", "validated execution profile required")
    if profile.roles["worker"].uid <= 0:
        raise WorkerProviderError("ISOLATION_UNAVAILABLE", "provider requires a non-root worker identity")
    if profile.provider != {"backend": "codex", "model": MODEL,
                            "reasoning_effort": "medium", "service_tier": "default"}:
        raise WorkerProviderError("CONFIG_CHANGED", "unsupported provider policy")
    tool = profile.tools["provider"]
    if tool.version not in (CLI_VERSION, "0.155.1"):
        raise WorkerProviderError("UNSUPPORTED_PROTOCOL", "Codex 0.155.1 is required")
    path = Path(tool.path)
    try:
        if path.resolve(strict=True) != path or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError()
        if _sha(path.read_bytes()) != tool.sha256:
            raise ValueError()
    except (OSError, ValueError):
        raise WorkerProviderError("CONFIG_CHANGED", "provider executable identity changed") from None


def _run(request: dict | None, profile: Any, argv: list[str], stdin: bytes = b"") -> Any:
    from .isolated_runner import run_provider_process
    return run_provider_process(request, profile, argv, stdin)


def _configured_sandbox_values(mode: str) -> tuple[str, str]:
    if mode == "trusted-local":
        return "codex-workspace-write-v1", "workspace-write"
    if mode == "isolated-linux":
        return "external-linux-v1", "danger-full-access"
    raise WorkerProviderError("ISOLATION_UNAVAILABLE", "unsupported execution mode")


def configured_sandbox_metadata(profile: Any) -> dict[str, str]:
    """Pure configured labels; this grants no launch authority or isolation proof."""
    from .execution_profile import ExecutionProfile
    if not isinstance(profile, ExecutionProfile):
        raise WorkerProviderError("CONFIG_CHANGED", "validated execution profile required")
    strategy, mode = _configured_sandbox_values(profile.mode)
    return {"configured_sandbox_strategy": strategy, "configured_cli_sandbox_mode": mode}


def _assert_boundary(request: dict | None, profile: Any) -> None:
    if profile.mode == "trusted-local":
        return
    if profile.mode != "isolated-linux":
        raise WorkerProviderError("ISOLATION_UNAVAILABLE", "unsupported execution mode")
    try:
        from .isolated_runner import assert_active_provider_boundary
    except ImportError:
        raise WorkerProviderError("ISOLATION_UNAVAILABLE", "active provider boundary guard unavailable") from None
    # The assertion validates root-private state. No boolean, request flag,
    # metadata label or fallback can substitute for that current context.
    if assert_active_provider_boundary(request, profile) is not None:
        raise WorkerProviderError("ISOLATION_UNAVAILABLE", "invalid provider boundary assertion")


def _successful_probe(result: Any, code: str) -> bytes:
    if (result.returncode != 0 or result.signal is not None or not result.descendants_reaped
            or result.timed_out or result.output_overflow):
        raise WorkerProviderError(code, "provider preflight failed")
    if len(result.stdout) + len(result.stderr) > MAX_PROMPT_BYTES:
        raise WorkerProviderError(code, "provider preflight output exceeded bound")
    return result.stdout + b"\n" + result.stderr


def execute_provider_preflight(profile: Any) -> dict:
    """Trusted launcher handler. Vendor probes run only under the worker UID."""
    _profile(profile)
    _assert_boundary(None, profile)
    configured = configured_sandbox_metadata(profile)
    exe = profile.tools["provider"].path
    version = _successful_probe(_run(None, profile, [exe, "--version"]), "PROVIDER_MISSING")
    if version.strip() != CLI_VERSION.encode():
        raise WorkerProviderError("UNSUPPORTED_PROTOCOL", "CLI version differs from frozen protocol")
    top_help = _successful_probe(_run(None, profile, [exe, "--help"]), "UNSUPPORTED_PROTOCOL")
    exec_help = _successful_probe(_run(None, profile, [exe, "exec", "--help"]), "UNSUPPORTED_PROTOCOL")
    if b"--ask-for-approval" not in top_help or any(flag not in exec_help for flag in (
            b"--ignore-user-config", b"--ephemeral", b"--sandbox",
            configured["configured_cli_sandbox_mode"].encode("ascii"),
            b"--json", b"--model", b"--output-schema", b"--color", b"--cd")):
        raise WorkerProviderError("UNSUPPORTED_PROTOCOL", "required CLI security capability missing")
    # Never retain or return vendor login output; it may contain account metadata.
    auth = _successful_probe(_run(None, profile, [exe, "login", "status"]), "AUTH_REQUIRED")
    normalized = auth.lower()
    if b"logged in using chatgpt" not in normalized or b"api key" in normalized or b"api_key" in normalized:
        raise WorkerProviderError("AUTH_REQUIRED", "existing ChatGPT CLI login required")
    return {"provider": "codex", "cli_version": CLI_VERSION,
            "executable_sha256": profile.tools["provider"].sha256,
            "model": MODEL, "authenticated": True, "auth_kind": "existing-cli-login",
            "inference_invoked": False, **configured}


def provider_preflight(profile: Any) -> dict:
    """Preflight through the finite launcher interface, before G reserves a launch."""
    _profile(profile)
    return _launcher(profile).request("provider-preflight", {})


def _launcher(profile: Any) -> Any:
    # trusted-local is an explicitly selected profile, not recovery from a
    # missing isolated launcher. Both clients expose the same finite actions.
    if profile.mode == "trusted-local":
        from .evaluation_broker import _client
        return _client(profile)
    from .isolated_runner import get_active_launcher
    return get_active_launcher()


def build_codex_argv(profile: Any, checkout: str, schema_path: Path, *, request: dict | None = None) -> list[str]:
    if profile.mode == "isolated-linux" and request is None:
        raise WorkerProviderError("ISOLATION_UNAVAILABLE", "registered worker request required for external mode")
    _assert_boundary(request, profile)
    if profile.mode == "isolated-linux" and (
            checkout != request["checkout"] or Path(schema_path) != _schema_path(profile)):
        raise WorkerProviderError("ISOLATION_UNAVAILABLE", "provider argv differs from registered request or pinned schema")
    _, sandbox_mode = _configured_sandbox_values(profile.mode)
    return [profile.tools["provider"].path, "--ask-for-approval", "never", "exec",
            "--ignore-user-config", "--ephemeral", "--sandbox", sandbox_mode,
            "--cd", checkout, "--json", "--color", "never", "--model", MODEL,
            "-c", 'model_reasoning_effort="medium"', "-c", 'service_tier="default"',
            "--output-schema", str(schema_path), "-"]


def _result(value: Any) -> str:
    _exact(value, {"schema_version", "status", "summary"}, "structured worker result")
    _integer(value["schema_version"], 1, 1, "result version")
    if not isinstance(value["status"], str) or value["status"] not in {"completed", "refused", "blocked", "failed"}:
        raise ValueError("unknown final result")
    if not isinstance(value["summary"], str) or not value["summary"].strip() or len(value["summary"]) > 4096:
        raise ValueError("invalid result summary")
    return {"completed": "COMPLETED", "refused": "REFUSED", "blocked": "BLOCKED", "failed": "PROVIDER_FAILED"}[value["status"]]


def _usage(counters: Any) -> dict | None:
    if counters is None:
        return None
    if type(counters) is not dict or len(counters) > 16:
        raise ValueError("invalid observed usage")
    for key, value in counters.items():
        if (not isinstance(key, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", key)
                or type(value) is not int or not 0 <= value <= 2**53 - 1):
            raise ValueError("invalid observed usage counter")
    return counters


def parse_codex_jsonl(output: bytes) -> dict:
    """Strict single-turn 0.155.1 protocol. Tool failures may be repaired in-turn."""
    if not isinstance(output, bytes) or not output or len(output) > MAX_OUTPUT_BYTES:
        raise ValueError("missing, oversized or truncated provider stream")
    lines = output.splitlines()
    if len(lines) > MAX_PROTOCOL_EVENTS:
        raise ValueError("too many provider events")
    session = None
    turn_started = False
    terminal = None
    messages: list[str] = []
    usage = None
    observed_model = None
    provider_error = False
    for line in lines:
        event = strict_loads(line)
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ValueError("invalid provider event")
        kind = event["type"]
        if terminal is not None:
            raise ValueError("provider event after terminal")
        if "model" in event:
            model = event["model"]
            if not isinstance(model, str) or model != MODEL:
                raise ValueError("provider model mismatch")
            observed_model = model
        if kind == "thread.started":
            if set(event) - {"type", "thread_id", "model"}:
                raise ValueError("unsupported session fields")
            if session is not None or turn_started:
                raise ValueError("duplicate or misplaced session")
            session = _hash(event.get("thread_id"), SAFE_ID, "provider session")
        elif kind == "turn.started":
            if set(event) - {"type", "model"}:
                raise ValueError("unsupported turn fields")
            if session is None or turn_started:
                raise ValueError("duplicate or misplaced turn")
            turn_started = True
        elif kind in ("turn.completed", "turn.failed"):
            allowed = {"type", "usage", "model"} if kind == "turn.completed" else {"type", "error", "model"}
            if set(event) - allowed:
                raise ValueError("unsupported or contradictory terminal fields")
            if not turn_started:
                raise ValueError("terminal without turn")
            terminal = kind
            if kind == "turn.completed":
                if "usage" in event and event["usage"] is not None:
                    usage = _usage(event["usage"])
            else:
                provider_error = True
        elif kind == "error":
            provider_error = True
        elif kind in ("item.started", "item.updated", "item.completed"):
            if not turn_started:
                raise ValueError("item outside turn")
            item = event.get("item")
            if type(item) is not dict or not isinstance(item.get("type"), str):
                raise ValueError("invalid provider item")
            if item["type"] in ("error", "refusal"):
                provider_error = True
            if kind == "item.completed" and item["type"] == "agent_message":
                if set(item) - {"id", "type", "text"}:
                    raise ValueError("unsupported agent message fields")
                if not isinstance(item.get("text"), str):
                    raise ValueError("invalid agent message")
                messages.append(item["text"])
        else:
            raise ValueError("unsupported provider event")
    if terminal is None:
        raise ValueError("missing provider terminal")
    completion = "PROVIDER_FAILED"
    if not provider_error:
        # Commentary may precede the single schema-valid final message. Earlier
        # schema-valid results are contradictory and never silently overwritten.
        results = []
        for text in messages:
            try:
                decoded = strict_loads(text)
            except (UnicodeError, ValueError):
                continue
            if isinstance(decoded, dict) and "schema_version" in decoded:
                results.append(_result(decoded))
        if len(results) != 1 or not messages:
            raise ValueError("missing or duplicate structured worker result")
        if _result(strict_loads(messages[-1])) != results[0]:
            raise ValueError("structured result must be the final message")
        completion = results[0]
    return {"completion": completion, "session_id": session,
            "usage_observed": usage, "model": observed_model}


def _reservation(request: dict) -> None:
    path = Path(request["checkout"]).parent / "reservation.json"
    try:
        from .artifact_builder import _read_stable_input
        reservation = strict_loads(_read_stable_input(path, maximum=MAX_OUTPUT_BYTES))
        _exact(reservation, {"schema_version", "attempt_id", "attempt_number", "invocation_count",
                             "request_sha256", "request", "reserved_at"}, "invocation reservation")
        if (type(reservation["schema_version"]) is not int or reservation["schema_version"] != 1
                or reservation["attempt_id"] != request["attempt_id"]
                or type(reservation["attempt_number"]) is not int
                or reservation["attempt_number"] != request["attempt_number"]
                or type(reservation["invocation_count"]) is not int
                or reservation["invocation_count"] != request["attempt_number"]
                or canonical_bytes(reservation["request"]) != canonical_bytes(request)
                or reservation["request_sha256"] != request_sha256(request)
                or not isinstance(reservation["reserved_at"], str) or not reservation["reserved_at"]):
            raise ValueError()
    except (OSError, ValueError, UnicodeError):
        raise WorkerProviderError("DURABLE_STATE_INVALID", "missing or mismatched invocation reservation") from None


def _schema_path(profile: Any) -> Path:
    root = Path(profile.paths["trusted_code_root"])
    candidates = (root / "schemas" / "worker-result.schema.json",
                  root / "control_plane" / "resources" / "worker-result.schema.json")
    present = []
    try:
        from .artifact_builder import _read_stable_input
        if not root.is_absolute() or root.resolve(strict=True) != root:
            raise ValueError()
        for path in candidates:
            # Inspect each present layout. A bad source copy cannot be masked by
            # a valid installed copy, including dangling or ancestor symlinks.
            if not path.exists() and not path.is_symlink():
                continue
            if path.resolve(strict=True) != path:
                raise ValueError()
            data = _read_stable_input(path, maximum=16_384)
            if _sha(data) != RESULT_SCHEMA_SHA256 or strict_loads(data) != RESULT_SCHEMA:
                raise ValueError()
            present.append(path)
        if not present:
            raise ValueError()
    except (OSError, ValueError, UnicodeError):
        raise WorkerProviderError("CONFIG_CHANGED", "trusted provider result schema missing or changed") from None
    return present[0]


def _head(request: dict, profile: Any) -> str:
    result = _run(request, profile, [profile.tools["git"].path, "-c", "core.fsmonitor=false",
                               "-c", "core.hooksPath=/dev/null", "-C", request["checkout"],
                               "rev-parse", "--verify", "HEAD^{commit}"])
    return _successful_probe(result, "DURABLE_STATE_INVALID").strip().decode("ascii")


def execute_worker(request: dict, profile: Any) -> dict:
    """Root launcher's registered handler; the launcher admits and seals replay."""
    request = validate_worker_request(request)
    _profile(profile)
    if request["profile_sha256"] != profile.sha256:
        raise WorkerProviderError("CONFIG_CHANGED", "profile request binding mismatch")
    _assert_boundary(request, profile)
    _reservation(request)
    schema_path = _schema_path(profile)
    if _head(request, profile) != request["base_sha"]:
        raise WorkerProviderError("DURABLE_STATE_INVALID", "worker checkout base mismatch")
    result = _run(request, profile, build_codex_argv(profile, request["checkout"], schema_path, request=request),
                  request["prompt"].encode("utf-8"))
    stdout, stderr = result.stdout, result.stderr
    protocol = {"completion": "PROTOCOL_INVALID", "session_id": None,
                "usage_observed": None, "model": None}
    try:
        protocol = parse_codex_jsonl(stdout)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        pass
    completion = protocol["completion"]
    if not result.descendants_reaped:
        completion = "CLEANUP_FAILED"
    elif result.timed_out or result.elapsed_seconds > request["limits"]["worker_timeout_seconds"] + CLEANUP_GRACE_SECONDS:
        completion = "TIMEOUT"
    elif result.output_overflow or len(stdout) + len(stderr) > request["limits"]["max_output_bytes"]:
        completion = "OUTPUT_LIMIT"
    elif result.returncode != 0 or result.signal is not None:
        completion = "PROVIDER_FAILED"
    elif completion == "COMPLETED":
        try:
            if _head(request, profile) != request["base_sha"]:
                completion = "HEAD_CHANGED"
        except (WorkerProviderError, UnicodeError):
            completion = "HEAD_CHANGED"
    # model is null if this pinned JSONL protocol did not report it. The explicit
    # requested model is already bound by profile_sha256; never invent telemetry.
    return {
        "schema_version": 1, "attempt_id": request["attempt_id"],
        "request_sha256": request_sha256(request), "task_sha256": request["task_sha256"],
        "profile_sha256": request["profile_sha256"], "prompt_sha256": request["prompt_sha256"],
        "provider": "codex", "cli_version": CLI_VERSION,
        "executable_sha256": profile.tools["provider"].sha256, "model": protocol["model"],
        "session_id": protocol["session_id"], "completion": completion,
        "usage_observed": protocol["usage_observed"], "exit_code": result.returncode,
        "signal": result.signal, "elapsed_seconds": result.elapsed_seconds,
        "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr),
        "stdout_bytes": len(stdout), "stderr_bytes": len(stderr),
        "descendants_reaped": result.descendants_reaped,
    }


def launch_worker(request: dict, profile: Any) -> dict:
    """Public finite launcher seam. No subprocess or isolation fallback exists."""
    request = validate_worker_request(request)
    _profile(profile)
    if request["profile_sha256"] != profile.sha256:
        raise WorkerProviderError("CONFIG_CHANGED", "profile request binding mismatch")
    _reservation(request)
    receipt = _launcher(profile).request("worker-launch", {"registered_request_id": request["attempt_id"]})
    validate_worker_receipt(receipt, request, profile)
    return receipt


def validate_worker_receipt(receipt: dict, request: dict, profile: Any) -> dict:
    _exact(receipt, RECEIPT_FIELDS, "worker receipt")
    for key, expected in {
        "schema_version": 1, "attempt_id": request["attempt_id"],
        "request_sha256": request_sha256(request), "task_sha256": request["task_sha256"],
        "profile_sha256": request["profile_sha256"], "prompt_sha256": request["prompt_sha256"],
        "provider": "codex", "cli_version": CLI_VERSION,
        "executable_sha256": profile.tools["provider"].sha256,
    }.items():
        if type(receipt[key]) is not type(expected) or receipt[key] != expected:
            raise WorkerProviderError("DURABLE_STATE_INVALID", "worker receipt binding mismatch")
    if receipt["completion"] not in COMPLETIONS or receipt["model"] not in (None, MODEL):
        raise WorkerProviderError("DURABLE_STATE_INVALID", "invalid provider completion")
    for field in ("stdout_sha256", "stderr_sha256"):
        _hash(receipt[field], HEX64, field)
    for field in ("stdout_bytes", "stderr_bytes"):
        _integer(receipt[field], 0, MAX_OUTPUT_BYTES, field)
    if type(receipt["descendants_reaped"]) is not bool:
        raise WorkerProviderError("DURABLE_STATE_INVALID", "invalid cleanup receipt")
    if type(receipt["exit_code"]) is not int or not -255 <= receipt["exit_code"] <= 255:
        raise WorkerProviderError("DURABLE_STATE_INVALID", "invalid provider exit")
    if receipt["signal"] is not None:
        _integer(receipt["signal"], 1, 64, "provider signal")
    elapsed = receipt["elapsed_seconds"]
    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
        raise WorkerProviderError("DURABLE_STATE_INVALID", "invalid provider elapsed time")
    if receipt["session_id"] is not None:
        _hash(receipt["session_id"], SAFE_ID, "provider session")
    try:
        _usage(receipt["usage_observed"])
    except ValueError:
        raise WorkerProviderError("DURABLE_STATE_INVALID", "invalid provider usage") from None
    if receipt["completion"] == "COMPLETED" and (
            receipt["exit_code"] != 0 or receipt["signal"] is not None
            or not receipt["descendants_reaped"] or receipt["session_id"] is None
            or receipt["stdout_bytes"] == 0
            or elapsed > request["limits"]["worker_timeout_seconds"] + CLEANUP_GRACE_SECONDS
            or receipt["stdout_bytes"] + receipt["stderr_bytes"] > request["limits"]["max_output_bytes"]):
        raise WorkerProviderError("DURABLE_STATE_INVALID", "contradictory successful receipt")
    return receipt
