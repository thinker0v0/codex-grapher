"""Root-private live provider admission; never serialized or accepted from RPC.

Root is an explicit TCB. These guards prevent borrowing stale dispatch state or
substituting a runner, not a claim of protection against compromised root Python.
"""
from __future__ import annotations

from contextlib import contextmanager
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import time

_ACTIVE_BOOTSTRAP = None
_ACTIVE_DISPATCH = None
_PRODUCTION_FUNCTIONS = None
_PRODUCTION_HELPERS = None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _deny(message):
    from .isolated_runner import IsolationError
    raise IsolationError("ISOLATION_UNAVAILABLE: " + message)


@dataclasses.dataclass(eq=False)
class _Bootstrap:
    broker: object
    profile: object
    pid: int
    store_identity: tuple
    workspace: str
    profile_bytes: bytes
    code_sha256: str
    observations: list = dataclasses.field(default_factory=list)
    active: bool = True


@dataclasses.dataclass(eq=False)
class _Dispatch:
    bootstrap: _Bootstrap
    request: bytes | None
    deadline: float
    stage: int = 0
    command_sha256: str | None = None
    active: bool = True


def freeze_runner_functions():
    """Called once at the end of trusted runner module import."""
    global _PRODUCTION_FUNCTIONS, _PRODUCTION_HELPERS
    if _PRODUCTION_FUNCTIONS is not None:
        _deny("runner identity may only be frozen once")
    from . import isolated_runner as runner
    names = ("run_provider_process", "run_role_process", "_sandbox", "_bind", "_mount", "_syscall",
             "_drop_role", "_restrict_syscalls", "_observation", "_validate_launch_authority")
    _PRODUCTION_FUNCTIONS = {name: (getattr(runner, name), getattr(runner, name).__code__) for name in names}
    from . import _boundary_attestation as boundary, worker_provider as provider
    helpers = [(boundary, name) for name, value in vars(boundary).items()
               if callable(value) and getattr(value, "__module__", None) == boundary.__name__]
    helpers.extend((provider, name) for name in ("build_codex_argv", "_schema_path", "_assert_boundary", "_run",
                                                "execute_worker", "execute_provider_preflight"))
    _PRODUCTION_HELPERS = [(module, name, getattr(module, name), getattr(module, name).__code__)
                           for module, name in helpers]


def _check_functions():
    from . import isolated_runner as runner
    if not _PRODUCTION_FUNCTIONS or not _PRODUCTION_HELPERS:
        _deny("production runner identity is absent")
    for name, (function, code) in _PRODUCTION_FUNCTIONS.items():
        current = getattr(runner, name)
        if current is not function or getattr(current, "__code__", None) is not code:
            _deny("production runner was substituted: " + name)
    for module, name, function, code in _PRODUCTION_HELPERS:
        current = getattr(module, name)
        if current is not function or getattr(current, "__code__", None) is not code:
            _deny("production boundary helper was substituted: " + name)


def _check_profile(profile, authority):
    from .execution_profile import executable_digest, trusted_code_digest
    if profile is not authority.profile or _canonical(profile.raw) != authority.profile_bytes:
        _deny("profile is not the admitted frozen profile")
    if profile.sha256 != authority.broker.frozen.record["profile_sha256"]:
        _deny("profile hash differs from frozen workspace")
    root = Path(profile.paths["trusted_code_root"])
    if root not in Path(__file__).resolve().parents:
        _deny("admission code is outside the trusted install")
    if trusted_code_digest(root) != authority.code_sha256 or authority.code_sha256 != profile.paths["trusted_code_sha256"]:
        _deny("trusted code changed since bootstrap admission")
    for tool in profile.tools.values():
        if tool is not None and executable_digest(tool.path) != tool.sha256:
            _deny("pinned tool changed since profile admission")


@contextmanager
def bootstrap_admission(broker, profile):
    """Only the installed explicit root bootstrap opens this authority scope."""
    global _ACTIVE_BOOTSTRAP
    from .evaluation_broker import EvaluationBroker
    from .execution_profile import ExecutionProfile
    from .isolated_runner import _validate_launch_authority
    _validate_launch_authority(profile)
    if type(broker) is not EvaluationBroker or type(profile) is not ExecutionProfile or broker.profile is not profile:
        _deny("bootstrap identity is not the production broker/profile")
    if _ACTIVE_BOOTSTRAP is not None:
        _deny("nested bootstrap authority is forbidden")
    info = os.fstat(broker.store.fd)
    authority = _Bootstrap(broker, profile, os.getpid(), (info.st_dev, info.st_ino),
                           str(broker.frozen.root), _canonical(profile.raw), profile.paths["trusted_code_sha256"])
    _check_functions(); _check_profile(profile, authority)
    _ACTIVE_BOOTSTRAP = authority
    try:
        yield authority
    finally:
        authority.active = False
        _ACTIVE_BOOTSTRAP = None


@contextmanager
def provider_dispatch(broker, request):
    """Enter only after finite dispatch has validated and sealed its request."""
    global _ACTIVE_DISPATCH
    authority = _ACTIVE_BOOTSTRAP
    if authority is None or authority.broker is not broker or _ACTIVE_DISPATCH is not None:
        _deny("provider action lacks the active root broker")
    if request is not None:
        key = "request-" + hashlib.sha256(_canonical(request["attempt_id"])).hexdigest()
        registered = broker.store.private_record(key)
        if registered != {"request_sha256": hashlib.sha256(_canonical(request)).hexdigest(), "request": request}:
            _deny("worker request is not the sealed private registration")
        duration = request["limits"]["worker_timeout_seconds"] + 45
    else:
        duration = 90
    current = _Dispatch(authority, None if request is None else _canonical(request), time.monotonic() + duration)
    _ACTIVE_DISPATCH = current
    try:
        assert_active_provider_boundary(request, broker.profile)
        yield
    finally:
        current.active = False
        _ACTIVE_DISPATCH = None


def assert_active_provider_boundary(request, profile):
    """Refuse absent, stale, cross-request or substituted production authority."""
    current, authority = _ACTIVE_DISPATCH, _ACTIVE_BOOTSTRAP
    if current is None or authority is None or current.bootstrap is not authority:
        _deny("no current isolated provider dispatch")
    if not current.active or not authority.active or authority.pid != os.getpid() or os.geteuid() != 0:
        _deny("bootstrap process identity is stale")
    if time.monotonic() >= current.deadline:
        _deny("provider dispatch has expired")
    if current.request != (None if request is None else _canonical(request)):
        _deny("request differs from current private dispatch")
    info = os.fstat(authority.broker.store.fd)
    if (info.st_dev, info.st_ino) != authority.store_identity or str(authority.broker.frozen.root) != authority.workspace:
        _deny("root-private store binding changed")
    authority.broker.store._pinned()
    _check_functions(); _check_profile(profile, authority)


def admit_provider_command(request, profile, argv, stdin):
    """Bind every preflight/Git/provider exec to its finite internal sequence."""
    assert_active_provider_boundary(request, profile)
    current = _ACTIVE_DISPATCH
    executable = profile.tools["provider"].path
    if request is None:
        allowed = [[executable, "--version"], [executable, "--help"],
                   [executable, "exec", "--help"], [executable, "login", "status"]]
        if current.stage >= len(allowed) or argv != allowed[current.stage] or stdin:
            _deny("preflight command differs from its fixed phase")
    else:
        git = [profile.tools["git"].path, "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-C", request["checkout"], "rev-parse", "--verify", "HEAD^{commit}"]
        if current.stage in {0, 2}:
            if argv != git or stdin:
                _deny("worker Git probe differs from its fixed phase")
        elif current.stage == 1:
            from .worker_provider import build_codex_argv, _schema_path
            expected = build_codex_argv(profile, request["checkout"], _schema_path(profile), request=request)
            if argv != expected or stdin != request["prompt"].encode("utf-8"):
                _deny("provider command differs from frozen task strategy")
        else:
            _deny("worker dispatch cannot launch another command")
    current.command_sha256 = hashlib.sha256(_canonical(argv)).hexdigest()
    current.stage += 1


def record_boundary(result):
    if _ACTIVE_DISPATCH is not None:
        if result.boundary is None or result.observation is None:
            _deny("actual child boundary was not admitted before exec")
        current = _ACTIVE_DISPATCH
        current.bootstrap.observations.append({
            "action": "provider-preflight" if current.request is None else "worker-launch",
            "request_sha256": None if current.request is None else hashlib.sha256(current.request).hexdigest(),
            "command_phase": current.stage - 1, "argv_sha256": current.command_sha256,
            "observation": result.observation, "boundary": result.boundary})
