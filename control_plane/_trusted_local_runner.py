"""Explicit trusted-local execution with bounded Linux descendant supervision.

This mode makes no hostile-code isolation claim. A dedicated subreaper, pinned
with a pidfd before launch, still proves descendant cleanup, including double
forks and sessions outside the original process group.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from .artifact_builder import (
    SUPERVISOR_CLEANUP_SECONDS,
    _direct_child_pids,
    _reap_adopted_children,
    _signal_pidfd,
    _terminate_supervised_descendants,
)


MAX_OUTPUT = 8 * 1024 * 1024
MAX_STATUS = 8192
_ALLOWED_ENV = {"HOME", "CODEX_HOME", "GRAPHER_LAUNCHER_SOCKET", "GRAPHER_WORKSPACE_ID",
                "GRAPHER_WORKER_CONTROL_SOCKET", "PYTHONPATH"}


def _prctl(option, value):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, value, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _observe():
    values = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    capabilities = {name: values[key].strip() for name, key in {
        "inheritable": "CapInh", "permitted": "CapPrm", "effective": "CapEff",
        "bounding": "CapBnd", "ambient": "CapAmb",
    }.items()}
    return {
        "actual_uid": os.getuid(), "actual_gid": os.getgid(),
        "namespaces": {name: os.stat("/proc/self/ns/" + kernel).st_ino for name, kernel in {
            "user": "user", "mount": "mnt", "pid": "pid", "ipc": "ipc", "net": "net",
        }.items()},
        "capabilities": capabilities, "no_new_privs": values["NoNewPrivs"].strip() == "1",
    }


def _close_other_fds(keep):
    # This is the dedicated post-fork helper, so closing unrelated inherited
    # descriptors cannot affect the caller. Candidate Popen closes them again.
    for entry in Path("/proc/self/fd").iterdir():
        descriptor = int(entry.name)
        if descriptor not in keep:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _supervise(parent_pid, role, argv, cwd, env, input_fd, out_fd, err_fd, status_fd, start_fd):
    stop = False

    def cancel(_signal, _frame):
        nonlocal stop
        stop = True

    process = None
    status = {"observation": None, "returncode": None, "reaped": False,
              "leaked": False, "error": None}
    try:
        _close_other_fds({input_fd, out_fd, err_fd, status_fd, start_fd})
        signal.signal(signal.SIGTERM, cancel)
        signal.signal(signal.SIGINT, cancel)
        _prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG: cleanup on caller death
        if os.getppid() != parent_pid:
            raise RuntimeError("local runner parent exited before setup")
        _prctl(36, 1)  # PR_SET_CHILD_SUBREAPER
        _direct_child_pids()
        if os.read(start_fd, 1) != b"1" or stop:
            raise RuntimeError("local runner start handshake was not authorized")
        os.close(start_fd)
        os.setsid()
        if os.geteuid() == 0:
            os.setgroups([])
            os.setresgid(role.gid, role.gid, role.gid)
            os.setresuid(role.uid, role.uid, role.uid)
            # A credential change clears PDEATHSIG.
            _prctl(1, signal.SIGTERM)
        if os.getppid() != parent_pid or stop:
            raise RuntimeError("local runner parent exited during credential setup")
        if os.getresuid() != (role.uid,) * 3 or os.getresgid() != (role.gid,) * 3:
            raise RuntimeError("local runner cannot assume the configured role")
        _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
        status["observation"] = _observe()
        if not status["observation"]["no_new_privs"]:
            raise RuntimeError("no_new_privs was not observed")
        if os.getppid() != parent_pid or stop:
            raise RuntimeError("local runner parent exited before command launch")
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=input_fd,
                                   stdout=out_fd, stderr=err_fd, close_fds=True)
        for descriptor in (input_fd, out_fd, err_fd):
            os.close(descriptor)
        while not stop and process.poll() is None:
            time.sleep(0.01)
        children = _direct_child_pids()
        no_children = _reap_adopted_children()
        children.update(_direct_child_pids())
        status["leaked"] = not stop and (bool(children) or not no_children)
        if stop or children or not no_children:
            _terminate_supervised_descendants(os.getpid(), process)
        status["returncode"] = process.returncode
        status["reaped"] = _reap_adopted_children() and not _direct_child_pids()
        if not status["reaped"]:
            raise RuntimeError("local runner did not prove ECHILD")
    except BaseException as exc:
        status["error"] = type(exc).__name__  # never echo candidate/key paths
        if process is not None:
            try:
                _terminate_supervised_descendants(os.getpid(), process)
                status["reaped"] = _reap_adopted_children() and not _direct_child_pids()
            except BaseException:
                status["reaped"] = False
    try:
        data = json.dumps(status, sort_keys=True, separators=(",", ":")).encode()
        while data:
            data = data[os.write(status_fd, data):]
    except OSError:
        pass
    os._exit(0 if status["error"] is None and status["reaped"] else 125)


def run_local_process(profile, role_name, argv, *, stdin=b"", cwd="/tmp",
                      timeout_seconds=30, max_output_bytes=262144, environment=None):
    """Run only explicitly trusted-local work; return observed bounded results."""
    from .isolated_runner import BoundedProcessResult, IsolationError

    if profile.mode != "trusted-local" or role_name not in profile.roles:
        raise IsolationError("trusted-local execution requires an explicit local profile and role")
    if (type(argv) not in (list, tuple) or not argv
            or any(type(item) is not str or not item or "\0" in item for item in argv)
            or not Path(argv[0]).is_absolute() or sum(map(len, argv)) > 65536):
        raise IsolationError("invalid local command argv")
    if (type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600
            or type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_OUTPUT
            or type(stdin) is not bytes or len(stdin) > MAX_OUTPUT):
        raise IsolationError("invalid local process bounds")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise IsolationError("local supervision requires Linux pidfd support")
    if not Path(cwd).is_absolute() or not Path(cwd).is_dir():
        raise IsolationError("local process cwd must be an existing absolute directory")
    if environment is not None and (type(environment) is not dict or set(environment) - _ALLOWED_ENV
                                    or any(type(v) is not str or "\0" in v or len(v) > 4096
                                           for v in environment.values())):
        raise IsolationError("unapproved local role environment")
    env = {"HOME": "/nonexistent", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
           "LC_ALL": "C.UTF-8", "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    env.update(environment or {})
    role = profile.roles[role_name]
    if (type(role.uid) is not int or type(role.gid) is not int or min(role.uid, role.gid) < 0
            or max(role.uid, role.gid) > 2**32 - 2):
        raise IsolationError("invalid local role identity")
    started = time.monotonic()
    input_read, input_write = os.pipe()
    out_read, out_write = os.pipe()
    err_read, err_write = os.pipe()
    status_read, status_write = os.pipe()
    start_read, start_write = os.pipe()
    all_fds = {input_read, input_write, out_read, out_write, err_read, err_write,
               status_read, status_write, start_read, start_write}
    parent_pid = os.getpid()
    try:
        pid = os.fork()
    except BaseException:
        for descriptor in all_fds:
            os.close(descriptor)
        raise
    if pid == 0:
        _supervise(parent_pid, role, argv, cwd, env, input_read, out_write, err_write,
                   status_write, start_read)
    for descriptor in (input_read, out_write, err_write, status_write, start_read):
        os.close(descriptor)
        all_fds.remove(descriptor)
    pidfd = None
    waited = False
    selector = selectors.DefaultSelector()
    buffers = {out_read: bytearray(), err_read: bytearray(), status_read: bytearray()}
    timed_out = overflow = False
    cancelled_at = None
    wait_status = None
    try:
        pidfd = os.pidfd_open(pid)
        os.write(start_write, b"1")
        os.close(start_write)
        all_fds.remove(start_write)
        for descriptor in buffers:
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
        pending = memoryview(stdin)
        if pending:
            os.set_blocking(input_write, False)
            selector.register(input_write, selectors.EVENT_WRITE)
        else:
            os.close(input_write)
            all_fds.remove(input_write)

        def close_selected(descriptor):
            selector.unregister(descriptor)
            os.close(descriptor)
            all_fds.remove(descriptor)

        while selector.get_map() or not waited:
            now = time.monotonic()
            if cancelled_at is None and now - started >= timeout_seconds:
                timed_out = True
                cancelled_at = now
                _signal_pidfd(pidfd, signal.SIGTERM)
            if cancelled_at is not None and now - cancelled_at > SUPERVISOR_CLEANUP_SECONDS + 1:
                raise IsolationError("local descendant cleanup proof timed out")
            for key, _event in selector.select(0.02):
                descriptor = key.fd
                if descriptor == input_write:
                    try:
                        written = os.write(descriptor, pending[:65536])
                        pending = pending[written:]
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        close_selected(descriptor)
                    continue
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    close_selected(descriptor)
                    continue
                if descriptor == status_read:
                    buffers[descriptor].extend(chunk)
                    if len(buffers[descriptor]) > MAX_STATUS:
                        raise IsolationError("local supervisor status exceeded its bound")
                else:
                    capacity = max_output_bytes - len(buffers[out_read]) - len(buffers[err_read])
                    buffers[descriptor].extend(chunk[:max(0, capacity)])
                    if len(chunk) > capacity:
                        overflow = True
                        if cancelled_at is None:
                            cancelled_at = time.monotonic()
                            _signal_pidfd(pidfd, signal.SIGTERM)
            if not waited:
                completed, candidate_status = os.waitpid(pid, os.WNOHANG)
                if completed:
                    waited = True
                    wait_status = candidate_status
        try:
            status = json.loads(bytes(buffers[status_read]))
        except (ValueError, UnicodeError):
            raise IsolationError("local supervisor returned invalid status") from None
        if (type(status) is not dict or set(status) != {"observation", "returncode", "reaped", "leaked", "error"}
                or status["error"] is not None or status["reaped"] is not True
                or type(status["leaked"]) is not bool or type(status["returncode"]) is not int
                or os.waitstatus_to_exitcode(wait_status) != 0):
            raise IsolationError("local supervisor did not prove successful containment")
        observation = status["observation"]
        if (type(observation) is not dict or observation.get("actual_uid") != role.uid
                or observation.get("actual_gid") != role.gid or observation.get("no_new_privs") is not True):
            raise IsolationError("local role observation does not match the configured role")
        returncode = status["returncode"]
        if status["leaked"] and returncode == 0:
            returncode = 125
        return BoundedProcessResult(bytes(buffers[out_read]), bytes(buffers[err_read]), returncode,
                                    time.monotonic() - started, True,
                                    -returncode if returncode < 0 else None,
                                    timed_out, overflow, observation)
    finally:
        # A missing pidfd never authorizes command launch: close the start pipe
        # first so the helper exits without creating descendants.
        if start_write in all_fds:
            os.close(start_write)
            all_fds.remove(start_write)
        if not waited:
            if pidfd is not None:
                _signal_pidfd(pidfd, signal.SIGTERM)
            deadline = time.monotonic() + SUPERVISOR_CLEANUP_SECONDS + 1
            while time.monotonic() < deadline:
                completed, _ = os.waitpid(pid, os.WNOHANG)
                if completed:
                    break
                time.sleep(0.01)
        for descriptor in all_fds:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        selector.close()
        if pidfd is not None:
            os.close(pidfd)
