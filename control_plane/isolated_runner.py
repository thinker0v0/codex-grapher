"""Privileged, short-lived Linux role launcher. No candidate code runs as root.

The bootstrap is explicitly trusted. It builds mount/PID/IPC/network namespaces
before dropping *real* kernel credentials; it does not map host root to a fake
non-root namespace UID. Public graph RPC cannot choose executables or identities.
"""
from __future__ import annotations

import contextlib
import ctypes
import dataclasses
import hashlib
import fcntl
import json
import os
from pathlib import Path
import select
import selectors
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time
from typing import Any

from .execution_profile import ExecutionProfile, load_execution_profile

MAX_FRAME = 8 * 1024 * 1024
CLONE_NEWNS, CLONE_NEWIPC, CLONE_NEWNET, CLONE_NEWPID, CLONE_NEWUTS = 0x20000, 0x8000000, 0x40000000, 0x20000000, 0x4000000
MS_BIND, MS_REC, MS_PRIVATE, MS_REMOUNT, MS_RDONLY = 4096, 16384, 262144, 32, 1
_LIBC = ctypes.CDLL(None, use_errno=True)
_ACTIVE_LAUNCHER = None
_GRAPH_PIDFD = None


class IsolationError(PermissionError):
    """The role boundary or its measured completion could not be established."""


@dataclasses.dataclass(frozen=True)
class BoundedProcessResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    elapsed_seconds: float
    descendants_reaped: bool
    signal: int | None = None
    timed_out: bool = False
    output_overflow: bool = False
    observation: dict | None = None
    boundary: dict | None = None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _syscall(name, *args):
    if getattr(_LIBC, name)(*args) != 0:
        error = ctypes.get_errno()
        raise IsolationError(f"{name} failed: {os.strerror(error)}")


def _mount(source, destination, flags, fstype=None):
    _syscall("mount", os.fsencode(source) if source else None, os.fsencode(destination),
             os.fsencode(fstype) if fstype else None, ctypes.c_ulong(flags), None)


def _drop_role(uid, gid):
    if type(uid) is not int or type(gid) is not int or uid <= 0 or gid < 0:
        raise IsolationError("a real non-root role is mandatory")
    os.setgroups([])
    os.setresgid(gid, gid, gid)
    last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
    for cap in range(last_cap + 1):
        _syscall("prctl", 24, cap, 0, 0, 0)  # PR_CAPBSET_DROP, before losing CAP_SETPCAP
    os.setresuid(uid, uid, uid)
    _syscall("prctl", 38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    _syscall("prctl", 4, 0, 0, 0, 0)   # PR_SET_DUMPABLE: role cannot inspect trusted parent
    if os.getresuid() != (uid,) * 3 or os.getresgid() != (gid,) * 3:
        raise IsolationError("kernel role drop failed")



def _restrict_syscalls():
    """Prevent namespace/mount/ptrace escape after the irreversible role drop."""
    if os.uname().machine != "x86_64":
        raise IsolationError("native syscall filter supports x86_64 only")
    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(Filter))]
    # Linux seccomp_data: nr offset0, arch offset4, first argument offset16.
    # Architecture and x32 checks prevent alternate syscall-number bypasses.
    instructions = [(0x20,0,0,4), (0x15,1,0,0xC000003E), (0x06,0,0,0x80000000),
                    (0x20,0,0,0), (0x35,0,1,0x40000000), (0x06,0,0,0x50026)]
    # mount, umount2, pivot_root, ptrace, unshare, setns, kexec, bpf,
    # open_by_handle_at, process_vm_readv/writev, userfaultfd, mount API.
    for number in (165,166,155,101,272,308,246,320,304,310,311,323,428,429,430,431,432,433,442):
        instructions.extend([(0x15,0,1,number), (0x06,0,0,0x50001)])
    # clone3 cannot inspect its pointed-to argument safely in classic BPF;
    # ENOSYS deliberately permits libc's ordinary clone/fork fallback.
    instructions.extend([(0x15,0,1,435), (0x06,0,0,0x50026),
                         (0x15,0,3,56), (0x20,0,0,16),
                         (0x45,0,1,0x10000000|CLONE_NEWNS|CLONE_NEWIPC|CLONE_NEWNET|CLONE_NEWPID|CLONE_NEWUTS|0x02000000),
                         (0x06,0,0,0x50001), (0x06,0,0,0x7fff0000)])
    array = (Filter * len(instructions))(*(Filter(*row) for row in instructions))
    program = Program(len(instructions), array)
    _syscall("prctl", 22, 2, ctypes.byref(program), 0, 0)
    return hashlib.sha256(b"".join(struct.pack("<HBBI", *row) for row in instructions)).hexdigest()


def _observation():
    values = {key: value.strip() for key, value in (line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)}
    cap_names = {"inheritable": "CapInh", "permitted": "CapPrm", "effective": "CapEff", "bounding": "CapBnd", "ambient": "CapAmb"}
    result = {"actual_uid": os.getuid(), "actual_gid": os.getgid(),
              "namespaces": {key: os.stat("/proc/self/ns/" + name).st_ino for key, name in
                             {"user": "user", "mount": "mnt", "pid": "pid", "ipc": "ipc", "net": "net"}.items()},
              "capabilities": {key: values[name] for key, name in cap_names.items()},
              "no_new_privs": values["NoNewPrivs"] == "1"}
    if not result["no_new_privs"] or any(int(v, 16) for v in result["capabilities"].values()):
        raise IsolationError("role retained privilege")
    return result


def _bind(sandbox, source, destination=None, *, writable=False, mount_plan=None):
    source = Path(source)
    destination = Path(destination or source)
    if not source.is_absolute() or not destination.is_absolute() or ".." in source.parts or ".." in destination.parts:
        raise IsolationError("mount input is missing or not absolute")
    target = sandbox / str(destination).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        target.mkdir(exist_ok=True)
    elif not target.exists():
        target.touch(exist_ok=False)
    # Mount the exact inode pinned by an O_PATH no-follow component walk.
    descriptor = os.open("/", os.O_PATH | os.O_DIRECTORY)
    try:
        for index, part in enumerate(source.parts[1:]):
            child = os.open(part, os.O_PATH | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor); descriptor = child
            info = os.fstat(descriptor)
            if stat.S_ISLNK(info.st_mode) or (index < len(source.parts) - 2 and not stat.S_ISDIR(info.st_mode)):
                raise IsolationError("mount source contains a symlink or non-directory ancestor")
        info = os.fstat(descriptor)
        _mount("/proc/self/fd/" + str(descriptor), target, MS_BIND | MS_REC)
        if mount_plan is not None:
            mount_plan.append({"destination": str(destination), "device": info.st_dev, "inode": info.st_ino,
                               "readonly": not writable, "recursive": stat.S_ISDIR(info.st_mode)})
    finally:
        os.close(descriptor)
    if not writable:
        # Each supplied mount must be an ordinary tree, not a nested mount farm.
        class MountAttributes(ctypes.Structure):
            _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64), ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]
        attributes = MountAttributes(1, 0, 0, 0)
        # mount_setattr(AT_RECURSIVE) protects nested mounts as well as the top.
        if _LIBC.syscall(442, -100, ctypes.c_char_p(os.fsencode(target)), 0x8000,
                         ctypes.byref(attributes), ctypes.sizeof(attributes)) != 0:
            raise IsolationError("recursive read-only mount protection unavailable")


def _sandbox(sandbox, profile, role, mounts, cwd, network):
    mount_plan = []
    flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWPID
    if not network:
        flags |= CLONE_NEWNET
    _syscall("unshare", flags)
    _mount(None, "/", MS_REC | MS_PRIVATE)
    # Trusted runtime dependencies are mounted read-only; host homes, /run and
    # other workspaces never enter the namespace.
    for source in ("/usr", "/lib", "/lib64"):
        if Path(source).exists():
            _bind(sandbox, Path(source).resolve(strict=True), source, mount_plan=mount_plan)
    for destination in ("/bin", "/sbin"):
        (sandbox / destination.lstrip("/")).symlink_to("usr" + destination)
    for directory in ("proc", "dev", "tmp", "home", "etc"):
        (sandbox / directory).mkdir(exist_ok=True)
    _mount("tmpfs", sandbox / "tmp", 0, "tmpfs")
    os.chmod(sandbox / "tmp", 0o1777)
    mount_plan.extend([{ "destination": "/tmp", "fstype": "tmpfs", "readonly": False, "recursive": False},
                       { "destination": "/proc", "fstype": "proc", "readonly": False, "recursive": False}])
    for name in ("null", "zero", "random", "urandom"):
        _bind(sandbox, "/dev/" + name, writable=True, mount_plan=mount_plan)
    for source in ("/etc/ld.so.cache", "/etc/ssl/certs", "/etc/passwd", "/etc/group"):
        if Path(source).exists():
            _bind(sandbox, Path(source).resolve(strict=True), source, mount_plan=mount_plan)
    if network:
        for source in ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"):
            if Path(source).exists():
                _bind(sandbox, Path(source).resolve(strict=True), source, mount_plan=mount_plan)
    trusted = Path(profile.paths["trusted_code_root"])
    if not str(trusted).startswith("/usr/"):
        _bind(sandbox, trusted, mount_plan=mount_plan)
    from .execution_profile import venv_runtime_metadata
    for metadata_path in venv_runtime_metadata(profile.tools["python"].path, trusted):
        _bind(sandbox, metadata_path, mount_plan=mount_plan)
    for tool in profile.tools.values():
        if tool is not None and not str(tool.path).startswith("/usr/"):
            _bind(sandbox, tool.path, mount_plan=mount_plan)
    if profile.sqlite.get("attestation"):
        _bind(sandbox, profile.sqlite["attestation"], mount_plan=mount_plan)
    auth_placeholder = sandbox / str(profile.auth_home).lstrip("/")
    auth_placeholder.mkdir(parents=True, exist_ok=True)
    os.chown(auth_placeholder, profile.roles["worker"].uid, profile.roles["worker"].gid)
    os.chmod(auth_placeholder, 0o700)
    for source, target, writable in mounts:
        _bind(sandbox, source, target, writable=writable, mount_plan=mount_plan)
    if role == "worker":
        vendor_dir = sandbox / str(profile.auth_home / ".codex").lstrip("/")
        vendor_dir.mkdir(parents=True, exist_ok=True)
        os.chown(vendor_dir, profile.roles[role].uid, profile.roles[role].gid)
        os.chmod(vendor_dir, 0o700)
    if role in {"graph", "signer"}:
        private_parent = sandbox / str(Path(profile.paths["signer_private_key"]).parent).lstrip("/")
        private_parent.mkdir(parents=True, exist_ok=True)
    os.chroot(sandbox)
    os.chdir(cwd)
    return mount_plan


def _validate_launch_authority(profile):
    if profile.mode != "isolated-linux" or os.geteuid() != 0:
        raise IsolationError("isolated launch requires the explicit root bootstrap")
    if len({role.uid for role in profile.roles.values()}) != 4:
        raise IsolationError("four distinct real role UIDs are required")
    # Original user namespace is intentionally retained. A mapping of this
    # root process to a container UID cannot claim the four host role domains.
    if Path("/proc/self/uid_map").read_text().split() != ["0", "0", "4294967295"]:
        raise IsolationError("bootstrap requires the initial kernel UID domain")


def run_role_process(profile, role_name, argv, *, stdin=b"", cwd="/tmp", mounts=(),
                     network=False, timeout_seconds=30, max_output_bytes=262144,
                     environment=None):
    """Private root primitive. Not exposed by the launcher wire protocol."""
    if profile.mode == "trusted-local":
        from ._trusted_local_runner import run_local_process
        return run_local_process(profile, role_name, argv, stdin=stdin, cwd=cwd, timeout_seconds=timeout_seconds, max_output_bytes=max_output_bytes, environment=environment)
    _validate_launch_authority(profile)
    role = profile.roles[role_name]
    if not argv or not Path(argv[0]).is_absolute():
        raise IsolationError("role executable must be an absolute pinned tool")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600 or type(max_output_bytes) is not int or not 1 <= max_output_bytes <= MAX_FRAME:
        raise IsolationError("invalid process bounds")
    env = {"HOME": "/tmp", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TZ": "UTC",
           "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    if environment:
        if set(environment) - {"HOME", "CODEX_HOME", "GRAPHER_LAUNCHER_SOCKET", "GRAPHER_WORKSPACE_ID", "GRAPHER_WORKER_CONTROL_SOCKET", "PYTHONPATH"}:
            raise IsolationError("unapproved role environment")
        env.update(environment)
    from ._boundary_attestation import capture_parent_boundary, validate_child_boundary
    parent_boundary = capture_parent_boundary()
    started = time.monotonic()
    input_r, input_w = os.pipe()
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    obs_r, obs_w = os.pipe()
    start_r, start_w = os.pipe()
    sandbox = Path(tempfile.mkdtemp(prefix="grapher-role-"))
    os.chmod(sandbox, 0o755)
    pid = os.fork()
    if pid == 0:
        try:
            os.close(start_w)
            if os.read(start_r, 1) != b"1": os._exit(125)
            os.close(start_r)
            os.close(input_w); os.close(out_r); os.close(err_r); os.close(obs_r)
            os.setsid()
            _syscall("prctl", 1, signal.SIGKILL, 0, 0, 0)
            mount_plan = _sandbox(sandbox, profile, role_name, mounts, str(cwd), network)
            outer_pidfd = os.pidfd_open(os.getpid())
            inner = os.fork()  # the child is PID 1 of the fresh namespace
            if inner:
                os.close(outer_pidfd)
                os.close(input_r); os.close(out_w); os.close(err_w)
                def stop_inner(signum, frame):
                    with contextlib.suppress(ProcessLookupError): os.kill(inner, signal.SIGKILL)
                signal.signal(signal.SIGTERM, stop_inner)
                _, status = os.waitpid(inner, 0)
                os.write(obs_w, b"\n" + _canonical({"reaped": True, "returncode": os.waitstatus_to_exitcode(status)}))
                os.close(obs_w)
                os._exit(os.waitstatus_to_exitcode(status) % 256)
            _syscall("prctl", 1, signal.SIGKILL, 0, 0, 0)
            _mount("proc", "/proc", 0, "proc")
            os.dup2(input_r, 0); os.dup2(out_w, 1); os.dup2(err_w, 2)
            # PID 1 is a trusted minimal supervisor. It owns no host authority
            # after the same real UID drop as its candidate child.
            _drop_role(role.uid, role.gid)
            _syscall("prctl", 1, signal.SIGKILL, 0, 0, 0)
            if select.select([outer_pidfd], [], [], 0)[0]: os._exit(125)
            os.close(outer_pidfd)
            policy_sha256 = _restrict_syscalls()
            observed = _observation()
            boundary = validate_child_boundary(observed, parent_boundary, expected_uid=role.uid,
                                               expected_gid=role.gid, network=network, mount_plan=mount_plan,
                                               seccomp_policy_sha256=policy_sha256)
            os.write(obs_w, _canonical({"observation": observed, "boundary": boundary}))
            command = os.fork()
            if command == 0:
                for fd in (input_r, out_w, err_w):
                    if fd > 2:
                        os.close(fd)
                maximum_fd = min(os.sysconf("SC_OPEN_MAX"), 1048576)
                os.closerange(3, maximum_fd)
                os.execve(argv[0], argv, env)
            for fd in (input_r, out_w, err_w):
                if fd > 2:
                    os.close(fd)
            _, status = os.waitpid(command, 0)
            os.write(obs_w, b"\n" + _canonical({"command_returncode": os.waitstatus_to_exitcode(status)}))
            os.close(obs_w)
            # SIGKILL every remaining member of this private PID namespace,
            # including double forks, setsid and background jobs.
            try:
                os.kill(-1, signal.SIGKILL)
            except ProcessLookupError:
                pass
            while True:
                try:
                    os.waitpid(-1, 0)
                except ChildProcessError:
                    break
            os._exit(os.waitstatus_to_exitcode(status) % 256)
        except BaseException as exc:
            try:
                os.write(err_w, ("isolation bootstrap: " + str(exc)).encode()[:2048])
            except OSError:
                pass
            os._exit(125)
    os.close(input_r); os.close(out_w); os.close(err_w); os.close(obs_w); os.close(start_r)
    try:
        pidfd = os.pidfd_open(pid)
    except BaseException:
        os.close(start_w); os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
        for fd in (input_w, out_r, err_r, obs_r): os.close(fd)
        shutil.rmtree(sandbox)
        raise IsolationError("pidfd acquisition failed before child admission") from None
    os.write(start_w, b"1"); os.close(start_w)
    selector = selectors.DefaultSelector()
    buffers = {out_r: bytearray(), err_r: bytearray(), obs_r: bytearray()}
    for fd in buffers:
        os.set_blocking(fd, False); selector.register(fd, selectors.EVENT_READ)
    os.set_blocking(input_w, False)
    pending = memoryview(stdin)
    if pending:
        selector.register(input_w, selectors.EVENT_WRITE)
    else:
        os.close(input_w)
    timed_out = overflow = False
    try:
        while selector.get_map():
            if _GRAPH_PIDFD is not None and select.select([_GRAPH_PIDFD], [], [], 0)[0]:
                timed_out = True
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                break
            if time.monotonic() - started > timeout_seconds:
                timed_out = True
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                break
            for key, event in selector.select(0.05):
                fd = key.fd
                if fd == input_w:
                    try:
                        count = os.write(fd, pending[:65536]); pending = pending[count:]
                    except BrokenPipeError:
                        pending = memoryview(b"")
                    if not pending:
                        selector.unregister(fd); os.close(fd)
                else:
                    data = os.read(fd, 65536)
                    if not data:
                        selector.unregister(fd); os.close(fd)
                    else:
                        buffers[fd].extend(data)
                        if len(buffers[out_r]) + len(buffers[err_r]) > max_output_bytes or len(buffers[obs_r]) > 262144:
                            overflow = True
                            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                            break
            if overflow:
                break
        cleanup_deadline = time.monotonic() + 5
        while True:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited: break
            if time.monotonic() >= cleanup_deadline:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise IsolationError("namespace supervisor cleanup exceeded five seconds")
            time.sleep(0.01)
        # The outer trusted supervisor writes completion only after waitpid of
        # PID 1, whose death destroys every process in its private namespace.
        if obs_r in selector.get_map():
            while True:
                chunk = os.read(obs_r, 8192)
                if not chunk: break
                buffers[obs_r].extend(chunk)
        returncode = os.waitstatus_to_exitcode(status)
        records = [line for line in bytes(buffers[obs_r]).splitlines() if line]
        first = json.loads(records[0]) if records else {}
        observation = first.get("observation")
        boundary = first.get("boundary")
        reaped = len(records) in {2, 3} and json.loads(records[-1]).get("reaped") is True
        if reaped:
            returncode = json.loads(records[-1])["returncode"]
        if len(records) == 3:
            returncode = json.loads(records[1])["command_returncode"]
        if observation is not None and (observation["actual_uid"] != role.uid or observation["actual_gid"] != role.gid):
            raise IsolationError("observed role differs from configured role")
        return BoundedProcessResult(bytes(buffers[out_r])[:max_output_bytes], bytes(buffers[err_r])[:max(0, max_output_bytes-len(buffers[out_r]))],
                                    returncode, time.monotonic() - started, observation is not None and reaped,
                                    -returncode if returncode < 0 else None, timed_out, overflow, observation, boundary)
    finally:
        for key in list(selector.get_map().values()):
            os.close(key.fd)
        selector.close(); os.close(pidfd)
        shutil.rmtree(sandbox)


def run_provider_process(request, profile, argv, stdin):
    """Root-private provider adapter used by the fixed provider handler."""
    if profile.mode == "isolated-linux":
        from ._provider_admission import admit_provider_command
        admit_provider_command(request, profile, argv, stdin)
    checkout = Path(request["checkout"]) if request else Path(profile.paths["trusted_code_root"])
    mounts = [(checkout, checkout, request is not None)]
    if request and (checkout / ".git").is_dir():
        mounts.append((checkout / ".git", checkout / ".git", False))
    auth_home = Path(profile.auth_home)
    auth_file = auth_home / ".codex" / "auth.json"
    if auth_file.is_file():
        mounts.append((auth_file, auth_file, False))
    environment = {"HOME": str(auth_home), "CODEX_HOME": str(auth_home / ".codex")}
    if request:
        control = checkout.parent.parent.parent / "state" / (request["attempt_id"] + ".control.sock")
        if control.exists():
            metadata = control.lstat()
            if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != profile.roles["graph"].uid:
                raise IsolationError("worker control endpoint ownership invalid")
            mounts.append((control, control, True))
            environment["GRAPHER_WORKER_CONTROL_SOCKET"] = str(control)
    if request and os.stat(checkout).st_uid != profile.roles["worker"].uid:
        # Directory ancestry is owned by bootstrap; only this checkout is given
        # to the worker. Provider cannot traverse to sibling attempts or state.
        for current, directories, files in os.walk(checkout):
            os.chown(current, profile.roles["worker"].uid, profile.roles["worker"].gid)
            for name in files:
                p = Path(current) / name
                if p.is_symlink():
                    raise IsolationError("worker checkout contains a symlink")
                os.chown(p, profile.roles["worker"].uid, profile.roles["worker"].gid)
    result = run_role_process(profile, "worker", argv, stdin=stdin, cwd=checkout, mounts=mounts, network=True,
                            timeout_seconds=request["limits"]["worker_timeout_seconds"] if request else 15,
                            max_output_bytes=request["limits"]["max_output_bytes"] if request else 262144,
                            environment=environment)
    if profile.mode == "isolated-linux":
        from ._provider_admission import record_boundary
        record_boundary(result)
    return result


def _git(profile, root, *arguments):
    return subprocess.check_output([profile.tools["git"].path, "-c", "safe.directory=*", "-c", "core.hooksPath=/dev/null",
                                    "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
                                   env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"},
                                   stderr=subprocess.PIPE, timeout=30)


def _tree_hash(profile, root, candidate_sha):
    from .evaluation_broker import candidate_tree_sha256
    return candidate_tree_sha256(root, profile, candidate_sha)


def _copy_candidate_nofollow(source, destination):
    """Copy data through pinned no-follow directory descriptors, never links."""
    source = Path(source)
    if not source.is_absolute() or source == Path("/") or ".." in source.parts:
        raise IsolationError("candidate source must be an absolute non-root path")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in source.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current); current = child
        def copy_directory(descriptor, target):
            target.mkdir(mode=0o755)
            names = sorted(os.listdir(descriptor))
            for name in names:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try: copy_directory(child, target / name)
                    finally: os.close(child)
                elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        before = os.fstat(child)
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or (before.st_dev, before.st_ino) != (metadata.st_dev, metadata.st_ino):
                            raise IsolationError("candidate entry changed before copy")
                        with (target / name).open("xb") as output:
                            total = 0
                            while True:
                                chunk = os.read(child, 65536)
                                if not chunk: break
                                total += len(chunk)
                                if total > 128 * 1024 * 1024:
                                    raise IsolationError("candidate file exceeds copy bound")
                                output.write(chunk)
                        after = os.fstat(child)
                        fingerprint = lambda v: (v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns,v.st_mode,v.st_nlink)
                        if fingerprint(before) != fingerprint(after) or total != before.st_size:
                            raise IsolationError("candidate entry changed during copy")
                        os.chmod(target / name, 0o755 if before.st_mode & 0o111 else 0o644)
                    finally: os.close(child)
                else:
                    raise IsolationError("candidate links and special files are forbidden")
            if sorted(os.listdir(descriptor)) != names:
                raise IsolationError("candidate directory changed during copy")
        copy_directory(current, destination)
    finally:
        os.close(current)


def execute_candidate_tests(request, profile):
    """Execute the root broker's prevalidated frozen test request."""
    if profile.mode == "isolated-linux":
        _validate_launch_authority(profile)
    candidate = Path(request["candidate_root"])
    pre = _tree_hash(profile, candidate, request["candidate_sha"])
    role = profile.roles["test_runner"]
    # Test only an independent copy; no test UID can rewrite graph Git objects.
    with tempfile.TemporaryDirectory(prefix="grapher-test-candidate-") as directory:
        isolated = Path(directory) / "candidate"
        _copy_candidate_nofollow(candidate, isolated)
        for current, directories, files in os.walk(isolated):
            os.chown(current, role.uid, role.gid)
            for name in files:
                os.chown(Path(current) / name, role.uid, role.gid)
        checks = ([{"id": f"required-{i:04d}", "command": command} for i, command in enumerate(request["commands"])]
                  if request["kind"] == "required" else request["checks"])
        started = time.monotonic(); outputs = {}; results = []; remaining = request["max_output_bytes"]; observation = None
        for i, check in enumerate(checks):
            _tree_hash(profile, isolated, request["candidate_sha"])
            argv = ["/bin/sh", "-c", check["command"]] if "command" in check else check["argv"]
            if not Path(argv[0]).is_absolute():
                tool = profile.tools.get(argv[0])
                if tool is None:
                    raise IsolationError("check executable is not a pinned tool")
                argv = [tool.path, *argv[1:]]
            seconds = max(1, request["timeout_seconds"] - int(time.monotonic() - started))
            result = run_role_process(profile, "test_runner", argv, cwd=isolated,
                                      mounts=[(isolated, isolated, True), (isolated / ".git", isolated / ".git", False)], timeout_seconds=seconds,
                                      max_output_bytes=max(1, remaining))
            if result.observation is None or not result.descendants_reaped:
                raise IsolationError("candidate isolation was not observed")
            observation = result.observation
            if result.timed_out or result.output_overflow:
                raise IsolationError("candidate test limit exceeded")
            entry = {"sequence": i, "id": check["id"], "command_sha256": hashlib.sha256(_canonical(check["command"] if "command" in check else check)).hexdigest(), "exit_code": result.returncode}
            for stream in ("stdout", "stderr"):
                output = getattr(result, stream); path = f"outputs/{i:04d}.{stream}"
                outputs[path] = output; remaining -= len(output)
                entry[stream] = {"sha256": hashlib.sha256(output).hexdigest(), "bytes": len(output), "relative_path": path}
            results.append(entry)
            _tree_hash(profile, isolated, request["candidate_sha"])
        post = _tree_hash(profile, isolated, request["candidate_sha"])
        if pre != post or not observation:
            raise IsolationError("candidate tree changed or checks were empty")
        return ({**observation, "pre_tree_sha256": pre, "post_tree_sha256": post,
                 "results": results, "elapsed_ms": int((time.monotonic() - started) * 1000),
                 "descendants": {"reaped": True, "survivors": 0}}, outputs)


def get_active_launcher():
    if _ACTIVE_LAUNCHER is None:
        raise IsolationError("no authenticated bootstrap launcher is active")
    return _ACTIVE_LAUNCHER


def set_active_launcher(client):
    global _ACTIVE_LAUNCHER
    _ACTIVE_LAUNCHER = client


def _send_frame(connection, value):
    data = _canonical(value)
    if len(data) > MAX_FRAME:
        raise IsolationError("launcher frame too large")
    connection.sendall(struct.pack("!I", len(data)) + data)


def _recv_frame(connection):
    def read_exact(count):
        output = bytearray()
        while len(output) < count:
            chunk = connection.recv(count - len(output))
            if not chunk:
                raise EOFError("launcher disconnected")
            output.extend(chunk)
        return bytes(output)
    size = struct.unpack("!I", read_exact(4))[0]
    from .sealed_protocol import MAX_WIRE_BYTES
    if not 1 <= size <= MAX_WIRE_BYTES:
        raise IsolationError("invalid launcher frame length")
    from .sealed_protocol import strict_json_loads
    return strict_json_loads(read_exact(size))


class LauncherClient:
    def __init__(self, path, workspace_id):
        self.path = str(path); self.workspace_id = workspace_id; self.sequence = 0; self.control_server = None; self.session = secrets.token_hex(12)

    def request(self, action, payload):
        self.sequence += 1
        request = {"schema_version": 1, "action": action, "workspace_id": self.workspace_id,
                   "request_id": f"rpc-{self.session}-{self.sequence}", "payload": payload}
        request["request_sha256"] = hashlib.sha256(_canonical(request)).hexdigest()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3700); connection.connect(self.path); _send_frame(connection, request)
            while not select.select([connection], [], [], 0.05)[0]:
                if self.control_server is not None: self.control_server.serve_once()
            result = _recv_frame(connection)
        if result.get("error"):
            raise IsolationError(result["error"])
        return result["result"]


def prepare_workspace_ownership(profile, workspace):
    _validate_launch_authority(profile)
    workspace = Path(workspace)
    role = profile.roles["graph"]
    if workspace.is_symlink():
        raise IsolationError("workspace symlink forbidden")
    os.chown(workspace, 0, 0); os.chmod(workspace, 0o755)
    immutable = {"frozen", "workflow.json", ".broker-receipts"}
    for item in workspace.iterdir():
        if item.is_symlink():
            raise IsolationError("workspace symlink forbidden")
        owner = (0, 0) if item.name in immutable else (role.uid, role.gid)
        paths = [item, *item.rglob("*")] if item.is_dir() else [item]
        for path in paths:
            if path.is_symlink():
                raise IsolationError("workspace symlink forbidden")
            relative = path.relative_to(workspace)
            current_owner = owner
            if len(relative.parts) >= 3 and relative.parts[0] == "attempts" and relative.parts[2] == "checkout":
                current_owner = (role.uid, role.gid)
            elif relative.parts[0] == "publications" or str(relative) == "state/binding.json":
                current_owner = (role.uid, profile.roles["worker"].gid)
            os.chown(path, *current_owner)
            if item.name in immutable:
                private = relative.parts[:2] == (".broker-receipts", ".private")
                os.chmod(path, (0o700 if path.is_dir() else 0o400) if private else (0o755 if path.is_dir() else 0o444))
    # Read-only worker group ownership is inherited during graph construction;
    # the dropped graph receives neither supplementary groups nor CAP_CHOWN.
    # State remains owner-only traversable. Publication groups gain read/execute.
    for name, mode in (("state", 0o2700), ("publications", 0o2750)):
        directory = workspace / name
        if directory.exists():
            os.chown(directory, role.uid, profile.roles["worker"].gid)
            os.chmod(directory, mode)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(descriptor)
            finally: os.close(descriptor)
    receipts = workspace / ".broker-receipts"
    receipts.mkdir(mode=0o755, exist_ok=True); os.chown(receipts, 0, 0); os.chmod(receipts, 0o755)
    from .evaluation_broker import BrokerStore
    store = BrokerStore(workspace, require_root=True); store.close()


def bootstrap_operation(profile, workspace, operation, *, stop_after=None, barrier=None):
    """Explicit root CLI entry; creates a finite post-drop authenticated broker."""
    global _GRAPH_PIDFD
    _validate_launch_authority(profile)
    if operation not in {"run", "recover", "rollback", "status"}:
        raise IsolationError("unknown graph operation")
    workspace = Path(workspace).resolve(strict=True)
    trusted = Path(profile.paths["trusted_code_root"]).resolve(strict=True)
    if trusted not in Path(__file__).resolve().parents:
        raise IsolationError("bootstrap code was imported from outside the pinned trusted install")
    from .evaluation_broker import EvaluationBroker
    metadata = json.loads((workspace / "workflow.json").read_bytes())
    broker = EvaluationBroker(workspace, profile)
    socket_path = workspace / ".launcher.sock"
    lock_path = workspace / ".bootstrap.lock"
    lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    lock_stat = os.fstat(lock_fd)
    if lock_stat.st_uid != 0 or lock_stat.st_nlink != 1 or not stat.S_ISREG(lock_stat.st_mode):
        os.close(lock_fd); raise IsolationError("bootstrap lock authority invalid")
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd); raise IsolationError("a bootstrap owner is already active") from None
    if socket_path.exists() or socket_path.is_symlink():
        metadata_socket = socket_path.lstat()
        if not stat.S_ISSOCK(metadata_socket.st_mode) or metadata_socket.st_uid != profile.roles["graph"].uid:
            os.close(lock_fd); raise IsolationError("unsafe stale launcher path")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            try:
                probe.connect(str(socket_path))
            except ConnectionRefusedError:
                socket_path.unlink()
            else:
                os.close(lock_fd); raise IsolationError("launcher is still active")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path)); os.chown(socket_path, profile.roles["graph"].uid, profile.roles["graph"].gid); os.chmod(socket_path, 0o600)
    listener.listen(4); listener.settimeout(0.1)
    result_r, result_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            listener.close(); os.close(result_r)
            _syscall("prctl", 1, signal.SIGKILL, 0, 0, 0)
            graph_sandbox = Path(tempfile.mkdtemp(prefix="grapher-graph-"))
            os.chmod(graph_sandbox, 0o755)
            graph_mounts = [(workspace, workspace, True),
                            (Path(profile.paths["signer_public_key"]), Path(profile.paths["signer_public_key"]), False)]
            _sandbox(graph_sandbox, profile, "graph", graph_mounts, str(workspace), False)
            outer_pidfd = os.pidfd_open(os.getpid())
            inner = os.fork()
            if inner:
                os.close(outer_pidfd)
                os.close(result_w)
                _, child_status = os.waitpid(inner, 0)
                os._exit(os.waitstatus_to_exitcode(child_status) % 256)
            _syscall("prctl", 1, signal.SIGKILL, 0, 0, 0)
            _mount("proc", "/proc", 0, "proc")
            # Graph inherits no root launcher descriptor; connects only after
            # the irreversible drop, making SO_PEERCRED actual graph authority.
            for descriptor_name in os.listdir("/proc/self/fd"):
                fd = int(descriptor_name)
                if fd > 2 and fd not in {result_w, outer_pidfd}:
                    with contextlib.suppress(OSError): os.close(fd)
            _drop_role(profile.roles["graph"].uid, profile.roles["graph"].gid)
            _syscall("prctl", 1, signal.SIGKILL, 0, 0, 0)
            if select.select([outer_pidfd], [], [], 0)[0]: os._exit(125)
            os.close(outer_pidfd)
            _restrict_syscalls()
            os.environ.clear()
            os.environ.update({"HOME": "/tmp", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                               "TZ": "UTC", "PYTHONDONTWRITEBYTECODE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
            set_active_launcher(LauncherClient(socket_path, metadata["workspace_id"]))
            from .repository_workflow import run_repository_workflow
            result = run_repository_workflow(workspace, operation, stop_after=stop_after, barrier=barrier)
            if dataclasses.is_dataclass(result): result = dataclasses.asdict(result)
            os.write(result_w, _canonical({"result": result})); os._exit(0)
        except BaseException as exc:
            os.write(result_w, _canonical({"error": str(exc)})); os._exit(1)
    os.close(result_w)
    _GRAPH_PIDFD = os.pidfd_open(pid)
    pending = bytearray(); status = None
    operation_limit = (sum(broker.frozen.task["limits"][key] for key in
                           ("worker_timeout_seconds", "required_test_timeout_seconds", "evaluation_timeout_seconds")) + 120
                       if operation == "run" else 180)
    operation_started = time.monotonic()
    from ._provider_admission import bootstrap_admission
    admission = bootstrap_admission(broker, profile)
    authority = None
    try:
        authority = admission.__enter__()
        while status is None:
            if time.monotonic() - operation_started > operation_limit:
                raise IsolationError("graph operation exceeded frozen task deadline")
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                connection = None
            if connection:
                with connection:
                    connection.settimeout(5)
                    _, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                    try:
                        if uid != profile.roles["graph"].uid or gid != profile.roles["graph"].gid:
                            raise IsolationError("launcher peer is not the actual graph role")
                        from .sealed_protocol import validate_launcher_request
                        request = validate_launcher_request(_recv_frame(connection))
                        if request["workspace_id"] != metadata["workspace_id"]:
                            raise IsolationError("launcher workspace mismatch")
                        wire_key = hashlib.sha256(request["request_id"].encode()).hexdigest()
                        old = broker.store.private_record("wire-result-" + wire_key)
                        if old is not None:
                            if old["request_sha256"] != request["request_sha256"]:
                                raise IsolationError("launcher request ID reused with different payload")
                            result = old["result"]
                        else:
                            if broker.store.private_record("wire-request-" + wire_key) is not None:
                                raise IsolationError("interrupted launcher request cannot rerun")
                            broker.store.reserve("wire-request-" + wire_key, {"request_sha256": request["request_sha256"]})
                            result = broker.handle(request["action"], request["payload"])
                            broker.store.reserve("wire-result-" + wire_key, {"request_sha256": request["request_sha256"], "result": result})
                        _send_frame(connection, {"result": result})
                    except BaseException as exc:
                        _send_frame(connection, {"error": str(exc)})
            waited, child_status = os.waitpid(pid, os.WNOHANG)
            if waited:
                status = child_status
            if select.select([result_r], [], [], 0)[0]:
                chunk = os.read(result_r, 65536); pending.extend(chunk)
                if len(pending) > MAX_FRAME:
                    raise IsolationError("graph response overflow")
        result = json.loads(pending)
        if "error" in result:
            raise IsolationError(result["error"])
        response = result["result"]
        if isinstance(response, dict):
            response["isolation_observations"] = authority.observations
        return response
    finally:
        if authority is not None:
            admission.__exit__(None, None, None)
        if status is None:
            os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
        os.close(result_r); listener.close(); socket_path.unlink(missing_ok=True); os.close(lock_fd)
        os.close(_GRAPH_PIDFD); _GRAPH_PIDFD = None; broker.close()


def run_signer_process(signing_request, profile, workspace):
    """The only signing process: fixed trusted code, sealed inputs, no candidate mount."""
    workspace = Path(workspace)
    trusted = str(profile.paths["trusted_code_root"])
    script = ("import json,sys;sys.path.insert(0," + repr(trusted) + ");"
              "from control_plane.execution_profile import validate_execution_profile;"
              "from control_plane.evaluation_broker import signer_main;"
              "v=json.load(sys.stdin);p=validate_execution_profile(v['profile'],raw_bytes=v['profile_raw'].encode(),require_private_key=True);"
              "r=signer_main(v['request'],p,v['workspace']);"
              "sys.stdout.write(json.dumps(r,sort_keys=True,separators=(',',':'),allow_nan=False))")
    # A root-derived, read-only public evidence view is the signer's entire
    # workspace. Candidate code is present only as Git/bundle data and never imported.
    from ._signer_view import signer_view
    frozen_profile = (workspace / "frozen/profile.json").read_text()
    value = {"request": signing_request, "profile": profile.to_dict(), "profile_raw": frozen_profile, "workspace": str(workspace)}
    with signer_view(workspace, profile) as view:
        mounts = [(view, workspace, False)]
        for key in ("signer_private_key", "signer_public_key"):
            path = Path(profile.paths[key]); mounts.append((path, path, False))
        result = run_role_process(profile, "signer", [profile.tools["python"].path, "-I", "-B", "-c", script],
                                  stdin=_canonical(value), cwd="/tmp", mounts=mounts,
                                  timeout_seconds=60, max_output_bytes=262144)
    if result.returncode or result.timed_out or result.output_overflow or not result.descendants_reaped:
        raise IsolationError("trusted signer rejected the sealed evaluation: " + result.stderr.decode(errors="replace")[:1024])
    from .sealed_protocol import strict_json_loads
    return strict_json_loads(result.stdout)


class ScopedWorkerControlServer:
    """Graph-owned one-task endpoint; no evaluator/integrator action exists."""
    def __init__(self, path, *, worker_uid, project_id, task_id, attempt_id, status, heartbeat):
        self.path = Path(path)
        self.worker_uid = worker_uid
        self.binding = {"project_id": project_id, "task_id": task_id, "attempt_id": attempt_id}
        self.status = status; self.heartbeat = heartbeat
        if self.path.exists() or self.path.is_symlink():
            raise IsolationError("worker control path already exists")
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(self.path)); os.chmod(self.path, 0o666)
        self.socket.listen(2); self.socket.settimeout(0.1)

    def serve_once(self):
        try:
            connection, _ = self.socket.accept()
        except socket.timeout:
            return False
        with connection:
            connection.settimeout(2)
            try:
                _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != self.worker_uid:
                    raise IsolationError("worker control requires the actual worker UID")
                request = _recv_frame(connection)
                if type(request) is not dict or set(request) != {"schema_version", "action", "project_id", "task_id", "attempt_id"} or type(request["schema_version"]) is not int or request["schema_version"] != 1:
                    raise IsolationError("invalid scoped worker request")
                if any(request[key] != value for key, value in self.binding.items()):
                    raise IsolationError("worker attempted cross-task access")
                if request["action"] == "status":
                    result = self.status()
                elif request["action"] == "heartbeat":
                    result = self.heartbeat()  # existing live lease check owns admission
                else:
                    raise IsolationError("worker action is not authorized")
                _send_frame(connection, {"result": result})
            except (PermissionError, ValueError, EOFError) as exc:
                _send_frame(connection, {"error": str(exc)})
        return True

    def close(self):
        self.socket.close(); self.path.unlink(missing_ok=True)


def finish_worker_checkout(request, profile):
    """Root transfers the complete candidate to graph after worker-tree quiescence."""
    if profile.mode != "isolated-linux":
        return
    _validate_launch_authority(profile)
    checkout = Path(request["checkout"])
    if not checkout.is_absolute() or checkout == Path("/") or ".." in checkout.parts:
        raise IsolationError("worker handoff must select an absolute checkout")
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in checkout.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current); current = child
        def transfer(descriptor, git_metadata=False):
            role = profile.roles["graph"]
            os.fchown(descriptor, role.uid, role.gid)
            for name in os.listdir(descriptor):
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try: transfer(child, git_metadata or name == ".git")
                    finally: os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                    try:
                        pinned = os.fstat(child)
                        if not stat.S_ISREG(pinned.st_mode) or pinned.st_nlink != 1 or (pinned.st_dev, pinned.st_ino) != (info.st_dev, info.st_ino):
                            raise IsolationError("worker handoff entry raced")
                        os.fchown(child, role.uid, role.gid)
                        # Ownership handoff preserves every original permission bit.
                    finally: os.close(child)
                else:
                    raise IsolationError("worker handoff rejects links and special entries")
        transfer(current)
    finally:
        os.close(current)


# Freeze installed production function identities after module definition.
from ._provider_admission import assert_active_provider_boundary, freeze_runner_functions
freeze_runner_functions()
