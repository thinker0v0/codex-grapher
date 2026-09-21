#!/usr/bin/env python3
"""Observe four actual Linux roles using bounded, disposable, inert fixtures.

This is fixture evidence, not an HG07 or release verdict. No provider, candidate,
real signing key, account mutation, service, package or guest is used.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from control_plane.execution_profile import load_execution_profile
from control_plane.sealed_protocol import canonical
from control_plane.isolated_runner import (
    ScopedWorkerControlServer, _drop_role, run_role_process,
)


ROOT = Path(__file__).resolve().parents[1]
ROLES = ("worker", "test_runner", "signer", "graph")
CAPS = {"inheritable": "CapInh", "permitted": "CapPrm", "effective": "CapEff",
        "bounding": "CapBnd", "ambient": "CapAmb"}
NAMESPACES = {"user": "user", "mount": "mnt", "pid": "pid", "ipc": "ipc", "net": "net"}

# Fixed trusted source. Signer runs this source only; none of it is supplied by a
# candidate. The key target is always an inert fixture and is never printed.
ROLE_PROBE = r'''
import ctypes, errno, json, os, pathlib, socket, struct, sys
config = json.load(sys.stdin)
values = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
observation = {
    "actual_uid": os.getuid(), "actual_gid": os.getgid(),
    "namespaces": {key: os.stat("/proc/self/ns/" + name).st_ino for key, name in
        {"user":"user", "mount":"mnt", "pid":"pid", "ipc":"ipc", "net":"net"}.items()},
    "capabilities": {key: values[name].strip() for key, name in
        {"inheritable":"CapInh", "permitted":"CapPrm", "effective":"CapEff", "bounding":"CapBnd", "ambient":"CapAmb"}.items()},
    "no_new_privs": values["NoNewPrivs"].strip() == "1",
}
checks = {}
def denied(name, operation):
    try:
        operation()
    except OSError as error:
        checks[name] = {"denied": error.errno in {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT}, "errno": error.errno}
    else:
        checks[name] = {"denied": False, "errno": None}
def write(path):
    with open(path, "ab") as stream:
        stream.write(b"unexpected mutation")
def read(path):
    with open(path, "rb") as stream:
        return bool(stream.read(1))
for name in ("trusted-code", "policy", "checks", "graph.db", "accepted"):
    denied("write_" + name, lambda name=name: write("/probe/public/" + name))
denied("write_receipt", lambda: write("/probe/receipts/receipt"))
denied("replace_receipt", lambda: os.rename("/probe/receipts/receipt", "/probe/receipts/forged-receipt"))
denied("cross_project_read", lambda: read("/probe/other-project/private"))
denied("root_uid", lambda: os.setuid(0))
libc = ctypes.CDLL(None, use_errno=True)
result = libc.unshare(0x10000000)  # CLONE_NEWUSER must not restore namespace capabilities
checks["new_user_namespace"] = {"denied": result == -1 and ctypes.get_errno() == errno.EPERM,
                                 "errno": ctypes.get_errno() if result == -1 else None}
with socket.socket(socket.AF_UNIX) as connection:
    denied("launcher_connect", lambda: connection.connect("/probe/bootstrap/launcher.sock"))
try:
    checks["key_read"] = {"allowed": read("/probe/key/private")}
except OSError as error:
    checks["key_read"] = {"allowed": False, "errno": error.errno}
denied("key_write", lambda: write("/probe/key/private"))
try:
    checks["receipt_read"] = {"allowed": read("/probe/receipts/receipt")}
except OSError as error:
    checks["receipt_read"] = {"allowed": False, "errno": error.errno}
own = pathlib.Path("/probe/own/positive")
own.write_text("bounded fixture write")
checks["own_write"] = own.read_text() == "bounded fixture write"
checks["parent_environment_absent"] = "ROLE_PROBE_PARENT_SECRET" not in os.environ
inherited = []
for name in os.listdir("/proc/self/fd"):
    if int(name) > 2:
        try:
            inherited.append(os.readlink("/proc/self/fd/" + name))
        except FileNotFoundError:
            pass
checks["no_inherited_descriptors"] = not inherited
mounts = []
for line in pathlib.Path("/proc/self/mountinfo").read_text().splitlines():
    fields = line.split()
    if fields[4] in {"/usr", config["trusted_code_root"]}:
        mounts.append({"target": fields[4], "readonly": "ro" in fields[5].split(",")})
expected_mounts = {"/usr"}
if not config["trusted_code_root"].startswith("/usr/"):
    expected_mounts.add(config["trusted_code_root"])
checks["trusted_mounts_readonly"] = {item["target"] for item in mounts} == expected_mounts and all(item["readonly"] for item in mounts)
control = []
def rpc(request):
    data = json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        connection.connect("/probe/control.sock")
        connection.sendall(struct.pack("!I", len(data)) + data)
        def exact(size):
            out = bytearray()
            while len(out) < size:
                chunk = connection.recv(size - len(out))
                if not chunk:
                    raise RuntimeError("scoped control disconnected")
                out.extend(chunk)
            return bytes(out)
        size = struct.unpack("!I", exact(4))[0]
        if not 1 <= size <= 8192:
            raise RuntimeError("scoped control response exceeded fixture bound")
        return json.loads(exact(size))
if config["control"]:
    base = {"schema_version":1, "action":"status", "project_id":"probe", "task_id":"task", "attempt_id":"attempt-1"}
    requests = [("status", base), ("heartbeat", dict(base, action="heartbeat")),
        ("cross_task", dict(base, task_id="other")), ("cross_project", dict(base, project_id="other")),
        ("cross_attempt", dict(base, attempt_id="attempt-2")),
        ("forged_role", dict(base, role="graph")),
        ("evaluate", dict(base, action="evaluate")), ("integrate", dict(base, action="integrate")),
        ("rollback", dict(base, action="rollback")), ("boolean_version", dict(base, schema_version=True)),
        ("expired_heartbeat", dict(base, action="heartbeat")), ("status_after_denials", base)]
    for name, request in requests:
        try:
            response = rpc(request)
        except (BrokenPipeError, ConnectionResetError):
            response = {"error":"peer rejected the connection"}
        control.append({"case": name, "response": response})
print(json.dumps({"observation":observation, "checks":checks, "control":control, "mounts":mounts, "python_version":sys.version}, sort_keys=True))
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stream_evidence(data):
    return {"sha256": sha(data), "bytes": len(data),
            "raw_base64": base64.b64encode(data).decode("ascii")}


def host_observation():
    return {"uid": os.getuid(), "gid": os.getgid(),
            "namespaces": {key: os.stat("/proc/self/ns/" + name).st_ino
                           for key, name in NAMESPACES.items()},
            "kernel": os.uname().release,
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


@contextlib.contextmanager
def scoped_server(profile, directory):
    """Real graph UID server; only fixture callbacks, bounded lifetime."""
    graph = profile.roles["graph"]
    directory.mkdir(mode=0o700)
    os.chown(directory, graph.uid, graph.gid)
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_r)
            signal.alarm(60)
            # AF_UNIX pathname capacity is short even when the fixture project
            # path is long or its ancestors are not graph-traversable. Bootstrap
            # pins this one graph-owned directory before irreversibly dropping.
            socket_dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            _drop_role(graph.uid, graph.gid)
            counts = {"status": 0, "heartbeat": 0}
            def status():
                counts["status"] += 1
                return {"state": "RUNNING", "task_id": "task", "callbacks": dict(counts)}
            def heartbeat():
                if counts["heartbeat"]:
                    raise PermissionError("inert fixture lease expired")
                counts["heartbeat"] += 1
                return {"lease": "live", "task_id": "task"}
            server = ScopedWorkerControlServer(
                Path(f"/proc/self/fd/{socket_dir_fd}/control.sock"), worker_uid=profile.roles["worker"].uid,
                project_id="probe", task_id="task", attempt_id="attempt-1",
                status=status, heartbeat=heartbeat)
            os.write(ready_w, b"READY"); os.close(ready_w)
            while True:
                server.serve_once()
        except BaseException as error:
            with contextlib.suppress(OSError):
                os.write(2, ("scoped fixture server: " + type(error).__name__ + ": " + str(error) + "\n").encode()[:2048])
            with contextlib.suppress(OSError):
                os.write(ready_w, b"FAILED")
            os._exit(1)
    os.close(ready_w)
    try:
        if not select.select([ready_r], [], [], 5)[0] or os.read(ready_r, 32) != b"READY":
            raise RuntimeError("actual graph-owned scoped server failed to start")
        yield directory / "control.sock"
    finally:
        os.close(ready_r)
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)


def inspect_role(profile, role, result, host):
    failures = []
    if (result.returncode != 0 or result.timed_out or result.output_overflow
            or not result.descendants_reaped or result.signal is not None):
        return ["bounded role process did not finish cleanly"], None
    try:
        value = json.loads(result.stdout)
        observed = value["observation"]
        if observed != result.observation:
            failures.append("child observation differs from trusted supervisor")
        if (observed["actual_uid"] != profile.roles[role].uid
                or observed["actual_gid"] != profile.roles[role].gid
                or observed["actual_uid"] == 0):
            failures.append("configured real identity mismatch")
        if not observed["no_new_privs"] or any(int(mask, 16) for mask in observed["capabilities"].values()):
            failures.append("role retained privilege")
        for name in ("mount", "pid", "ipc", "net"):
            if observed["namespaces"][name] == host["namespaces"][name]:
                failures.append("host namespace retained: " + name)
        for name, check in value["checks"].items():
            if name == "key_read":
                if check["allowed"] != (role == "signer"):
                    failures.append("inert key role boundary failed")
            elif name == "receipt_read":
                if check["allowed"] != (role in {"signer", "graph"}):
                    failures.append("root-held receipt visibility boundary failed")
            elif type(check) is dict and not check["denied"]:
                failures.append("forbidden operation succeeded: " + name)
            elif type(check) is bool and not check:
                failures.append("positive/inheritance check failed: " + name)
        for case in value["control"]:
            allowed = role == "worker" and case["case"] in {"status", "heartbeat", "status_after_denials"}
            response = case["response"]
            if allowed and set(response) != {"result"}:
                failures.append("scoped positive failed: " + case["case"])
            if not allowed and set(response) != {"error"}:
                failures.append("scoped denial failed: " + case["case"])
            if (role == "worker" and case["case"] == "status_after_denials"
                    and response.get("result", {}).get("callbacks") != {"status": 2, "heartbeat": 1}):
                failures.append("denied scoped requests triggered state callbacks")
    except (KeyError, TypeError, ValueError) as error:
        failures.append("malformed observed role output: " + type(error).__name__)
        value = None
    return failures, value


def verify(profile, taskroot):
    if profile.mode != "isolated-linux":
        raise PermissionError("a validated isolated-linux profile is required")
    taskroot.chmod(0o755)
    public = taskroot / "root-owned"
    public.mkdir(mode=0o755)
    public.chmod(0o755)  # Fixture visibility must not depend on the caller's umask.
    inventory = {}
    for name in ("trusted-code", "policy", "checks", "graph.db", "accepted"):
        path = public / name
        path.write_bytes(("inert fixture: " + name).encode())
        path.chmod(0o666)  # denial must come from the read-only mount as well as identity
        inventory[name] = sha(path.read_bytes())
    receipts = taskroot / "root-held-receipts"
    receipts.mkdir(mode=0o755)
    receipts.chmod(0o755)
    (receipts / "receipt").write_text("inert sealed receipt fixture")
    (receipts / "receipt").chmod(0o444)
    receipt_hash = sha((receipts / "receipt").read_bytes())
    keydir = taskroot / "fixture-key-outside-workspace"
    keydir.mkdir(mode=0o700)
    key = keydir / "inert-private"
    key.write_bytes(b"INERT FIXTURE ONLY; NOT A CRYPTOGRAPHIC KEY")
    key_hash = sha(key.read_bytes())
    os.chown(key, 0, profile.roles["signer"].gid); key.chmod(0o440)
    other = taskroot / "other-project"
    other.mkdir(mode=0o700)
    (other / "private").write_bytes(b"inert other project")
    bootstrap = taskroot / "bootstrap"
    bootstrap.mkdir(mode=0o700)
    host = host_observation()
    result = {"host": host, "roles": {}, "failures": []}
    previous = os.environ.get("ROLE_PROBE_PARENT_SECRET")
    os.environ["ROLE_PROBE_PARENT_SECRET"] = "inert-parent-only-marker"
    try:
        with socket.socket(socket.AF_UNIX) as launcher, scoped_server(profile, taskroot / "graph-owned") as control:
            socket_dir_fd = os.open(bootstrap, os.O_RDONLY | os.O_DIRECTORY)
            try:
                launcher.bind(f"/proc/self/fd/{socket_dir_fd}/launcher.sock")
            finally:
                os.close(socket_dir_fd)
            launcher.listen(1)
            for name in ROLES:
                role = profile.roles[name]
                own = taskroot / (name + "-work")
                own.mkdir(mode=0o700); os.chown(own, role.uid, role.gid)
                mounts = [(public, "/probe/public", False), (own, "/probe/own", True)]
                if name == "signer":
                    mounts.append((key, "/probe/key/private", False))
                if name in {"signer", "graph"}:
                    mounts.append((receipts, "/probe/receipts", False))
                has_control = name in {"worker", "test_runner"}
                if has_control:
                    mounts.append((control, "/probe/control.sock", False))
                data = canonical({"trusted_code_root": profile.paths["trusted_code_root"], "control": has_control})
                argv = [profile.tools["python"].path, "-I", "-B", "-c", ROLE_PROBE]
                execution = run_role_process(profile, name, argv, stdin=data, cwd="/tmp",
                    mounts=mounts, timeout_seconds=15, max_output_bytes=131072)
                failures, observed = inspect_role(profile, name, execution, host)
                result["roles"][name] = {
                    "argv": argv, "cwd": "/tmp", "stdin_sha256": sha(data),
                    "configured_uid": role.uid, "configured_gid": role.gid,
                    "limits": {"timeout_seconds": 15, "max_output_bytes": 131072},
                    "returncode": execution.returncode, "signal": execution.signal,
                    "elapsed_seconds": execution.elapsed_seconds,
                    "timed_out": execution.timed_out, "output_overflow": execution.output_overflow,
                    "descendants_reaped": execution.descendants_reaped,
                    "supervisor_observation": execution.observation, "observed": observed,
                    "stdout": stream_evidence(execution.stdout), "stderr": stream_evidence(execution.stderr),
                    "failures": failures,
                }
                result["failures"].extend(name + ": " + failure for failure in failures)
        for name, expected in inventory.items():
            path = public / name
            if not path.is_file() or sha(path.read_bytes()) != expected:
                result["failures"].append("protected fixture changed: " + name)
        for path, expected in ((key, key_hash), (receipts / "receipt", receipt_hash)):
            if not path.is_file() or sha(path.read_bytes()) != expected:
                result["failures"].append("root-held inert fixture changed: " + path.name)
        if len({entry["configured_uid"] for entry in result["roles"].values()}) != 4:
            result["failures"].append("roles do not have four distinct UIDs")
    finally:
        if previous is None:
            os.environ.pop("ROLE_PROBE_PARENT_SECRET", None)
        else:
            os.environ["ROLE_PROBE_PARENT_SECRET"] = previous
    return result


def source_provenance():
    """Hash the imported package, even when the wheel stores this script in share/."""
    from control_plane import execution_profile, isolated_runner, sealed_protocol
    sources = {
        "scripts/verify-role-isolation.py": Path(__file__).resolve(strict=True),
        "control_plane/isolated_runner.py": Path(isolated_runner.__file__).resolve(strict=True),
        "control_plane/execution_profile.py": Path(execution_profile.__file__).resolve(strict=True),
        "control_plane/sealed_protocol.py": Path(sealed_protocol.__file__).resolve(strict=True),
    }
    evidence = {"source_sha256": {label: sha(path.read_bytes()) for label, path in sources.items()},
                "source_paths": {label: str(path) for label, path in sources.items()}, "git_sha": None}
    # A nearby/unrelated repository says nothing about an installed wheel. Only
    # report Git identity when every actual source is in this exact checkout.
    if all(path == ROOT / label for label, path in sources.items()):
        try:
            lines = subprocess.check_output(
                ["git", "-C", str(ROOT), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                 "rev-parse", "--show-toplevel", "HEAD"], timeout=5,
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
                     "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"},
                stderr=subprocess.DEVNULL).decode().splitlines()
            if (len(lines) == 2 and Path(lines[0]).resolve(strict=True) == ROOT
                    and len(lines[1]) in {40, 64} and all(character in "0123456789abcdef" for character in lines[1])):
                evidence["git_sha"] = lines[1]
        except (OSError, subprocess.SubprocessError, UnicodeError):
            pass
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    evidence = {"schema_version": 1, "result": "UNPROVEN", "argv": sys.argv,
                "cwd": str(Path.cwd()), "claim_scope": "four real Linux roles using inert local fixtures",
                "remaining_unproven": ["HG07 end-to-end provider, required tests and independent signing acceptance",
                                       "actual operator key isolation and provider authentication store boundary",
                                       "guest recovery and release gates"],
                "git_sha": None}
    try:
        evidence.update(source_provenance())
        if os.geteuid() != 0:
            raise PermissionError("root is required; no role-isolation evidence was collected")
        profile = load_execution_profile(args.profile)
        evidence["profile_sha256"] = profile.sha256
        evidence["tools"] = {name: {"path": tool.path, "sha256": tool.sha256, "version": tool.version}
                             for name, tool in profile.tools.items() if tool is not None}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".role-isolation-", dir=args.output.parent.resolve()) as temporary:
            evidence.update(verify(profile, Path(temporary)))
        evidence["result"] = "OBSERVED_FIXTURE_ISOLATION" if not evidence["failures"] else "NOT_PASS"
    except Exception as error:
        evidence["error"] = type(error).__name__ + ": " + str(error)
    evidence["elapsed_seconds"] = round(time.monotonic() - started, 6)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(evidence, output, indent=2, sort_keys=True, allow_nan=False)
        output.write("\n")
    print(json.dumps({"result": evidence["result"], "evidence": str(args.output),
                      "sha256": sha(args.output.read_bytes())}, sort_keys=True))
    return 0 if evidence["result"] == "OBSERVED_FIXTURE_ISOLATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
