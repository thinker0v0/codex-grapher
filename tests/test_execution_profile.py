"""Real inert role execution and adverse launcher admission; no provider use."""
from __future__ import annotations

import importlib.util
import contextlib
import json
import errno
import os
from pathlib import Path
import pwd
import select
import signal
import stat
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from control_plane.execution_profile import (
    executable_digest, load_execution_profile, trusted_code_digest,
)
from control_plane import isolated_runner as runner
from control_plane.sealed_protocol import (
    MAX_WIRE_BYTES, ProtocolError, canonical, digest, validate_launcher_request,
)


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("role_isolation_probe", ROOT / "scripts/verify-role-isolation.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def fixture_profile(root):
    """Validate actual local account metadata; never create a host account."""
    accounts = [entry for entry in pwd.getpwall() if entry.pw_uid > 0 and entry.pw_gid > 0
                and Path(entry.pw_dir).is_dir() and Path(entry.pw_dir).stat().st_uid == entry.pw_uid]
    if not accounts:
        raise RuntimeError("root isolation tests need an existing non-root account with an owned home")
    account = sorted(accounts, key=lambda entry: entry.pw_uid)[0]
    root.chmod(0o755)
    code = root / "installed"
    code.mkdir(mode=0o755)
    (code / "trusted.txt").write_text("inert trusted fixture; never imported\n")
    public = root / "public.pem"
    public.write_text("inert public fixture, not a cryptographic key\n")
    python = str(Path(sys.executable).resolve())
    # All tools are pinned, but only Python runs. The provider entry deliberately
    # points to inert Python: no vendor login, model or help command is invoked.
    tool_paths = {"python": python, "provider": python, "git": "/usr/bin/git",
                  "openssl": "/usr/bin/openssl", "bwrap": "/usr/bin/bwrap", "setpriv": "/usr/bin/setpriv"}
    unused = [uid for uid in range(61100, 61110) if uid != account.pw_uid]
    roles = {"worker": {"uid": account.pw_uid, "gid": account.pw_gid}}
    roles.update({name: {"uid": uid, "gid": uid} for name, uid in
                  zip(("test_runner", "signer", "graph"), unused)})
    value = {"schema_version": 1, "mode": "isolated-linux",
             "tools": {name: {"path": str(Path(path).resolve()),
                               "sha256": executable_digest(Path(path).resolve()),
                               "version": "inert role test; provider not invoked"}
                       for name, path in tool_paths.items()},
             "provider": {"backend": "codex", "model": "gpt-5.6-sol",
                          "reasoning_effort": "medium", "service_tier": "default"},
             "roles": roles, "auth": {"kind": "existing-cli-login", "account": account.pw_name},
             "paths": {"trusted_code_root": str(code), "trusted_code_sha256": trusted_code_digest(code),
                       "signer_private_key": str(root / "absent-private.pem"), "signer_public_key": str(public)},
             "sqlite": {"profile": "delete-extra", "attestation": None}}
    path = root / "profile.json"
    path.write_bytes(canonical(value))
    return load_execution_profile(path), path


class LauncherProtocolTests(unittest.TestCase):
    def request(self, **changes):
        value = {"schema_version": 1, "action": "candidate-tests", "workspace_id": "a" * 64,
                 "request_id": "request-1", "payload": {"registered_request_id": "required-1"}}
        value.update(changes)
        value["request_sha256"] = digest(value)
        return value

    def test_workspace_socket_paths_count_encoded_bytes_and_preserve_boundary(self):
        launcher, control = runner.workspace_socket_paths(Path("/" + "w" * 79))
        self.assertEqual(len(os.fsencode(control)), 107)
        self.assertEqual(control.name, ".worker-control.sock")
        self.assertEqual(launcher.name, ".launcher.sock")
        for root in (Path("/" + "w" * 80), Path("/" + "é" * 40)):
            with self.subTest(root=str(root)), self.assertRaisesRegex(runner.IsolationError, "80 encoded-byte"):
                runner.workspace_socket_paths(root)
        for root in (Path("relative"), Path("/tmp/../bad")):
            with self.subTest(root=str(root)), self.assertRaises(runner.IsolationError):
                runner.workspace_socket_paths(root)

    def test_scoped_control_refuses_existing_socket_and_symlink_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="cg-control-") as directory:
            path = Path(directory) / "control.sock"
            arguments = {"worker_uid": os.getuid(), "project_id": "project", "task_id": "task",
                         "attempt_id": "attempt", "status": lambda: {}, "heartbeat": lambda: {}}
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as existing:
                existing.bind(str(path))
            identity = path.lstat()
            with patch.object(runner.socket, "socket", side_effect=AssertionError("must reject before socket creation")), \
                    self.assertRaisesRegex(runner.IsolationError, "already exists"):
                runner.ScopedWorkerControlServer(path, **arguments)
            self.assertEqual((path.lstat().st_dev, path.lstat().st_ino), (identity.st_dev, identity.st_ino))
            path.unlink()
            path.symlink_to(Path(directory) / "absent")
            with patch.object(runner.socket, "socket", side_effect=AssertionError("must reject before socket creation")), \
                    self.assertRaisesRegex(runner.IsolationError, "already exists"):
                runner.ScopedWorkerControlServer(path, **arguments)
            self.assertTrue(path.is_symlink())

    def test_exact_registered_request_round_trips(self):
        value = self.request()
        self.assertEqual(validate_launcher_request(canonical(value)), value)

    def test_untrusted_launch_authority_and_schema_fail_closed(self):
        cases = [self.request(schema_version=True), self.request(action="integrate"),
                 self.request(action=[]), self.request(workspace_id="A" * 64),
                 self.request(payload={"registered_request_id": "../escape"}),
                 self.request(payload={"registered_request_id": "run", "uid": 0}),
                 self.request(payload={"registered_request_id": "run", "argv": ["/bin/sh"]}),
                 self.request(payload={"registered_request_id": "run", "env": {}}),
                 self.request(payload={"registered_request_id": "run", "path": "/tmp/result"}),
                 self.request(role="signer")]
        changed = self.request()
        changed["payload"]["registered_request_id"] = "changed"
        cases.append(changed)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                validate_launcher_request(value)

    def test_duplicate_noncanonical_and_nonfinite_wire_reject(self):
        value = canonical(self.request())
        for data in (value.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1'),
                     value.replace(b'"schema_version":1', b'"schema_version":NaN'), value + b"\n",
                     value.replace(b'"registered_request_id":"required-1"',
                                   b'"registered_request_id":"required-1","registered_request_id":"other"')):
            with self.subTest(data=data), self.assertRaises(ProtocolError):
                validate_launcher_request(data)

    def test_frame_length_rejects_before_reading_body(self):
        class HeaderOnly:
            def __init__(self, length):
                self.header = struct.pack("!I", length)
                self.calls = 0

            def recv(self, count):
                self.calls += 1
                if self.calls != 1 or count != 4:
                    raise AssertionError("oversized frame body was requested")
                return self.header

        for size in (0, MAX_WIRE_BYTES + 1, 0xFFFFFFFF):
            with self.subTest(size=size), self.assertRaises((runner.IsolationError, ProtocolError)):
                runner._recv_frame(HeaderOnly(size))

    def test_truncated_frame_and_duplicate_fields_reject(self):
        for data in (b"\0\0", struct.pack("!I", 3) + b"{", struct.pack("!I", 13) + b'{"a":1,"a":2}'):
            with self.subTest(data=data):
                left, right = socket.socketpair()
                with left, right:
                    left.sendall(data); left.shutdown(socket.SHUT_WR)
                    with self.assertRaises((EOFError, ProtocolError)):
                        runner._recv_frame(right)


class CandidateCopyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="grapher-copy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_copy_preserves_regular_bytes_and_executable_modes(self):
        source = self.root / "source"
        (source / ".git" / "objects").mkdir(parents=True)
        contents = {"plain.txt": (b"plain\x00data\xff", 0o644),
                    "run.sh": (b"#!/bin/sh\nexit 0\n", 0o755),
                    ".git/HEAD": (b"ref: refs/heads/main\n", 0o644),
                    ".git/objects/inert": (b"inert metadata fixture", 0o644)}
        for name, (data, mode) in contents.items():
            (source / name).write_bytes(data); (source / name).chmod(mode)
        destination = self.root / "copied"
        runner._copy_candidate_nofollow(source, destination)
        self.assertEqual({p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()}, set(contents))
        for name, (data, mode) in contents.items():
            with self.subTest(name=name):
                self.assertEqual((destination / name).read_bytes(), data)
                self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), mode)
                self.assertNotEqual((destination / name).stat().st_ino, (source / name).stat().st_ino)
                self.assertEqual((source / name).read_bytes(), data)
                self.assertEqual(stat.S_IMODE((source / name).stat().st_mode), mode)

    def test_copy_rejects_file_directory_git_and_hardlinks_without_outside_reads(self):
        outside = self.root / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker_bytes = b"outside marker must never enter a candidate copy"
        marker.write_bytes(marker_bytes)
        original_read = os.read
        identity = (marker.stat().st_dev, marker.stat().st_ino)
        def guarded_read(fd, count):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == identity:
                self.fail("candidate copy attempted to read the outside marker")
            return original_read(fd, count)
        for index, kind in enumerate(("file", "directory", "git-directory", "git-file", "hardlink", "git-hardlink")):
            with self.subTest(kind=kind):
                source = self.root / f"source-{index}"
                source.mkdir()
                name = ".git" if kind.startswith("git-") else "escape"
                entry = source / name
                if "hardlink" in kind:
                    os.link(marker, entry)
                else:
                    target = outside if kind in {"directory", "git-directory"} else marker
                    entry.symlink_to(target, target_is_directory=target.is_dir())
                destination = self.root / f"copy-{index}"
                with patch.object(runner.os, "read", side_effect=guarded_read), self.assertRaises(runner.IsolationError):
                    runner._copy_candidate_nofollow(source, destination)
                self.assertFalse((destination / name).exists())
                self.assertFalse((destination / name).is_symlink())
                for copied in destination.rglob("*"):
                    if copied.is_file():
                        self.assertNotIn(marker_bytes, copied.read_bytes())
                self.assertEqual(marker.read_bytes(), marker_bytes)

    def test_copy_relative_source_rejects_before_filesystem_traversal(self):
        with patch.object(runner.os, "open", side_effect=AssertionError("relative source reached filesystem traversal")):
            for source in (".", "relative", "relative/child"):
                with self.subTest(source=source), self.assertRaises(runner.IsolationError):
                    runner._copy_candidate_nofollow(source, self.root / "never-created")

    def test_copy_rechecks_hardlink_count_on_opened_file(self):
        source = self.root / "source"
        source.mkdir()
        marker = source / "marker"
        marker.write_bytes(b"raced hardlink marker")
        original_open, original_read = os.open, os.read
        raced = False
        marker_identity = (marker.stat().st_dev, marker.stat().st_ino)
        def racing_open(path, flags, *args, **kwargs):
            nonlocal raced
            if path == "marker" and kwargs.get("dir_fd") is not None and not raced:
                os.link(marker, self.root / "outside-hardlink")
                raced = True
            return original_open(path, flags, *args, **kwargs)
        def guarded_read(fd, count):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == marker_identity:
                self.fail("copy read a file after its hardlink count changed")
            return original_read(fd, count)
        with patch.object(runner.os, "open", side_effect=racing_open), patch.object(runner.os, "read", side_effect=guarded_read):
            with self.assertRaises(runner.IsolationError):
                runner._copy_candidate_nofollow(source, self.root / "copy")
        self.assertTrue(raced)
        self.assertFalse((self.root / "copy/marker").exists())


@unittest.skipUnless(os.geteuid() == 0, "UNPROVEN: actual isolation requires explicit root bootstrap")
class ActualExecutionRoleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="grapher-role-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile, self.profile_path = fixture_profile(self.root)

    def run_python(self, code, **kwargs):
        return runner.run_role_process(self.profile, "test_runner",
            [self.profile.tools["python"].path, "-I", "-B", "-c", code], **kwargs)

    def test_four_actual_roles_scoped_success_and_authority_denials(self):
        fixture = self.root / "task"
        fixture.mkdir()
        evidence = probe.verify(self.profile, fixture)
        diagnostics = {name: {key: role[key] for key in ("returncode", "failures", "stderr")}
                       for name, role in evidence["roles"].items()}
        self.assertEqual(evidence["failures"], [], json.dumps(diagnostics, indent=2))
        self.assertEqual(set(evidence["roles"]), set(probe.ROLES))
        for name, role in evidence["roles"].items():
            self.assertEqual(role["supervisor_observation"]["actual_uid"], self.profile.roles[name].uid)

    def test_private_caller_umask_keeps_role_devices_usable_and_output_private(self):
        devices = {name: os.stat(name) for name in ("/dev/null", "/dev/urandom")}
        previous = os.umask(0o077)
        try:
            code = """
import json,os,pathlib,stat
mask=os.umask(0o077);os.umask(mask)
with open('/dev/null','r+b',buffering=0) as stream:
    assert stream.write(b'inert probe') == 11
    assert stream.read(1) == b''
with open('/dev/urandom','rb',buffering=0) as stream:
    assert len(stream.read(8)) == 8
output=pathlib.Path('/tmp/private-output');output.write_text('inert')
try:
    pathlib.Path('/dev/forbidden-role-file').write_text('must not write')
except PermissionError:
    denied=True
else:
    denied=False
null=os.stat('/dev/null')
print(json.dumps({'mask':mask,'output_mode':stat.S_IMODE(output.stat().st_mode),
                  'dev_mode':stat.S_IMODE(os.stat('/dev').st_mode),'dev_write_denied':denied,
                  'null_identity':[null.st_dev,null.st_ino,null.st_mode]}))
"""
            for name in self.profile.roles:
                with self.subTest(role=name):
                    result = runner.run_role_process(self.profile, name,
                        [self.profile.tools["python"].path, "-I", "-B", "-c", code])
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertTrue(result.descendants_reaped)
                    self.assertEqual(json.loads(result.stdout), {
                        "mask": 0o077, "output_mode": 0o600,
                        "dev_mode": 0o755, "dev_write_denied": True,
                        "null_identity": [devices["/dev/null"].st_dev, devices["/dev/null"].st_ino, devices["/dev/null"].st_mode]})
                    self.assertEqual(result.observation["actual_uid"], self.profile.roles[name].uid)
                    self.assertEqual(os.umask(0o077), 0o077, "launcher changed parent umask")
            for name, before in devices.items():
                after = os.stat(name)
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode),
                                 (before.st_dev, before.st_ino, before.st_mode))
        finally:
            os.umask(previous)

    def test_timeout_kills_actual_namespace_and_reports_cleanup(self):
        result = self.run_python("import time;time.sleep(60)", timeout_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.descendants_reaped)
        self.assertLess(result.elapsed_seconds, 7)

    def test_output_bound_is_combined_across_both_streams(self):
        result = self.run_python("import os,time;os.write(1,b'a'*80);os.write(2,b'b'*80);time.sleep(60)",
                                 timeout_seconds=3, max_output_bytes=100)
        self.assertTrue(result.output_overflow)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 100)
        self.assertTrue(result.descendants_reaped)

    def test_exact_output_bound_succeeds_and_signal_is_not_exit_code(self):
        result = self.run_python("import os;os.write(1,b'a'*60);os.write(2,b'b'*40)",
                                 timeout_seconds=3, max_output_bytes=100)
        self.assertEqual((result.returncode, result.output_overflow, len(result.stdout) + len(result.stderr)), (0, False, 100))
        for sig in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=sig):
                result = self.run_python(f"import os,signal;os.kill(os.getpid(),{int(sig)})", timeout_seconds=3)
                self.assertEqual(result.returncode, -int(sig))
                self.assertEqual(result.signal, int(sig))
                self.assertTrue(result.descendants_reaped)

    def test_success_and_timeout_reap_double_fork_setsid_descendants(self):
        owned = self.root / "owned"
        owned.mkdir(mode=0o700)
        role = self.profile.roles["test_runner"]
        os.chown(owned, role.uid, role.gid)
        code = '''
import os,pathlib,signal,time
ready_r,ready_w=os.pipe()
if os.fork() == 0:
    os.close(ready_r);os.setsid()
    if os.fork() != 0: os._exit(0)
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    os.write(ready_w,b'R');os.close(ready_w)
    time.sleep(2)
    pathlib.Path('/probe-owned/late').write_text('survived')
    time.sleep(60)
os.close(ready_w)
assert os.read(ready_r,1)==b'R'
os.close(ready_r)
TIMEOUT
'''
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                result = self.run_python(code.replace("TIMEOUT", "time.sleep(60)" if timeout else ""),
                    mounts=[(owned, "/probe-owned", True)], timeout_seconds=1 if timeout else 4)
                self.assertEqual(result.timed_out, timeout)
                self.assertTrue(result.descendants_reaped)
                if not timeout:
                    self.assertEqual(result.returncode, 0)
                time.sleep(2.1)
                self.assertFalse((owned / "late").exists(), "setsid descendant survived namespace cleanup")

    def test_invalid_bounds_and_environment_reject_before_fork(self):
        cases = [{"timeout_seconds": True}, {"timeout_seconds": 0}, {"timeout_seconds": 1.5},
                 {"max_output_bytes": True}, {"max_output_bytes": 0},
                 {"max_output_bytes": runner.MAX_FRAME + 1}, {"environment": {"LD_PRELOAD": "/bad"}}]
        with patch.object(runner.os, "fork", side_effect=AssertionError("fork before admission")):
            for options in cases:
                with self.subTest(options=options), self.assertRaises(runner.IsolationError):
                    self.run_python("pass", **options)

    def test_prepare_inherits_reader_group_without_extra_graph_privilege(self):
        workspace = self.root / "ownership-workspace"
        workspace.mkdir()
        for name in ("state", "publications"):
            (workspace / name).mkdir(mode=0o700)
        runner.prepare_workspace_ownership(self.profile, workspace)
        graph, worker = self.profile.roles["graph"], self.profile.roles["worker"]
        for name, mode in (("state", 0o2700), ("publications", 0o2750)):
            info = (workspace / name).stat()
            self.assertEqual((info.st_uid, info.st_gid, info.st_mode & 0o7777), (graph.uid, worker.gid, mode))
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                runner._drop_role(graph.uid, graph.gid)
                for name in ("state", "publications"):
                    path = workspace / name / "inherited"
                    path.write_text("owned by graph, worker group inherited")
                    self.assertEqual((path.stat().st_uid, path.stat().st_gid), (graph.uid, worker.gid))
                os.write(write_fd, b"OK"); os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write_fd)
        try:
            self.assertTrue(select.select([read_fd], [], [], 3)[0])
            self.assertEqual(os.read(read_fd, 16), b"OK")
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
        finally:
            os.close(read_fd)

    def test_socket_limit_rejects_bootstrap_before_broker_or_lock_effects(self):
        root = self.root / ("w" * (81 - len(os.fsencode(self.root)) - 1))
        root.mkdir()
        with patch("control_plane.evaluation_broker.EvaluationBroker", side_effect=AssertionError("broker before validation")), \
                patch.object(runner.os, "fork", side_effect=AssertionError("fork before validation")), \
                self.assertRaisesRegex(runner.IsolationError, "80 encoded-byte"):
            runner.bootstrap_operation(self.profile, root, "status")
        self.assertEqual(list(root.iterdir()), [])

    def test_fixed_control_socket_at_limit_binds_200_character_protocol_identity(self):
        # This proves socket/protocol binding, not end-to-end workflow ID limits.
        root = self.root / ("w" * (80 - len(os.fsencode(self.root)) - 1))
        root.mkdir(); root.chmod(0o755)
        state = root / "state"
        state.mkdir(mode=0o700)
        graph, worker = self.profile.roles["graph"], self.profile.roles["worker"]
        os.chown(state, graph.uid, graph.gid)
        state.chmod(0o700)
        _launcher, control = runner.workspace_socket_paths(root)
        self.assertEqual(len(os.fsencode(control)), 107)
        binding = {"project_id": "project", "task_id": "t" * 200, "attempt_id": "a" * 200}
        ready_r, ready_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(ready_r); signal.alarm(10)
                runner._drop_role(graph.uid, graph.gid)
                server = runner.ScopedWorkerControlServer(control, worker_uid=worker.uid, **binding,
                    status=lambda: {"state": "RUNNING"}, heartbeat=lambda: {"lease": "LIVE"})
                os.write(ready_w, b"READY"); os.close(ready_w)
                count = 0
                while count < 5:
                    count += int(server.serve_once())
                server.close(); os._exit(0)
            except BaseException as exc:
                with contextlib.suppress(OSError): os.write(ready_w, repr(exc).encode()[:1024])
                os._exit(1)
        os.close(ready_w)
        try:
            self.assertTrue(select.select([ready_r], [], [], 3)[0])
            self.assertEqual(os.read(ready_r, 1024), b"READY")
            self.assertEqual(control.stat().st_uid, graph.uid)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3); connection.connect(str(control))
                runner._send_frame(connection, {"schema_version": 1, "action": "status", **binding})
                denied = runner._recv_frame(connection)
            self.assertIn("actual worker UID", denied["error"])
            requests = [{"schema_version": 1, "action": action, **binding} for action in
                        ("status", "status", "heartbeat", "heartbeat")]
            requests[1]["task_id"] = "x" * 200
            requests[2]["attempt_id"] = "b" * 200
            code = """
import json,socket,struct,sys
value=json.load(sys.stdin); responses=[]
def read_exact(connection,count):
    data=b''
    while len(data)<count:
        chunk=connection.recv(count-len(data))
        if not chunk: raise EOFError('server closed')
        data+=chunk
    return data
for request in value['requests']:
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(3);connection.connect(value['path'])
        body=json.dumps(request,sort_keys=True,separators=(',',':')).encode()
        connection.sendall(struct.pack('!I',len(body))+body)
        size=struct.unpack('!I',read_exact(connection,4))[0]
        responses.append(json.loads(read_exact(connection,size)))
print(json.dumps(responses))
"""
            result = runner.run_role_process(self.profile, "worker",
                [self.profile.tools["python"].path, "-I", "-B", "-c", code],
                stdin=canonical({"path": str(control), "requests": requests}),
                mounts=[(control, control, True)], timeout_seconds=5)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertTrue(result.descendants_reaped)
            responses = json.loads(result.stdout)
            self.assertEqual(responses[0], {"result": {"state": "RUNNING"}})
            self.assertIn("cross-task", responses[1]["error"])
            self.assertIn("cross-task", responses[2]["error"])
            self.assertEqual(responses[3], {"result": {"lease": "LIVE"}})
            self.assertEqual(os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1]), 0)
            pid = None
            self.assertFalse(control.exists())
        finally:
            os.close(ready_r)
            if pid is not None:
                with contextlib.suppress(ProcessLookupError): os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)

    def test_nonroot_bootstrap_denies_before_workspace_effects(self):
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                role = self.profile.roles["worker"]
                os.setgroups([]); os.setgid(role.gid); os.setuid(role.uid)
                runner.bootstrap_operation(self.profile, self.root / "must-not-exist", "status")
            except runner.IsolationError:
                os.write(write_fd, b"DENIED"); os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(3)
        os.close(write_fd)
        try:
            self.assertTrue(select.select([read_fd], [], [], 3)[0], "root admission test hung")
            self.assertEqual(os.read(read_fd, 32), b"DENIED")
        finally:
            os.close(read_fd)
            waited, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertFalse((self.root / "must-not-exist").exists())

    def test_inherited_root_socketpair_does_not_become_graph_identity(self):
        left, right = socket.socketpair()
        pid = os.fork()
        if pid == 0:
            try:
                left.close()
                role = self.profile.roles["graph"]
                runner._drop_role(role.uid, role.gid)
                peer = struct.unpack("3i", right.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                right.sendall(canonical({"actual_uid": os.getuid(), "peer_uid": peer[1]}))
                os._exit(0)
            except BaseException:
                os._exit(1)
        right.close()
        try:
            left.settimeout(3)
            value = json.loads(left.recv(1024))
            self.assertEqual(value["actual_uid"], self.profile.roles["graph"].uid)
            self.assertEqual(value["peer_uid"], 0)
            self.assertNotEqual(value["peer_uid"], self.profile.roles["graph"].uid)
        finally:
            left.close(); os.waitpid(pid, 0)

    def test_worker_handoff_transfers_quiescent_checkout_to_graph_preserving_bytes_modes(self):
        checkout = self.root / "checkout"
        (checkout / ".git" / "objects").mkdir(parents=True)
        (checkout / "src").mkdir()
        contents = {"src/plain": (b"worktree\x00bytes", 0o600),
                    "run": (b"executable fixture", 0o711),
                    ".git/HEAD": (b"ref: refs/heads/main\n", 0o600),
                    ".git/objects/inert": (b"not a real git object", 0o444)}
        for name, (data, mode) in contents.items():
            (checkout / name).write_bytes(data); (checkout / name).chmod(mode)
        checkout.chmod(0o750); (checkout / "src").chmod(0o700)
        worker = self.profile.roles["worker"]
        for path in (checkout, *checkout.rglob("*")):
            os.chown(path, worker.uid, worker.gid)
        inodes = {name: (checkout / name).stat().st_ino for name in contents}
        modes = {path.relative_to(checkout).as_posix(): stat.S_IMODE(path.stat().st_mode)
                 for path in (checkout, *checkout.rglob("*"))}
        role = self.profile.roles["graph"]
        for invocation in (1, 2):
            runner.finish_worker_checkout({"checkout": str(checkout)}, self.profile)
            for path in (checkout, *checkout.rglob("*")):
                name = path.relative_to(checkout).as_posix()
                with self.subTest(name=name, invocation=invocation):
                    info = path.stat()
                    self.assertEqual((info.st_uid, info.st_gid), (role.uid, role.gid))
                    self.assertEqual(stat.S_IMODE(info.st_mode), modes[name])
                    if path.is_file():
                        self.assertEqual(path.read_bytes(), contents[name][0])
                        self.assertEqual(info.st_ino, inodes[name])

    def test_worker_handoff_rejects_links_without_changing_outside_targets(self):
        outside = self.root / "outside-handoff"
        outside.mkdir(mode=0o711)
        marker = outside / "marker"
        marker.write_bytes(b"outside handoff marker"); marker.chmod(0o640)
        identities = {(p.stat().st_dev, p.stat().st_ino) for p in (outside, marker)}
        original_chown, original_chmod = os.fchown, os.fchmod
        def guarded(operation):
            def invoke(fd, *args):
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) in identities:
                    self.fail("handoff attempted to change outside ownership or mode")
                return operation(fd, *args)
            return invoke
        def snapshot(path):
            info = path.stat()
            return info.st_uid, info.st_gid, info.st_mode, info.st_size, info.st_ctime_ns
        for index, kind in enumerate(("file", "directory", "git-directory", "git-file", "hardlink", "git-hardlink")):
            with self.subTest(kind=kind):
                checkout = self.root / f"checkout-{index}"
                checkout.mkdir()
                entry = checkout / (".git" if kind.startswith("git-") else "escape")
                if "hardlink" in kind:
                    os.link(marker, entry)
                else:
                    target = outside if kind in {"directory", "git-directory"} else marker
                    entry.symlink_to(target, target_is_directory=target.is_dir())
                before = {path: snapshot(path) for path in (outside, marker)}
                with patch.object(runner.os, "fchown", side_effect=guarded(original_chown)), patch.object(runner.os, "fchmod", side_effect=guarded(original_chmod)):
                    with self.assertRaises(runner.IsolationError):
                        runner.finish_worker_checkout({"checkout": str(checkout)}, self.profile)
                self.assertEqual({path: snapshot(path) for path in (outside, marker)}, before)
                self.assertEqual(marker.read_bytes(), b"outside handoff marker")

    def test_worker_handoff_relative_checkout_rejects_before_traversal(self):
        with patch.object(runner.os, "open", side_effect=AssertionError("relative checkout reached filesystem traversal")):
            for checkout in (".", "relative", "relative/child"):
                with self.subTest(checkout=checkout), self.assertRaises(runner.IsolationError):
                    runner.finish_worker_checkout({"checkout": checkout}, self.profile)

    def test_worker_handoff_rechecks_hardlink_count_on_opened_file(self):
        checkout = self.root / "checkout-race"
        checkout.mkdir()
        marker = checkout / "marker"
        marker.write_bytes(b"handoff race marker"); marker.chmod(0o640)
        original_open, original_chown, original_chmod = os.open, os.fchown, os.fchmod
        identity = (marker.stat().st_dev, marker.stat().st_ino)
        raced = False
        def racing_open(path, flags, *args, **kwargs):
            nonlocal raced
            if path == "marker" and kwargs.get("dir_fd") is not None and not raced:
                os.link(marker, self.root / "outside-handoff-hardlink")
                raced = True
            return original_open(path, flags, *args, **kwargs)
        def guard(operation):
            def invoke(fd, *args):
                info = os.fstat(fd)
                if (info.st_dev, info.st_ino) == identity:
                    self.fail("handoff changed a file after its hardlink count changed")
                return operation(fd, *args)
            return invoke
        with patch.object(runner.os, "open", side_effect=racing_open), patch.object(runner.os, "fchown", side_effect=guard(original_chown)), patch.object(runner.os, "fchmod", side_effect=guard(original_chmod)):
            with self.assertRaises(runner.IsolationError):
                runner.finish_worker_checkout({"checkout": str(checkout)}, self.profile)
        self.assertTrue(raced)
        self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o640)
        self.assertEqual(marker.read_bytes(), b"handoff race marker")

    def test_pidfd_acquisition_failure_reaps_unadmitted_child_without_execution(self):
        owned = self.root / "pidfd-owned"
        owned.mkdir(mode=0o700)
        role = self.profile.roles["test_runner"]
        os.chown(owned, role.uid, role.gid)
        bootstrap_marker = self.root / "bootstrap-reached"
        def forbidden_sandbox(*args, **kwargs):
            bootstrap_marker.write_text("launch gate bypassed")
            raise AssertionError("sandbox executed before pidfd admission")
        def fail_pidfd(*args):
            time.sleep(0.05)  # Give the real child an opportunity to expose a missing gate.
            raise OSError(errno.EMFILE, "inert pidfd failure")
        sandboxes = []
        original_mkdtemp = tempfile.mkdtemp
        def tracked_sandbox(*args, **kwargs):
            directory = original_mkdtemp(*args, **kwargs)
            sandboxes.append(Path(directory))
            return directory
        before_fds = set(os.listdir("/proc/self/fd"))
        with patch.object(runner.os, "pidfd_open", side_effect=fail_pidfd) as acquire, patch.object(runner, "_sandbox", side_effect=forbidden_sandbox), patch.object(runner.tempfile, "mkdtemp", side_effect=tracked_sandbox):
            with self.assertRaisesRegex(runner.IsolationError, "pidfd acquisition failed"):
                self.run_python("from pathlib import Path;Path('/pidfd-owned/executed').write_text('bad')",
                    mounts=[(owned, "/pidfd-owned", True)], timeout_seconds=2)
        acquire.assert_called_once()
        child_pid = acquire.call_args.args[0]
        with self.assertRaises(ChildProcessError):
            os.waitpid(child_pid, os.WNOHANG)
        self.assertFalse(bootstrap_marker.exists())
        self.assertFalse((owned / "executed").exists())
        self.assertEqual(set(os.listdir("/proc/self/fd")), before_fds)
        self.assertEqual(len(sandboxes), 1)
        self.assertFalse(sandboxes[0].exists())

    def test_workspace_receipt_permissions_ignore_private_umask_and_allow_graph_read(self):
        from control_plane.evaluation_broker import BrokerStore
        workspace = self.root / "workspace"
        previous = os.umask(0o077)
        try:
            workspace.mkdir()
            runner.prepare_workspace_ownership(self.profile, workspace)
        finally:
            os.umask(previous)
        store_root = workspace / ".broker-receipts"
        expected = {workspace: 0o755, store_root: 0o755, store_root / "receipts": 0o755,
                    store_root / "rejections": 0o755, store_root / ".private": 0o700}
        for path, mode in expected.items():
            with self.subTest(path=path):
                info = path.stat()
                self.assertEqual(info.st_uid, 0)
                self.assertEqual(stat.S_IMODE(info.st_mode), mode)
        marker = store_root / "receipts" / "inert-public-marker"
        marker.write_bytes(b"public fixture bytes"); marker.chmod(0o444)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd); signal.alarm(5)
                role = self.profile.roles["graph"]
                runner._drop_role(role.uid, role.gid)
                store = BrokerStore(workspace, require_root=True, create=False)
                public_fd = store._dir("receipts")
                marker_fd = os.open("inert-public-marker", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=public_fd)
                data = os.read(marker_fd, 64)
                os.close(marker_fd); os.close(public_fd)
                private_denied = False
                try:
                    private_fd = store._dir(".private")
                except PermissionError:
                    private_denied = True
                else:
                    os.close(private_fd)
                store.close()
                os.write(write_fd, canonical({"uid": os.getuid(), "public_read": data == b"public fixture bytes",
                                              "private_denied": private_denied}))
                os._exit(0)
            except BaseException:
                os._exit(2)
        os.close(write_fd)
        try:
            self.assertTrue(select.select([read_fd], [], [], 3)[0], "graph store read timed out")
            value = json.loads(os.read(read_fd, 1024))
            self.assertEqual(value, {"uid": self.profile.roles["graph"].uid,
                                     "public_read": True, "private_denied": True})
        finally:
            os.close(read_fd)
            _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)


if __name__ == "__main__":
    unittest.main()
