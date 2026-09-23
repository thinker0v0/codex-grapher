"""Exercise trusted-local bounds and actual kernel descendant cleanup."""

import json
import os
from pathlib import Path
import signal
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from control_plane._trusted_local_runner import run_local_process
from control_plane.isolated_runner import IsolationError


class TrustedLocalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = SimpleNamespace(
            mode="trusted-local",
            roles={"test_runner": SimpleNamespace(uid=os.getuid(), gid=os.getgid())},
        )

    def run_python(self, code, **kwargs):
        return run_local_process(self.profile, "test_runner", [sys.executable, "-c", code],
                                 cwd=self.root, **kwargs)

    def test_streams_stdin_environment_and_observed_identity(self):
        code = ("import json,os,sys; data=sys.stdin.buffer.read(); "
                "print(json.dumps({'length':len(data),'secret':os.getenv('GRAPHER_TEST_SECRET'),"
                "'uid':os.getuid(),'gid':os.getgid(),'nnp':[x for x in open('/proc/self/status') if x.startswith('NoNewPrivs:')][0].strip()})); "
                "sys.stderr.write('separate stderr\\n')")
        with patch.dict(os.environ, {"GRAPHER_TEST_SECRET": "must-not-inherit"}):
            result = self.run_python(code, stdin=b"x" * 100000, timeout_seconds=5)
        output = json.loads(result.stdout)
        self.assertEqual(output["length"], 100000)
        self.assertIsNone(output["secret"])
        self.assertEqual(output["uid"], os.getuid())
        self.assertEqual(output["gid"], os.getgid())
        self.assertEqual(output["nnp"].split()[-1], "1")
        self.assertEqual(result.stderr, b"separate stderr\n")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.descendants_reaped)
        self.assertTrue(result.observation["no_new_privs"])
        self.assertEqual(result.observation["actual_uid"], os.getuid())
        self.assertEqual(set(result.observation["namespaces"]), {"user", "mount", "pid", "ipc", "net"})
        self.assertEqual(result.observation["namespaces"]["mount"], os.stat("/proc/self/ns/mnt").st_ino)

    def test_nonzero_and_signal_exits_are_not_success(self):
        result = self.run_python("raise SystemExit(17)")
        self.assertEqual(result.returncode, 17)
        self.assertTrue(result.descendants_reaped)
        result = self.run_python("import os,signal;os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(result.returncode, -signal.SIGTERM)
        self.assertEqual(result.signal, signal.SIGTERM)

    def test_inheritable_caller_file_descriptors_are_closed(self):
        path = self.root / "authority-file"
        path.write_text("local fixture")
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        os.set_inheritable(descriptor, True)
        code = ("import os; from pathlib import Path; targets=[]; "
                "\nfor f in Path('/proc/self/fd').iterdir():\n"
                " try: targets.append(os.readlink(f))\n"
                " except OSError: pass\n"
                "print('\\n'.join(targets))")
        result = self.run_python(code)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(str(path).encode(), result.stdout)

    def test_output_combines_both_streams_under_one_bound(self):
        code = "import os;os.write(1,b'x'*4096);os.write(2,b'y'*4096)"
        result = self.run_python(code, max_output_bytes=128, timeout_seconds=5)
        self.assertTrue(result.output_overflow)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 128)
        self.assertTrue(result.descendants_reaped)

    def test_timeout_cleans_setsid_and_double_fork_descendants(self):
        pidfile = self.root / "detached.pid"
        code = ("import os,time; from pathlib import Path; "
                "\npid=os.fork()\n"
                "if pid==0:\n"
                " os.setsid()\n"
                " if os.fork(): os._exit(0)\n"
                f" Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
                " time.sleep(60)\n"
                "else:\n"
                " os.waitpid(pid,0)\n"
                " time.sleep(60)\n")
        result = self.run_python(code, timeout_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.descendants_reaped)
        self.assertLess(result.elapsed_seconds, 7)
        descendant = int(pidfile.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(descendant, 0)

    def test_detached_child_after_successful_parent_prevents_success(self):
        pidfile = self.root / "detached.pid"
        code = ("import os,time; from pathlib import Path; "
                "\npid=os.fork()\n"
                "if pid==0:\n"
                " os.setsid()\n"
                " if os.fork(): os._exit(0)\n"
                f" Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
                " time.sleep(60)\n"
                "else:\n"
                " os.waitpid(pid,0)\n"
                f" while not Path({str(pidfile)!r}).exists(): time.sleep(0.005)\n")
        result = self.run_python(code, timeout_seconds=5)
        self.assertEqual(result.returncode, 125)
        self.assertTrue(result.descendants_reaped)
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_closed_output_does_not_hide_a_running_command(self):
        result = self.run_python("import os,time;os.close(1);os.close(2);time.sleep(60)", timeout_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.descendants_reaped)

    def test_mode_and_bounds_fail_before_launch(self):
        for changes in ({"timeout_seconds": True}, {"timeout_seconds": 0},
                        {"max_output_bytes": True}, {"max_output_bytes": 8388609},
                        {"environment": {"LD_PRELOAD": "/bad"}}, {"stdin": "text"}):
            with self.subTest(changes=changes), self.assertRaises(IsolationError):
                self.run_python("raise SystemExit(0)", **changes)
        self.profile.mode = "isolated-linux"
        with self.assertRaises(IsolationError):
            self.run_python("raise SystemExit(0)")

    def test_explicit_scoped_worker_control_environment_is_available(self):
        expected = str(self.root / "worker.control.sock")
        result = self.run_python(
            "import os;print(os.environ['GRAPHER_WORKER_CONTROL_SOCKET'])",
            environment={"GRAPHER_WORKER_CONTROL_SOCKET": expected},
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.decode().strip(), expected)

    def test_failed_pidfd_acquisition_never_launches_command(self):
        marker = self.root / "must-not-exist"
        with patch("control_plane._trusted_local_runner.os.pidfd_open", side_effect=OSError("unavailable")):
            with self.assertRaises(OSError):
                self.run_python(f"from pathlib import Path;Path({str(marker)!r}).touch()")
        self.assertFalse(marker.exists())

    @unittest.skipUnless(os.geteuid() == 0, "requires dropping the disposable subprocess identity")
    def test_root_runner_drops_to_the_explicit_local_role(self):
        self.root.chmod(0o755)
        self.profile.roles["test_runner"] = SimpleNamespace(uid=20001, gid=20002)
        result = self.run_python("import os;print(os.getuid(),os.getgid(),os.getgroups())")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"20001 20002 []\n")
        self.assertEqual(result.observation["actual_uid"], 20001)
        self.assertEqual(result.observation["actual_gid"], 20002)
        self.assertTrue(result.observation["no_new_privs"])


if __name__ == "__main__":
    unittest.main()
