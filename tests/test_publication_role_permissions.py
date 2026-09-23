"""Exercise publication group inheritance with real capability-free role UIDs."""

import ctypes
import json
import os
import select
import signal
import stat
import unittest
from unittest import mock

from control_plane.project_integrator import ProjectIntegrator
from control_plane.publication_store import PublicationStore
from tests import test_publication_store as fixtures


@unittest.skipUnless(os.geteuid() == 0 and hasattr(os, "fork"), "requires root to drop test identities")
class PublicationRolePermissionsTests(unittest.TestCase):
    graph_uid = 61112
    graph_gid = 61112
    worker_uid = 61109
    worker_gid = 1000

    def setUp(self):
        self.fixture = fixtures.PublicationStoreTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        fixture = self.fixture
        fixture.root.chmod(0o755)
        for path in (fixture.repo, *fixture.repo.rglob("*")):
            os.chown(path, self.graph_uid, self.graph_gid)
        self.state = fixture.root / "state"
        self.state.mkdir()
        os.chown(self.state, self.graph_uid, self.worker_gid)
        self.state.chmod(0o2700)
        self.binding = self.state / "binding.json"
        fixture.binding.rename(self.binding)
        os.chown(self.binding, self.graph_uid, self.worker_gid)
        self.publications = fixture.store.root
        self.publications.mkdir()
        os.chown(self.publications, self.graph_uid, self.worker_gid)
        self.publications.chmod(0o2750)
        self.key = fixture.root / "public.pem"
        self.key.write_text("fixture public verification input\n")
        self.key.chmod(0o444)
        self.rubric = fixture.root / "rubric.md"
        self.rubric.write_text("fixture frozen rubric\n")
        self.rubric.chmod(0o444)

    def as_role(self, uid, gid, operation):
        reader, writer = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(reader)
            try:
                libc = ctypes.CDLL(None, use_errno=True)
                os.setgroups([])
                os.setresgid(gid, gid, gid)
                with open("/proc/sys/kernel/cap_last_cap") as stream:
                    last_capability = int(stream.read())
                for capability in range(last_capability + 1):
                    if libc.prctl(24, capability, 0, 0, 0):  # PR_CAPBSET_DROP
                        raise OSError(ctypes.get_errno(), "cannot drop bounding capability")
                os.setresuid(uid, uid, uid)
                if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
                    raise OSError(ctypes.get_errno(), "cannot set no_new_privs")
                with open("/proc/self/status") as stream:
                    observed = dict(line.split(":", 1) for line in stream if ":" in line)
                assert os.getresuid() == (uid,) * 3
                assert os.getresgid() == (gid,) * 3
                assert os.getgroups() == []
                for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    assert int(observed[name], 16) == 0, (name, observed[name])
                assert int(observed["NoNewPrivs"]) == 1
                result = {"ok": True, "uid": uid, "gid": gid, "groups": [],
                          "capabilities": "all_zero", "result": operation()}
            except BaseException as error:
                result = {"ok": False, "error_type": type(error).__name__, "error": str(error)}
            os.write(writer, json.dumps(result).encode())
            os.close(writer)
            os._exit(0)
        os.close(writer)
        try:
            ready, _, _ = select.select([reader], [], [], 30)
            if not ready:
                os.kill(child, signal.SIGKILL)
                self.fail("dropped role did not finish within 30 seconds")
            result = json.loads(os.read(reader, 65536))
        finally:
            os.close(reader)
            os.waitpid(child, 0)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["capabilities"], "all_zero")
        return result["result"]

    @staticmethod
    def ownership(path):
        metadata = path.stat()
        return metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)

    def test_dropped_graph_publishes_twice_and_replaces_binding_without_group_privilege(self):
        fixture = self.fixture

        def publish():
            original_chmod = os.chmod

            def keep_root_sgid(path, mode, *args, **kwargs):
                if os.fspath(path) == str(self.publications):
                    raise AssertionError("unnecessary root chmod can clear inherited group authority")
                return original_chmod(path, mode, *args, **kwargs)

            integrator = ProjectIntegrator(
                fixture.repo, self.binding, self.key, self.rubric,
                "refs/ai-ops/accepted/opensource", publication_root=self.publications,
            )
            with mock.patch("control_plane.publication_store.os.chmod", side_effect=keep_root_sgid):
                first = integrator.ensure_bound_publication()
                metadata = self.binding.stat()
                second = integrator.publications.ensure(fixture.repo, "test", fixture.new, metadata)
                self.assertEqual(integrator.publications.ensure(
                    fixture.repo, "test", fixture.old, metadata,
                ), first)
                integrator._atomic_write({"repo": "test", "base_sha": second.base_sha}, metadata)
            self.assertEqual(self.ownership(self.publications),
                             (self.graph_uid, self.worker_gid, 0o2750))
            self.assertEqual(self.ownership(self.state),
                             (self.graph_uid, self.worker_gid, 0o2700))
            self.assertEqual(self.ownership(self.binding),
                             (self.graph_uid, self.worker_gid, 0o440))
            for path in self.publications.rglob("*"):
                metadata = path.stat()
                self.assertEqual((metadata.st_uid, metadata.st_gid),
                                 (self.graph_uid, self.worker_gid))
                self.assertFalse(metadata.st_mode & 0o7022)
            return [first.base_sha, second.base_sha]

        self.assertEqual(self.as_role(self.graph_uid, self.graph_gid, publish),
                         [fixture.old, fixture.new])

        def read_as_worker():
            values = []
            for sha in (fixture.old, fixture.new):
                path = self.publications / sha / "value.txt"
                values.append(path.read_text())
                with self.assertRaises(PermissionError):
                    path.write_text("reader must not modify accepted bytes")
            return values

        self.assertEqual(self.as_role(self.worker_uid, self.worker_gid, read_as_worker),
                         ["old\n", "new\n"])

    def test_dropped_graph_rejects_unsafe_modes_and_foreign_owner_or_group(self):
        cases = (
            (self.graph_uid, self.worker_gid, 0o2770),
            (self.graph_uid, self.worker_gid, 0o2752),
            (self.graph_uid, self.worker_gid, 0o2740),
            (self.graph_uid, self.worker_gid, 0o3750),
            (self.graph_uid + 1, self.worker_gid, 0o2750),
            (self.graph_uid, self.worker_gid + 1, 0o2750),
        )
        for uid, gid, mode in cases:
            with self.subTest(uid=uid, gid=gid, mode=oct(mode)):
                os.chown(self.publications, uid, gid)
                self.publications.chmod(mode)
                before = self.ownership(self.publications)

                def reject():
                    with self.assertRaises(PermissionError):
                        PublicationStore(self.publications)._ensure_root(self.binding.stat())
                    return True

                self.assertTrue(self.as_role(self.graph_uid, self.graph_gid, reject))
                self.assertEqual(self.ownership(self.publications), before)
                self.assertEqual(list(self.publications.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
