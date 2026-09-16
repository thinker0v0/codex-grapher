import json
import os
import shlex
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

import jsonschema

from control_plane.artifact_builder import (
    RequiredTestOutputLimitExceeded,
    _parse_proc_stat,
    build,
    produce_required_test_results,
    sha256,
    validate_required_test_results,
)
from control_plane.project_integrator import ProjectIntegrator
from tests.evaluation_helpers import generate_keypair


class ArtifactBuilderTests(unittest.TestCase):
    @staticmethod
    def make_clean_repo(root: Path) -> tuple[Path, str]:
        repo = root / "workspace"
        repo.mkdir()
        subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", repo, "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", repo, "config", "user.name", "Required Test Fixture"],
            check=True,
        )
        (repo / "tracked.txt").write_text("candidate bytes\n")
        subprocess.run(["git", "-C", repo, "add", "."], check=True)
        subprocess.run(["git", "-C", repo, "commit", "-qm", "candidate"], check=True)
        candidate = subprocess.run(
            ["git", "-C", repo, "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        return repo, candidate

    def assert_process_gone(self, process_id: int) -> None:
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            stat_path = Path("/proc") / str(process_id) / "stat"
            try:
                state = _parse_proc_stat(stat_path.read_text())[1]
            except (FileNotFoundError, ValueError):
                return
            if state == "Z":
                return
            time.sleep(0.02)
        self.fail(f"required-test child process {process_id} remained active")

    def test_candidate_bundle_and_manifest_are_bound_and_verifiable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = root / "attempt"; repo.mkdir()
            subprocess.run(["git","-C",str(repo),"init","-q"],check=True)
            subprocess.run(["git","-C",str(repo),"config","user.email","test@example.invalid"],check=True)
            subprocess.run(["git","-C",str(repo),"config","user.name","Test"],check=True)
            (repo / "src").mkdir(); (repo / "src/base.txt").write_text("base\n")
            subprocess.run(["git","-C",str(repo),"add","."],check=True)
            subprocess.run(["git","-C",str(repo),"commit","-qm","base"],check=True)
            base = subprocess.run(["git","-C",str(repo),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
            (repo / "src/value.txt").write_text("value\n")
            contract = root / "contract.json"
            commands = [
                "python3 -c 'print(\"fixture-one\")'",
                "python3 -c 'print(\"fixture-two\")'",
            ]
            contract.write_text(json.dumps({"task_id":"task-1","project_id":"oss","base_sha":base,
                                "builder_identity":"hermes-oss","required_tests":commands}))
            path_check = root / "path-check.json"
            path_check.write_text('{"valid":true,"violations":[]}\n')
            result = build(repo, contract, path_check, root / "evidence", 1)
            manifest_path = Path(result["manifest_path"])
            manifest = json.loads(manifest_path.read_text())
            schema = json.loads(
                (Path(__file__).resolve().parents[1] / "schemas" / "artifact-manifest.schema.json").read_text()
            )
            jsonschema.Draft202012Validator(schema).validate(manifest)
            bundle_path = manifest_path.parent / manifest["bundle"]["path"]
            self.assertEqual(manifest["schema_version"], 4)
            self.assertEqual(manifest["attempt"], 1)
            self.assertEqual(
                manifest_path.relative_to(root / "evidence").as_posix(),
                "task-1/attempt-1/manifest.json",
            )
            self.assertFalse(Path(manifest["bundle"]["path"]).is_absolute())
            self.assertEqual(manifest["bundle"]["sha256"], sha256(bundle_path))
            self.assertEqual(manifest["bundle"]["byte_length"], bundle_path.stat().st_size)
            path_check_copy = manifest_path.parent / manifest["path_check"]["path"]
            self.assertEqual(manifest["path_check"]["sha256"], sha256(path_check_copy))
            self.assertEqual(
                manifest["path_check"]["byte_length"], path_check_copy.stat().st_size,
            )
            self.assertNotEqual(path_check.stat().st_ino, path_check_copy.stat().st_ino)
            self.assertEqual(path_check_copy.stat().st_nlink, 1)
            self.assertEqual([item["command"] for item in manifest["required_tests"]], commands)
            self.assertEqual([item["sequence"] for item in manifest["required_tests"]], [0, 1])
            self.assertTrue(all(type(item["exit_code"]) is int and item["exit_code"] == 0
                                for item in manifest["required_tests"]))
            self.assertTrue(all(item["candidate_sha"] == manifest["candidate_sha"]
                                for item in manifest["required_tests"]))
            validate_required_test_results(
                manifest["required_tests"], commands, manifest["candidate_sha"], manifest_path.parent,
            )
            self.assertEqual(manifest["base_sha"], base)
            self.assertNotEqual(manifest["candidate_sha"], base)
            self.assertEqual(
                subprocess.run(
                    ["git", "-C", str(repo), "rev-list", "--parents", "-n", "1",
                     manifest["candidate_sha"]],
                    check=True, capture_output=True, text=True,
                ).stdout.split(),
                [manifest["candidate_sha"], base],
            )
            subprocess.run(["git","-C",str(repo),"bundle","verify",bundle_path],check=True,capture_output=True)
            canonical = root / "canonical"; canonical.mkdir()
            subprocess.run(["git","-C",str(canonical),"init","-q"],check=True)
            subprocess.run(["git","-C",str(canonical),"fetch",str(repo),f"{base}:refs/heads/main"],check=True,capture_output=True)
            binding=root/"binding.json"; binding.write_text(json.dumps({"repo":"test","base_sha":base}))
            os.chmod(binding, 0o440)
            rubric=root/"rubric.md"; rubric.write_text("frozen")
            _, public_key = generate_keypair(root)
            integrator=ProjectIntegrator(canonical,binding,public_key,rubric,"refs/ai-ops/accepted/opensource")
            candidate = integrator.preflight_bundle(
                Path(result["manifest_path"]), root / "evidence", expected_project_id="oss",
                expected_task_id="task-1", expected_base_sha=base,
                expected_candidate_sha=manifest["candidate_sha"],
            )
            self.assertEqual(integrator.import_bundle(candidate), manifest["candidate_sha"])

    def test_required_test_failure_prevents_manifest_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = root / "attempt"; repo.mkdir()
            subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
            subprocess.run(["git", "-C", repo, "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", repo, "config", "user.name", "Test"], check=True)
            (repo / "base.txt").write_text("base\n")
            subprocess.run(["git", "-C", repo, "add", "."], check=True)
            subprocess.run(["git", "-C", repo, "commit", "-qm", "base"], check=True)
            base = subprocess.run(
                ["git", "-C", repo, "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            (repo / "candidate.txt").write_text("candidate\n")
            contract = root / "contract.json"
            contract.write_text(json.dumps({
                "task_id": "failing-test", "project_id": "oss", "base_sha": base,
                "builder_identity": "hermes-oss",
                "required_tests": ["python3 -c 'raise SystemExit(7)'"],
            }))
            path_check = root / "path-check.json"
            path_check.write_text('{"valid":true,"violations":[]}\n')
            with self.assertRaises(PermissionError):
                build(repo, contract, path_check, root / "evidence", 1)
            self.assertFalse(
                (root / "evidence" / "failing-test" / "attempt-1" / "manifest.json").exists()
            )

    def test_no_change_attempt_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = root / "attempt"; repo.mkdir()
            subprocess.run(["git","-C",str(repo),"init","-q"],check=True)
            subprocess.run(["git","-C",str(repo),"config","user.email","test@example.invalid"],check=True)
            subprocess.run(["git","-C",str(repo),"config","user.name","Test"],check=True)
            (repo / "base.txt").write_text("base\n"); subprocess.run(["git","-C",str(repo),"add","."],check=True)
            subprocess.run(["git","-C",str(repo),"commit","-qm","base"],check=True)
            base=subprocess.run(["git","-C",str(repo),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
            contract=root/"c.json"; contract.write_text(json.dumps({"task_id":"t","project_id":"oss","base_sha":base,"builder_identity":"hermes-oss","required_tests":["true"]}))
            check=root/"p.json"; check.write_text('{"valid":true,"violations":[]}\n')
            with self.assertRaises(ValueError): build(repo,contract,check,root/"out",1)

    def test_attempt_with_hidden_history_is_rejected_before_artifact_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); repo = root / "attempt"; repo.mkdir()
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "base.txt").write_text("base\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            base = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            (repo / "prior.txt").write_text("hidden prior commit\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "prior"], check=True)
            (repo / "candidate.txt").write_text("new candidate bytes\n")
            contract = root / "contract.json"
            contract.write_text(json.dumps({
                "task_id": "task-hidden", "project_id": "oss", "base_sha": base,
                "builder_identity": "hermes-oss", "required_tests": ["true"],
            }))
            path_check = root / "path-check.json"
            path_check.write_text('{"valid":true,"violations":[]}\n')
            output = root / "evidence"
            with self.assertRaises(ValueError):
                build(repo, contract, path_check, output, 1)
            self.assertFalse(output.exists())

    def test_multiple_attempts_publish_to_distinct_immutable_namespaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "-C", source, "init", "-q"], check=True)
            subprocess.run(
                ["git", "-C", source, "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", source, "config", "user.name", "Attempt Fixture"],
                check=True,
            )
            (source / "base.txt").write_text("base\n")
            subprocess.run(["git", "-C", source, "add", "."], check=True)
            subprocess.run(["git", "-C", source, "commit", "-qm", "base"], check=True)
            base = subprocess.run(
                ["git", "-C", source, "rev-parse", "HEAD"], check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            contract = root / "contract.json"
            contract.write_text(json.dumps({
                "task_id": "repeatable-task", "project_id": "oss", "base_sha": base,
                "builder_identity": "hermes-oss", "required_tests": ["true"],
            }))
            path_check = root / "path-check.json"
            path_check.write_text('{"valid":true,"violations":[]}\n')
            output = root / "evidence"
            manifests = []
            for attempt_number in (1, 2):
                workspace = root / f"attempt-{attempt_number}"
                subprocess.run(
                    ["git", "clone", "-q", str(source), str(workspace)], check=True,
                )
                (workspace / f"value-{attempt_number}.txt").write_text(
                    f"attempt {attempt_number}\n"
                )
                result = build(
                    workspace, contract, path_check, output, attempt_number,
                )
                manifest = Path(result["manifest_path"])
                manifests.append(manifest)
                self.assertEqual(
                    manifest.relative_to(output).as_posix(),
                    f"repeatable-task/attempt-{attempt_number}/manifest.json",
                )
                self.assertEqual(json.loads(manifest.read_text())["attempt"], attempt_number)
            self.assertNotEqual(manifests[0].read_bytes(), manifests[1].read_bytes())
            first_hash = sha256(manifests[0])
            raced = root / "attempt-1-replay"
            subprocess.run(["git", "clone", "-q", str(source), str(raced)], check=True)
            (raced / "replacement.txt").write_text("must not replace attempt one\n")
            with self.assertRaises(FileExistsError):
                build(raced, contract, path_check, output, 1)
            self.assertEqual(sha256(manifests[0]), first_hash)

    def test_required_tests_use_a_scrubbed_environment_and_isolated_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, candidate = self.make_clean_repo(root)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            token_name = "SEEDED_FIXTURE_TOKEN"
            token_value = "must-not-enter-evidence"
            command = (
                "python3 -c 'import json,os; "
                "print(json.dumps(dict(os.environ),sort_keys=True))'"
            )
            previous = os.environ.get(token_name)
            os.environ[token_name] = token_value
            try:
                results = produce_required_test_results(
                    workspace, [command], candidate, artifacts,
                )
            finally:
                if previous is None:
                    os.environ.pop(token_name, None)
                else:
                    os.environ[token_name] = previous
            output = (artifacts / results[0]["output"]["path"]).read_text()
            self.assertNotIn(token_name, output)
            self.assertNotIn(token_value, output)
            self.assertNotIn(str(Path.home()), output)

    def test_required_test_output_is_exactly_candidate_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, candidate = self.make_clean_repo(root)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            command = (
                "python3 -c 'import sys; print(\"out\",flush=True); "
                "print(\"err\",file=sys.stderr,flush=True)'"
            )
            results = produce_required_test_results(
                workspace, [command], candidate, artifacts,
            )
            output_path = artifacts / results[0]["output"]["path"]
            self.assertEqual(output_path.read_bytes(), b"out\nerr\n")
            self.assertEqual(results[0]["candidate_sha"], candidate)
            self.assertEqual(results[0]["output"]["sha256"], sha256(output_path))
            self.assertEqual(results[0]["output"]["byte_length"], 8)

    def test_output_overflow_kills_all_supervised_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, candidate = self.make_clean_repo(root)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            command = (
                "python3 -c 'import subprocess,time; "
                "child=subprocess.Popen([\"python3\",\"-c\",\"import time;time.sleep(60)\"]); "
                "print(child.pid,flush=True); print(\"x\"*4096,flush=True); time.sleep(60)'"
            )
            with self.assertRaises(RequiredTestOutputLimitExceeded) as caught:
                produce_required_test_results(
                    workspace, [command], candidate, artifacts,
                    timeout_seconds=5, max_output_bytes=128,
                )
            child_pid = int(caught.exception.output.splitlines()[0])
            self.assert_process_gone(child_pid)
            self.assertFalse((artifacts / "required-tests" / "0000.output").exists())

    def test_timeout_kills_all_supervised_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, candidate = self.make_clean_repo(root)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            command = (
                "python3 -c 'import subprocess,time; "
                "child=subprocess.Popen([\"python3\",\"-c\",\"import time;time.sleep(60)\"]); "
                "print(child.pid,flush=True); time.sleep(60)'"
            )
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                produce_required_test_results(
                    workspace, [command], candidate, artifacts, timeout_seconds=1,
                )
            child_pid = int(caught.exception.output.splitlines()[0])
            self.assert_process_gone(child_pid)
            self.assertFalse((artifacts / "required-tests" / "0000.output").exists())

    def test_closed_output_pipe_cannot_bypass_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, candidate = self.make_clean_repo(root)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            started = time.monotonic()
            with self.assertRaises(subprocess.TimeoutExpired):
                produce_required_test_results(
                    workspace,
                    ["python3 -c 'import os,time;os.close(1);os.close(2);time.sleep(60)'"],
                    candidate, artifacts, timeout_seconds=1,
                )
            self.assertLess(time.monotonic() - started, 3)

    def test_timeout_and_output_overflow_contain_detached_descendants_only(self):
        for mode in ("timeout", "overflow"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace, candidate = self.make_clean_repo(root)
                artifacts = root / "artifacts"
                artifacts.mkdir()
                detached_pid = root / "detached.pid"
                script = root / "detached-bound.py"
                script.write_text(
                    "import os,sys,time\n"
                    f"pid_path={str(detached_pid)!r}\n"
                    f"tracked_path={str(workspace / 'tracked.txt')!r}\n"
                    "mode=sys.argv[1]\n"
                    "first=os.fork()\n"
                    "if first:\n"
                    "    os.waitpid(first,0)\n"
                    "    if mode == 'overflow':\n"
                    "        os.write(1,b'x'*4096)\n"
                    "    time.sleep(30)\n"
                    "os.setsid()\n"
                    "grandchild=os.fork()\n"
                    "if grandchild:\n"
                    "    with open(pid_path,'w',encoding='ascii') as stream:\n"
                    "        stream.write(str(grandchild))\n"
                    "        stream.flush()\n"
                    "        os.fsync(stream.fileno())\n"
                    "    os._exit(0)\n"
                    "os.close(0);os.close(1);os.close(2)\n"
                    "time.sleep(1.5)\n"
                    "with open(tracked_path,'w',encoding='utf-8') as stream:\n"
                    "    stream.write('late outer-bound mutation\\n')\n"
                    "time.sleep(30)\n",
                    encoding="utf-8",
                )
                sentinel = subprocess.Popen(
                    ["python3", "-c", "import time;time.sleep(30)"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                command = (
                    f"python3 {shlex.quote(str(script))} {shlex.quote(mode)}"
                )
                expected_exception = (
                    subprocess.TimeoutExpired
                    if mode == "timeout" else RequiredTestOutputLimitExceeded
                )
                try:
                    with self.assertRaises(expected_exception):
                        produce_required_test_results(
                            workspace, [command], candidate, artifacts,
                            timeout_seconds=1,
                            max_output_bytes=128,
                        )
                    self.assertTrue(detached_pid.is_file())
                    self.assert_process_gone(int(detached_pid.read_text()))
                    self.assertIsNone(sentinel.poll(), "unrelated process was terminated")
                    self.assertEqual(
                        (workspace / "tracked.txt").read_text(), "candidate bytes\n",
                    )
                    time.sleep(1.6)
                    self.assertEqual(
                        (workspace / "tracked.txt").read_text(), "candidate bytes\n",
                    )
                    self.assertFalse(
                        (artifacts / "required-tests" / "0000.output").exists()
                    )
                finally:
                    if sentinel.poll() is None:
                        sentinel.terminate()
                        sentinel.wait(timeout=2)

    def test_detached_double_fork_is_reaped_rejected_and_cannot_mutate_late(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace, candidate = self.make_clean_repo(root)
            artifacts = root / "artifacts"
            artifacts.mkdir()
            detached_pid = root / "detached.pid"
            script = root / "detach.py"
            script.write_text(
                "import ctypes,os,time\n"
                f"pid_path={str(detached_pid)!r}\n"
                f"tracked_path={str(workspace / 'tracked.txt')!r}\n"
                "first=os.fork()\n"
                "if first:\n"
                "    os.waitpid(first,0)\n"
                "    raise SystemExit(0)\n"
                "os.setsid()\n"
                "ready_read,ready_write=os.pipe()\n"
                "grandchild=os.fork()\n"
                "if grandchild:\n"
                "    os.close(ready_write)\n"
                "    os.read(ready_read,1)\n"
                "    os.close(ready_read)\n"
                "    with open(pid_path,'w',encoding='ascii') as stream:\n"
                "        stream.write(str(grandchild))\n"
                "        stream.flush()\n"
                "        os.fsync(stream.fileno())\n"
                "    os._exit(0)\n"
                "os.close(ready_read)\n"
                "ctypes.CDLL(None).prctl(15,b'late writer',0,0,0)\n"
                "os.write(ready_write,b'1')\n"
                "os.close(ready_write)\n"
                "os.close(0);os.close(1);os.close(2)\n"
                "time.sleep(0.5)\n"
                "with open(tracked_path,'w',encoding='utf-8') as stream:\n"
                "    stream.write('late mutation\\n')\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            sentinel = subprocess.Popen(
                ["python3", "-c", "import time;time.sleep(30)"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                with self.assertRaisesRegex(PermissionError, "detached descendant"):
                    produce_required_test_results(
                        workspace, [f"python3 {shlex.quote(str(script))}"],
                        candidate, artifacts, timeout_seconds=5,
                    )
                deadline = time.monotonic() + 1
                while not detached_pid.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(detached_pid.is_file())
                self.assert_process_gone(int(detached_pid.read_text()))
                self.assertIsNone(sentinel.poll(), "unrelated process was terminated")
                self.assertEqual(
                    (workspace / "tracked.txt").read_text(), "candidate bytes\n",
                )
                time.sleep(0.7)
                self.assertEqual(
                    (workspace / "tracked.txt").read_text(), "candidate bytes\n",
                )
                self.assertFalse(
                    (artifacts / "required-tests" / "0000.output").exists()
                )
            finally:
                if sentinel.poll() is None:
                    sentinel.terminate()
                    sentinel.wait(timeout=2)

    def test_proc_stat_parser_preserves_comm_with_spaces(self):
        suffix = ["S", "7", "123", *(["0"] * 16), "456"]
        parsed = _parse_proc_stat(f"42 (worker name with spaces) {' '.join(suffix)}")
        self.assertEqual(parsed, (42, "S", 7, 123, 456))

    def test_head_switch_and_worktree_mutation_cannot_be_bound(self):
        commands = {
            "head-switch": None,
            "tracked-mutation": "printf 'mutated\\n' > tracked.txt",
        }
        for name, supplied_command in commands.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace, first = self.make_clean_repo(root)
                (workspace / "second.txt").write_text("second\n")
                subprocess.run(["git", "-C", workspace, "add", "."], check=True)
                subprocess.run(
                    ["git", "-C", workspace, "commit", "-qm", "second"], check=True,
                )
                candidate = subprocess.run(
                    ["git", "-C", workspace, "rev-parse", "HEAD"], check=True,
                    capture_output=True, text=True,
                ).stdout.strip()
                command = supplied_command or f"git checkout --detach --force {first}"
                artifacts = root / "artifacts"
                artifacts.mkdir()
                with self.assertRaises(PermissionError):
                    produce_required_test_results(
                        workspace, [command], candidate, artifacts,
                    )
                self.assertFalse((artifacts / "required-tests" / "0000.output").exists())


if __name__ == "__main__": unittest.main()
