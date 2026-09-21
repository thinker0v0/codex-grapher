"""Adversarial protocol and durable authority-store checks (no model launches)."""
import base64
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from control_plane.evaluation_broker import (
    BrokerStore, broker_client, evaluate_artifact, fetch_receipt_output,
    run_candidate_tests, signer_main, verify_public_receipt_store, validate_git_repository_metadata,
)
from control_plane.sealed_protocol import (
    ProtocolError, canonical, digest, load_json, sha256,
    validate_candidate_test_request, validate_evaluation_rejection,
    validate_evaluation_request, validate_launcher_request,
    validate_sealed_test_receipt, validate_signing_request,
)

H = "a" * 64
C = "b" * 40


def request():
    return {"schema_version": 1, "run_id": "task-attempt-1-required", "kind": "required",
        "candidate_sha": C, "candidate_root": "/owned/attempts/task-attempt-1/checkout",
        "task_sha256": H, "profile_sha256": H, "commands_sha256": digest(["true"]),
        "commands": ["true"], "checks": [], "timeout_seconds": 10, "max_output_bytes": 1000}


def evaluation():
    return {"schema_version": 1, "workspace_id": H, "task_sha256": H, "profile_sha256": H,
        "policy_sha256": H, "checks_sha256": H, "producer_contract_sha256": H,
        "artifact_id": "sha256:" + H, "manifest_sha256": H, "evaluation_id": "task-evaluation-v1",
        "evaluator_contract_id": "task-acceptance-v1", "claim_id": "claim:" + H,
        "previous_ledger_hash": None, "required_receipt_id": H}


def receipt():
    req = request()
    out = {"outputs/0000.stdout": b"passed\n", "outputs/0000.stderr": b""}
    value = {"schema_version": 1, "request_id": req["run_id"], "request_sha256": digest(req),
        "run_id": req["run_id"], "kind": req["kind"], "workspace_id": H,
        "task_sha256": H, "profile_sha256": H, "commands_sha256": req["commands_sha256"],
        "candidate_sha": C, "pre_tree_sha256": H, "post_tree_sha256": H,
        "actual_uid": 12345, "actual_gid": 12345,
        "namespaces": {name: index + 1 for index, name in enumerate(("user", "mount", "pid", "ipc", "net"))},
        "capabilities": {name: "0000000000000000" for name in ("inheritable", "permitted", "effective", "bounding", "ambient")},
        "no_new_privs": True, "results": [{"sequence": 0, "id": "required-0000", "command_sha256": digest("true"), "exit_code": 0,
            **{stream: {"sha256": sha256(out[f"outputs/0000.{stream}"]), "bytes": len(out[f"outputs/0000.{stream}"]),
                        "relative_path": f"outputs/0000.{stream}"} for stream in ("stdout", "stderr")}}],
        "elapsed_ms": 1, "limits": {"timeout_seconds": 10, "max_output_bytes": 1000},
        "descendants": {"reaped": True, "survivors": 0}, "replayed": False}
    value["receipt_id"] = digest(value)
    return value, out


def reseal(value, field="receipt_id"):
    value[field] = digest({k: v for k, v in value.items() if k != field})
    return value


class ProtocolTests(unittest.TestCase):
    def test_exact_canonical_bytes_and_duplicate_keys(self):
        self.assertEqual(canonical({"z": "한", "a": 1}), b'{"a":1,"z":"\\ud55c"}')
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e400}', b'{"a":1}\n'):
            with self.subTest(data=data), self.assertRaises((ProtocolError, ValueError)):
                load_json(data)

    def test_every_contract_rejects_unknown_and_duplicate_fields(self):
        r, _ = receipt()
        e = evaluation()
        s = {"schema_version": 1, "evaluation": e, "evaluation_request_sha256": digest(e), "independent_receipt_id": H, "candidate_sha": C}
        reject = {"schema_version": 1, "evaluation_request_sha256": digest(e), "artifact_id": e["artifact_id"], "claim_id": e["claim_id"], "failed_receipt_id": None, "reason": "CHECK_FAILED"}
        reject = reseal(reject, "rejection_id")
        launch = {"schema_version": 1, "action": "candidate-tests", "workspace_id": H, "request_id": "request-1", "payload": {"registered_request_id": request()["run_id"]}}
        launch = reseal(launch, "request_sha256")
        for validator, item in ((validate_candidate_test_request, request()), (validate_evaluation_request, e),
            (validate_signing_request, s), (validate_sealed_test_receipt, r),
            (validate_evaluation_rejection, reject), (validate_launcher_request, launch)):
            with self.subTest(validator=validator.__name__):
                self.assertEqual(validator(canonical(item)), item)
                extra = {**item, "role": "root"}
                with self.assertRaises(ProtocolError):
                    validator(extra)
                duplicate = canonical(item)[:-1] + b',"schema_version":1}'
                with self.assertRaises(ProtocolError):
                    validator(duplicate)
                invalid_version = {**item, "schema_version": True}
                with self.assertRaises(ProtocolError):
                    validator(invalid_version)

    def test_candidate_request_denies_paths_unknown_authority_and_float_limits(self):
        mutations = [{"candidate_root": "/safe/../secret"}, {"candidate_root": "relative"},
            {"candidate_root": "/safe//checkout"}, {"timeout_seconds": True},
            {"timeout_seconds": 10.0}, {"max_output_bytes": 8388609},
            {"commands_sha256": "A" * 64}, {"commands": ["steal"]},
            {"run_id": "../task"}, {"checks": [{"id": "evil", "argv": ["sh"]}]}]
        for change in mutations:
            with self.subTest(change=change), self.assertRaises(ProtocolError):
                validate_candidate_test_request({**request(), **change})

    def test_independent_ids_and_argv_exact(self):
        checks = [{"id": "correctness", "argv": ["/usr/bin/python3", "-c", "print(1)"]}]
        r = {**request(), "kind": "independent", "commands": [], "checks": checks, "commands_sha256": digest(checks)}
        self.assertEqual(validate_candidate_test_request(r), r)
        for bad in ([checks[0], checks[0]], [{**checks[0], "cwd": "/tmp"}], [{"id": "../x", "argv": ["x"]}], [{"id": "x", "argv": []}]):
            with self.assertRaises(ProtocolError):
                validate_candidate_test_request({**r, "checks": bad, "commands_sha256": digest(bad)})

    def test_launcher_accepts_only_names_not_commands_or_signing_requests(self):
        for action, payload in (("candidate-tests", request()), ("worker-launch", {"registered_request_id": "x", "argv": ["sh"]}),
            ("sign-evaluation", {"bytes": "sign me"}), ("register", {"registered_request_id": "x"}),
            ("immutable-receipt-fetch", {"receipt_id": H, "relative_path": "../../key"}), ([], {})):
            v = {"schema_version": 1, "action": action, "workspace_id": H, "request_id": "request-1", "payload": payload}
            with self.subTest(action=action), self.assertRaises(ProtocolError):
                validate_launcher_request(reseal(v, "request_sha256"))

    def test_receipt_rejects_output_aliases_forged_hashes_and_numeric_bools(self):
        for mutation in (lambda v: v["results"][0]["stdout"].update(relative_path="../secret"),
            lambda v: v["results"][0].update(sequence=True),
            lambda v: v["results"][0]["stdout"].update(bytes=True),
            lambda v: v["limits"].update(timeout_seconds=1.5),
            lambda v: v["namespaces"].update(user=False),
            lambda v: v["capabilities"].update(effective="GG"),
            lambda v: v.update(replayed=True), lambda v: v.update(no_new_privs=False),
            lambda v: v["results"][0].update(id="wrong")):
            v, _ = receipt()
            mutation(v)
            with self.assertRaises(ProtocolError):
                validate_sealed_test_receipt(reseal(v))
        v, _ = receipt()
        v["candidate_sha"] = "c" * 40
        with self.assertRaises(ProtocolError):
            validate_sealed_test_receipt(v)

    def test_evaluation_signing_subject_and_digest_bound(self):
        for change in ({"artifact_id": "sha256:" + "b" * 64}, {"claim_id": "not-a-claim"}, {"previous_ledger_hash": False}, {"required_receipt_id": "../file"}):
            with self.assertRaises(ProtocolError):
                validate_evaluation_request({**evaluation(), **change})
        signing = {"schema_version": 1, "evaluation": evaluation(), "evaluation_request_sha256": "b" * 64, "independent_receipt_id": H, "candidate_sha": C}
        with self.assertRaises(ProtocolError):
            validate_signing_request(signing)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = BrokerStore(self.root, require_root=False)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def seal(self):
        value, outputs = receipt()
        with self.store.lock():
            self.store.seal_receipt(value, outputs)
        return value, outputs

    def test_receipt_exact_replay_outputs_and_readonly_archive_validation(self):
        value, outputs = self.seal()
        first = (self.store.root / "receipts" / value["receipt_id"] / "receipt.json").read_bytes()
        with self.store.lock():
            self.assertEqual(self.store.seal_receipt(value, outputs), value)
        self.assertEqual(self.store.fetch(value["receipt_id"]), value)
        self.assertEqual(self.store.output(value["receipt_id"], "outputs/0000.stdout"), b"passed\n")
        self.assertEqual((self.store.root / "receipts" / value["receipt_id"] / "receipt.json").read_bytes(), first)
        self.assertFalse(value["replayed"])
        profile = {"mode": "trusted-local"}
        self.assertEqual(verify_public_receipt_store(self.root, profile), {"receipt_ids": [value["receipt_id"]], "rejection_ids": []})

    def test_output_hash_inventory_permissions_and_hardlink_tampering(self):
        v, out = receipt()
        with self.assertRaises(PermissionError):
            self.store.seal_receipt(v, {**out, "outputs/secret": b"x"})
        with self.assertRaises(PermissionError):
            self.store.seal_receipt(v, {**out, "outputs/0000.stdout": b"tampered"})
        self.seal()
        output = self.store.root / "receipts" / v["receipt_id"] / "outputs/0000.stdout"
        output.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.store.fetch(v["receipt_id"])
        output.chmod(0o444)
        os.link(output, self.root / "alias")
        with self.assertRaises(PermissionError):
            self.store.fetch(v["receipt_id"])

    def test_symlink_and_extra_output_never_admitted(self):
        v, _ = self.seal()
        output = self.store.root / "receipts" / v["receipt_id"] / "outputs/0000.stdout"
        original = output.read_bytes()
        output.unlink()
        output.symlink_to(self.root / "secret")
        with self.assertRaises(OSError):
            self.store.fetch(v["receipt_id"])
        output.unlink()
        output.write_bytes(original)
        output.chmod(0o444)
        extra = output.parent / "extra"
        extra.write_bytes(b"unexpected")
        extra.chmod(0o444)
        with self.assertRaises(PermissionError):
            self.store.fetch(v["receipt_id"])

    def test_pinned_store_and_workspace_replacement_rejected(self):
        v, _ = self.seal()
        self.store.root.rename(self.root / "moved")
        self.store.root.mkdir()
        with self.assertRaises(PermissionError):
            self.store.fetch(v["receipt_id"])

    def test_root_owner_sealing_guard_and_private_reservation_exclusive(self):
        with self.store.lock():
            self.store.reserve("request-test", {"request_sha256": H})
            with self.assertRaises(FileExistsError):
                self.store.reserve("request-test", {"request_sha256": "b" * 64})
        self.assertEqual(self.store.private_record("request-test"), {"request_sha256": H})
        with patch("control_plane.evaluation_broker.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(PermissionError):
                self.store.reserve("forged", {})

    @unittest.skipUnless(os.geteuid() == 0, "actual dropped UID denial requires root test process")
    def test_actual_nonowner_cannot_modify_receipt_or_replace_store(self):
        v, _ = self.seal()
        self.root.chmod(0o755)
        output = self.store.root / "receipts" / v["receipt_id"] / "receipt.json"
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(read_fd)
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                denied = 0
                for effect in (lambda: output.write_bytes(b"forged"), lambda: self.store.root.rename(self.root / "replaced")):
                    try:
                        effect()
                    except PermissionError:
                        denied += 1
                os.write(write_fd, str(denied).encode())
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write_fd)
        result = os.read(read_fd, 100)
        os.close(read_fd)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertEqual(result, b"2")
        self.assertEqual(self.store.fetch(v["receipt_id"]), v)

    def test_root_bootstrap_rejects_writable_ancestor(self):
        if os.geteuid() == 0:
            unsafe = self.root / "unsafe"
            unsafe.mkdir()
            unsafe.chmod(0o777)
            child = unsafe / "workspace"
            child.mkdir()
            with self.assertRaises(PermissionError):
                BrokerStore(child, require_root=True)


class PublicSeamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = BrokerStore(self.root, require_root=False)
        self.addCleanup(self.store.close)
        self.value, self.outputs = receipt()
        with self.store.lock():
            self.store.seal_receipt(self.value, self.outputs)

    def test_public_requests_delegate_finite_names_and_read_sealed_output(self):
        value, root = self.value, self.root
        calls = []
        class Client:
            workspace = root
            def request(self, action, payload):
                calls.append((action, payload))
                return value
        with broker_client(Client()):
            self.assertEqual(run_candidate_tests(request(), {"mode": "trusted-local"}), value)
            self.assertEqual(calls[0], ("candidate-tests", {"registered_request_id": request()["run_id"]}))
            self.assertEqual(fetch_receipt_output(value["receipt_id"], "outputs/0000.stdout", {"mode": "trusted-local"}), b"passed\n")
            with self.assertRaises(ProtocolError):
                fetch_receipt_output(value["receipt_id"], "../key", {"mode": "trusted-local"})

    def test_forged_received_receipt_and_arbitrary_signing_bytes_reject(self):
        value, root = self.value, self.root
        forged = copy.deepcopy(value)
        forged["results"][0]["stdout"]["sha256"] = H
        reseal(forged)
        class Client:
            workspace = root
            def request(self, action, payload):
                return forged
        with broker_client(Client()), self.assertRaises(PermissionError):
            fetch_receipt_output(value["receipt_id"], "outputs/0000.stdout", {"mode": "trusted-local"})
        with self.assertRaises(ProtocolError):
            signer_main({"message": "arbitrary bytes"}, {}, "/tmp")
        with self.assertRaises(ProtocolError):
            evaluate_artifact({**evaluation(), "signature": "caller signature"}, {})


class GitMetadataAdmissionTests(unittest.TestCase):
    def test_executable_and_external_git_configuration_rejects_without_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            config = root / ".git/config"
            inert = "[core]\nrepositoryformatversion = 0\nbare = false\nfilemode = true\nlogallrefupdates = true\nhooksPath = /dev/null\n"
            config.write_text(inert)
            with patch("control_plane.evaluation_broker.subprocess.run", side_effect=AssertionError("Git must not execute during config admission")):
                validate_git_repository_metadata(root)
                for extra in ('[filter "test"]\nclean = arbitrary-program\n', '[include]\npath = /outside/config\n', '[core]\nfsmonitor = arbitrary-program\n', '[extensions]\npartialClone = origin\n'):
                    config.write_text(inert + extra)
                    with self.assertRaises(PermissionError):
                        validate_git_repository_metadata(root)
                config.write_text(inert)
                (root / ".git/commondir").write_text("/outside/repository")
                with self.assertRaises(PermissionError):
                    validate_git_repository_metadata(root)


class BrokerWorkflowIntegrationTests(unittest.TestCase):
    def _fixture(self, *, failed_independent=False):
        # Reuse only the disclosed repository setup. Worker inference is a
        # deterministic edit; required/independent processes, sealed storage,
        # OpenSSL signing and graph acceptance below are real.
        import test_repository_workflow as fixture_module
        from types import SimpleNamespace
        fixture = fixture_module.RepositoryWorkflowTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        profile = fixture.profile
        profile.roles = {name: SimpleNamespace(uid=os.geteuid(), gid=os.getegid())
                         for name in ("worker", "graph", "signer", "test_runner")}
        profile.tools["openssl"] = SimpleNamespace(path="/usr/bin/openssl")
        profile.paths["signer_private_key"] = str(fixture.private)
        profile.raw.update(mode="trusted-local", paths=profile.paths,
            roles={name: {"uid": role.uid, "gid": role.gid} for name, role in profile.roles.items()},
            tools={name: {"path": tool.path} for name, tool in profile.tools.items() if hasattr(tool, "path")})
        profile.to_dict = lambda: copy.deepcopy(profile.raw)
        if failed_independent:
            checks = json.loads((fixture.directory / "checks.json").read_bytes())
            checks["checks"][0]["argv"][-1] = "raise AssertionError('declared independent failure')"
            (fixture.directory / "checks.json").write_text(json.dumps(checks))
        fixture.initialize()
        return fixture, fixture_module.workflow

    def test_real_local_checks_sealed_receipts_signature_and_graph_acceptance(self):
        fixture, workflow = self._fixture()
        with patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}), \
             patch("control_plane.worker_provider.launch_worker", side_effect=fixture.fake_worker):
            result = workflow.run_repository_workflow(fixture.root, stop_after="evaluated")
        self.assertEqual(result["task_state"], "PASSED")
        self.assertEqual(fixture.launches, 1)
        inventory = verify_public_receipt_store(fixture.root, fixture.profile)
        self.assertEqual(len(inventory["receipt_ids"]), 2)
        self.assertEqual(inventory["rejection_ids"], [])

    def test_graph_selected_unknown_run_cannot_register_commands(self):
        fixture, workflow = self._fixture()
        from control_plane.evaluation_broker import EvaluationBroker
        with patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}), \
             patch("control_plane.worker_provider.launch_worker", side_effect=fixture.fake_worker):
            workflow.run_repository_workflow(fixture.root, stop_after="built")
        # A graph-selected unknown run cannot install caller commands.
        broker = EvaluationBroker(fixture.root, fixture.profile)
        self.addCleanup(broker.close)
        with self.assertRaises(PermissionError):
            broker.handle("candidate-tests", {"registered_request_id": "other-task-attempt-1-required"})
        with self.assertRaises(ProtocolError):
            broker.handle("candidate-tests", {"registered_request_id": "repair-value-attempt-1-required", "commands": ["false"]})


    def test_interrupted_unsealed_test_run_is_not_executed_again(self):
        fixture, workflow = self._fixture()
        from control_plane.evaluation_broker import EvaluationBroker
        with patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}), \
             patch("control_plane.worker_provider.launch_worker", side_effect=fixture.fake_worker):
            workflow.run_repository_workflow(fixture.root, stop_after="built")
        broker = EvaluationBroker(fixture.root, fixture.profile)
        self.addCleanup(broker.close)
        test_request = broker.frozen.required_request("repair-value-attempt-1-required")
        test_request["run_id"] = "interrupted-internal-test"
        with patch("control_plane.isolated_runner.execute_candidate_tests", side_effect=RuntimeError("simulated interruption")) as execute:
            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                broker._run_tests(test_request)
            with self.assertRaisesRegex(PermissionError, "WORKER_INTERRUPTED_UNSEALED"):
                broker._run_tests(test_request)
            self.assertEqual(execute.call_count, 1)

    def test_failed_independent_check_seals_rejection_and_resolves_active_claim(self):
        fixture, workflow = self._fixture(failed_independent=True)
        with patch("control_plane.worker_provider.provider_preflight", return_value={"fixture": True}), \
             patch("control_plane.worker_provider.launch_worker", side_effect=fixture.fake_worker), \
             patch("control_plane.evaluation_broker.signer_main") as signer:
            result = workflow.run_repository_workflow(fixture.root, stop_after="evaluated")
        self.assertEqual(result["task_state"], "FAILED_GATE")
        self.assertIsNone(result["outcome_id"])
        signer.assert_not_called()
        public = verify_public_receipt_store(fixture.root, fixture.profile)
        self.assertEqual(len(public["receipt_ids"]), 2)
        self.assertEqual(len(public["rejection_ids"]), 1)
        store = BrokerStore(fixture.root, require_root=False, create=False)
        self.addCleanup(store.close)
        rejection = store.fetch_rejection(public["rejection_ids"][0])
        self.assertEqual(rejection["reason"], "CHECK_FAILED")
        self.assertIn(rejection["failed_receipt_id"], public["receipt_ids"])


if __name__ == "__main__":
    unittest.main()
