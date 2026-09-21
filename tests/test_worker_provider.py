"""Deterministic protocol/launcher fixtures; these never invoke a model."""

import copy
import hashlib
import json
import tempfile
import types
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from control_plane import worker_provider as provider
from control_plane.execution_profile import ExecutionProfile, Role, Tool
# Freeze real provider/runner identities before boundary fixtures patch helpers.
from control_plane import isolated_runner


def digest(value):
    return hashlib.sha256(value).hexdigest()


def stream(events):
    return b"".join(json.dumps(event).encode() + b"\n" for event in events)


def events(status="completed", usage=None):
    return [
        {"type": "thread.started", "thread_id": "fixture-session"},
        {"type": "turn.started"},
        {"type": "item.completed", "item": {"id": "item_0", "type": "agent_message",
         "text": json.dumps({"schema_version": 1, "status": status, "summary": "Fixture result."})}},
        {"type": "turn.completed", "usage": usage},
    ]


def process(stdout=b"", stderr=b"", **overrides):
    fields = dict(stdout=stdout, stderr=stderr, returncode=0, signal=None,
                  elapsed_seconds=0.01, descendants_reaped=True,
                  timed_out=False, output_overflow=False)
    fields.update(overrides)
    return types.SimpleNamespace(**fields)


class ProtocolTests(unittest.TestCase):
    def test_completed_and_absent_telemetry_is_explicit_null(self):
        result = provider.parse_codex_jsonl(stream(events()))
        self.assertEqual(result, {"completion": "COMPLETED", "model": None,
                                 "session_id": "fixture-session", "usage_observed": None})

    def test_usage_preserves_all_observed_counters_without_invented_cost(self):
        usage = {"input_tokens": 20, "cached_input_tokens": 5, "cache_write_input_tokens": 2,
                 "output_tokens": 3, "reasoning_output_tokens": 1}
        self.assertEqual(provider.parse_codex_jsonl(stream(events(usage=usage)))["usage_observed"], usage)

    def test_intermediate_failure_and_commentary_can_be_repaired(self):
        values = events()
        values[2:2] = [
            {"type": "item.completed", "item": {"type": "command_execution", "exit_code": 1,
             "aggregated_output": "permission denied", "status": "failed"}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "Repairing the failure."}},
        ]
        self.assertEqual(provider.parse_codex_jsonl(stream(values))["completion"], "COMPLETED")

    def test_complete_last_json_object_needs_no_trailing_newline(self):
        self.assertEqual(provider.parse_codex_jsonl(stream(events()).rstrip(b"\n"))["completion"], "COMPLETED")

    def test_refused_blocked_failed_are_not_success(self):
        for status, expected in (("refused", "REFUSED"), ("blocked", "BLOCKED"), ("failed", "PROVIDER_FAILED")):
            with self.subTest(status=status):
                self.assertEqual(provider.parse_codex_jsonl(stream(events(status)))["completion"], expected)

    def test_failed_terminal_and_error_are_failure(self):
        values = events()
        values[-1] = {"type": "turn.failed", "error": {"message": "fixture failure"}}
        self.assertEqual(provider.parse_codex_jsonl(stream(values))["completion"], "PROVIDER_FAILED")
        values = events()
        values.insert(2, {"type": "error", "message": "fixture error"})
        self.assertEqual(provider.parse_codex_jsonl(stream(values))["completion"], "PROVIDER_FAILED")

    def test_malformed_utf8_duplicate_json_nonobject_blank_truncated_fail(self):
        for value in (b"", b"\xff\n", b"[]\n", b"\n", b'{"type":"thread.started","type":"turn.started"}\n',
                      stream(events())[:-4], b'{"type":"thread.started","thread_id":NaN}\n'):
            with self.subTest(value=value):
                with self.assertRaises((ValueError, UnicodeError)):
                    provider.parse_codex_jsonl(value)

    def test_missing_duplicate_out_of_order_or_unknown_terminal_fail(self):
        good = events()
        cases = [good[:-1], good + [good[-1]], good + [{"type": "error"}],
                 good[:1] + good, good[:2] + [good[1]] + good[2:],
                 good[1:], [good[-1]], [good[0], good[2], good[1], good[-1]],
                 good[:-1] + [{"type": "turn.finished"}]]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    provider.parse_codex_jsonl(stream(value))

    def test_contradictory_terminal_and_agent_fields_never_succeed(self):
        for index, addition in ((3, {"status": "failed"}), (3, {"error": {"message": "blocked"}}),
                                (3, {"refusal": True}), (0, {"role": "root"}),
                                (1, {"status": "blocked"})):
            values = events(); values[index].update(addition)
            with self.subTest(index=index, addition=addition), self.assertRaises(ValueError):
                provider.parse_codex_jsonl(stream(values))
        values = events(); values[2]["item"]["refusal"] = True
        with self.assertRaises(ValueError):
            provider.parse_codex_jsonl(stream(values))

    def test_invalid_and_duplicate_structured_results_fail(self):
        bad_text = ["I cannot do this.", '```json\n{"status":"completed"}\n```',
                    '{"schema_version":1,"status":"completed","summary":"x","extra":1}',
                    '{"schema_version":true,"status":"completed","summary":"x"}',
                    '{"schema_version":1,"status":"completed","status":"blocked","summary":"x"}',
                    '{"schema_version":1,"status":"completed","summary":""}',
                    '{"schema_version":1,"status":"unknown","summary":"x"}']
        for text in bad_text:
            values = events()
            values[2]["item"]["text"] = text
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    provider.parse_codex_jsonl(stream(values))
        values = events()
        values.insert(2, copy.deepcopy(values[2]))
        with self.assertRaises(ValueError):
            provider.parse_codex_jsonl(stream(values))
        values = events()
        values.insert(3, {"type": "item.completed", "item": {"type": "agent_message", "text": "I refuse."}})
        with self.assertRaises(ValueError):
            provider.parse_codex_jsonl(stream(values))

    def test_non_numeric_boolean_negative_and_unbounded_usage_fail(self):
        for usage in ([], {"input_tokens": True}, {"input_tokens": -1}, {"input_tokens": "4"},
                      {"input_tokens": 1.5}, {"input_tokens": 2**60}, {"token": float("inf")}):
            with self.subTest(usage=usage):
                with self.assertRaises(ValueError):
                    provider.parse_codex_jsonl(stream(events(usage=usage)))

    def test_observed_model_is_checked_not_inferred(self):
        values = events()
        values[0]["model"] = provider.MODEL
        self.assertEqual(provider.parse_codex_jsonl(stream(values))["model"], provider.MODEL)
        values[0]["model"] = "another-model"
        with self.assertRaises(ValueError):
            provider.parse_codex_jsonl(stream(values))


class ProviderBoundaryFixtures(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.checkout = self.root / "attempt" / "checkout"
        (self.checkout / ".git").mkdir(parents=True)
        schema = self.root / "schemas" / "worker-result.schema.json"
        schema.parent.mkdir()
        schema.write_bytes((Path(__file__).resolve().parents[1] / "schemas" / "worker-result.schema.json").read_bytes())
        self.profile = ExecutionProfile(
            sha256="c" * 64, mode="isolated-linux",
            tools={"provider": Tool("/trusted/codex", "e" * 64, provider.CLI_VERSION),
                   "git": Tool("/trusted/git", "f" * 64, "fixture")},
            paths={"trusted_code_root": str(self.root)}, roles={"worker": Role(1000, 1000)},
            provider={"backend": "codex", "model": provider.MODEL, "reasoning_effort": "medium", "service_tier": "default"},
            auth_account="fixture", auth_home=self.root, sqlite={"profile": "delete-extra", "attestation": None}, _json=b"{}")
        self.request = {
            "schema_version": 1, "project_id": "project", "task_id": "task",
            "idempotency_key": "idempotent", "attempt_id": "task-attempt-1", "attempt_number": 1,
            "base_sha": "a" * 40, "checkout": str(self.checkout), "task_sha256": "b" * 64,
            "profile_sha256": self.profile.sha256, "prompt": "Repair the fixture.",
            "prompt_sha256": digest(b"Repair the fixture."),
            "limits": {"worker_invocations": 1, "worker_timeout_seconds": 5, "max_output_bytes": 4096},
        }
        self.reserve()
        self.profile_patch = mock.patch.object(provider, "_profile")
        self.profile_patch.start()
        self.addCleanup(self.profile_patch.stop)
        self.boundary_patch = mock.patch.object(provider, "_assert_boundary")
        self.boundary_patch.start()
        self.addCleanup(self.boundary_patch.stop)
        self.retention_patch = mock.patch.object(provider, "_retain_diagnostics")
        self.retention_sink = self.retention_patch.start()
        self.addCleanup(self.retention_patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def reserve(self):
        value = {"schema_version": 1, "attempt_id": self.request["attempt_id"], "attempt_number": 1,
                 "invocation_count": 1, "request_sha256": provider.request_sha256(self.request),
                 "request": self.request, "reserved_at": "2026-09-21T00:00:00Z"}
        (self.checkout.parent / "reservation.json").write_bytes(provider.canonical_bytes(value))

    def execute(self, result=None, final_head=None):
        result = result or process(stream(events()))
        responses = [process((self.request["base_sha"] + "\n").encode()), result]
        if result.returncode == 0 and not result.signal and result.descendants_reaped and not result.timed_out and not result.output_overflow:
            responses.append(process(((final_head or self.request["base_sha"]) + "\n").encode()))
        with mock.patch.object(provider, "_run", side_effect=responses) as runner:
            receipt = provider.execute_worker(self.request, self.profile)
        return receipt, runner

    def test_valid_request_and_receipt_exact_hash_bindings(self):
        receipt, runner = self.execute()
        self.assertEqual(set(receipt), provider.RECEIPT_FIELDS)
        self.assertEqual(receipt["completion"], "COMPLETED")
        self.assertEqual(receipt["request_sha256"], provider.request_sha256(self.request))
        self.assertEqual(receipt["stdout_sha256"], digest(stream(events())))
        self.assertIsNone(receipt["model"])
        self.assertIsNone(receipt["usage_observed"])
        self.assertEqual(provider.validate_worker_receipt(receipt, self.request, self.profile), receipt)
        self.assertEqual(runner.call_args_list[1].args[3], self.request["prompt"].encode())

    def test_no_command_shell_or_ambient_configuration_in_argv(self):
        receipt, runner = self.execute()
        argv = runner.call_args_list[1].args[2]
        self.assertEqual(argv[:4], ["/trusted/codex", "--ask-for-approval", "never", "exec"])
        for required in ("--ignore-user-config", "--ephemeral", "danger-full-access", "--json",
                         provider.MODEL, 'model_reasoning_effort="medium"', 'service_tier="default"'):
            self.assertIn(required, argv)
        for forbidden in ("--dangerously-bypass-approvals-and-sandbox", "--ignore-rules", "--oss", "--search"):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(argv[-1], "-")
        self.assertNotIn(self.request["prompt"], argv)

    def test_timeout_overflow_nonzero_signal_cleanup_failures_are_receipts(self):
        cases = [(dict(timed_out=True), "TIMEOUT"), (dict(output_overflow=True), "OUTPUT_LIMIT"),
                 (dict(returncode=1), "PROVIDER_FAILED"), (dict(returncode=-9, signal=9), "PROVIDER_FAILED"),
                 (dict(descendants_reaped=False), "CLEANUP_FAILED")]
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                receipt, _ = self.execute(process(stream(events()), **overrides))
                self.assertEqual(receipt["completion"], expected)
                provider.validate_worker_receipt(receipt, self.request, self.profile)

    def test_cleanup_failure_takes_precedence_over_completed_and_timeout(self):
        receipt, _ = self.execute(process(stream(events()), timed_out=True, descendants_reaped=False))
        self.assertEqual(receipt["completion"], "CLEANUP_FAILED")

    def test_combined_stdout_stderr_limit(self):
        receipt, _ = self.execute(process(stream(events()), stderr=b"x" * 4096))
        self.assertEqual(receipt["completion"], "OUTPUT_LIMIT")

    def test_process_zero_missing_terminal_and_refusal_not_completed(self):
        for data, expected in ((stream(events()[:-1]), "PROTOCOL_INVALID"),
                               (stream(events("refused")), "REFUSED"),
                               (stream(events("blocked")), "BLOCKED")):
            with self.subTest(expected=expected):
                receipt, _ = self.execute(process(data))
                self.assertEqual(receipt["completion"], expected)

    def test_changed_head_is_failure(self):
        receipt, _ = self.execute(final_head="d" * 40)
        self.assertEqual(receipt["completion"], "HEAD_CHANGED")

    def test_missing_or_changed_reservation_denied_before_process(self):
        path = self.checkout.parent / "reservation.json"
        for mutation in ("missing", "changed-count", "changed-prompt", "nested-bool", "extra"):
            self.reserve()
            value = json.loads(path.read_text())
            if mutation == "missing":
                path.unlink()
            else:
                if mutation == "changed-count": value["invocation_count"] = True
                if mutation == "changed-prompt": value["request"]["prompt"] = "Replace authority."
                if mutation == "nested-bool": value["request"]["schema_version"] = True
                if mutation == "extra": value["authority"] = "root"
                path.write_text(json.dumps(value))
            with self.subTest(mutation=mutation), mock.patch.object(provider, "_run") as runner:
                with self.assertRaisesRegex(provider.WorkerProviderError, "DURABLE_STATE_INVALID"):
                    provider.execute_worker(self.request, self.profile)
                runner.assert_not_called()

    def test_request_unknown_fields_bool_limits_prompt_hash_and_symlinks_denied(self):
        cases = []
        for field, value in (("schema_version", True), ("prompt_sha256", "d" * 64),
                             ("attempt_number", 2), ("checkout", str(self.checkout) + "/../checkout")):
            item = copy.deepcopy(self.request); item[field] = value; cases.append(item)
        item = copy.deepcopy(self.request); item["executable"] = "/bin/sh"; cases.append(item)
        item = copy.deepcopy(self.request); item["limits"]["worker_timeout_seconds"] = True; cases.append(item)
        item = copy.deepcopy(self.request); item["prompt"] = "x" * (provider.MAX_PROMPT_BYTES + 1); cases.append(item)
        alias = self.root / "alias"; alias.symlink_to(self.checkout, target_is_directory=True)
        item = copy.deepcopy(self.request); item["checkout"] = str(alias); cases.append(item)
        for request in cases:
            with self.subTest(request=request), mock.patch.object(provider, "_run") as runner:
                with self.assertRaises(provider.WorkerProviderError):
                    provider.execute_worker(request, self.profile)
                runner.assert_not_called()

    def test_unsupported_hard_token_and_dollar_budgets_fail(self):
        for field in ("max_tokens", "max_cost_usd"):
            request = copy.deepcopy(self.request); request["limits"][field] = 1
            with self.assertRaisesRegex(provider.WorkerProviderError, "BUDGET_UNSUPPORTED"):
                provider.validate_worker_request(request)

    def test_profile_and_base_and_schema_changed_deny_before_inference(self):
        request = copy.deepcopy(self.request); request["profile_sha256"] = "f" * 64
        with mock.patch.object(provider, "_run") as runner:
            with self.assertRaisesRegex(provider.WorkerProviderError, "CONFIG_CHANGED"):
                provider.execute_worker(request, self.profile)
            runner.assert_not_called()
        with mock.patch.object(provider, "_run", return_value=process(b"f" * 40)) as runner:
            with self.assertRaisesRegex(provider.WorkerProviderError, "base mismatch"):
                provider.execute_worker(self.request, self.profile)
            self.assertEqual(runner.call_count, 1)
        (self.root / "schemas" / "worker-result.schema.json").write_text("{}")
        with mock.patch.object(provider, "_run") as runner:
            with self.assertRaisesRegex(provider.WorkerProviderError, "schema missing or changed"):
                provider.execute_worker(self.request, self.profile)
            runner.assert_not_called()

    def test_forged_receipt_binding_and_contradictory_success_reject(self):
        receipt, _ = self.execute()
        for key, value in (("task_sha256", "f" * 64), ("schema_version", True), ("exit_code", 1),
                           ("signal", 9), ("descendants_reaped", False), ("session_id", None),
                           ("elapsed_seconds", float("nan")), ("usage_observed", {"input_tokens": True})):
            changed = dict(receipt); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                provider.validate_worker_receipt(changed, self.request, self.profile)

    def test_empty_stream_or_unbounded_time_cannot_be_successful_receipt(self):
        receipt, _ = self.execute()
        for field, value in (("stdout_bytes", 0), ("elapsed_seconds", 11)):
            altered = dict(receipt); altered[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "contradictory successful"):
                provider.validate_worker_receipt(altered, self.request, self.profile)
        receipt, _ = self.execute(process(stream(events()), elapsed_seconds=11))
        self.assertEqual(receipt["completion"], "TIMEOUT")

    def test_public_launch_passes_only_registered_id_and_verifies_receipt(self):
        receipt, _ = self.execute()
        client = mock.Mock(); client.request.return_value = receipt
        module = types.ModuleType("control_plane.isolated_runner")
        module.get_active_launcher = lambda: client
        with mock.patch.dict("sys.modules", {"control_plane.isolated_runner": module}):
            self.assertEqual(provider.launch_worker(self.request, self.profile), receipt)
        client.request.assert_called_once_with("worker-launch", {"registered_request_id": self.request["attempt_id"]})

    def test_no_launcher_never_falls_back_to_a_process(self):
        module = types.ModuleType("control_plane.isolated_runner")
        module.get_active_launcher = mock.Mock(side_effect=PermissionError("ISOLATION_UNAVAILABLE"))
        with mock.patch.dict("sys.modules", {"control_plane.isolated_runner": module}), mock.patch.object(provider, "_run") as runner:
            with self.assertRaisesRegex(PermissionError, "ISOLATION_UNAVAILABLE"):
                provider.launch_worker(self.request, self.profile)
            runner.assert_not_called()

    def test_explicit_trusted_local_uses_its_broker_for_preflight_and_launch(self):
        receipt, _ = self.execute()
        self.profile = replace(self.profile, mode="trusted-local")
        client = mock.Mock()
        client.request.side_effect = [{"inference_invoked": False}, receipt]
        with mock.patch("control_plane.evaluation_broker._client", return_value=client) as factory, \
                mock.patch("control_plane.isolated_runner.get_active_launcher", side_effect=AssertionError("isolated path selected")):
            self.assertEqual(provider.provider_preflight(self.profile), {"inference_invoked": False})
            self.assertEqual(provider.launch_worker(self.request, self.profile), receipt)
        self.assertEqual(factory.call_args_list, [mock.call(self.profile), mock.call(self.profile)])
        self.assertEqual(client.request.call_args_list, [mock.call("provider-preflight", {}),
            mock.call("worker-launch", {"registered_request_id": self.request["attempt_id"]})])

    def test_trusted_local_without_explicit_broker_does_not_fall_back(self):
        self.profile = replace(self.profile, mode="trusted-local")
        with mock.patch("control_plane.evaluation_broker._client", side_effect=PermissionError("explicit broker required")), \
                mock.patch("control_plane.isolated_runner.get_active_launcher") as isolated:
            with self.assertRaisesRegex(PermissionError, "explicit broker required"):
                provider.provider_preflight(self.profile)
            isolated.assert_not_called()

    def test_preflight_uses_only_bounded_worker_runner_and_suppresses_auth_output(self):
        probes = [process((provider.CLI_VERSION + "\n").encode()),
                  process(b"--ask-for-approval"),
                  process(b"--ignore-user-config --ephemeral --sandbox workspace-write danger-full-access --json --model --output-schema --color --cd"),
                  process(stderr=b"Logged in using ChatGPT")]
        with mock.patch.object(provider, "_run", side_effect=probes) as runner:
            report = provider.execute_provider_preflight(self.profile)
        self.assertEqual(runner.call_count, 4)
        self.assertTrue(all(call.args[0] is None for call in runner.call_args_list))
        self.assertFalse(report["inference_invoked"])
        self.assertNotIn("ChatGPT", json.dumps(report))
        self.retention_sink.assert_not_called()

    def test_preflight_rejects_api_auth_old_version_and_missing_security_flag(self):
        good = [process(provider.CLI_VERSION.encode()), process(b"--ask-for-approval"),
                process(b"--ignore-user-config --ephemeral --sandbox workspace-write danger-full-access --json --model --output-schema --color --cd"),
                process(b"Logged in using ChatGPT")]
        for index, response, code in ((0, process(b"codex-cli 0.100.0"), "UNSUPPORTED_PROTOCOL"),
                                      (2, process(b"--json"), "UNSUPPORTED_PROTOCOL"),
                                      (3, process(b"Logged in using an API key"), "AUTH_REQUIRED")):
            probes = list(good); probes[index] = response
            with self.subTest(index=index), mock.patch.object(provider, "_run", side_effect=probes):
                with self.assertRaisesRegex(provider.WorkerProviderError, code):
                    provider.execute_provider_preflight(self.profile)

    def test_public_schema_matches_embedded_contract(self):
        path = Path(__file__).resolve().parents[1] / "schemas" / "worker-result.schema.json"
        self.assertEqual(json.loads(path.read_text()), provider.RESULT_SCHEMA)
        self.assertEqual(digest(path.read_bytes()), provider.RESULT_SCHEMA_SHA256)

    def test_absent_active_boundary_denies_worker_before_git_or_provider(self):
        self.boundary_patch.stop()
        with mock.patch.object(provider, "_run") as runner:
            with self.assertRaises((provider.WorkerProviderError, PermissionError)):
                provider.execute_worker(self.request, self.profile)
            runner.assert_not_called()

    def test_stale_or_spoofed_guard_denies_worker_and_preflight_before_exec(self):
        self.boundary_patch.stop()
        for effect in (PermissionError("ISOLATION_UNAVAILABLE: stale context"),
                       PermissionError("ISOLATION_UNAVAILABLE: wrong request"), True, False, {"isolated": True}):
            with self.subTest(effect=effect), mock.patch(
                    "control_plane.isolated_runner.assert_active_provider_boundary", create=True) as guard, \
                    mock.patch.object(provider, "_run") as runner:
                if isinstance(effect, Exception):
                    guard.side_effect = effect
                else:
                    guard.return_value = effect
                with self.assertRaises((provider.WorkerProviderError, PermissionError)):
                    provider.execute_worker(self.request, self.profile)
                with self.assertRaises((provider.WorkerProviderError, PermissionError)):
                    provider.execute_provider_preflight(self.profile)
                runner.assert_not_called()

    def test_boundary_rechecked_immediately_before_external_argv(self):
        self.boundary_patch.stop()
        with mock.patch("control_plane.isolated_runner.assert_active_provider_boundary", create=True,
                        side_effect=[None, PermissionError("ISOLATION_UNAVAILABLE: changed context")]) as guard, \
                mock.patch.object(provider, "_run", return_value=process((self.request["base_sha"] + "\n").encode())) as runner:
            with self.assertRaisesRegex(PermissionError, "changed context"):
                provider.execute_worker(self.request, self.profile)
            self.assertEqual(guard.call_args_list, [mock.call(self.request, self.profile)] * 2)
            self.assertEqual(runner.call_count, 1)
            self.assertEqual(runner.call_args.args[2][0], "/trusted/git")

    def test_isolated_argv_requires_registered_request_even_with_guard_fixture(self):
        with self.assertRaisesRegex(provider.WorkerProviderError, "registered worker request"):
            provider.build_codex_argv(self.profile, str(self.checkout), self.root / "schema.json")

    def test_isolated_argv_cannot_override_registered_checkout_or_schema(self):
        for checkout, schema in ((str(self.root), self.root / "schemas" / "worker-result.schema.json"),
                                 (str(self.checkout), self.root / "different-schema.json")):
            with self.subTest(checkout=checkout, schema=schema):
                with self.assertRaisesRegex(provider.WorkerProviderError, "registered request or pinned schema"):
                    provider.build_codex_argv(self.profile, checkout, schema, request=self.request)

    def test_trusted_local_stays_workspace_write_after_failed_launch(self):
        self.profile = replace(self.profile, mode="trusted-local")
        self.boundary_patch.stop()
        with mock.patch("control_plane.isolated_runner.assert_active_provider_boundary", create=True,
                        side_effect=AssertionError("isolated admission selected")):
            receipt, runner = self.execute(process(stream(events()), returncode=1))
            self.assertEqual(receipt["completion"], "PROVIDER_FAILED")
            argv = runner.call_args_list[1].args[2]
            self.assertEqual(argv[argv.index("--sandbox") + 1], "workspace-write")
            self.assertNotIn("danger-full-access", argv)
            self.assertEqual(runner.call_count, 2)

    def test_isolated_preflight_rejects_missing_external_mode_before_auth_probe(self):
        probes = [process(provider.CLI_VERSION.encode()), process(b"--ask-for-approval"),
                  process(b"--ignore-user-config --ephemeral --sandbox workspace-write --json --model --output-schema --color --cd")]
        with mock.patch.object(provider, "_run", side_effect=probes) as runner:
            with self.assertRaisesRegex(provider.WorkerProviderError, "UNSUPPORTED_PROTOCOL"):
                provider.execute_provider_preflight(self.profile)
            self.assertEqual(runner.call_count, 3)

    def test_configured_metadata_is_pure_and_not_an_admission_result(self):
        with mock.patch.object(provider, "_profile", side_effect=AssertionError("not a pure query")), \
                mock.patch.object(provider, "_assert_boundary", side_effect=AssertionError("not an admission")), \
                mock.patch.object(provider, "_run", side_effect=AssertionError("no vendor command")):
            self.assertEqual(provider.configured_sandbox_metadata(self.profile), {
                "configured_sandbox_strategy": "external-linux-v1", "configured_cli_sandbox_mode": "danger-full-access"})
            self.assertEqual(provider.configured_sandbox_metadata(replace(self.profile, mode="trusted-local")), {
                "configured_sandbox_strategy": "codex-workspace-write-v1", "configured_cli_sandbox_mode": "workspace-write"})
            with self.assertRaisesRegex(provider.WorkerProviderError, "validated execution profile"):
                provider.configured_sandbox_metadata({"mode": "isolated-linux"})

    def test_caller_cannot_add_sandbox_authority_to_request(self):
        request = copy.deepcopy(self.request)
        request["configured_cli_sandbox_mode"] = "danger-full-access"
        with mock.patch.object(provider, "_run") as runner:
            with self.assertRaisesRegex(provider.WorkerProviderError, "INVALID_TASK"):
                provider.execute_worker(request, self.profile)
            runner.assert_not_called()

    def test_rejected_exec_stream_goes_only_to_private_sink_with_sanitized_diagnostics(self):
        values = events(usage={"input_tokens": 5})
        values[2]["item"]["unknown_extra"] = "RAW_MODEL_SENTINEL"
        output = stream(values)
        receipt, runner = self.execute(process(output, stderr=b"RAW_STDERR_SENTINEL"))
        self.assertEqual(receipt["completion"], "PROTOCOL_INVALID")
        self.assertIsNone(receipt["session_id"])
        self.assertIsNone(receipt["usage_observed"])
        self.assertEqual(runner.call_count, 2)
        args = self.retention_sink.call_args.args
        self.assertEqual(args[:4], (self.request, self.profile, output, b"RAW_STDERR_SENTINEL"))
        self.assertEqual(args[4]["error_code"], "AGENT_FIELDS_UNSUPPORTED")
        self.assertEqual(args[4]["error_line"], 3)
        encoded = provider.canonical_bytes(args[4])
        for secret in (b"RAW_MODEL_SENTINEL", b"RAW_STDERR_SENTINEL", b"fixture-session", b"unknown_extra"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(set(receipt), provider.RECEIPT_FIELDS)

    def test_capture_failure_closes_before_post_head_or_receipt(self):
        self.retention_sink.side_effect = PermissionError("private capture unavailable")
        with mock.patch.object(provider, "_run", side_effect=[
                process((self.request["base_sha"] + "\n").encode()), process(stream(events()))]) as runner:
            with self.assertRaisesRegex(PermissionError, "private capture unavailable"):
                provider.execute_worker(self.request, self.profile)
            self.assertEqual(runner.call_count, 2)

    def test_private_retention_never_falls_back_when_capability_missing(self):
        self.retention_patch.stop()
        module = types.ModuleType("control_plane.isolated_runner")
        with mock.patch.dict("sys.modules", {"control_plane.isolated_runner": module}):
            with self.assertRaisesRegex(provider.WorkerProviderError, "sink unavailable"):
                provider._retain_diagnostics(self.request, self.profile, b"x", b"", {})

    def test_trusted_local_has_no_private_retention_capability(self):
        self.retention_patch.stop()
        self.profile = replace(self.profile, mode="trusted-local")
        with mock.patch("control_plane.isolated_runner.retain_provider_diagnostics", create=True) as sink:
            provider._retain_diagnostics(self.request, self.profile, b"x", b"", {})
            sink.assert_not_called()


class ProtocolDiagnosticTests(unittest.TestCase):
    def diagnostic(self, output, stderr=b""):
        state = {}
        error = None
        try:
            provider.parse_codex_jsonl(output, _diagnostic_state=state)
        except (ValueError, UnicodeError, TypeError, RecursionError) as caught:
            error = caught
        return provider.protocol_diagnostics(output, stderr, error, error_line=state.get("line"))

    def test_sanitizer_retains_only_shape_and_hashes(self):
        values = events()
        values[0]["thread_id"] = "PRIVATE_SESSION_SENTINEL"
        values[2]["item"]["text"] = json.dumps({"schema_version": 1, "status": "completed", "summary": "PRIVATE_SUMMARY_SENTINEL"})
        result = self.diagnostic(stream(values), b"PRIVATE_STDERR_SENTINEL")
        self.assertEqual(result["parse_status"], "accepted")
        self.assertIsNone(result["error_code"])
        self.assertIsNone(result["error_line"])
        self.assertEqual(result["stdout"]["sha256"], digest(stream(values)))
        encoded = provider.canonical_bytes(result)
        for value in (b"PRIVATE_SESSION_SENTINEL", b"PRIVATE_SUMMARY_SENTINEL", b"PRIVATE_STDERR_SENTINEL"):
            self.assertNotIn(value, encoded)

    def test_rejection_line_and_finite_code_without_exception_fragments(self):
        values = events(); values[2]["item"]["opaque-secret-key"] = "SECRET_VALUE_SENTINEL"
        result = self.diagnostic(stream(values))
        self.assertEqual((result["parse_status"], result["error_code"], result["error_line"]),
                         ("rejected", "AGENT_FIELDS_UNSUPPORTED", 3))
        encoded = provider.canonical_bytes(result)
        self.assertNotIn(b"opaque-secret-key", encoded)
        self.assertNotIn(b"SECRET_VALUE_SENTINEL", encoded)
        result = provider.protocol_diagnostics(b"{}", b"", ValueError("PRIVATE_EXCEPTION_SENTINEL"))
        self.assertEqual(result["error_code"], "PROTOCOL_INVALID")
        self.assertNotIn(b"PRIVATE_EXCEPTION_SENTINEL", provider.canonical_bytes(result))

    def test_missing_duplicate_terminal_and_refusal_rules_unchanged(self):
        for output, status, code in ((stream(events()[:-1]), "rejected", "TERMINAL_MISSING"),
                                     (stream(events() + [events()[-1]]), "rejected", "EVENT_AFTER_TERMINAL"),
                                     (stream(events("refused")), "accepted", None)):
            with self.subTest(code=code):
                result = self.diagnostic(output)
                self.assertEqual((result["parse_status"], result["error_code"]), (status, code))
        self.assertEqual(provider.parse_codex_jsonl(stream(events("refused")))["completion"], "REFUSED")

    def test_malformed_utf8_json_and_nested_duplicate_have_safe_codes(self):
        for output, code in ((b"\xff\n", "UTF8_INVALID"), (b'{"SECRET_FRAGMENT"\n', "JSON_INVALID"),
                             (b'{"type":"thread.started","thread_id":"x","nested":{"a":1,"a":2}}\n', "DUPLICATE_JSON_KEY")):
            with self.subTest(code=code):
                result = self.diagnostic(output)
                self.assertEqual(result["error_code"], code)
                self.assertNotIn(b"SECRET_FRAGMENT", provider.canonical_bytes(result))

    def test_large_stream_shape_capture_is_capped_and_prioritizes_failure(self):
        values = events()[:2]
        for index in range(512):
            values.append({"type": "item.completed", "item": {
                "type": "command_execution", **{f"unknown_{number}_{index}": "RAW_TOOL_TEXT_SENTINEL" for number in range(20)}}})
        output = stream(values)
        result = provider.protocol_diagnostics(output, b"", ValueError("invalid provider item"), error_line=257)
        self.assertLessEqual(len(provider.canonical_bytes(result)), provider.MAX_DIAGNOSTIC_BYTES)
        self.assertGreater(result["omitted_line_count"], 0)
        self.assertIn(257, [shape["line"] for shape in result["event_shapes"]])
        self.assertNotIn(b"RAW_TOOL_TEXT_SENTINEL", provider.canonical_bytes(result))
        for shape in result["event_shapes"]:
            self.assertLessEqual(len(shape.get("fields", [])), provider.MAX_DIAGNOSTIC_FIELDS)
            self.assertLessEqual(len(shape.get("item", {}).get("fields", [])), provider.MAX_DIAGNOSTIC_FIELDS)

    def test_escaped_surrogates_cannot_break_diagnostic_retention(self):
        output = b'{"type":"\\ud800","\\ud800":"sensitive"}\n'
        result = self.diagnostic(output)
        self.assertEqual(result["parse_status"], "rejected")
        self.assertNotIn(b"sensitive", provider.canonical_bytes(result))

    def test_schema_valid_final_message_diagnostics_do_not_change_parser_result(self):
        output = stream(events(usage={"input_tokens": 19, "output_tokens": 4}))
        baseline = provider.parse_codex_jsonl(output)
        state = {}
        observed = provider.parse_codex_jsonl(output, _diagnostic_state=state)
        self.assertEqual(observed, baseline)
        self.assertEqual(self.diagnostic(output)["parse_status"], "accepted")


class SchemaLayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "trusted"
        self.root.mkdir()
        self.profile = types.SimpleNamespace(paths={"trusted_code_root": str(self.root)})
        self.source = self.root / "schemas" / "worker-result.schema.json"
        self.installed = self.root / "control_plane" / "resources" / "worker-result.schema.json"
        self.public_bytes = (Path(__file__).resolve().parents[1] / "schemas" / "worker-result.schema.json").read_bytes()

    def write_schema(self, path, data=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.public_bytes if data is None else data)

    def test_source_layout_uses_pinned_root_schema(self):
        self.write_schema(self.source)
        self.assertEqual(provider._schema_path(self.profile), self.source)

    def test_installed_layout_uses_resource_only_inside_pinned_root(self):
        self.write_schema(self.installed)
        self.assertEqual(provider._schema_path(self.profile), self.installed)
        self.assertEqual(provider.build_codex_argv(self.profile_with_tool(), "/owned/checkout", self.installed)[-2], str(self.installed))

    def profile_with_tool(self):
        return types.SimpleNamespace(mode="trusted-local", tools={"provider": types.SimpleNamespace(path="/trusted/codex")})

    def test_both_layouts_must_match_exact_public_bytes(self):
        self.write_schema(self.source)
        self.write_schema(self.installed)
        self.assertEqual(provider._schema_path(self.profile), self.source)
        self.installed.write_bytes(self.public_bytes + b"\n")
        with self.assertRaisesRegex(provider.WorkerProviderError, "CONFIG_CHANGED"):
            provider._schema_path(self.profile)

    def test_present_invalid_source_never_falls_back_to_valid_installed_copy(self):
        self.write_schema(self.source, b"{}")
        self.write_schema(self.installed)
        with self.assertRaisesRegex(provider.WorkerProviderError, "CONFIG_CHANGED"):
            provider._schema_path(self.profile)

    def test_missing_pinned_schema_does_not_use_module_checkout(self):
        with self.assertRaisesRegex(provider.WorkerProviderError, "CONFIG_CHANGED"):
            provider._schema_path(self.profile)

    def test_schema_symlink_outside_pinned_root_is_denied(self):
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_bytes(self.public_bytes)
        self.source.parent.mkdir()
        self.source.symlink_to(outside)
        self.write_schema(self.installed)
        with self.assertRaisesRegex(provider.WorkerProviderError, "CONFIG_CHANGED"):
            provider._schema_path(self.profile)


class ValidatedProfileAdmissionFixtures(unittest.TestCase):
    def test_real_profile_type_policy_and_pinned_executable_are_required(self):
        from control_plane.execution_profile import ExecutionProfile, Role, Tool
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "codex-fixture"
            path.write_bytes(b"fixture executable bytes; never executed")
            profile = ExecutionProfile(
                mode="isolated-linux", tools={"provider": Tool(str(path), digest(path.read_bytes()), provider.CLI_VERSION)},
                provider={"backend": "codex", "model": provider.MODEL, "reasoning_effort": "medium", "service_tier": "default"},
                roles={"worker": Role(1000, 1000)}, auth_account="fixture", auth_home=Path(name), paths={}, sqlite={}, sha256="e" * 64, _json=b"{}")
            provider._profile(profile)
            root_worker = replace(profile, mode="trusted-local", roles={"worker": Role(0, 0)})
            with self.assertRaisesRegex(provider.WorkerProviderError, "non-root worker"):
                provider._profile(root_worker)
            with self.assertRaisesRegex(provider.WorkerProviderError, "validated execution profile"):
                provider._profile(profile.raw)
            path.write_bytes(b"changed executable fixture")
            with self.assertRaisesRegex(provider.WorkerProviderError, "identity changed"):
                provider._profile(profile)


if __name__ == "__main__":
    unittest.main()
