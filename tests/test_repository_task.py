"""Public admission checks: invalid documents cannot become task authority."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from control_plane.repository_task import (
    DEFAULT_LIMITS, MAX_ARRAY_ITEMS, MAX_DOCUMENT_BYTES, MAX_LIMITS,
    RepositoryTaskError, canonical, load_repository_task, parse_checks_bytes,
    parse_task_bytes, read_regular, strict_json_bytes, validate_checks, validate_task,
)


def task() -> dict:
    return {
        "schema_version": 1, "project_id": "external-repo", "task_id": "fix-1",
        "idempotency_key": "fix-1.once", "base_sha": "a" * 40,
        "objective": "Fix the regression.",
        "acceptance_criteria": ["Existing behavior is preserved."],
        "allowed_paths": ["src/module.py", "tests/"],
        "required_tests": ["python3 -m unittest discover -s tests"],
        "worker": {"backend": "codex"},
        "evaluation": {"policy": "acceptance/policy.json", "checks": "acceptance/checks.json"},
    }


def checks() -> dict:
    return {"schema_version": 1, "checks": [
        {"id": "behavior", "argv": ["python3", "-I", "-c", "assert 1 + 1 == 2"]},
    ]}


class RepositoryTaskTests(unittest.TestCase):
    def assert_invalid(self, callback, value, code="INVALID_TASK"):
        with self.assertRaises(RepositoryTaskError) as caught:
            callback(value)
        self.assertEqual(caught.exception.code, code)

    def test_defaults_return_a_copy_and_leave_source_bytes_available(self):
        original = task()
        raw = json.dumps(original, indent=2).encode() + b"\n"
        result = parse_task_bytes(raw)
        self.assertEqual(result["limits"], DEFAULT_LIMITS)
        self.assertNotIn("limits", original)
        result["worker"]["backend"] = "changed"
        self.assertEqual(original["worker"]["backend"], "codex")
        self.assertNotEqual(hashlib.sha256(raw).digest(), hashlib.sha256(canonical(parse_task_bytes(raw))).digest())

    def test_partial_and_maximum_limits(self):
        value = task()
        value["limits"] = {"worker_timeout_seconds": 10}
        self.assertEqual(validate_task(value)["limits"], {**DEFAULT_LIMITS, "worker_timeout_seconds": 10})
        value["limits"] = dict(MAX_LIMITS)
        self.assertEqual(validate_task(value)["limits"], MAX_LIMITS)
        value["limits"] = {name: 1 for name in MAX_LIMITS}
        self.assertEqual(validate_task(value)["limits"], value["limits"])

    def test_every_limit_rejects_bool_float_zero_negative_and_overflow(self):
        for name, maximum in MAX_LIMITS.items():
            for invalid in (True, False, 1.0, 0, -1, maximum + 1, "1", None):
                with self.subTest(name=name, invalid=invalid):
                    value = task()
                    value["limits"] = {name: invalid}
                    self.assert_invalid(validate_task, value)

    def test_unsupported_budgets_are_classified_and_never_ignored(self):
        for field in ("max_tokens", "max_cost_usd", "token_budget", "max_dollars"):
            for location in ("root", "limits", "budget"):
                with self.subTest(field=field, location=location):
                    value = task()
                    if location == "root":
                        value[field] = 1
                    else:
                        value[location] = {field: 1}
                    self.assert_invalid(validate_task, value, "BUDGET_UNSUPPORTED")

    def test_task_cannot_select_authority(self):
        fields = ("uid", "gid", "executable", "home", "environment", "key", "socket", "profile", "credential_path")
        for field in fields:
            for location in ("root", "worker", "evaluation", "limits"):
                with self.subTest(field=field, location=location):
                    value = task()
                    target = value if location == "root" else value.setdefault(location, {})
                    target[field] = "attacker-selected"
                    self.assert_invalid(validate_task, value)

    def test_unknown_and_missing_fields_at_each_object(self):
        for name in task():
            value = task()
            del value[name]
            self.assert_invalid(validate_task, value)
        for location in ("root", "worker", "evaluation", "limits"):
            value = task()
            target = value if location == "root" else value.setdefault(location, {})
            target["unknown"] = 1
            self.assert_invalid(validate_task, value)
        for invalid in (None, [], "task", True):
            self.assert_invalid(validate_task, invalid)

    def test_schema_and_backend_are_exact(self):
        for invalid in (True, 1.0, "1", 0, 2):
            value = task()
            value["schema_version"] = invalid
            self.assert_invalid(validate_task, value)
        for invalid in ("claude", "Codex", "", None):
            value = task()
            value["worker"]["backend"] = invalid
            self.assert_invalid(validate_task, value)

    def test_ids_hashes_and_text_are_bounded_and_exact(self):
        for field in ("project_id", "task_id", "idempotency_key"):
            for invalid in ("", "../escape", ".hidden", "has space", "a/child", "a\n", "x" * 201, True):
                value = task()
                value[field] = invalid
                self.assert_invalid(validate_task, value)
        for invalid in ("a" * 39, "A" * 40, "g" * 40, "a" * 40 + "\n", True):
            value = task()
            value["base_sha"] = invalid
            self.assert_invalid(validate_task, value)
        for invalid in ("", " \n", "bad\x00text", "x" * 65537, True, "\ud800"):
            value = task()
            value["objective"] = invalid
            self.assert_invalid(validate_task, value)
        value = task()
        value["project_id"] = "x" * 200
        self.assertEqual(validate_task(value)["project_id"], value["project_id"])

    def test_relative_paths_cannot_escape_or_name_git_metadata(self):
        bad = ("/absolute", "../escape", "a/../b", "a/./b", ".", "a//b", "//server/share",
               "C:/windows", "a\\b", ".git", ".git/config", "a/.GiT/config", "a/\nname", "a/\x7fname", "src//")
        for path in bad:
            for field in ("allowed_paths", "policy", "checks"):
                with self.subTest(path=path, field=field):
                    value = task()
                    if field == "allowed_paths":
                        value[field] = [path]
                    else:
                        value["evaluation"][field] = path
                    self.assert_invalid(validate_task, value)
        value = task()
        value["allowed_paths"] = ["src/", "src/*.py", ".github/workflows/ci.yml", "src/한국어.py"]
        self.assertEqual(validate_task(value)["allowed_paths"], value["allowed_paths"])
        value["evaluation"]["checks"] = "acceptance/"
        self.assert_invalid(validate_task, value)

    def test_task_lists_are_nonempty_ordered_and_bounded(self):
        for field in ("allowed_paths", "required_tests", "acceptance_criteria"):
            for invalid in ([], "not a list", ["ok"] * (MAX_ARRAY_ITEMS + 1), [None], [""]):
                value = task()
                value[field] = invalid
                self.assert_invalid(validate_task, value)
        value = task()
        value["required_tests"] = ["first", "second", "first"]
        self.assertEqual(validate_task(value)["required_tests"], value["required_tests"])

    def test_checks_preserve_inline_code_and_order_in_independent_copy(self):
        value = checks()
        value["checks"].append({"id": "second", "argv": ["python3", "-c", "print('한글')\nassert True"]})
        result = parse_checks_bytes(canonical(value))
        self.assertEqual(result, value)
        result["checks"][0]["argv"].append("changed")
        self.assertNotEqual(result, value)

    def test_checks_reject_duplicate_ids_and_unknown_nested_fields(self):
        value = checks()
        value["checks"].append({"id": "behavior", "argv": ["different"]})
        self.assert_invalid(validate_checks, value)
        for location in ("root", "check"):
            value = checks()
            target = value if location == "root" else value["checks"][0]
            target["shell"] = True
            self.assert_invalid(validate_checks, value)

    def test_checks_validate_all_container_and_value_types(self):
        for invalid in (True, 1.0, "1", 2):
            value = checks()
            value["schema_version"] = invalid
            self.assert_invalid(validate_checks, value)
        for invalid in ([], "command", None, ["x"] * (MAX_ARRAY_ITEMS + 1), [True], [""], ["\x00"]):
            value = checks()
            value["checks"][0]["argv"] = invalid
            self.assert_invalid(validate_checks, value)
        for invalid in ([], {}, [None], [{"id": "x"}], [checks()["checks"][0]] * 257):
            value = checks()
            value["checks"] = invalid
            self.assert_invalid(validate_checks, value)


class StrictJSONTests(unittest.TestCase):
    def test_duplicate_keys_at_root_and_nested_levels(self):
        for raw in (b'{"a":1,"a":2}', b'{"nested":{"x":1,"x":2}}', b'{"a":1,"\\u0061":2}'):
            with self.assertRaisesRegex(RepositoryTaskError, "duplicate"):
                strict_json_bytes(raw)

    def test_malformed_nonfinite_oversized_and_invalid_unicode_documents(self):
        values = (b"", b"{} {}", b"{", b"NaN", b"Infinity", b"-Infinity", b"1e999",
                  b"\xff", b"\xef\xbb\xbf{}", b'"\\ud800"', b"[" * 70 + b"0" + b"]" * 70,
                  b" " * (MAX_DOCUMENT_BYTES + 1), "{}")
        for raw in values:
            with self.subTest(raw=repr(raw)[:80]), self.assertRaises(RepositoryTaskError):
                strict_json_bytes(raw)

    def test_canonical_is_exact_and_rejects_non_json_inputs(self):
        self.assertEqual(canonical({"z": [True, None, 1], "a": "한"}), b'{"a":"\\ud55c","z":[true,null,1]}')
        for invalid in ({1: "coerced"}, {"x": float("nan")}, {"x": float("inf")}, (1, 2), {"x": "\udfff"}):
            with self.assertRaises(RepositoryTaskError):
                canonical(invalid)

    def test_regular_file_load_preserves_bytes_and_rejects_nonregular_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "task.json"
            raw = json.dumps(task(), indent=2).encode() + b"\n"
            path.write_bytes(raw)
            self.assertEqual(read_regular(path), raw)
            self.assertEqual(load_repository_task(path), validate_task(task()))
            link = root / "symlink"
            link.symlink_to(path)
            directory_link = root / "linked-directory"
            directory_link.symlink_to(root, target_is_directory=True)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            empty = root / "empty"
            empty.touch()
            oversized = root / "oversized"
            with oversized.open("wb") as stream:
                stream.truncate(MAX_DOCUMENT_BYTES + 1)
            for invalid in (root, link, directory_link / "task.json", fifo, empty, oversized, root / "absent"):
                with self.subTest(path=invalid), self.assertRaises(RepositoryTaskError):
                    read_regular(invalid)

    def test_public_schemas_are_strict_and_match_documented_limit_constants(self):
        root = Path(__file__).resolve().parents[1] / "schemas"
        task_schema = strict_json_bytes((root / "repository-task.schema.json").read_bytes())
        checks_schema = strict_json_bytes((root / "repository-checks.schema.json").read_bytes())
        self.assertFalse(task_schema["additionalProperties"])
        self.assertFalse(checks_schema["additionalProperties"])
        for name, definition in task_schema["properties"]["limits"]["properties"].items():
            self.assertEqual(definition["default"], DEFAULT_LIMITS[name])
            self.assertEqual(definition["maximum"], MAX_LIMITS[name])

    def test_file_mutation_during_read_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "task.json"
            path.write_bytes(canonical(task()))
            original_read = os.read
            changed = False

            def mutate_after_read(descriptor, size):
                nonlocal changed
                data = original_read(descriptor, size)
                if not changed:
                    changed = True
                    path.write_bytes(b"{}")
                return data

            with mock.patch("control_plane.repository_task.os.read", side_effect=mutate_after_read):
                with self.assertRaisesRegex(RepositoryTaskError, "changed"):
                    read_regular(path)


if __name__ == "__main__":
    unittest.main()
