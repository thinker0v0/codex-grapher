"""Public identifiers fit their derived worker and sealed-receipt protocols."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import jsonschema

from control_plane import repository_workflow
from control_plane.repository_task import (
    MAX_CHECK_IDENTIFIER_LENGTH, MAX_LIMITS, MAX_TASK_IDENTIFIER_LENGTH,
    RepositoryTaskError, canonical, parse_checks_bytes, parse_task_bytes,
)
from control_plane.sealed_protocol import ProtocolError, identifier
from control_plane.worker_provider import validate_worker_request
from tests.test_repository_task import checks, task


class RepositoryIdentifierTests(unittest.TestCase):
    def test_task_identifier_exact_derived_protocol_boundary(self):
        self.assertEqual(MAX_TASK_IDENTIFIER_LENGTH, 173)
        value = task()
        value["task_id"] = "t" * 173
        self.assertEqual(parse_task_bytes(canonical(value))["task_id"], value["task_id"])
        value["task_id"] += "t"
        with self.assertRaises(RepositoryTaskError) as caught:
            parse_task_bytes(canonical(value))
        self.assertEqual(caught.exception.code, "INVALID_TASK")

    def test_project_and_idempotency_keep_their_200_character_boundary(self):
        for field in ("project_id", "idempotency_key"):
            with self.subTest(field=field):
                value = task()
                value[field] = "a" * 200
                self.assertEqual(parse_task_bytes(canonical(value))[field], value[field])
                value[field] += "a"
                with self.assertRaises(RepositoryTaskError):
                    parse_task_bytes(canonical(value))

    def test_check_identifier_matches_sealed_protocol_boundary(self):
        self.assertEqual(MAX_CHECK_IDENTIFIER_LENGTH, 192)
        value = checks()
        value["checks"][0]["id"] = "c" * 192
        parsed = parse_checks_bytes(canonical(value))
        identifier(parsed["checks"][0]["id"])
        value["checks"][0]["id"] += "c"
        with self.assertRaises(RepositoryTaskError):
            parse_checks_bytes(canonical(value))
        with self.assertRaises(ProtocolError):
            identifier(value["checks"][0]["id"])

    def test_public_schemas_agree_with_every_identifier_boundary(self):
        schemas = Path(__file__).resolve().parents[1] / "schemas"
        task_schema = json.loads((schemas / "repository-task.schema.json").read_bytes())
        check_schema = json.loads((schemas / "repository-checks.schema.json").read_bytes())
        for schema in (task_schema, check_schema):
            jsonschema.Draft202012Validator.check_schema(schema)
        task_validator = jsonschema.Draft202012Validator(task_schema)
        check_validator = jsonschema.Draft202012Validator(check_schema)
        for field, limit in (("task_id", 173), ("project_id", 200), ("idempotency_key", 200)):
            with self.subTest(field=field):
                value = task()
                value[field] = "a" * limit
                task_validator.validate(value)
                parse_task_bytes(canonical(value))
                value[field] += "a"
                with self.assertRaises(jsonschema.ValidationError):
                    task_validator.validate(value)
                with self.assertRaises(RepositoryTaskError):
                    parse_task_bytes(canonical(value))
        value = checks()
        value["checks"][0]["id"] = "c" * 192
        check_validator.validate(value)
        parse_checks_bytes(canonical(value))
        value["checks"][0]["id"] += "c"
        with self.assertRaises(jsonschema.ValidationError):
            check_validator.validate(value)
        with self.assertRaises(RepositoryTaskError):
            parse_checks_bytes(canonical(value))

    def test_all_permitted_attempt_suffixes_fit_worker_and_receipt_identifiers(self):
        # The fixed maximum of three launches keeps the derived attempt suffix
        # one digit wide; changing that bound must reconsider public task IDs.
        self.assertEqual(MAX_LIMITS["worker_invocations"], 3)
        task_id = "t" * 173
        for suffix in ("-evaluation-v1", "-acceptance-v1"):
            derived = task_id + suffix
            self.assertEqual(len(derived), 187)
            identifier(derived)
        independent_run_id = "independent-" + "a" * 64
        self.assertEqual(len(independent_run_id), 76)
        identifier(independent_run_id)
        prompt = "Disclosed protocol validation fixture."
        with tempfile.TemporaryDirectory(prefix="grapher-id-protocol-") as temporary:
            checkout = Path(temporary) / "checkout"
            checkout.mkdir()
            (checkout / ".git").mkdir()
            for number in range(1, MAX_LIMITS["worker_invocations"] + 1):
                with self.subTest(attempt=number):
                    attempt_id = f"{task_id}-attempt-{number}"
                    required_run_id = attempt_id + "-required"
                    self.assertEqual(len(required_run_id), 192)
                    identifier(required_run_id)
                    with self.assertRaises(ProtocolError):
                        identifier("t" + required_run_id)
                    request = {
                        "schema_version": 1, "project_id": "p" * 200,
                        "task_id": task_id, "idempotency_key": "i" * 200,
                        "attempt_id": attempt_id, "attempt_number": number,
                        "base_sha": "a" * 40, "checkout": str(checkout),
                        "task_sha256": "b" * 64, "profile_sha256": "c" * 64,
                        "prompt": prompt, "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                        "limits": {"worker_invocations": 3, "worker_timeout_seconds": 30,
                                   "max_output_bytes": 65536},
                    }
                    self.assertEqual(validate_worker_request(request), request)

    def test_task_ref_shape_matches_git_and_public_schema(self):
        schema_path = Path(__file__).resolve().parents[1] / "schemas/repository-task.schema.json"
        validator = jsonschema.Draft202012Validator(json.loads(schema_path.read_bytes()))
        environment = {
            "PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        }
        # task_id is an intermediate component; Git permits a trailing dot
        # and case-sensitive .LOCK there, while rejecting '..' and '.lock'.
        cases = {"a..b": False, "a.lock": False, "a.": True,
                 "a.LOCK": True, "a.locked": True, "a.lock.": True}
        with tempfile.TemporaryDirectory(prefix="grapher-id-git-ref-") as temporary:
            for task_id, accepted in cases.items():
                with self.subTest(task_id=task_id):
                    reference = f"refs/ai-ops/candidates/{task_id}/" + "a" * 40
                    result = subprocess.run(["/usr/bin/git", "check-ref-format", reference],
                                            env=environment, cwd=temporary, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode == 0, accepted, result.stderr.decode())
                    value = task()
                    value["task_id"] = task_id
                    if accepted:
                        validator.validate(value)
                        self.assertEqual(parse_task_bytes(canonical(value))["task_id"], task_id)
                    else:
                        with self.assertRaises(jsonschema.ValidationError):
                            validator.validate(value)
                        with self.assertRaises(RepositoryTaskError):
                            parse_task_bytes(canonical(value))
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_git_ref_restriction_does_not_change_other_identifier_fields(self):
        schemas = Path(__file__).resolve().parents[1] / "schemas"
        task_validator = jsonschema.Draft202012Validator(json.loads(
            (schemas / "repository-task.schema.json").read_bytes()))
        check_validator = jsonschema.Draft202012Validator(json.loads(
            (schemas / "repository-checks.schema.json").read_bytes()))
        for spelling in ("a..b", "a.lock", "a.", "a.LOCK"):
            for field in ("project_id", "idempotency_key"):
                with self.subTest(spelling=spelling, field=field):
                    value = task()
                    value[field] = spelling
                    task_validator.validate(value)
                    self.assertEqual(parse_task_bytes(canonical(value))[field], spelling)
            with self.subTest(spelling=spelling, field="check.id"):
                value = checks()
                value["checks"][0]["id"] = spelling
                check_validator.validate(value)
                self.assertEqual(parse_checks_bytes(canonical(value))["checks"][0]["id"], spelling)
                identifier(spelling)

    def test_invalid_task_identifiers_rejected_before_profile_git_or_workspace_effects(self):
        with tempfile.TemporaryDirectory(prefix="grapher-id-admission-") as temporary:
            directory = Path(temporary)
            source, workspace = directory / "source", directory / "workspace"
            source.mkdir()
            task_path, profile_path = directory / "task.json", directory / "profile.json"
            profile_path.write_bytes(b"{}")
            for task_id in ("t" * 174, "a..b", "a.lock"):
                with self.subTest(task_id=task_id):
                    value = task()
                    value["task_id"] = task_id
                    task_bytes = canonical(value)
                    task_path.write_bytes(task_bytes)
                    with patch.object(repository_workflow, "_profile", side_effect=AssertionError("profile validation ran before task rejection")) as profile, \
                         patch.object(repository_workflow, "_git", side_effect=AssertionError("Git ran before task rejection")) as git, \
                         patch.object(repository_workflow, "_snapshot_repository", side_effect=AssertionError("snapshot ran before task rejection")) as snapshot:
                        with self.assertRaises(RepositoryTaskError) as caught:
                            repository_workflow.initialize_repository_workflow(source, task_path, workspace, profile_path)
                        self.assertEqual(caught.exception.code, "INVALID_TASK")
                        profile.assert_not_called()
                        git.assert_not_called()
                        snapshot.assert_not_called()
                    self.assertFalse(workspace.exists())
                    self.assertEqual(list(source.iterdir()), [])
                    self.assertEqual(task_path.read_bytes(), task_bytes)
                    self.assertEqual(profile_path.read_bytes(), b"{}")


if __name__ == "__main__":
    unittest.main()
