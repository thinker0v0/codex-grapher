"""Control preparation must reject false negatives and incomplete source trees."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import tarfile
import tempfile
import unittest
from unittest import mock

from control_plane.repository_task import validate_checks, validate_task
from control_plane.evaluation_policy import TaskEvaluationPolicy


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("representative_preparation", ROOT / "scripts/prepare-representative-tasks.py")
assert SPEC is not None and SPEC.loader is not None
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)


class RepresentativePreparationTests(unittest.TestCase):
    def test_parent_alias_is_canonicalized_before_any_frozen_control_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            (real / "python").write_bytes(b"fixture executable")
            (real / "git").write_bytes(b"fixture executable")
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            class BeforeExecution(Exception):
                pass
            with mock.patch.object(PREP, "record_command", side_effect=BeforeExecution) as command:
                with self.assertRaises(BeforeExecution):
                    PREP.prepare(ROOT / "docs/cycles/20260921-portable-workers/representative-task-cases.json",
                                 root / "new-output", alias / "python", alias / "git")
            self.assertEqual(command.call_args.args[0][0], str(real / "python"))

    def test_frozen_commands_roundtrip_into_strict_public_contract_without_seed_hints(self):
        raw = (ROOT / "docs/cycles/20260921-portable-workers/representative-task-cases.json").read_bytes()
        self.assertEqual(PREP.sha256(raw), PREP.MANIFEST_SHA256)
        for case in json.loads(raw)["cases"]:
            with self.subTest(project=case["project_id"]):
                task, policy, checks = PREP.task_documents(case, "/task local/venv/bin/python", "a" * 40)
                validate_task(task)
                validate_checks(checks)
                TaskEvaluationPolicy(json.dumps(policy).encode())
                self.assertEqual(shlex.split(task["required_tests"][0]),
                    ["/task local/venv/bin/python", "-I", "-B", "-c", case["required_python_source"]])
                self.assertEqual(checks["checks"][0]["argv"][-1], case["independent_evaluator_python_source"])
                self.assertNotIn("seed", task)
                self.assertNotIn(case["commit"], json.dumps(task))
                self.assertNotIn(case["seed"]["old"], task["objective"])

    def test_import_errors_cannot_count_as_seeded_negative(self):
        intended = "AssertionError: (11, 'male')"
        self.assertEqual(PREP.negative_reason("humanize", "independent", 1, intended),
                         "EXPECTED_SEEDED_ASSERTION_FAILURE")
        for output in [intended + "\nModuleNotFoundError: pytest", "ImportError: missing", "AssertionError: wrong cause"]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                PREP.negative_reason("humanize", "independent", 1, output)
        for code in (0, -9, 2):
            with self.subTest(code=code), self.assertRaises(ValueError):
                PREP.negative_reason("humanize", "independent", code, intended)

    def test_itsdangerous_negative_uses_actual_upstream_test_name(self):
        message = "FAILED test_int_bytes[192-\\xc0]\nAssertionError: assert bytes differ"
        self.assertEqual(PREP.negative_reason("itsdangerous", "required", 1, message),
                         "EXPECTED_SEEDED_ASSERTION_FAILURE")

    def test_tar_links_traversal_duplicates_and_git_injection_are_rejected(self):
        for name, kind, duplicate in [("../outside", tarfile.REGTYPE, False),
                ("/outside", tarfile.REGTYPE, False), ("a/.git/config", tarfile.REGTYPE, False),
                ("link", tarfile.SYMTYPE, False), ("hard", tarfile.LNKTYPE, False),
                ("fifo", tarfile.FIFOTYPE, False), ("same", tarfile.REGTYPE, True)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                raw = io.BytesIO()
                with tarfile.open(fileobj=raw, mode="w") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/outside"
                    archive.addfile(member, io.BytesIO())
                    if duplicate:
                        archive.addfile(member, io.BytesIO())
                with self.assertRaises(ValueError):
                    PREP.extract_snapshot(raw.getvalue(), Path(temporary) / "snapshot")
                self.assertFalse((Path(temporary) / "outside").exists())

    def test_missing_export_ignored_file_and_modified_git_blob_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b"complete source\n"
            path = root / "source.py"
            path.write_bytes(raw)
            path.chmod(0o644)
            oid = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            records = f"100644 blob {oid}\tsource.py\0".encode()
            self.assertEqual(PREP.verify_full_tree(root, records), 1)
            with self.assertRaises(ValueError):
                PREP.verify_full_tree(root, records + f"100644 blob {oid}\tomitted.py\0".encode())
            path.write_bytes(b"changed source\n")
            with self.assertRaises(ValueError):
                PREP.verify_full_tree(root, records)

    def test_only_seeded_source_changes_and_wrong_seed_refuses_before_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original, seeded = b"value = 2\n", b"value = 1\n"
            (root / "source.py").write_bytes(original)
            (root / "LICENSE").write_bytes(b"license notice\n")
            case = {"source_path": "source.py", "files": {
                "LICENSE": {"sha256": PREP.sha256(b"license notice\n"), "bytes": 15}},
                "seed": {"old": "value = 2\n", "new": "value = 1\n", "expected_count": 1,
                         "original_sha256": PREP.sha256(original), "seeded_sha256": PREP.sha256(seeded)}}
            before = PREP.inventory(root)
            wrong = json.loads(json.dumps(case))
            wrong["seed"]["seeded_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                PREP.apply_seed(wrong, root)
            self.assertEqual(PREP.inventory(root), before)
            result = PREP.apply_seed(case, root)
            self.assertEqual(result["changed_paths"], ["source.py"])
            self.assertEqual((root / "LICENSE").read_bytes(), b"license notice\n")


if __name__ == "__main__":
    unittest.main()
