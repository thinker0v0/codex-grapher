import json
import tempfile
import unittest
from pathlib import Path

import jsonschema

from control_plane.runtime_config import load_runtime, validate_source_security


ROOT = Path(__file__).resolve().parents[1]


class RuntimeConfigTests(unittest.TestCase):
    def test_example_is_exactly_the_four_final_routes(self):
        example = ROOT / "config/project-runtime.example.json"
        source = json.loads(example.read_text())
        schema = json.loads((ROOT / "schemas/project-runtime.schema.json").read_text())
        jsonschema.validate(source, schema)
        runtime = load_runtime(example)
        self.assertEqual(set(runtime), {"nomad", "opensource", "business", "hynix"})
        self.assertEqual(runtime["nomad"]["worker_project_id"], "fin-korea")
        self.assertEqual(runtime["opensource"]["accepted_ref"], "refs/ai-ops/accepted/opensource")
        for project, entry in runtime.items():
            worker = entry["worker_project_id"]
            self.assertEqual(entry["repo"], f"/srv/hermes/{worker}/workspace")
            self.assertEqual(
                entry["binding"], f"/srv/hermes/{worker}/runtime/repo-binding.json"
            )
            self.assertEqual(
                entry["evidence_root"], f"/srv/hermes/evaluator/artifacts/{project}"
            )

    def test_wrong_route_alias_duplicate_path_and_extra_field_are_denied(self):
        source = json.loads((ROOT / "config/project-runtime.example.json").read_text())
        mutations = []
        wrong_worker = json.loads(json.dumps(source))
        wrong_worker["projects"]["nomad"]["worker_project_id"] = "fin-global"
        mutations.append(wrong_worker)
        duplicate = json.loads(json.dumps(source))
        duplicate["projects"]["hynix"]["repo"] = duplicate["projects"]["business"]["repo"]
        mutations.append(duplicate)
        extra = json.loads(json.dumps(source))
        extra["projects"]["opensource"]["secret"] = "must-not-be-accepted"
        mutations.append(extra)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            for value in mutations:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_runtime(path)

    def test_symlink_runtime_source_is_denied(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "runtime.json"
            target.write_bytes((ROOT / "config/project-runtime.example.json").read_bytes())
            link = root / "runtime-link.json"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                load_runtime(link)
            with self.assertRaises(ValueError):
                validate_source_security(link, False)

    def test_cross_swapped_paths_are_rejected_by_parser_and_schema(self):
        source = json.loads((ROOT / "config/project-runtime.example.json").read_text())
        schema = json.loads((ROOT / "schemas/project-runtime.schema.json").read_text())
        mutations = []
        for field in ("repo", "binding", "evidence_root"):
            swapped = json.loads(json.dumps(source))
            left = swapped["projects"]["nomad"][field]
            swapped["projects"]["nomad"][field] = swapped["projects"]["opensource"][field]
            swapped["projects"]["opensource"][field] = left
            mutations.append(swapped)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            for value in mutations:
                with self.subTest(value=value):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(ValueError):
                        load_runtime(path)
                    with self.assertRaises(jsonschema.ValidationError):
                        jsonschema.validate(value, schema)

    def test_parser_and_schema_reject_the_same_route_field_drift(self):
        source = json.loads((ROOT / "config/project-runtime.example.json").read_text())
        schema = json.loads((ROOT / "schemas/project-runtime.schema.json").read_text())
        mutations = []
        for project in source["projects"]:
            for field in (
                "worker_project_id", "repo", "binding", "evidence_root", "accepted_ref"
            ):
                changed = json.loads(json.dumps(source))
                changed["projects"][project][field] += "-drift"
                mutations.append((project, field, changed))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            for project, field, value in mutations:
                with self.subTest(project=project, field=field):
                    path.write_text(json.dumps(value))
                    with self.assertRaises(ValueError):
                        load_runtime(path)
                    with self.assertRaises(jsonschema.ValidationError):
                        jsonschema.validate(value, schema)


if __name__ == "__main__":
    unittest.main()
