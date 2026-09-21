"""Build and install the public source archive without network or host writes."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SourceDistributionTests(unittest.TestCase):
    def test_source_archive_installs_and_preserves_documented_development_workflow(self):
        # Build only in a copy: setuptools creates egg-info during sdist creation.
        with tempfile.TemporaryDirectory(prefix="grapher-sdist-test-") as temporary:
            temporary = Path(temporary)
            source = temporary / "source"
            source.mkdir()
            manifest = (ROOT / "MANIFEST.in").read_text()
            public_paths = [line.removeprefix("include ") for line in manifest.splitlines()
                            if line.startswith("include ")]
            self.assertTrue(public_paths)
            for relative in public_paths:
                path = Path(relative)
                self.assertFalse(path.is_absolute())
                self.assertNotIn("..", path.parts)
                self.assertNotRegex(relative, r"[?*\[]", "public sources must be explicitly listed")
                target = source / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / path, target)
            # These are inert marker files, not real credentials or runtime data.
            excluded = [".env", ".evaluator-private/local.pem", "config/project-runtime.json",
                        "artifacts/result.json", "evidence/assessments/unreviewed.json",
                        "docs/unreviewed.json", "secrets/local.key", "graph.sqlite",
                        "control_plane/local_private.py", "tests/test_unreviewed.py"]
            for relative in excluded:
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("not part of the public distribution\n")
            environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INDEX": "1",
                           "PIP_NO_CACHE_DIR": "1"}
            environment.pop("PYTHONPATH", None)

            def run(arguments, *, cwd, env=environment):
                result = subprocess.run(arguments, cwd=cwd, env=env,
                                        capture_output=True, text=True, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result

            archives = temporary / "archives"
            archives.mkdir()
            run([sys.executable, "-c", "from setuptools.build_meta import build_sdist; "
                 "import sys; build_sdist(sys.argv[1])", str(archives)], cwd=source)
            archive = next(archives.glob("*.tar.gz"))
            extracted = temporary / "extracted"
            with tarfile.open(archive) as package:
                members = package.getmembers()
                self.assertTrue(all(not member.issym() and not member.islnk() for member in members))
                prefix = Path(members[0].name).parts[0]
                inventory = {str(Path(member.name).relative_to(prefix)) for member in members if member.isfile()}
                self.assertTrue(set(public_paths).issubset(inventory), sorted(set(public_paths) - inventory))
                self.assertFalse(set(excluded) & inventory)
                package.extractall(extracted, filter="data")
            unpacked = extracted / prefix

            # README hyperlinks and executable examples must survive the archive.
            for link in re.findall(r"\]\(([^)]+)\)", (unpacked / "README.md").read_text()):
                if "://" not in link and not link.startswith("#"):
                    self.assertTrue((unpacked / link.split("#", 1)[0]).is_file(), link)
            for relative in ("requirements-dev.txt", "scripts/verify-foundation.sh",
                             "examples/verified_lifecycle.py", "examples/offline_demo.py",
                             "tests/evaluation_helpers.py"):
                self.assertTrue((unpacked / relative).is_file(), relative)
            foundation = (unpacked / "scripts/verify-foundation.sh").read_text()
            required = re.search(r"required_files=\((.*?)\)", foundation, re.DOTALL)
            self.assertIsNotNone(required)
            for relative in required.group(1).split():
                self.assertTrue((unpacked / relative).is_file(), relative)
            # Keep the full suite for the foundation job; here check its shell and
            # installer inputs through a safe, explicit dry run.
            run(["bash", "-n", "scripts/verify-foundation.sh"], cwd=unpacked)
            run(["bash", "scripts/install-project-graph.sh", "--dry-run", "--runtime",
                 "config/project-runtime.example.json"], cwd=unpacked)

            installed = temporary / "installed"
            outside = temporary / "outside"
            outside.mkdir()
            run([sys.executable, "-m", "pip", "install", "--no-build-isolation", "--no-deps",
                 "--no-index", "--target", str(installed), str(archive)], cwd=outside)
            self.assertTrue((installed / "bin/codex-grapher").is_file())
            public_schema = (unpacked / "schemas/worker-result.schema.json").read_bytes()
            self.assertEqual((installed / "control_plane/resources/worker-result.schema.json").read_bytes(),
                             public_schema)
            resources = installed / "share/codex-grapher"
            self.assertEqual((resources / "schemas/worker-result.schema.json").read_bytes(), public_schema)
            for relative in ("docs/REPOSITORY_WORKFLOW.md", "examples/repository-workflow/task.template.json",
                             "examples/guest-recovery/guest_driver.py", "scripts/verify-guest-recovery.py",
                             "scripts/provision-sqlite-runtime.sh"):
                self.assertTrue((resources / relative).is_file(), relative)
            self.assertFalse((installed / "control_plane/local_private.py").exists())
            runtime_environment = {**environment, "PYTHONPATH": str(installed)}
            result = run([str(installed / "bin/codex-grapher"), "doctor", "--json"],
                         cwd=outside, env=runtime_environment)
            self.assertTrue(json.loads(result.stdout)["ok"])
            result = run([sys.executable, "-I", "-c",
                          "import pathlib,sys; sys.path.insert(0,sys.argv[1]); "
                          "import control_plane.cli as cli; "
                          "assert pathlib.Path(cli.__file__).is_relative_to(sys.argv[1]); "
                          "raise SystemExit(cli.main(['--help']))", str(installed)], cwd=outside)
            self.assertIn("codex-grapher", result.stdout)
            run([sys.executable, "examples/offline_demo.py"], cwd=unpacked)


if __name__ == "__main__":
    unittest.main()
