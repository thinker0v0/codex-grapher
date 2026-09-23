#!/usr/bin/env python3
"""Prepare the frozen, deliberately seeded acceptance tasks without a model.

The output is curator material. Give Grapher only sources/<project> and the
matching tasks/<project>/task.json; never mount operator/ into a worker. Source
is fetched from the three official pinned Git repositories. All preparation
and dependencies belong in disposable directories, outside the product tree.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import signal
import stat
import subprocess
import tarfile
import time


MANIFEST_SHA256 = "09de0ce5b777a49f4825ea749b64faaa5dd787b87b5c4e044f81249179d7f935"
MAX_OUTPUT = 262144
MAX_ARCHIVE = 64 * 1024 * 1024
PROJECTS = {"more-itertools", "humanize", "itsdangerous"}
FIXED_DATE = "2026-09-21T00:00:00+00:00"
DEPENDENCIES = {"humanize": "4.10.0", "iniconfig": "2.3.0", "packaging": "26.3",
                "pluggy": "1.6.0", "Pygments": "2.21.0", "pytest": "9.0.2"}


def dependency_probe_source() -> str:
    return ("import importlib.util, json\nfrom importlib.metadata import version\n"
            f"expected = {DEPENDENCIES!r}\n"
            "actual = {name: version(name) for name in expected}\n"
            "assert actual == expected, actual\n"
            "assert importlib.util.find_spec('humanize') is None, "
            "'humanize must be metadata-only: remove the installed humanize source directory, retaining dist-info'\n"
            "print(json.dumps(actual, sort_keys=True))\n")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: object) -> str:
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    return sha256(raw)


def inventory(root: Path) -> dict[str, dict]:
    """Hash every file, including Git state, without following any links."""
    result = {}
    for path in sorted(root.rglob("*")):
        mode = path.lstat().st_mode
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(mode):
            result[relative] = {"type": "directory", "mode": stat.S_IMODE(mode)}
        elif stat.S_ISREG(mode):
            result[relative] = {"type": "file", "mode": stat.S_IMODE(mode),
                                "bytes": path.stat().st_size, "sha256": sha256(path.read_bytes())}
        else:
            raise ValueError(f"unsupported filesystem member: {relative}")
    return result


def inventory_digest(value: dict) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def verify_full_tree(root: Path, records: bytes) -> int:
    """Compare every archived blob to the pinned Git tree, including modes.

    Git archive can honor export-ignore/export-subst attributes. An archive
    that omits or substitutes a tracked file is not the required full tree.
    """
    expected = {}
    for record in records.split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode("ascii").split()
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("upstream tree contains unsupported links or submodules")
        expected[name.decode("utf-8")] = (mode, object_id)
    actual = {name: value for name, value in inventory(root).items() if value["type"] == "file"}
    if set(actual) != set(expected):
        raise ValueError("archive differs from the complete pinned Git tree")
    for name, (mode, object_id) in expected.items():
        raw = (root / name).read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        if git_blob != object_id or actual[name]["mode"] != (0o755 if mode == "100755" else 0o644):
            raise ValueError("archive file differs from its pinned Git blob or mode")
    return len(expected)


def extract_snapshot(raw: bytes, destination: Path) -> None:
    """Accept only bounded regular Git-tree files and directories."""
    if len(raw) > MAX_ARCHIVE:
        raise ValueError("upstream archive exceeds preparation limit")
    destination.mkdir(parents=True)
    names = set()
    total = 0
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) > 10000:
            raise ValueError("upstream archive member limit exceeded")
        for member in members:
            name = member.name.rstrip("/")
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or "\\" in name or
                    any(part in {"", ".", "..", ".git"} for part in name.split("/")) or
                    any(ord(character) < 32 for character in name) or name in names):
                raise ValueError("unsafe or duplicate upstream archive member")
            names.add(name)
            total += member.size
            if total > MAX_ARCHIVE or not (member.isdir() or member.isfile()):
                raise ValueError("upstream archive contains a link, special file or excessive content")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("missing archive file content")
                with target.open("xb") as output:
                    output.write(stream.read())
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def apply_seed(case: dict, root: Path) -> dict:
    before = inventory(root)
    for name, expected in case["files"].items():
        raw = (root / name).read_bytes()
        if sha256(raw) != expected["sha256"] or len(raw) != expected["bytes"]:
            raise ValueError(f"upstream file identity mismatch: {name}")
    source = root / case["source_path"]
    raw = source.read_bytes()
    seed = case["seed"]
    old, new = seed["old"].encode(), seed["new"].encode()
    if sha256(raw) != seed["original_sha256"] or raw.count(old) != seed["expected_count"]:
        raise ValueError("seed does not match exactly the frozen source")
    seeded = raw.replace(old, new)
    if sha256(seeded) != seed["seeded_sha256"]:
        raise ValueError("seed result differs from frozen hash")
    source.write_bytes(seeded)
    after = inventory(root)
    changed = [name for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)]
    if changed != [case["source_path"]]:
        raise ValueError("seed changed unexpected paths")
    return {"before": before, "after": after, "changed_paths": changed,
            "seed_metadata_sha256": sha256(json.dumps(seed, sort_keys=True).encode())}


def negative_reason(project: str, kind: str, exit_code: int, output: str) -> str:
    """A setup/import failure must never masquerade as an expected regression."""
    forbidden = ("ModuleNotFoundError", "ImportError", "SyntaxError", "ERROR collecting",
                 "INTERNALERROR", "PermissionError", "No module named", "can't open file")
    if exit_code != 1 or any(marker in output for marker in forbidden):
        raise ValueError("negative control failed for a setup, import, timeout or unexpected-exit reason")
    markers = {
        ("more-itertools", "required"): ("test_strict_being_true", "AssertionError: ValueError not raised", "Ran 7 tests"),
        ("more-itertools", "independent"): ("AssertionError: (2, 1, 'missing ValueError')",),
        ("humanize", "required"): ("FAILED", "test_ordinal", "11st", "11th"),
        ("humanize", "independent"): ("AssertionError: (11, 'male')",),
        ("itsdangerous", "required"): ("FAILED", "test_int_bytes", "AssertionError"),
        ("itsdangerous", "independent"): ("AssertionError: (1,",),
    }
    if not all(marker in output for marker in markers[(project, kind)]):
        raise ValueError(f"negative control lacks the intended {project}/{kind} assertion")
    return "EXPECTED_SEEDED_ASSERTION_FAILURE"


def clean_environment(home: Path) -> dict[str, str]:
    return {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0", "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}


def record_command(argv: list[str], cwd: Path, environment: dict[str, str], prefix: Path,
                   *, timeout: int = 60, output_limit: int = MAX_OUTPUT) -> tuple[dict, bytes, bytes]:
    """Bound wall time and disk output; record complete bytes or fail preparation."""
    prefix.parent.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = Path(str(prefix) + ".stdout"), Path(str(prefix) + ".stderr")
    started = time.monotonic()
    interrupted = None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        child = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=stdout, stderr=stderr,
                                 stdin=subprocess.DEVNULL, start_new_session=True)
        while child.poll() is None:
            if time.monotonic() - started > timeout:
                interrupted = "TIMEOUT"
            if stdout_path.stat().st_size + stderr_path.stat().st_size > output_limit:
                interrupted = "OUTPUT_LIMIT"
            if interrupted:
                os.killpg(child.pid, signal.SIGKILL)
                break
            time.sleep(0.01)
        exit_code = child.wait(timeout=5)
    raw_stdout, raw_stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
    if len(raw_stdout) + len(raw_stderr) > output_limit:
        interrupted = "OUTPUT_LIMIT"
    result = {"argv": argv, "cwd": str(cwd), "environment": environment, "exit_code": exit_code,
              "duration_seconds": round(time.monotonic() - started, 6), "timeout_seconds": timeout,
              "max_output_bytes": output_limit, "interrupted": interrupted,
              "stdout": {"path": str(stdout_path), "bytes": len(raw_stdout), "sha256": sha256(raw_stdout)},
              "stderr": {"path": str(stderr_path), "bytes": len(raw_stderr), "sha256": sha256(raw_stderr)}}
    write_json(Path(str(prefix) + ".json"), result)
    if interrupted:
        raise ValueError(f"preparation command stopped: {interrupted}")
    return result, raw_stdout, raw_stderr


def task_documents(case: dict, python: str, base_sha: str) -> tuple[dict, dict, dict]:
    required = [python, "-I", "-B", "-c", case["required_python_source"]]
    independent = [python, "-I", "-B", "-c", case["independent_evaluator_python_source"]]
    task = {"schema_version": 1, "project_id": case["project_id"], "task_id": case["task_id"],
            "idempotency_key": case["idempotency_key"], "base_sha": base_sha,
            "objective": case["objective"],
            "acceptance_criteria": [case["objective"], "Pass the frozen required and independent checks.",
                "Change only the permitted source path; preserve tests, metadata, dependency environment and Git configuration."],
            "allowed_paths": case["allowed_paths"], "required_tests": [shlex.join(required)],
            "worker": {"backend": "codex"},
            "limits": {"worker_invocations": 1, "worker_timeout_seconds": 300,
                       "required_test_timeout_seconds": 60, "evaluation_timeout_seconds": 60,
                       "max_output_bytes": MAX_OUTPUT},
            "evaluation": {"policy": "policy.json", "checks": "checks.json"}}
    policy = {"schema_version": 1, "name": case["id"],
              "sections": {"correctness": {"minimum": 100, "maximum": 100}},
              "mandatory_gates": ["required_tests", "independent_checks", "authorized_scope"], "threshold": 100}
    checks = {"schema_version": 1, "checks": [{"id": "independent-" + case["project_id"], "argv": independent}]}
    return task, policy, checks


def prepare(manifest_path: Path, output: Path, python: Path, git: Path) -> dict:
    raw_manifest = manifest_path.read_bytes()
    if sha256(raw_manifest) != MANIFEST_SHA256:
        raise ValueError("representative manifest differs from the frozen design input")
    manifest = json.loads(raw_manifest)
    if {case["project_id"] for case in manifest["cases"]} != PROJECTS:
        raise ValueError("unexpected representative project set")
    for executable in (python, git):
        if not executable.is_absolute() or executable.is_symlink() or not executable.is_file():
            raise ValueError("tools must be absolute, regular executables (use venv --copies)")
    # Resolve parent aliases before freezing argv: execution profiles reject
    # symlink components even when they point to the same copied interpreter.
    python, git = python.resolve(), git.resolve()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    home = output / "operator/home"
    home.mkdir(parents=True)
    environment = clean_environment(home)
    packet = {"schema_version": 1, "status": "PREPARING", "model_invocations": 0,
              "scope": "Seeded control preparation only; no worker, isolation, integration or release verdict.",
              "manifest_sha256": sha256(raw_manifest), "preparer_sha256": sha256(Path(__file__).read_bytes()),
              "tools": {"python": {"path": str(python), "sha256": sha256(python.read_bytes())},
                        "git": {"path": str(git), "sha256": sha256(git.read_bytes())}}, "cases": []}
    version, stdout, _ = record_command([str(python), "-I", "-B", "-c", "import platform; print(platform.python_version())"],
                                         output, environment, output / "operator/python-version")
    if version["exit_code"]:
        raise ValueError("Python executable failed")
    packet["tools"]["python"]["version"] = stdout.decode().strip()
    dependencies, stdout, _ = record_command([str(python), "-I", "-B", "-c", dependency_probe_source()],
                                              output, environment, output / "operator/dependency-probe")
    if dependencies["exit_code"]:
        raise ValueError("dependencies must match the frozen versions and humanize must expose metadata only")
    packet["dependencies"] = json.loads(stdout)
    for case in manifest["cases"]:
        project = case["project_id"]
        operator = output / "operator" / project
        operator.mkdir()
        bare = operator / "upstream.git"
        def git_command(arguments: list[str], label: str, *, cwd: Path = operator,
                        output_limit: int = MAX_OUTPUT) -> tuple[dict, bytes, bytes]:
            result = record_command([str(git), "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
                                     *arguments], cwd, environment, operator / label, timeout=120, output_limit=output_limit)
            if result[0]["exit_code"]:
                raise ValueError(f"Git preparation failed: {project}/{label}")
            return result
        git_command(["init", "--bare", "--template=", str(bare)], "git-init-upstream")
        official = "https://github.com/" + case["repo"] + ".git"
        git_command(["--git-dir=" + str(bare), "fetch", "--depth=1", "--no-tags", official, case["commit"]], "git-fetch")
        _, fetched, _ = git_command(["--git-dir=" + str(bare), "rev-parse", "FETCH_HEAD^{commit}"], "git-commit")
        if fetched.decode().strip() != case["commit"]:
            raise ValueError("upstream fetch did not return the exact pinned commit")
        _, tree, _ = git_command(["--git-dir=" + str(bare), "rev-parse", case["commit"] + "^{tree}"], "git-tree")
        _, tree_records, _ = git_command(["--git-dir=" + str(bare), "ls-tree", "-rz", case["commit"]], "git-tree-records")
        _, archive, _ = git_command(["--git-dir=" + str(bare), "archive", "--format=tar", case["commit"]],
                                    "git-archive", output_limit=MAX_ARCHIVE)
        pristine, seeded = operator / "pristine", output / "sources" / project
        extract_snapshot(archive, pristine)
        extract_snapshot(archive, seeded)
        tracked_files = verify_full_tree(pristine, tree_records)
        verify_full_tree(seeded, tree_records)
        pristine_before = inventory(pristine)
        for name, expected in case["files"].items():
            actual = pristine_before.get(name, {})
            if actual.get("sha256") != expected["sha256"] or actual.get("bytes") != expected["bytes"]:
                raise ValueError(f"upstream frozen provenance mismatch: {project}/{name}")
        controls = []
        for kind, field in (("required", "required_python_source"), ("independent", "independent_evaluator_python_source")):
            argv = [str(python), "-I", "-B", "-c", case[field]]
            result, _, _ = record_command(argv, pristine, environment, operator / ("pristine-" + kind))
            if result["exit_code"]:
                raise ValueError(f"pristine positive control failed: {project}/{kind}")
            controls.append({"source": "pristine", "kind": kind, "result": "EXPECTED_PASS", **result})
        if inventory(pristine) != pristine_before:
            raise ValueError("pristine control changed original snapshot")
        seed = apply_seed(case, seeded)
        commit_environment = {**environment, "GIT_AUTHOR_NAME": "Grapher acceptance fixtures",
                              "GIT_AUTHOR_EMAIL": "fixtures@example.invalid", "GIT_AUTHOR_DATE": FIXED_DATE,
                              "GIT_COMMITTER_NAME": "Grapher acceptance fixtures",
                              "GIT_COMMITTER_EMAIL": "fixtures@example.invalid", "GIT_COMMITTER_DATE": FIXED_DATE}
        # No fetch/clone/copy of Git objects into this repository: one new root commit.
        for label, arguments in (("seed-init", ["init", "--template=", "--initial-branch=fixture", str(seeded)]),
                                 ("seed-add", ["-C", str(seeded), "add", "--force", "--all"]),
                                 ("seed-commit", ["-C", str(seeded), "-c", "commit.gpgsign=false", "commit", "-m", "Seeded acceptance baseline"]),
                                 ("seed-sha", ["-C", str(seeded), "rev-parse", "HEAD"]),
                                 ("seed-history", ["-C", str(seeded), "rev-list", "--all"]),
                                 ("seed-remotes", ["-C", str(seeded), "remote"]),
                                 ("seed-object-check", ["-C", str(seeded), "fsck", "--strict", "--no-reflogs"])):
            result, stdout, _ = record_command([str(git), "-c", "core.hooksPath=/dev/null", *arguments],
                                                operator, commit_environment, operator / label)
            if result["exit_code"]:
                raise ValueError(f"seeded Git creation failed: {label}")
            if label == "seed-sha":
                base_sha = stdout.decode().strip()
                if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
                    raise ValueError("seeded root commit is invalid")
            elif label == "seed-history" and stdout.decode().splitlines() != [base_sha]:
                raise ValueError("seeded repository exposes upstream history")
            elif label == "seed-remotes" and stdout.strip():
                raise ValueError("seeded repository unexpectedly has remotes")
        seeded_before = inventory(seeded)
        for kind, field in (("required", "required_python_source"), ("independent", "independent_evaluator_python_source")):
            result, stdout, stderr = record_command([str(python), "-I", "-B", "-c", case[field]],
                                                     seeded, environment, operator / ("seeded-" + kind))
            reason = negative_reason(project, kind, result["exit_code"], (stdout + stderr).decode("utf-8", "replace"))
            controls.append({"source": "seeded", "kind": kind, "result": reason, **result})
        if inventory(seeded) != seeded_before or inventory(pristine) != pristine_before:
            raise ValueError("control checks changed the original or seeded source/Git state")
        documents = task_documents(case, str(python), base_sha)
        task_root = output / "tasks" / project
        document_hashes = {name: write_json(task_root / name, value) for name, value in
                           zip(("task.json", "policy.json", "checks.json"), documents)}
        inventory_hash = write_json(operator / "seeded-inventory.json", seeded_before)
        write_json(operator / "pristine-inventory.json", pristine_before)
        packet["cases"].append({"project_id": project, "source_url": official, "upstream_commit": case["commit"],
            "upstream_tree": tree.decode().strip(), "upstream_archive_sha256": sha256(archive),
            "upstream_tracked_files_verified": tracked_files,
            "license": case["license"], "license_path": case["license_path"],
            "license_sha256": case["files"][case["license_path"]]["sha256"],
            "source": str(seeded), "task": str(task_root / "task.json"), "base_sha": base_sha,
            "root_commit_count": 1, "remote_count": 0, "changed_paths": seed["changed_paths"],
            "seed_metadata_sha256": seed["seed_metadata_sha256"], "document_hashes": document_hashes,
            "seeded_inventory_file_sha256": inventory_hash, "seeded_inventory_digest": inventory_digest(seeded_before),
            "pristine_preserved": True, "seeded_preserved_during_controls": True, "controls": controls})
    packet["status"] = "PREPARATION_CONTROLS_COMPLETE"
    write_json(output / "preparation.json", packet)
    return packet


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path, help="exact frozen representative-task-cases.json")
    parser.add_argument("--output", required=True, type=Path, help="new disposable directory; contains curator-only material")
    parser.add_argument("--python", required=True, type=Path, help="absolute pinned --copies venv Python with frozen dependencies")
    parser.add_argument("--git", default=Path("/usr/bin/git"), type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.manifest.absolute(), args.output.absolute(), args.python.absolute(), args.git.absolute())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "PREPARATION_FAILED", "reason": str(exc), "model_invocations": 0}))
        return 1
    print(json.dumps({"status": result["status"], "manifest": str(args.output.absolute() / "preparation.json"),
                      "cases": len(result["cases"]), "model_invocations": 0}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
