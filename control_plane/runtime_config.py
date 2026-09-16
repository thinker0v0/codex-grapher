#!/usr/bin/env python3
"""Validate the operator-supplied, non-secret project runtime map."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


PROJECT_WORKERS = {
    "nomad": "fin-korea",
    "opensource": "oss",
    "business": "business",
    "hynix": "hynix",
}
EXPECTED_PATHS = {
    project: {
        "repo": f"/srv/hermes/{worker}/workspace",
        "binding": f"/srv/hermes/{worker}/runtime/repo-binding.json",
        "evidence_root": f"/srv/hermes/evaluator/artifacts/{project}",
    }
    for project, worker in PROJECT_WORKERS.items()
}
ENTRY_FIELDS = {
    "worker_project_id",
    "repo",
    "binding",
    "evidence_root",
    "accepted_ref",
}


def _absolute_path(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"runtime {field} must be a non-empty absolute path")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != str(path.resolve(strict=False)):
        raise ValueError(f"runtime {field} must be a normalized absolute path")
    return str(path)


def load_runtime(path: Path) -> dict[str, dict[str, str]]:
    """Load an exact four-route runtime file without resolving external state."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("runtime configuration must be a regular non-symlink file")
    path = path.resolve(strict=True)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"version", "projects"} or value["version"] != 1:
        raise ValueError("runtime configuration must be the version 1 object")
    projects = value["projects"]
    if not isinstance(projects, dict) or set(projects) != set(PROJECT_WORKERS):
        raise ValueError("runtime configuration must define exactly nomad, opensource, business, and hynix")

    result: dict[str, dict[str, str]] = {}
    seen_paths: list[Path] = []
    for project, expected_worker in PROJECT_WORKERS.items():
        entry = projects[project]
        if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
            raise ValueError(f"runtime project {project} has an invalid field set")
        if entry["worker_project_id"] != expected_worker:
            raise ValueError(f"runtime project {project} must use worker route {expected_worker}")
        accepted_ref = entry["accepted_ref"]
        if accepted_ref != f"refs/ai-ops/accepted/{project}":
            raise ValueError(f"runtime project {project} has a non-canonical accepted ref")
        normalized = {
            "worker_project_id": expected_worker,
            "repo": _absolute_path(entry["repo"], f"{project}.repo"),
            "binding": _absolute_path(entry["binding"], f"{project}.binding"),
            "evidence_root": _absolute_path(entry["evidence_root"], f"{project}.evidence_root"),
            "accepted_ref": accepted_ref,
        }
        for field, expected_path in EXPECTED_PATHS[project].items():
            if normalized[field] != expected_path:
                raise ValueError(
                    f"runtime project {project}.{field} must be exactly {expected_path}"
                )
        for field in ("repo", "binding", "evidence_root"):
            item = Path(normalized[field])
            if any(item == other or item in other.parents or other in item.parents for other in seen_paths):
                raise ValueError(f"runtime paths must not overlap: {item}")
            seen_paths.append(item)
        result[project] = normalized
    return result


def validate_source_security(path: Path, require_root_owner: bool) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError("runtime source must be a regular non-symlink file")
    metadata = path.stat()
    if require_root_owner and metadata.st_uid != 0:
        raise PermissionError("runtime source must be root-owned for --apply")
    if require_root_owner and metadata.st_mode & 0o022:
        raise PermissionError("runtime source must not be group- or world-writable for --apply")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--require-root-owner", action="store_true")
    args = parser.parse_args()
    validate_source_security(args.runtime, args.require_root_owner)
    load_runtime(args.runtime)
    print("runtime configuration valid")
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    raise SystemExit(main())
