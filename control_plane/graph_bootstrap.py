#!/usr/bin/env python3
"""Read-only graph bootstrap planning and synthetic accepted-state verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

from control_plane.graph_schema import SchemaError, SchemaPlan, ensure_current_schema, inspect_schema
from control_plane.publication_store import PublicationStore


HEX40 = re.compile(r"[0-9a-f]{40}")
ACCEPTED_REF = re.compile(r"refs/ai-ops/accepted/[a-z]+")


def _read_only_uri(path: Path) -> str:
    return f"file:{quote(str(path), safe='/')}?mode=ro&immutable=1"


def inspect_database(database: Path) -> SchemaPlan:
    """Return a migration plan without creating or modifying the database."""
    database = Path(os.path.abspath(database))
    if database.is_symlink():
        raise SchemaError("graph database must not be a symlink")
    if not database.exists():
        memory = sqlite3.connect(":memory:")
        try:
            return inspect_schema(memory)
        finally:
            memory.close()
    if not database.is_file():
        raise SchemaError("graph database must be a regular file")
    sidecars = [Path(f"{database}{suffix}") for suffix in ("-journal", "-wal", "-shm")]
    if any(path.exists() for path in sidecars):
        raise SchemaError("read-only inspection requires an offline database with no journal/WAL sidecars")
    connection = sqlite3.connect(_read_only_uri(database), uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        return inspect_schema(connection)
    finally:
        connection.close()


def apply_database(database: Path) -> SchemaPlan:
    """Explicitly create or migrate one database; callers choose the path."""
    database = Path(os.path.abspath(database))
    if database.is_symlink():
        raise SchemaError("graph database must not be a symlink")
    if not database.parent.is_dir():
        raise SchemaError("graph database parent directory must already exist")
    if database.exists() and not database.is_file():
        raise SchemaError("graph database must be a regular file")
    sidecars = [Path(f"{database}{suffix}") for suffix in ("-journal", "-wal", "-shm")]
    if database.exists() and any(path.exists() for path in sidecars):
        raise SchemaError("schema apply requires an offline database with no journal/WAL sidecars")
    created = not database.exists()
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys=ON")
        result = ensure_current_schema(connection, allow_create=True)
    finally:
        connection.close()
    if created:
        os.chmod(database, 0o600)
    return result


def _git(repo: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments], check=check, capture_output=True, text=True,
    )
    return result.stdout.strip()


def _regular_directory(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink() or not absolute.is_dir():
        raise PermissionError(f"{label} must be a non-symlink directory")
    return absolute.resolve(strict=True)


def _inventory(root: Path) -> dict[str, Any]:
    entries: list[dict[str, str]] = []

    def walk_error(error: OSError) -> None:
        raise error

    for directory, directory_names, file_names in os.walk(
        root, followlinks=False, onerror=walk_error,
    ):
        directory_path = Path(directory)
        for name in directory_names:
            item = directory_path / name
            if item.is_symlink():
                raise PermissionError(f"evidence root contains symlink: {item.relative_to(root)}")
        for name in file_names:
            item = directory_path / name
            if item.is_symlink() or not item.is_file():
                raise PermissionError(f"evidence root contains non-regular file: {item.relative_to(root)}")
            entries.append({
                "path": item.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(item.read_bytes()).hexdigest(),
            })
    entries.sort(key=lambda value: value["path"])
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    return {"file_count": len(entries), "inventory_sha256": hashlib.sha256(encoded).hexdigest()}


def _verify_publication(
    publication_root: Path | None, repo_name: str, accepted_sha: str,
) -> dict[str, Any]:
    if publication_root is None:
        raise PermissionError("versioned bootstrap verification requires a publication root")
    pin = PublicationStore(publication_root).verify(repo_name, accepted_sha)
    return {
        "status": "verified",
        "generation": pin.generation,
        "base_sha": pin.base_sha,
        "tree_sha": pin.tree_sha,
        "path": pin.path.name,
    }


def verify_project(
    repo: Path,
    binding: Path,
    accepted_ref: str,
    publication_root: Path | None,
    evidence_root: Path,
) -> dict[str, Any]:
    """Verify one canonical accepted project without changing Git or filesystem state."""
    if not ACCEPTED_REF.fullmatch(accepted_ref):
        raise ValueError("accepted ref is not canonical")
    repo = _regular_directory(repo, "canonical repository")
    if _git(repo, "rev-parse", "--is-inside-work-tree", check=False) != "true":
        raise PermissionError("canonical repository is not a Git worktree")
    top = _git(repo, "rev-parse", "--show-toplevel", check=False)
    if not top or Path(top).resolve(strict=True) != repo:
        raise PermissionError("canonical repository path is not the Git worktree root")
    accepted_sha = _git(repo, "rev-parse", "--verify", f"{accepted_ref}^{{commit}}", check=False)
    if not HEX40.fullmatch(accepted_sha):
        raise PermissionError("accepted ref does not resolve to a commit")
    if _git(repo, "rev-parse", f"{accepted_sha}^{{commit}}", check=False) != accepted_sha:
        raise PermissionError("accepted source object is absent")
    if (
        _git(repo, "status", "--porcelain=v1", "--untracked-files=all")
        or _git(repo, "ls-files", "--others", "--ignored", "--exclude-standard")
    ):
        raise PermissionError("canonical publication source is not clean")

    binding = Path(os.path.abspath(binding))
    if binding.is_symlink() or not binding.is_file():
        raise PermissionError("repository binding must be a regular non-symlink file")
    metadata = binding.stat()
    if stat.S_IMODE(metadata.st_mode) != 0o440 or metadata.st_uid != os.geteuid():
        raise PermissionError("repository binding owner or mode is unsafe")
    value = json.loads(binding.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"repo", "base_sha"}:
        raise PermissionError("repository binding must have the exact {repo,base_sha} schema")
    if value["repo"] != repo.name or value["base_sha"] != accepted_sha:
        raise PermissionError("repository binding differs from the canonical accepted state")

    evidence = _regular_directory(evidence_root, "evidence root")
    return {
        "repo": repo.name,
        "accepted_ref": accepted_ref,
        "accepted_sha": accepted_sha,
        "binding_sha256": hashlib.sha256(binding.read_bytes()).hexdigest(),
        "evidence": _inventory(evidence),
        "publication": _verify_publication(publication_root, repo.name, accepted_sha),
    }


def verify_bootstrap(database: Path, projects: Iterable[dict[str, Any]]) -> dict[str, Any]:
    schema = inspect_database(database)
    if schema.action != "none":
        raise SchemaError(schema.reason or "graph database is not at the current exact schema")
    verified = [verify_project(**project) for project in projects]
    return {"schema": schema.to_dict(), "projects": verified, "pass": True}


def synthetic_bootstrap_verification() -> dict[str, Any]:
    """Exercise dry-run, explicit apply, idempotence, and project checks in /tmp only."""
    with tempfile.TemporaryDirectory(prefix="vapg-bootstrap-") as temporary:
        root = Path(temporary)
        repo = root / "fixture-repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Bootstrap Fixture"], check=True)
        (repo / "fixture.txt").write_text("synthetic bootstrap fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "fixture.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "fixture"], check=True)
        accepted_sha = _git(repo, "rev-parse", "HEAD")
        accepted_ref = "refs/ai-ops/accepted/opensource"
        subprocess.run(["git", "-C", str(repo), "update-ref", accepted_ref, accepted_sha], check=True)

        binding = root / "binding.json"
        binding.write_text(
            json.dumps({"repo": repo.name, "base_sha": accepted_sha}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(binding, 0o440)
        evidence = root / "evidence"
        evidence.mkdir()
        (evidence / "fixture.json").write_text(
            json.dumps({"accepted_sha": accepted_sha}, sort_keys=True) + "\n", encoding="utf-8",
        )
        publication = root / "publication"
        publication.mkdir()
        PublicationStore(publication).ensure(repo, repo.name, accepted_sha, binding.stat())

        database = root / "graph.sqlite"
        dry_run = inspect_database(database)
        if dry_run.action != "create" or database.exists():
            raise RuntimeError("read-only bootstrap planning created or misclassified the fixture database")
        first_apply = apply_database(database)
        second_apply = apply_database(database)
        verified = verify_bootstrap(database, [{
            "repo": repo,
            "binding": binding,
            "accepted_ref": accepted_ref,
            "publication_root": publication,
            "evidence_root": evidence,
        }])
        return {
            "pass": True,
            "database_created_only_by_apply": first_apply.changed,
            "second_apply_changed": second_apply.changed,
            "schema_sha256": verified["schema"]["schema_sha256"],
            "accepted_sha": accepted_sha,
            "publication_status": verified["projects"][0]["publication"]["status"],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    database_command = commands.add_parser("database", help="plan or explicitly apply the DB schema")
    database_command.add_argument("--database", type=Path, required=True)
    database_command.add_argument("--apply", action="store_true")
    verify_command = commands.add_parser("verify", help="verify one synthetic/staged accepted project")
    verify_command.add_argument("--database", type=Path, required=True)
    verify_command.add_argument("--repo", type=Path, required=True)
    verify_command.add_argument("--binding", type=Path, required=True)
    verify_command.add_argument("--accepted-ref", required=True)
    verify_command.add_argument("--publication-root", type=Path)
    verify_command.add_argument("--evidence-root", type=Path, required=True)
    commands.add_parser("synthetic", help="run the canonical temporary-fixture verifier")
    args = parser.parse_args(argv)
    try:
        if args.command == "database":
            result = apply_database(args.database) if args.apply else inspect_database(args.database)
            payload: dict[str, Any] = result.to_dict()
            payload["mode"] = "apply" if args.apply else "read-only"
        elif args.command == "verify":
            payload = verify_bootstrap(args.database, [{
                "repo": args.repo,
                "binding": args.binding,
                "accepted_ref": args.accepted_ref,
                "publication_root": args.publication_root,
                "evidence_root": args.evidence_root,
            }])
        else:
            payload = synthetic_bootstrap_verification()
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(json.dumps({"pass": False, "error": f"{type(exc).__name__}: {exc}"}, sort_keys=True), file=sys.stderr)
        return 65
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
