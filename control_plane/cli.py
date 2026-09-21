"""Public developer commands, with offline, non-mutating database inspection.

No SQLite connection is opened against a user's diagnostic source. An offline
file is copied and verified in a disposable directory. Live WAL/journal state is
refused: use the service's authorized status API or close the owning process.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterator

from control_plane.graph_schema import SCHEMA_VERSION
from control_plane.graph_state import ACTIVE_PROJECTS
from control_plane.project_graph import ProjectGraph


DATABASE_SCOPE = (
    "Offline snapshot: database schema, static bindings and event hashes only. "
    "External artifact bytes, evaluator signatures, deployed identities and "
    "production readiness are not verified."
)


def _no_sidecars(database: Path) -> None:
    if any(os.path.lexists(str(database) + suffix) for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError(
            "database inspection requires an offline database with no WAL/journal "
            "sidecars; close its owning process cleanly or use status --socket SOCKET "
            "for live state. Do not delete sidecars."
        )


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns, metadata.st_mode)


@contextmanager
def read_only_graph(
    database: Path, *, evaluator_public_key: Path | None = None,
    rubric_sha256: str | None = None, evaluation_policy: Any = None,
) -> Iterator[ProjectGraph]:
    """Verify a stable offline copy, leaving source bytes/mode/sidecars intact.

    The caller must close writers first. Sidecar and source-identity checks fail
    closed on observed concurrent changes; this is not a live SQLite backup API.
    The yielded graph refers only to a temporary copy, never the input path.
    """
    database = Path(os.path.abspath(database))
    metadata = database.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("database must be an existing regular file, not a symlink")
    if metadata.st_nlink != 1:
        raise ValueError("database must have exactly one hard link; aliases can hide live WAL/journal state")
    _no_sidecars(database)
    with tempfile.TemporaryDirectory(prefix="codex-grapher-inspect-") as temporary:
        snapshot = Path(temporary) / "graph.sqlite"
        descriptor = os.open(database, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            if _identity(os.fstat(source.fileno())) != _identity(metadata):
                raise ValueError("database changed before snapshot; close writers and retry")
            with snapshot.open("xb") as destination:
                shutil.copyfileobj(source, destination, length=1024 * 1024)
            if _identity(os.fstat(source.fileno())) != _identity(metadata):
                raise ValueError("database changed during snapshot; close writers and retry")
        _no_sidecars(database)
        if _identity(database.lstat()) != _identity(metadata):
            raise ValueError("database changed during snapshot; close writers and retry")
        # integrity_check detects damaged page/index structure before graph code.
        connection = sqlite3.connect(snapshot)
        try:
            if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
                raise ValueError("database SQLite integrity check failed")
        finally:
            connection.close()
        kwargs: dict[str, Any] = {}
        if evaluation_policy is not None:
            kwargs["evaluation_policy"] = evaluation_policy
        graph = ProjectGraph(snapshot, evaluator_public_key, rubric_sha256, **kwargs)
        try:
            yield graph
        finally:
            graph.connection.close()


def _probe_command(command: list[str]) -> tuple[bool, str]:
    if shutil.which(command[0]) is None:
        return False, f"{command[0]} is missing from PATH"
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"{command[0]} probe failed ({type(error).__name__})"
    if result.returncode:
        return False, f"{command[0]} probe exited {result.returncode}"
    return True, result.stdout.strip()[:8192]


def doctor() -> dict[str, Any]:
    """Query local prerequisites. Never install packages or repair state."""
    checks = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    check("python", sys.version_info >= (3, 12), sys.version.split()[0] + "; requires >=3.12")
    check("platform", sys.platform == "linux", sys.platform + "; Linux required")
    check("proc", Path("/proc/self/stat").is_file(), "Linux /proc/self/stat")
    pidfd_ok = False
    try:
        descriptor = os.pidfd_open(os.getpid())
        try:
            signal.pidfd_send_signal(descriptor, 0)
            pidfd_ok = True
        finally:
            os.close(descriptor)
    except (AttributeError, OSError):
        pass
    check("pidfd", pidfd_ok, "pidfd_open and pidfd_send_signal(0) on this process")
    subreaper_ok = False
    if sys.platform == "linux":
        try:
            current = ctypes.c_int()
            subreaper_ok = ctypes.CDLL(None).prctl(37, ctypes.byref(current), 0, 0, 0) == 0
        except (AttributeError, OSError):
            pass
    check("subreaper", subreaper_ok, "PR_GET_CHILD_SUBREAPER query; containment is tested by the lifecycle")
    connection = sqlite3.connect(":memory:")
    try:
        sqlite_ok = connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    check("sqlite", sqlite_ok, sqlite3.sqlite_version)
    git_ok, git_detail = _probe_command(["git", "--version"])
    check("git", git_ok, git_detail)
    openssl_ok, openssl_detail = _probe_command(["openssl", "list", "-public-key-algorithms"])
    check("openssl_ed25519", openssl_ok and "ED25519" in openssl_detail.upper(),
          "OpenSSL ED25519 algorithm available" if openssl_ok and "ED25519" in openssl_detail.upper()
          else "OpenSSL with ED25519 is required")
    return {"ok": all(item["ok"] for item in checks), "command": "doctor", "checks": checks,
            "scope": "Local runtime prerequisites only; no installation, service, worker or deployment verification.",
            "release_verdict": "NOT_PASS"}


def _policy_arguments(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    from control_plane.evaluation_policy import load_task_policy
    policy = load_task_policy(path)
    return {"evaluation_policy": policy, "rubric_sha256": policy.sha256}


def _node_summary(graph: ProjectGraph, row: sqlite3.Row, status: dict[str, Any]) -> dict[str, Any]:
    value = dict(row)
    dependencies = [dict(item) for item in graph.connection.execute(
        "SELECT d.dependency_id AS node_id,n.state FROM dependencies d "
        "JOIN nodes n ON n.node_id=d.dependency_id WHERE d.node_id=? ORDER BY d.dependency_id",
        (row["node_id"],),
    )]
    value["dependencies"] = dependencies
    value["blockers"] = [f"dependency {item['node_id']} is {item['state']}" for item in dependencies
                         if item["state"] != "INTEGRATED"]
    spec = json.loads(graph.get_node(row["node_id"])["spec_json"])
    if spec.get("human_gate") is True:
        value["blockers"].append("pending human authorization; this CLI cannot grant approval")
    if row["state"] in {"NEEDS_HUMAN", "FAILED_GATE", "FAILED_PERMANENT", "FAILED_BUDGET", "CANCELLED"}:
        value["blockers"].append(f"node is {row['state']}; review its event history")
    value["event_head"] = dict(graph.connection.execute(
        "SELECT version,event_hash,reason FROM events WHERE node_id=? ORDER BY version DESC LIMIT 1",
        (row["node_id"],),
    ).fetchone())
    # Reuse richer retry projections as available; lease capabilities are private.
    for key in ("retry", "heartbeat_at", "human_gate", "blocked_reason"):
        if key in status:
            value[key] = status[key]
    if status.get("blocked_reason") and status["blocked_reason"] not in value["blockers"]:
        value["blockers"].append(status["blocked_reason"])
    return value


def inspect_database(database: Path, *, project: str | None = None,
                     node_id: str | None = None, events: bool = False,
                     policy_path: Path | None = None) -> dict[str, Any]:
    with read_only_graph(database, **_policy_arguments(policy_path)) as graph:
        rows = graph.connection.execute(
            "SELECT g.project,g.goal_id,g.accepted_sha,g.state AS goal_state,n.node_id,n.kind,"
            "n.state,n.version,n.attempt,n.base_sha,n.result_sha,n.evidence_hash,n.evaluation_hash,"
            "n.integration_sha,n.active_artifact_id,n.lease_owner,n.lease_expires_at "
            "FROM goals g JOIN nodes n ON n.goal_id=g.goal_id "
            "WHERE (? IS NULL OR g.project=?) AND (? IS NULL OR n.node_id=?) "
            "ORDER BY g.project,g.goal_id,n.node_id", (project, project, node_id, node_id),
        ).fetchall()
        if node_id is not None and not rows:
            raise ValueError("node does not exist in the selected project")
        result: dict[str, Any] = {
            "ok": True, "source": "offline_database_snapshot", "database": str(database.absolute()),
            "schema_version": SCHEMA_VERSION, "database_integrity": "VERIFIED",
            "event_hashes": "VERIFIED", "external_evidence": "UNPROVEN",
            "release_verdict": "NOT_PASS", "scope": DATABASE_SCOPE,
        }
        if events:
            result["events"] = [dict(event) for event in graph.connection.execute(
                "SELECT g.project,n.goal_id,e.* FROM events e JOIN nodes n ON n.node_id=e.node_id "
                "JOIN goals g ON g.goal_id=n.goal_id "
                "WHERE (? IS NULL OR g.project=?) AND (? IS NULL OR n.node_id=?) "
                "ORDER BY e.event_id", (project, project, node_id, node_id),
            )]
        else:
            statuses = {item["node_id"]: item for item in graph.portfolio_status()}
            result["nodes"] = [_node_summary(graph, row, statuses.get(row["node_id"], {})) for row in rows]
            result["goals"] = [dict(goal) for goal in graph.connection.execute(
                "SELECT goal_id,project,objective,accepted_sha,state FROM goals "
                "WHERE (? IS NULL OR project=?) AND "
                "(? IS NULL OR goal_id=(SELECT goal_id FROM nodes WHERE node_id=?)) "
                "ORDER BY project,goal_id", (project, project, node_id, node_id),
            )]
        return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codex-grapher", description="Local verified task workflow and read-only graph diagnostics.")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor_parser = commands.add_parser("doctor", help="check actual local runtime prerequisites without installation")
    doctor_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    for name in ("status", "events", "inspect"):
        command = commands.add_parser(name, help=f"read {name} from an offline database snapshot")
        source = command.add_mutually_exclusive_group(required=True)
        source.add_argument("--database", type=Path, help="offline database; refuses WAL/journal sidecars and never repairs")
        if name == "status":
            source.add_argument("--socket", type=Path, help="query authorized live service status instead of offline database")
        command.add_argument("--project", choices=sorted(ACTIVE_PROJECTS))
        command.add_argument("--policy", type=Path, help="trusted frozen task policy JSON; required for task-policy databases")
        command.add_argument("--json", action="store_true")
        if name == "inspect":
            command.add_argument("node", help="exact node ID")
        elif name == "events":
            command.add_argument("--node", help="limit history to an exact node ID")
    demo = commands.add_parser("demo", help="run the full local fixture workflow, including verification and recovery")
    demo.add_argument("--workspace", "--directory", type=Path, dest="workspace", help="persistent local workflow directory")
    demo.add_argument("--operation", choices=("run", "recover", "rollback", "status"), default="run")
    demo.add_argument("--stop-after", choices=("built", "evaluated", "promoted"))
    demo.add_argument("--failure", choices=("required-test", "evaluator"), help="inject an intentional local task failure (exit 3)")
    demo.add_argument("--crash-at", choices=("after_binding",), help="intentional process exit 86; requires --workspace, then recover")
    demo.add_argument("--json", action="store_true")
    for operation in ("recover", "rollback"):
        command = commands.add_parser(operation, help=f"{operation} a persistent local fixture workflow")
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--json", action="store_true")
        command.set_defaults(operation=operation, stop_after=None, failure=None, crash_at=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor()
        elif args.command in {"demo", "recover", "rollback"}:
            if (args.operation != "run" or args.crash_at) and args.workspace is None:
                raise ValueError("--workspace is required for recovery, rollback, status or an intentional crash")
            from control_plane.local_workflow import run_local_workflow
            result = run_local_workflow(args.workspace, operation=args.operation,
                                        stop_after=args.stop_after, failure=args.failure, crash_at=args.crash_at)
        elif getattr(args, "socket", None) is not None:
            if args.policy is not None:
                raise ValueError("--policy applies to offline databases; the service owns its live policy")
            from control_plane.graph_client import request
            response = request(args.socket, {"action": "status", "project": args.project})
            if response.get("ok") is not True:
                raise ValueError("graph service denied status: " + str(response.get("error", "unknown response")))
            result = {"ok": True, "source": "authorized_graph_service", "status": response.get("result"),
                      "scope": "Live service status under its configured identity and evidence checks; not deployment proof.",
                      "release_verdict": "NOT_PASS"}
        else:
            result = inspect_database(args.database, project=args.project, node_id=getattr(args, "node", None),
                                      events=args.command == "events", policy_path=args.policy)
        print(json.dumps(result, sort_keys=True, indent=None if args.json else 2, allow_nan=False))
        if result.get("workflow_state") == "failed":
            return 3
        return 0 if result.get("ok", True) else 1
    except (OSError, ValueError, RuntimeError, TypeError, KeyError, sqlite3.Error, subprocess.SubprocessError) as error:
        # Do not print subprocess output: a user's worker may emit sensitive data.
        message = str(error) if not isinstance(error, subprocess.SubprocessError) else type(error).__name__
        failure = {"ok": False, "error": message, "command": args.command, "release_verdict": "NOT_PASS"}
        if args.json:
            print(json.dumps(failure, sort_keys=True))
        else:
            print(f"codex-grapher: {message}", file=sys.stderr)
        return 2
