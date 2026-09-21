#!/usr/bin/python3
"""Guest-only service driver for the public deterministic recovery harness.

Never run on the host. Admission requires root, QEMU DMI and a NoCloud marker.
The driver calls public runtime modules, never tests or private research helpers.
"""
from __future__ import annotations
import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
CODE = Path("/opt/codex-grapher")
STATE = Path("/var/lib/grapher-guest-state")
WORKSPACE = Path("/srv/grapher-guest/workspace")
BARRIER = WORKSPACE / "state/guest-fixture-barrier/reached.json"
INPUT = Path("/srv/grapher-guest/input")
KEYS = Path("/etc/grapher-guest-keys")
PROFILE = Path("/etc/grapher-guest-profile.json")
UNIT = "grapher-recovery-fixture.service"
BOUNDARIES = {"after_reservation", "after_artifact_admission", "after_evaluation", "after_binding", "rollback_after_binding"}
ROLES = {"worker": 21001, "test_runner": 21002, "signer": 21003, "graph": 21004}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}


def command(argv, *, cwd=None, timeout=30, check=True):
    return subprocess.run(list(map(str, argv)), cwd=cwd, env=ENV, capture_output=True,
                          text=True, check=check, timeout=timeout)


def save(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".guest-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def hash_file(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def guarded_imports():
    marker = Path("/etc/grapher-disposable-guest")
    if os.geteuid() != 0 or not marker.is_file() or marker.read_text().strip() != "codex-grapher-guest-recovery-v1":
        raise RuntimeError("guest-only driver requires root and explicit NoCloud fixture marker")
    dmi = Path("/sys/class/dmi/id/product_name").read_text()
    if "QEMU" not in dmi and "Standard PC" not in dmi:
        raise RuntimeError("driver is restricted to the disposable QEMU guest")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("guest requires systemd PID 1")
    if Path(__file__).resolve() != CODE / "examples/guest-recovery/guest_driver.py":
        raise RuntimeError("guest driver must use the fixed root-owned installed path")
    sys.path.insert(0, str(CODE))


def accounts():
    for role, uid in ROLES.items():
        name = "grapher-" + role.replace("_", "-")
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            try:
                pwd.getpwuid(uid)
            except KeyError:
                pass
            else:
                raise RuntimeError("guest fixture UID is already allocated")
            command(["/usr/sbin/groupadd", "--gid", uid, name])
            command(["/usr/sbin/useradd", "--uid", uid, "--gid", uid, "--create-home", "--shell", "/usr/sbin/nologin", name])
            account = pwd.getpwnam(name)
        if account.pw_uid != uid or account.pw_gid != uid:
            raise RuntimeError("guest role account identity mismatch")


def profile(*, require_private=True):
    from control_plane.execution_profile import load_execution_profile
    return load_execution_profile(PROFILE, require_private_key=require_private)


def create_profile(*, require_private=True):
    from control_plane.execution_profile import trusted_code_digest
    provider = CODE / "examples/guest-recovery/deterministic_provider.py"
    provider.chmod(0o555)
    tools = {}
    for name in ("python", "git", "provider", "openssl", "bwrap", "setpriv"):
        located = provider if name == "provider" else Path(shutil.which("python3" if name == "python" else name) or "/absent").resolve()
        if not located.is_file():
            raise RuntimeError("missing guest prerequisite: " + name)
        version_args = ["version"] if name == "openssl" else ["--version"]
        version = command([located, *version_args]).stdout.strip().splitlines()[0]
        tools[name] = {"path": str(located), "sha256": hash_file(located), "version": version}
    value = {"schema_version": 1, "mode": "isolated-linux", "tools": tools,
        "provider": {"backend": "codex", "model": "gpt-5.6-sol", "reasoning_effort": "medium", "service_tier": "default"},
        "roles": {name: {"uid": uid, "gid": uid} for name, uid in ROLES.items()},
        "auth": {"kind": "existing-cli-login", "account": "grapher-worker"},
        "paths": {"trusted_code_root": str(CODE), "trusted_code_sha256": trusted_code_digest(CODE),
                  "signer_private_key": str(KEYS / "fixture-private.pem"), "signer_public_key": str(KEYS / "fixture-public.pem")},
        "sqlite": {"profile": "delete-extra", "attestation": None}}
    save(PROFILE, value); PROFILE.chmod(0o444)
    return profile(require_private=require_private)


def prepare(run_id):
    from control_plane.repository_workflow import initialize_repository_workflow
    from control_plane.isolated_runner import prepare_workspace_ownership
    accounts()
    STATE.mkdir(mode=0o755, exist_ok=True)
    if WORKSPACE.exists() or INPUT.exists():
        raise RuntimeError("fixture requires a fresh guest managed root")
    if not (KEYS / "fixture-private.pem").is_file():
        raise RuntimeError("separate task-local fixture signer key provisioning is required")
    execution = create_profile()
    INPUT.mkdir(parents=True, mode=0o755)
    source = INPUT / "source"
    source.mkdir()
    (source / "value.py").write_text("VALUE = 0\n")
    (source / "fixture-launches.jsonl").write_text("")
    command(["git", "init", "-q", source])
    command(["git", "-C", source, "add", "value.py", "fixture-launches.jsonl"])
    command(["git", "-C", source, "-c", "user.name=Guest Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Explicit deterministic seeded guest fixture"])
    sha = command(["git", "-C", source, "rev-parse", "HEAD"]).stdout.strip()
    python = execution.tools["python"].path
    check = "from pathlib import Path; assert Path('value.py').read_text() == 'VALUE = 42\\n'; assert Path('fixture-launches.jsonl').read_text() == '{\"fixture\":true}\\n'"
    save(INPUT / "policy.json", {"schema_version": 1, "name": "deterministic-guest-fixture", "threshold": 100,
        "sections": {"correctness": {"minimum": 100, "maximum": 100}}, "mandatory_gates": ["required_tests", "authorized_scope"]})
    save(INPUT / "checks.json", {"schema_version": 1, "checks": [{"id": "accepted-value", "argv": [python, "-I", "-B", "-c", check]}]})
    task = {"schema_version": 1, "project_id": "guest-recovery", "task_id": "guest-recovery-task",
        "idempotency_key": "guest-recovery-" + run_id, "base_sha": sha,
        "objective": "Set the deterministic fixture value to 42.", "acceptance_criteria": ["value.py contains VALUE = 42"],
        "allowed_paths": ["value.py", "fixture-launches.jsonl"], "required_tests": [shlex.join([python, "-I", "-B", "-c", check])],
        "worker": {"backend": "codex"}, "evaluation": {"policy": "policy.json", "checks": "checks.json"},
        "limits": {"worker_invocations": 1, "worker_timeout_seconds": 45, "required_test_timeout_seconds": 30,
                   "evaluation_timeout_seconds": 30, "max_output_bytes": 262144}}
    save(INPUT / "task.json", task)
    initialize_repository_workflow(source, INPUT / "task.json", WORKSPACE, PROFILE)
    prepare_workspace_ownership(execution, WORKSPACE)
    return observe()


def run_operation(operation, barrier=None):
    from control_plane.isolated_runner import bootstrap_operation
    return bootstrap_operation(profile(), WORKSPACE, operation, barrier=barrier)


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def service_identity():
    response = command(["systemctl", "show", UNIT, "--property=InvocationID,MainPID,ActiveState,SubState"], check=False).stdout
    return dict(line.split("=", 1) for line in response.splitlines() if "=" in line)


def raw_observe():
    # At a live pause the graph owns the writer lock. Read only committed DB
    # facts here; full closure is verified after that owner has been reaped.
    database = sqlite3.connect(f"file:{WORKSPACE / 'state/graph.sqlite'}?mode=ro", uri=True, timeout=2)
    try:
        count = database.execute("SELECT count(*) FROM publication_journal").fetchone()[0]
        operations = database.execute("SELECT count(DISTINCT operation_id) FROM publication_journal").fetchone()[0]
        completed = database.execute("SELECT count(DISTINCT operation_id) FROM publication_journal WHERE phase='COMPLETED'").fetchone()[0]
        tail = database.execute("SELECT last_sequence,last_hash FROM publication_journal_tail WHERE singleton=1").fetchone()
        journal = {"sequence": tail[0], "hash": tail[1]} if tail else {"sequence": None, "hash": None}
    finally:
        database.close()
    binding = json.loads((WORKSPACE / "state/binding.json").read_text())
    record = json.loads((WORKSPACE / "workflow.json").read_text())
    reservations = list((WORKSPACE / "attempts").rglob("reservation.json"))
    launches = 0
    witnesses = list((WORKSPACE / "attempts").glob("*/checkout/fixture-launches.jsonl"))
    for path in witnesses:
        if path.stat().st_size > 4096:
            raise RuntimeError("fixture launch witness exceeds bound")
        records = path.read_text().splitlines()
        if any(record != '{"fixture":true}' for record in records):
            raise RuntimeError("invalid fixture launch witness")
        launches += len(records)
    if reservations and not witnesses:
        launches = None  # Backup excludes worker scratch; never call absence zero launches.
    # Broker receipts are trusted read-only outputs; counting exact request kinds
    # detects extra required/independent test launches after a completed outcome.
    tests = []
    for path in (WORKSPACE / ".broker-receipts").rglob("*.json"):
        value = json.loads(path.read_text())
        if isinstance(value, dict) and value.get("kind") in {"required", "independent"} and "receipt_id" in value:
            tests.append(value["receipt_id"])
    identity = service_identity()
    return {"managed_root": str(WORKSPACE), "boot_id": boot_id(), "accepted_sha": binding["base_sha"],
        "baseline_sha": record["baseline_sha"], "attempts": len(reservations), "test_runs": sorted(set(tests)),
        "publication_journal_entries": count, "publication_operations": operations, "publication_journal_tail": journal,
        "completed_publication_operations": completed, "fixture_provider_executions": launches,
        "service_invocation_id": identity.get("InvocationID"), "service": identity,
        "fixture_provider": True, "actual_model_invocations": 0}


def observe():
    from control_plane.repository_workflow import verify_workspace, workspace_lock
    with workspace_lock(WORKSPACE):
        summary = verify_workspace(WORKSPACE)
    value = raw_observe()
    value.update(summary)
    value["closure_valid"] = summary["integrity_verified"] is True
    value["next_safe_action"] = summary.get("classification") or summary["next_safe_action"]
    # A separate bounded process sees the accepted generation, independently of
    # the workflow return value. It executes trusted Git, not candidate Python.
    generation = Path(summary["accepted_generation"])
    value["consumer_sha"] = command(["git", "-c", "safe.directory=" + str(generation), "-C", generation, "rev-parse", "HEAD"]).stdout.strip()
    return value


def install_service(boundary):
    if boundary not in BOUNDARIES:
        raise ValueError("unknown fixture boundary")
    save(STATE / "service-request.json", {"boundary": boundary})
    BARRIER.parent.mkdir(mode=0o700)
    os.chown(BARRIER.parent, ROLES["graph"], ROLES["graph"])
    unit = ("[Unit]\nDescription=Disposable Grapher recovery fixture\nAfter=network.target\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\nRestart=on-failure\nRestartSec=1\n"
        "KillMode=control-group\nTimeoutStartSec=540\nTimeoutStopSec=15\n"
        "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        f"ExecStart=/usr/bin/python3 -I {CODE}/examples/guest-recovery/guest_driver.py serve\n"
        "[Install]\nWantedBy=multi-user.target\n")
    Path("/etc/systemd/system", UNIT).write_text(unit)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", UNIT])
    command(["systemctl", "start", "--no-block", UNIT])
    return {"started": True, "boundary": boundary}


def serve():
    request = json.loads((STATE / "service-request.json").read_text())
    started = STATE / "started.json"
    if started.exists():
        result = run_operation("recover")
    else:
        save(started, {"boot_id": boot_id(), "first_service": os.environ.get("INVOCATION_ID")})
        wanted = request["boundary"]
        def barrier(name):
            if name != wanted:
                return
            save(BARRIER, {"boundary": name, "boot_id": boot_id(),
                 "service_invocation_id": os.environ.get("INVOCATION_ID"), "pid": os.getpid()})
            deadline = time.monotonic() + 540
            while time.monotonic() < deadline:
                time.sleep(0.5)
            raise TimeoutError("fixture barrier was not interrupted within 540 seconds")
        if wanted == "rollback_after_binding":
            run_operation("run")
            result = run_operation("rollback", barrier)
        else:
            result = run_operation("run", barrier)
    save(STATE / "service-result.json", result)
    return result


def wait_for(path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return json.loads(path.read_text())
        time.sleep(0.5)
    raise TimeoutError("guest fixture result deadline: " + path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "start", "serve", "wait-barrier", "observe", "restart-service", "wait-recovered", "recover", "complete", "rollback", "backup", "restore", "key-status"])
    parser.add_argument("--run-id", default="guest-fixture")
    parser.add_argument("--boundary", choices=sorted(BOUNDARIES))
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    guarded_imports()
    if args.action == "prepare": result = prepare(args.run_id)
    elif args.action == "start": result = install_service(args.boundary)
    elif args.action == "serve": result = serve()
    elif args.action == "wait-barrier":
        result = wait_for(BARRIER, 170)
        if result["boundary"] != args.boundary: raise RuntimeError("wrong reached boundary")
    elif args.action == "observe": result = raw_observe()
    elif args.action == "restart-service":
        command(["systemctl", "kill", "--signal=KILL", "--kill-whom=all", UNIT])
        result = {"signal": "KILL", "unit": UNIT, "systemd_restart_policy": "on-failure"}
    elif args.action == "wait-recovered":
        wait_for(STATE / "service-result.json", 170)
        result = observe()
    elif args.action in {"recover", "complete", "rollback"}:
        run_operation("run" if args.action == "complete" else args.action)
        result = observe()
    elif args.action == "backup":
        from control_plane.workspace_backup import backup_workspace
        archive = Path("/var/lib/grapher-workspace-backup.tar")
        receipt = backup_workspace(WORKSPACE, archive)
        result = {"archive": str(archive), "archive_sha256": hash_file(archive),
            "receipt": dataclasses.asdict(receipt) if dataclasses.is_dataclass(receipt) else receipt}
    elif args.action == "restore":
        from control_plane.workspace_backup import restore_workspace
        accounts(); create_profile(require_private=False)
        WORKSPACE.parent.mkdir(parents=True, exist_ok=True)
        receipt = restore_workspace(args.archive, WORKSPACE, profile(require_private=False))
        result = observe()
        result["restore_receipt"] = dataclasses.asdict(receipt) if dataclasses.is_dataclass(receipt) else receipt
    elif args.action == "key-status":
        derived = command(["openssl", "pkey", "-in", KEYS / "fixture-private.pem", "-pubout"]).stdout.encode()
        frozen = (WORKSPACE / "frozen/public-key.pem").read_bytes()
        if derived != frozen:
            raise RuntimeError("separately provisioned key does not match frozen public identity")
        result = {"key_matches_frozen_public": True, "public_key_sha256": hashlib.sha256(frozen).hexdigest(), "private_key_recorded": False}
    print(json.dumps(result, sort_keys=True, default=str))


if __name__ == "__main__":
    main()
