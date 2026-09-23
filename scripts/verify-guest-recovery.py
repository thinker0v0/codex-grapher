#!/usr/bin/env python3
"""Bounded, disposable QEMU recovery checks; never alters host services/accounts.

Run --help before use. The deterministic guest provider is NOT a real-model test.
Each invocation runs one scenario, with one guest and a 600-second deadline.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples" / "guest-recovery"
GUEST_CODE = "/opt/codex-grapher"
GUEST_DRIVER = GUEST_CODE + "/examples/guest-recovery/guest_driver.py"
BOUNDARIES = {
    "B1": "after_reservation", "B2": "after_artifact_admission",
    "B3": "after_evaluation", "B4": "after_binding",
    "B5": "rollback_after_binding",
}
SCENARIOS = ["provision", "boot-reboot", "restore"] + [
    f"{boundary}-{fault}" for boundary in BOUNDARIES
    for fault in ("service", "reset")
]
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}

# The source archive has file members only. Tar creates their parent directories
# using the guest caller's umask, so merely removing write bits is insufficient:
# 0700 becomes 0500 and prevents the dropped roles from reading trusted code.
# This fixed program operates only on our explicit installed public source tree.
PUBLIC_TREE_MODE_PROGRAM = """import os, stat, sys
from pathlib import Path
root = Path(sys.argv[1])
entries = [root, *root.rglob('*')]
for path in entries:
    mode = path.lstat().st_mode
    if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
        raise RuntimeError('public install contains a link or special entry')
for path in entries:
    mode = path.lstat().st_mode
    os.chmod(path, 0o555 if stat.S_ISDIR(mode) or mode & 0o111 else 0o444)
"""


def make_public_directory(path: Path) -> None:
    """Give only newly created task-owned public directories explicit modes."""
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    if not current.is_dir():
        raise NotADirectoryError(current)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o755)
        except FileExistsError:
            if not directory.is_dir():
                raise NotADirectoryError(directory) from None
            # Another owner created it. Never chmod an existing arbitrary path.
        else:
            directory.chmod(0o755)


def digest(path: Path, algorithm: str = "sha256") -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".evidence-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def resource_check(path: Path) -> dict:
    mem = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(mem["MemAvailable"].split()[0]) * 1024
    free = shutil.disk_usage(path).free
    if available < 3 * 1024**3:
        raise RuntimeError("require 3 GiB host MemAvailable for one 1 GiB TCG guest")
    if free < 6 * 1024**3:
        raise RuntimeError("require 6 GiB free task-local disk")
    others = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            if entry.joinpath("exe").resolve(strict=True).name.startswith("qemu-system-"):
                others.append(int(entry.name))
        except (OSError, RuntimeError):
            pass
    if others:
        raise RuntimeError("another QEMU process is active; one-guest limit")
    return {"mem_available_bytes": available, "disk_free_bytes": free,
            "minimum_memory_bytes": 3 * 1024**3, "minimum_disk_bytes": 6 * 1024**3}


class Harness:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.started = time.monotonic()
        self.deadline = self.started + args.timeout
        self.runtime = args.runtime.absolute()
        if self.runtime.is_symlink():
            raise ValueError("runtime cannot be a symlink")
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.runtime = self.runtime.resolve()
        if os.geteuid() == 0:
            os.chown(self.runtime, 0, args.qemu_gid)
            self.runtime.chmod(0o750)
        self.cache = (args.cache or self.runtime / "cache").resolve()
        make_public_directory(self.cache)
        self.local = self.runtime / "qemu-root"
        make_public_directory(self.local)
        self.key_dir = self.runtime / "keys"
        self.key_dir.mkdir(exist_ok=True, mode=0o700)
        self.key_dir.chmod(0o700)
        self.key = self.key_dir / "fixture-ed25519"
        self.prepared = None
        if args.prepared_runtime:
            prepared_root = args.prepared_runtime.resolve(strict=True)
            self.prepared = json.loads((prepared_root / "prepared-image.json").read_text())
            self.prepared["runtime"] = str(prepared_root)
            self.key = prepared_root / "keys/fixture-ed25519"  # use in place; never copy private key
        self.report = {
            "schema_version": 1, "project_id": "opensource",
            "task_id": "guest-recovery-" + args.scenario,
            "idempotency_key": args.run_id, "scenario": args.scenario,
            "scope": "disposable guest; deterministic provider; no actual model",
            "started_utc": utc(), "limits": {"scenario_seconds": args.timeout,
            "boot_seconds": 180, "guest_count": 1, "vcpus": 1,
            "guest_memory_mib": 1024, "tcg_tb_size_mib": 64,
            "combined_command_output_bytes": 8 * 1024**2},
            "commands": [], "observations": {}, "assertions": {},
            "status": "RUNNING", "private_key_bytes_recorded": False,
        }
        self.report["harness_sha256"] = digest(Path(__file__))
        self.report["fixture_hashes"] = {str(path.relative_to(ROOT)): digest(path)
            for path in FIXTURES.rglob("*") if path.is_file() and "__pycache__" not in path.parts}
        self.process: subprocess.Popen | None = None
        self.stderr_stream = None
        self.guest_dir: Path | None = None
        self.port = 0
        self.env = dict(ENVIRONMENT)
        self.env["LD_LIBRARY_PATH"] = ":".join(str(self.local / p) for p in
            ("usr/lib/x86_64-linux-gnu", "lib/x86_64-linux-gnu"))
        self.env["QEMU_MODULE_DIR"] = str(self.local / "usr/lib/x86_64-linux-gnu/qemu")
        self.lock = (self.runtime / ".harness.lock").open("a+")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def save(self):
        atomic_json(self.args.output, self.report)

    def remaining(self, maximum: float) -> float:
        left = min(maximum, self.deadline - time.monotonic())
        if left <= 0:
            raise TimeoutError("scenario deadline reached")
        return left

    def run(self, argv, *, timeout=60, check=True, env=None, record=True, stdin=None):
        argv = [str(arg) for arg in argv]
        began = time.monotonic()
        end = began + self.remaining(timeout)
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or ENVIRONMENT,
            start_new_session=True)
        output = {"stdout": bytearray(), "stderr": bytearray()}
        timed_out = overflow = False
        try:
            if stdin is not None:
                # Input transfers use a regular file descriptor through transfer(),
                # not this bounded small JSON/stdin path.
                process.stdin.write(stdin)
                process.stdin.close()
            streams = {process.stdout: "stdout", process.stderr: "stderr"}
            while streams:
                if time.monotonic() >= end:
                    timed_out = True
                    raise TimeoutError("command deadline")
                ready, _, _ = select.select(list(streams), [], [], min(0.2, end - time.monotonic()))
                for stream in ready:
                    data = os.read(stream.fileno(), 65536)
                    if not data:
                        del streams[stream]
                        continue
                    output[streams[stream]].extend(data)
                    if sum(map(len, output.values())) > 8 * 1024**2:
                        overflow = True
                        raise RuntimeError("command output bound exceeded")
            code = process.wait(timeout=max(0.1, end - time.monotonic()))
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
            raise
        finally:
            if record:
                result = {"argv": argv, "cwd": str(Path.cwd()), "environment": env or ENVIRONMENT,
                    "exit": process.returncode, "timeout": timed_out, "output_overflow": overflow,
                    "elapsed_seconds": round(time.monotonic() - began, 3)}
                for name, data in output.items():
                    result[name] = data.decode("utf-8", errors="replace")
                    result[name + "_sha256"] = hashlib.sha256(data).hexdigest()
                    result[name + "_bytes"] = len(data)
                self.report["commands"].append(result)
                self.save()
            process.stdout.close()
            process.stderr.close()
        text = output["stdout"].decode("utf-8", errors="strict")
        if check and code:
            raise RuntimeError(f"command failed ({code}): {argv[0]}: " + output["stderr"].decode(errors="replace")[-1000:])
        return code, text

    def download(self, spec, algorithm):
        path = self.cache / spec["filename"]
        if not path.exists() and spec["filename"].startswith("debian-13-genericcloud"):
            legacy = self.cache / "debian-13-genericcloud-amd64.qcow2"
            if legacy.is_file() and not legacy.is_symlink() and legacy.stat().st_size == spec["size_bytes"] and digest(legacy, algorithm) == spec[algorithm]:
                path = legacy  # Verified pilot cache alias; never follow an unverified image.
        if not path.is_file():
            if not self.args.download:
                raise RuntimeError(f"missing pinned cache file {path.name}; use --download explicitly")
            request = urllib.request.Request(spec["url"], headers={"User-Agent": "codex-grapher-guest/1"})
            partial = path.with_suffix(path.suffix + ".part")
            try:
                with urllib.request.urlopen(request, timeout=self.remaining(60)) as response, partial.open("wb") as target:
                    total = 0
                    while True:
                        self.remaining(60)
                        data = response.read(1024 * 1024)
                        if not data:
                            break
                        total += len(data)
                        if total > spec["size_bytes"]:
                            raise RuntimeError("download larger than pinned size")
                        target.write(data)
                    target.flush()
                    os.fsync(target.fileno())
                os.replace(partial, path)
            finally:
                partial.unlink(missing_ok=True)
        if path.is_symlink() or path.stat().st_size != spec["size_bytes"] or digest(path, algorithm) != spec[algorithm]:
            raise RuntimeError("pinned download size/hash/type mismatch: " + path.name)
        return path

    def prepare(self):
        lock_path = FIXTURES / "toolchain-lock.json"
        lock = json.loads(lock_path.read_text())
        self.report["toolchain_lock_sha256"] = digest(lock_path)
        self.report["resources_before"] = resource_check(self.runtime)
        for package in lock["packages"]:
            path = self.download(package, "sha256")
            self.run(["dpkg-deb", "-x", path, self.local], timeout=20)
        self.base = self.download(lock["image"], "sha512")
        self.base.chmod(0o444)
        if self.prepared:
            prepared_disk = Path(self.prepared["runtime"]) / "original/overlay.qcow2"
            if (self.prepared["base_sha512"] != lock["image"]["sha512"]
                    or digest(prepared_disk) != self.prepared["overlay_sha256"]
                    or self.prepared["guest_packages_lock_sha256"] != digest(FIXTURES / "guest-packages-lock.json")):
                raise RuntimeError("prepared inert image provenance mismatch")
        self.qemu = self.local / "usr/bin/qemu-system-x86_64"
        self.qimg = self.local / "usr/bin/qemu-img"
        self.iso = self.local / "usr/bin/genisoimage"
        self.report["image"] = lock["image"]
        self.report["runtime_tools"] = {}
        for name, path in (("qemu", self.qemu), ("qemu-img", self.qimg), ("genisoimage", self.iso)):
            _, output = self.run([path, "--version" if name != "genisoimage" else "-version"], env=self.env)
            self.report["runtime_tools"][name] = {"sha256": digest(path), "version": output.strip()}
        # The .deb pins do not fix host-provided dynamic dependencies. Record their
        # actual loaded resolution and hashes instead of claiming a hermetic host.
        _, linked = self.run(["ldd", self.qemu], env=self.env)
        self.report["host_runtime_libraries"] = {}
        for line in linked.splitlines():
            fields = line.split()
            path = next((Path(item) for item in fields if item.startswith("/")), None)
            if path and path.is_file():
                self.report["host_runtime_libraries"][str(path)] = digest(path)
        if not self.key.exists() and self.prepared:
            raise RuntimeError("prepared image fixture SSH identity is unavailable")
        if not self.key.exists():
            self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                "disposable-grapher-guest", "-f", self.key])
        if self.key.is_symlink() or self.key.stat().st_mode & 0o077:
            raise RuntimeError("fixture SSH key must be a private regular file")
        self.save()

    def disk(self, name):
        directory = self.runtime / name
        directory.mkdir(exist_ok=False, mode=0o700)
        # QEMU never runs as root. The containing task tree must already permit
        # this existing UID; this harness does not chmod unrelated ancestors.
        if os.geteuid() == 0:
            os.chown(directory, self.args.qemu_uid, self.args.qemu_gid)
        seed = directory / "seed"
        seed.mkdir(mode=0o700)
        (seed / "meta-data").write_text(f"instance-id: grapher-{self.args.run_id}-{name}\nlocal-hostname: grapher-disposable\n")
        (seed / "user-data").write_text("#cloud-config\nusers:\n  - name: grapher\n"
            "    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n    lock_passwd: true\n"
            "    ssh_authorized_keys:\n      - " + self.key.with_suffix(".pub").read_text().strip() + "\n"
            "ssh_pwauth: false\ndisable_root: true\npackage_update: false\npackage_upgrade: false\n"
            "write_files:\n  - path: /etc/grapher-disposable-guest\n    permissions: '0444'\n"
            "    content: 'codex-grapher-guest-recovery-v1'\n")
        self.run([self.iso, "-quiet", "-output", directory / "seed.iso", "-volid", "cidata",
            "-joliet", "-rock", seed / "user-data", seed / "meta-data"], env=self.env)
        backing = (Path(self.prepared["runtime"]) / "original/overlay.qcow2") if self.prepared else self.base
        self.run([self.qimg, "create", "-f", "qcow2", "-F", "qcow2", "-b", backing,
            directory / "overlay.qcow2", "4G"], env=self.env)
        if os.geteuid() == 0:
            for path in (directory / "seed.iso", directory / "overlay.qcow2"):
                os.chown(path, self.args.qemu_uid, self.args.qemu_gid)
        return directory

    def start(self, directory):
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("one guest already running")
        resource_check(self.runtime)
        self.guest_dir = directory
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        qmp = directory / "qmp.sock"
        qmp.unlink(missing_ok=True)
        command = [str(self.qemu), "-L", str(self.local / "usr/share/qemu"), "-bios",
            str(self.local / "usr/share/seabios/bios-256k.bin"), "-vga", "none",
            "-machine", "pc,smm=off", "-cpu", "max", "-accel", "tcg,thread=single,tb-size=64",
            "-smp", "1", "-m", "1024", "-display", "none", "-monitor", "none",
            "-serial", "file:" + str(directory / "serial.log"),
            "-qmp", "unix:" + str(qmp) + ",server=on,wait=off",
            "-drive", f"file={directory / 'overlay.qcow2'},format=qcow2,if=virtio,cache=none",
            "-drive", f"file={directory / 'seed.iso'},format=raw,media=cdrom,readonly=on",
            "-netdev", f"user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:{self.port}-:22",
            "-device", "virtio-net-pci,netdev=net0,romfile=",
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
        if os.geteuid() == 0:
            if self.args.qemu_uid <= 0 or self.args.qemu_gid <= 0:
                raise RuntimeError("QEMU host UID/GID must be nonzero")
            command = ["setpriv", f"--reuid={self.args.qemu_uid}", f"--regid={self.args.qemu_gid}",
                "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
                "--no-new-privs"] + command
        self.stderr_stream = (directory / "qemu-stderr.log").open("ab")
        self.process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=self.stderr_stream, env=self.env, start_new_session=True)
        self.report.setdefault("guest_launches", []).append({"argv": command, "pid": self.process.pid,
            "started_utc": utc(), "disk": directory.name, "environment": self.env})
        self.save()
        self.ready()

    def ssh_argv(self):
        return ["ssh", "-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=accept-new",
            "-o", "UserKnownHostsFile=" + str(self.key_dir / (self.guest_dir.name + "-known-hosts")),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "LogLevel=ERROR",
            "-i", str(self.key), "-p", str(self.port), "grapher@127.0.0.1"]

    def ssh(self, command, **kwargs):
        return self.run(self.ssh_argv() + [command], **kwargs)

    def ready(self, *, previous_boot_id=None):
        began = time.monotonic()
        until = min(began + 180, self.deadline)
        attempts = 0
        while time.monotonic() < until:
            attempts += 1
            if self.process.poll() is not None:
                raise RuntimeError("QEMU exited: " + (self.guest_dir / "qemu-stderr.log").read_text()[-1500:])
            try:
                code, output = self.ssh("cat /proc/sys/kernel/random/boot_id", timeout=min(8, until-time.monotonic()), check=False, record=False)
                boot_id = output.strip()
                if code == 0 and len(boot_id) == 36 and boot_id != previous_boot_id:
                    self.report.setdefault("boots", []).append({"boot_id": boot_id,
                        "previous_boot_id": previous_boot_id, "attempts": attempts,
                        "elapsed_seconds": round(time.monotonic()-began, 3), "disk": self.guest_dir.name})
                    self.save()
                    return boot_id
            except TimeoutError:
                # TCG can accept TCP before sshd finishes an eight-second handshake.
                # Only the overall boot deadline terminates the readiness loop.
                pass
            time.sleep(min(2, max(0, until-time.monotonic())))
        raise TimeoutError("180-second guest boot/readiness deadline exceeded")

    def stop(self, *, abrupt=False):
        if self.process is None:
            return
        if self.process.poll() is None:
            if abrupt:
                self.process.kill()
            else:
                self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.report.setdefault("guest_stops", []).append({"pid": self.process.pid,
            "exit": self.process.returncode, "abrupt_sigkill": abrupt, "stopped_utc": utc()})
        if self.stderr_stream:
            self.stderr_stream.close()
        self.process = None
        self.save()

    def driver(self, action, *, timeout=90, **values):
        command = ["sudo", "-n", "/usr/bin/python3", "-I", GUEST_DRIVER, action]
        for key, value in values.items():
            command.extend(["--" + key.replace("_", "-"), str(value)])
        _, result = self.ssh(shlex.join(command), timeout=timeout)
        value = json.loads(result)
        if not isinstance(value, dict):
            raise ValueError("guest driver did not return an object")
        return value

    def transfer(self, source: Path, destination: str, *, sensitive=False):
        # No host mounts: stream only the explicit public archive/backup over SSH.
        with source.open("rb") as stream:
            command = self.ssh_argv() + ["sudo -n sh -c " + shlex.quote("umask 077; cat > " + shlex.quote(destination))]
            began = time.monotonic()
            process = subprocess.Popen(command, stdin=stream, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, env=ENVIRONMENT, start_new_session=True)
            try:
                _, err = process.communicate(timeout=self.remaining(90))
                if process.returncode:
                    raise RuntimeError("SSH explicit transfer failed: " + err.decode(errors="replace")[-500:])
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
            self.report["commands"].append({"argv": command, "exit": process.returncode,
                "stdin_sha256": None if sensitive else digest(source),
                "stdin_bytes": None if sensitive else source.stat().st_size,
                "input_scope": "separate private fixture key; bytes omitted" if sensitive else "public archive",
                "stderr_sha256": hashlib.sha256(err).hexdigest(), "stderr_bytes": len(err),
                "elapsed_seconds": round(time.monotonic()-began, 3)})
            self.save()

    def install_public_source(self):
        _, sha = self.run(["git", "-c", "safe.directory=" + str(ROOT), "-C", ROOT, "rev-parse", "HEAD"])
        _, status = self.run(["git", "-c", "safe.directory=" + str(ROOT), "-C", ROOT, "status", "--porcelain"])
        if status and not self.args.allow_dirty_source:
            raise RuntimeError("acceptance requires clean source; --allow-dirty-source is development-only")
        self.report["source"] = {"git_sha": sha.strip(), "dirty": bool(status), "files": {}}
        _, tracked = self.run(["git", "-c", "safe.directory=" + str(ROOT), "-C", ROOT, "ls-files", "-z"])
        names = set(tracked.split("\0"))
        if self.args.allow_dirty_source:
            # New implementation files are an explicit development allowlist;
            # ignored/unreviewed local files never enter a public source transfer.
            names.update("control_plane/" + name + ".py" for name in (
                "repository_workflow", "repository_task", "worker_provider", "execution_profile",
                "isolated_runner", "evaluation_broker", "sealed_protocol", "workspace_backup",
                "backup_archive", "sqlite_runtime"))
            names.update("examples/guest-recovery/" + name for name in (
                "guest_driver.py", "deterministic_provider.py", "toolchain-lock.json",
                "guest-packages-lock.json", "README.md", "PINNING.md"))
        files = []
        for name in sorted(names):
            path = ROOT / name
            if not name.startswith(("control_plane/", "schemas/", "examples/guest-recovery/")):
                continue
            if path.is_symlink():
                raise RuntimeError("public source transfer refuses symlinks")
            if path.is_file():
                files.append(path)
        archive = self.runtime / "public-source.tar"
        with tarfile.open(archive, "w") as target:
            for path in files:
                relative = path.relative_to(ROOT).as_posix()
                self.report["source"]["files"][relative] = digest(path)
                target.add(path, arcname=relative, recursive=False)
        self.transfer(archive, "/tmp/grapher-public-source.tar")
        self.ssh("sudo -n mkdir -p /opt/codex-grapher && sudo -n tar --no-same-owner -xf /tmp/grapher-public-source.tar -C /opt/codex-grapher", timeout=30)
        self.ssh(shlex.join(["sudo", "-n", "/usr/bin/python3", "-I", "-c",
            PUBLIC_TREE_MODE_PROGRAM, GUEST_CODE]), timeout=30)
        self.save()

    def provision(self):
        # Network is restricted by QEMU. All prerequisite inputs are checked
        # against a public Debian package lock, then installed inside the guest.
        package_lock = FIXTURES / "guest-packages-lock.json"
        if not self.prepared:
            packages = json.loads(package_lock.read_text())["packages"]
            archive = self.runtime / "guest-packages.tar"
            with tarfile.open(archive, "w") as target:
                for package in packages:
                    path = self.download(package, "sha256")
                    target.add(path, arcname=package["filename"], recursive=False)
            self.transfer(archive, "/tmp/grapher-guest-packages.tar")
            self.ssh("sudo -n mkdir -p /var/tmp/grapher-packages && sudo -n tar --no-same-owner -xf /tmp/grapher-guest-packages.tar -C /var/tmp/grapher-packages", timeout=30)
            self.ssh(shlex.join(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "dpkg", "--install",
                *("/var/tmp/grapher-packages/" + package["filename"] for package in packages)]), timeout=120)
        self.report["guest_packages_lock_sha256"] = digest(package_lock)
        _, output = self.ssh("python3 - <<'PY'\nimport json,platform,shutil\nfrom pathlib import Path\nprint(json.dumps({'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'kernel':platform.release(),'python':platform.python_version(),'pid1':Path('/proc/1/comm').read_text().strip(),'tools':{x:shutil.which(x) for x in ['git','openssl','bwrap','setpriv','systemctl']}}))\nPY", timeout=30)
        self.report["observations"]["guest_prerequisites"] = json.loads(output)
        if any(not path for path in self.report["observations"]["guest_prerequisites"]["tools"].values()):
            raise RuntimeError("guest prerequisite missing after pinned package provisioning")
        self.save()

    def seal_prepared(self):
        self.ssh("test ! -e /srv/grapher-guest && test ! -e /etc/grapher-guest-keys && test ! -e /opt/codex-grapher && test ! -e /var/lib/grapher-guest-state", timeout=15)
        self.ssh("sudo -n systemctl poweroff", timeout=15, check=False)
        self.process.wait(timeout=self.remaining(45))
        if self.process.returncode:
            raise RuntimeError("prepared guest did not complete orderly shutdown")
        self.stop()
        overlay = self.runtime / "original/overlay.qcow2"
        overlay.chmod(0o444)
        prepared = {"schema_version": 1, "base_sha512": self.report["image"]["sha512"],
            "overlay_sha256": digest(overlay), "guest_packages_lock_sha256": self.report["guest_packages_lock_sha256"],
            "credential_free": True, "product_state_absent": True,
            "fixture_ssh_public_key_sha256": digest(self.key.with_suffix(".pub")),
            "prepared_utc": utc(), "orderly_shutdown": True}
        atomic_json(self.runtime / "prepared-image.json", prepared)
        self.report["prepared_image"] = prepared
        self.save()

    def provision_signer(self, *, public_only=False):
        private = self.key_dir / "fixture-signer.pem"
        public = self.key_dir / "fixture-signer-public.pem"
        if not private.exists():
            self.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private])
            private.chmod(0o600)
            self.run(["openssl", "pkey", "-in", private, "-pubout", "-out", public])
        self.ssh("sudo -n install -d -m 0755 /etc/grapher-guest-keys", timeout=15)
        self.transfer(public, "/etc/grapher-guest-keys/fixture-public.pem")
        self.ssh("sudo -n chmod 0444 /etc/grapher-guest-keys/fixture-public.pem", timeout=15)
        if not public_only:
            self.transfer(private, "/etc/grapher-guest-keys/fixture-private.pem", sensitive=True)
            self.ssh("sudo -n chown 0:21003 /etc/grapher-guest-keys/fixture-private.pem && sudo -n chmod 0440 /etc/grapher-guest-keys/fixture-private.pem", timeout=15)
        self.report.setdefault("separate_signer_provisioning", []).append({"disk": self.guest_dir.name,
            "public_only": public_only, "public_key_sha256": digest(public), "included_in_backup": False})
        self.save()

    def boundary(self):
        boundary, fault = self.args.scenario.split("-")
        self.install_public_source()
        self.provision_signer()
        prepared = self.driver("prepare", run_id=self.args.run_id)
        self.report["observations"]["prepared"] = prepared
        self.driver("start", boundary=BOUNDARIES[boundary], timeout=30)
        self.report["observations"]["barrier"] = self.driver("wait-barrier", boundary=BOUNDARIES[boundary], timeout=180)
        before = self.driver("observe")
        self.report["observations"]["before_fault"] = before
        if fault == "service":
            self.driver("restart-service", timeout=30)
        else:
            directory = self.guest_dir
            self.stop(abrupt=True)
            self.start(directory)
        after = self.driver("wait-recovered", timeout=180)
        self.report["observations"]["after_recovery"] = after
        replay = self.driver("recover", timeout=120)
        self.report["observations"]["replay"] = replay
        self.assert_recovery(boundary, fault, before, after, replay)

    def assert_recovery(self, boundary, fault, before, after, replay):
        checks = {"no_duplicate_invocation": before["attempts"] == after["attempts"] == replay["attempts"],
            "no_duplicate_provider_execution": before["fixture_provider_executions"] == after["fixture_provider_executions"] == replay["fixture_provider_executions"],
            "replay_no_publication_operation": after["publication_journal_entries"] == replay["publication_journal_entries"],
            "replay_same_journal_tail": after["publication_journal_tail"] == replay["publication_journal_tail"],
            "replay_same_accepted": after["accepted_sha"] == replay["accepted_sha"],
            "closure": after["closure_valid"] is True and replay["closure_valid"] is True,
            "service_recreated": before["service_invocation_id"] != after["service_invocation_id"]}
        checks["boot_identity"] = (before["boot_id"] != after["boot_id"]) if fault == "reset" else (before["boot_id"] == after["boot_id"])
        if boundary == "B1":
            checks["unsealed_pauses"] = after["next_safe_action"] == "WORKER_INTERRUPTED_UNSEALED"
            checks["baseline_preserved"] = after["accepted_sha"] == before["accepted_sha"]
            checks["no_publication"] = after["publication_journal_entries"] == before["publication_journal_entries"]
        else:
            checks["accepted_consumer"] = after["consumer_sha"] == after["accepted_sha"] and replay["consumer_sha"] == after["accepted_sha"]
            checks["exact_publication_operation_count"] = after["publication_operations"] == (2 if boundary == "B5" else 1)
            checks["all_publication_operations_complete"] = after["completed_publication_operations"] == after["publication_operations"] == replay["completed_publication_operations"]
            checks["final_workflow_state"] = after["workflow_state"] == replay["workflow_state"] == ("rolled_back" if boundary == "B5" else "promoted")
            checks["one_actual_fixture_execution"] = after["fixture_provider_executions"] == 1
        if boundary == "B5":
            checks["rollback_predecessor"] = after["accepted_sha"] == replay["accepted_sha"] == after["baseline_sha"]
        if boundary in {"B3", "B4", "B5"}:
            checks["no_completed_test_rerun"] = before["test_runs"] == after["test_runs"] == replay["test_runs"]
            checks["required_and_independent_receipts_exist"] = len(before["test_runs"]) >= 2
        self.report["assertions"].update(checks)
        if not all(checks.values()):
            raise AssertionError("recovery assertions failed: " + ", ".join(k for k, v in checks.items() if not v))

    def restore(self):
        self.install_public_source()
        self.provision_signer()
        self.driver("prepare", run_id=self.args.run_id)
        completed = self.driver("complete", timeout=180)
        self.report["observations"]["backup_source"] = completed
        backup = self.driver("backup", timeout=90)
        archive = self.runtime / "workspace-backup.tar"
        # Archive is public-state-only; fixture private signer key remains in its
        # independently protected key store and is never an archive member.
        command = self.ssh_argv() + ["sudo -n cat " + shlex.quote(backup["archive"])]
        with archive.open("wb") as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.PIPE, env=ENVIRONMENT)
            try:
                _, err = process.communicate(timeout=self.remaining(60))
                if process.returncode:
                    raise RuntimeError("backup retrieval failed")
            finally:
                if process.poll() is None:
                    process.kill(); process.wait(timeout=10)
        if digest(archive) != backup["archive_sha256"]:
            raise RuntimeError("backup transfer hash mismatch")
        self.report["observations"]["backup"] = backup
        original = self.guest_dir
        self.stop()
        # Distinct overlay backed only by the immutable base: no original disk,
        # host share or source workspace is reachable from this guest.
        fresh = self.disk("restored")
        self.start(fresh)
        self.provision()
        self.install_public_source()
        self.provision_signer(public_only=True)
        self.transfer(archive, "/tmp/grapher-workspace-backup.tar")
        restored = self.driver("restore", archive="/tmp/grapher-workspace-backup.tar", timeout=180)
        self.report["observations"]["restored"] = restored
        if restored["restore_receipt"]["verify_only"] is not True:
            raise AssertionError("fresh restore without private key must remain verify-only")
        self.provision_signer()
        self.report["observations"]["restored_signer"] = self.driver("key-status")
        replay = self.driver("recover", timeout=120)
        rollback = self.driver("rollback", timeout=120)
        self.report["observations"].update(restore_replay=replay, restored_rollback=rollback)
        self.report["assertions"].update({"original_guest_inaccessible": self.guest_dir != original,
            "fresh_boot_id": completed["boot_id"] != restored["boot_id"],
            "same_managed_root": completed["managed_root"] == restored["managed_root"],
            "restore_accepted_sha": completed["accepted_sha"] == restored["accepted_sha"] == replay["accepted_sha"],
            "restore_no_duplicate_invocation": completed["attempts"] == restored["attempts"] == replay["attempts"],
            "restore_idempotent_journal": completed["publication_journal_tail"] == restored["publication_journal_tail"] == replay["publication_journal_tail"],
            "restore_consumer": replay["consumer_sha"] == replay["accepted_sha"],
            "restore_closure": restored["closure_valid"] and replay["closure_valid"] and rollback["closure_valid"],
            "separate_matching_signer": self.report["observations"]["restored_signer"]["key_matches_frozen_public"],
            "rollback_predecessor": rollback["accepted_sha"] == completed["baseline_sha"]})
        if not all(self.report["assertions"].values()):
            raise AssertionError("fresh guest restore assertions failed")

    def capture_failure_service_diagnostics(self):
        # Failure evidence only: fixed disposable-fixture unit, never keys,
        # provider captures or arbitrary guest commands. Leave time for the
        # existing command reap (10s) and QEMU cleanup without extending deadlines.
        diagnostics = {"scope": "fixed fixture unit; read-only failure diagnostics",
            "maximum_collection_seconds": 20, "cleanup_reserve_seconds": 25,
            "command_reap_reserve_seconds": 10, "entries": []}
        self.report["failure_service_diagnostics"] = diagnostics
        if self.process is None or self.process.poll() is not None or self.guest_dir is None or not self.port:
            diagnostics["status"] = "SKIPPED_GUEST_NOT_RUNNING"
            return
        until = min(time.monotonic() + 20, self.deadline - 25)
        commands = (
            ("status", "sudo -n /usr/bin/systemctl --no-pager --full --lines=0 status grapher-recovery-fixture.service"),
            ("journal", "sudo -n /usr/bin/journalctl --unit=grapher-recovery-fixture.service --boot=0 --no-pager --quiet --lines=80 --output=short-precise"),
        )
        for kind, command in commands:
            # run() may spend 10s reaping a command after timeout or overflow.
            # Reserve that allowance before dispatch, then recompute for the next.
            budget = min(10, until - time.monotonic() - 10)
            entry = {"kind": kind}
            diagnostics["entries"].append(entry)
            if budget < 3:
                entry["status"] = "SKIPPED_INSUFFICIENT_REMAINING_BUDGET"
                continue
            index = len(self.report["commands"])
            entry["timeout_seconds"] = budget
            try:
                code, _ = self.ssh(command, timeout=budget, check=False)
                entry.update(status="RECORDED", exit=code)
            except BaseException as exc:
                entry.update(status="CAPTURE_ERROR", error_type=type(exc).__name__)
                if not isinstance(exc, Exception):
                    diagnostics["status"] = "INTERRUPTED"
                    return
            finally:
                if len(self.report["commands"]) > index:
                    entry["recorded_command_index"] = index
        diagnostics["status"] = "FINISHED"

    def execute(self):
        try:
            self.prepare()
            self.start(self.disk("original"))
            self.provision()
            if self.args.scenario == "boot-reboot":
                before = self.report["boots"][-1]["boot_id"]
                self.ssh("sudo -n systemctl reboot", timeout=15, check=False)
                after = self.ready(previous_boot_id=before)
                self.report["assertions"]["orderly_reboot_changed_boot_id"] = before != after
            elif self.args.scenario == "restore":
                self.restore()
            elif self.args.scenario == "provision":
                self.seal_prepared()
            else:
                self.boundary()
            self.report["status"] = "OBSERVED"  # independent judge owns any pass verdict
        except BaseException as exc:
            self.report["status"] = "INCOMPLETE"
            self.report["error"] = {"type": type(exc).__name__, "message": str(exc)}
            try:
                self.capture_failure_service_diagnostics()
            except BaseException as diagnostic_error:
                self.report["failure_service_diagnostics"] = {
                    "status": "CAPTURE_UNAVAILABLE", "error_type": type(diagnostic_error).__name__}
            raise
        finally:
            self.stop()
            self.report["finished_utc"] = utc()
            self.report["elapsed_seconds"] = round(time.monotonic()-self.started, 3)
            self.report["cleanup"] = {"no_guest_running": self.process is None,
                "retained_runtime": str(self.runtime), "key_location": "runtime/keys (not evidence)",
                "remove_instruction": "Remove only the explicit runtime directory after review."}
            self.report["runtime_logs"] = {}
            for path in self.runtime.glob("*/serial.log"):
                self.report["runtime_logs"][str(path.relative_to(self.runtime))] = {"sha256": digest(path), "bytes": path.stat().st_size}
            self.save()
            self.lock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=SCENARIOS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True, help="new task-local runtime; no secret material belongs in Git")
    parser.add_argument("--cache", type=Path, help="existing checksum-verified package/image cache")
    parser.add_argument("--prepared-runtime", type=Path, help="sealed credential-free provision scenario runtime; its fixture SSH key is used in place")
    parser.add_argument("--download", action="store_true", help="explicitly permit pinned public artifact downloads")
    parser.add_argument("--run-id", default="guest-recovery-1")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--qemu-uid", type=int, default=1000, help="existing non-root host UID; creates no account")
    parser.add_argument("--qemu-gid", type=int, default=1000)
    parser.add_argument("--allow-dirty-source", action="store_true", help="development only; output cannot prove clean-SHA acceptance")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600:
        parser.error("scenario timeout must be 1..600 seconds")
    if args.scenario == "provision" and args.prepared_runtime:
        parser.error("provision creates a fresh inert image; do not supply --prepared-runtime")
    if not args.run_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for c in args.run_id):
        parser.error("run-id must contain safe identifier characters")
    try:
        harness = Harness(args)
        def interrupted(signum, frame):
            raise InterruptedError(f"received signal {signum}")
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        harness.execute()
    except Exception as exc:
        print(json.dumps({"status": "INCOMPLETE", "error": str(exc), "evidence": str(args.output)}))
        return 1
    print(json.dumps({"status": "OBSERVED", "scenario": args.scenario, "evidence": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
