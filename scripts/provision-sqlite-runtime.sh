#!/usr/bin/env bash
# Explicit, task-local SQLite provisioning. Never modifies the host loader or packages.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: provision-sqlite-runtime.sh --prefix /absolute/task/runtime [options]

Build pinned SQLite 3.53.4 for the selected Python on Linux.

  --prefix ABS   Dedicated absent or empty task-local destination (required).
  --archive ABS  Use this exact source archive instead of downloading it.
  --python ABS   Python interpreter to verify and wrap (default: python3 on PATH).
  -h, --help     Show this help without downloading or building anything.

Requires Python 3 and cc. Downloads only the pinned official HTTPS archive when
--archive is omitted. Verifies archive and source size, SHA-256 and SHA3-256;
compiles one shared library with a 600-second limit; verifies Python's actual
loaded library, source ID and compile options. No package installation, system
loader configuration, database access or host service changes occur.

Outputs: lib/libsqlite3.so.0, source/sqlite3.c, the verified source archive,
build.log, attestation.json and bin/python-sqlite. The wrapper scopes
LD_LIBRARY_PATH to this runtime. A failed build retains its diagnostic files
without a completed attestation; choose a fresh prefix to retry.
USAGE
}

prefix=''
archive=''
python=''
while (($#)); do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --prefix|--archive|--python)
      (($# >= 2)) || { echo "$1 requires an absolute path" >&2; exit 64; }
      [[ "$2" == /* ]] || { echo "$1 requires an absolute path" >&2; exit 64; }
      case "$1" in
        --prefix) [[ -z "$prefix" ]] || exit 64; prefix="$2" ;;
        --archive) [[ -z "$archive" ]] || exit 64; archive="$2" ;;
        --python) [[ -z "$python" ]] || exit 64; python="$2" ;;
      esac
      shift 2
      ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done
[[ -n "$prefix" ]] || { echo '--prefix is required' >&2; usage >&2; exit 64; }
if [[ -z "$python" ]]; then
  python="$(command -v python3)" || { echo 'Python 3 is required' >&2; exit 69; }
fi
[[ -x "$python" && "$python" == /* ]] || { echo 'Python must be an absolute executable path' >&2; exit 69; }

# -I keeps user site packages and PYTHONPATH out of the provisioning process.
exec "$python" -I - "$prefix" "$archive" "$python" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request

VERSION = "3.53.4"
SOURCE_ID = "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc"
ARCHIVE_NAME = "sqlite-autoconf-3530400.tar.gz"
ARCHIVE_URL = "https://sqlite.org/2026/" + ARCHIVE_NAME
ARCHIVE_SIZE = 3283177
ARCHIVE_SHA256 = "0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c"
ARCHIVE_SHA3 = "454e45f61c6bd75b7420e7190732dea03ce6639c63ada47bbc592f67fc340338"
SOURCE_SIZE = 9515341
SOURCE_SHA256 = "b1dd5d74ec7f29055a6684fa06fb3c2f6821c87dd38f9a458dfd2e8a1db28189"
SOURCE_SHA3 = "67f423e9ebbbdc473cbc4772c872ee6b89f31fde4ed0279a5c25d5f65c043a16"
FLAGS = ["-O2", "-fPIC", "-shared", "-DSQLITE_THREADSAFE=1",
         "-DSQLITE_ENABLE_FTS5", "-DSQLITE_ENABLE_COLUMN_METADATA",
         "-ldl", "-lpthread", "-lm", "-Wl,-soname,libsqlite3.so.0"]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_bytes(data, size, sha256, sha3, label):
    require(len(data) == size, label + " byte length mismatch")
    require(hashlib.sha256(data).hexdigest() == sha256, label + " SHA-256 mismatch")
    require(hashlib.sha3_256(data).hexdigest() == sha3, label + " SHA3-256 mismatch")


def write_exclusive(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlsplit
        target = urlsplit(newurl)
        require(target.scheme == "https" and target.hostname in {"sqlite.org", "www.sqlite.org"},
                "refusing archive redirect outside SQLite HTTPS origin")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# This runs in the selected interpreter with the new library in its loader path.
# The mapping inode/device checks bind the hashed file to the live process mapping.
PROBE = r'''
import _sqlite3
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys

library = Path(sys.argv[1]).resolve(strict=True)
expected_hash, expected_version, expected_source = sys.argv[2:5]
mapped = set()
for line in Path("/proc/self/maps").read_text().splitlines():
    fields = line.split(None, 5)
    if len(fields) != 6:
        continue
    path = fields[5]
    if Path(path).name.startswith("libsqlite3.so") or path == str(library):
        if path.endswith(" (deleted)"):
            raise RuntimeError("loaded SQLite mapping was deleted")
        actual = Path(path).resolve(strict=True)
        st = actual.stat()
        major, minor = (int(value, 16) for value in fields[3].split(":"))
        if st.st_ino != int(fields[4]) or st.st_dev != os.makedev(major, minor):
            raise RuntimeError("loaded SQLite mapping does not match the file inode")
        mapped.add(str(actual))
if mapped != {str(library)}:
    raise RuntimeError("Python did not load exactly the provisioned SQLite library")
library_hash = hashlib.sha256(library.read_bytes()).hexdigest()
if library_hash != expected_hash:
    raise RuntimeError("loaded SQLite library hash changed")
with sqlite3.connect(":memory:") as connection:
    version, source = connection.execute("SELECT sqlite_version(), sqlite_source_id()").fetchone()
    options = sorted(row[0] for row in connection.execute("PRAGMA compile_options"))
    if version != expected_version or source != expected_source:
        raise RuntimeError("Python SQLite runtime version/source identity mismatch")
    if not {"THREADSAFE=1", "ENABLE_FTS5", "ENABLE_COLUMN_METADATA"}.issubset(options):
        raise RuntimeError("Python SQLite runtime compile options mismatch")
    connection.execute("CREATE VIRTUAL TABLE provision_fts USING fts5(content)")
extension = Path(_sqlite3.__file__).resolve(strict=True)
print(json.dumps({"version": version, "source_id": source,
                  "library_path": str(library), "library_sha256": library_hash,
                  "compile_options": options,
                  "python_sqlite_extension_sha256": hashlib.sha256(extension.read_bytes()).hexdigest()},
                 sort_keys=True))
'''


def main():
    require(sys.platform == "linux", "Linux /proc mapping verification is required")
    raw_prefix, raw_archive, raw_python = sys.argv[1:]
    for value in (raw_prefix, raw_archive, raw_python):
        require(not any(ord(char) < 32 for char in value), "control characters in paths are unsupported")
    prefix_path = Path(raw_prefix)
    require(prefix_path.is_absolute() and not prefix_path.is_symlink(), "prefix must be an absolute non-symlink path")
    prefix = prefix_path.resolve()
    forbidden = ("/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/sbin", "/sys", "/usr")
    require(str(prefix) not in {"/", "/root", "/home", "/opt", "/srv", "/tmp", "/var", "/var/tmp"},
            "prefix must be a dedicated task-local directory")
    require(not any(prefix == Path(item) or Path(item) in prefix.parents for item in forbidden),
            "system installation prefixes are forbidden")
    require(Path("/var") not in prefix.parents or Path("/var/tmp") in prefix.parents,
            "only task-local /var/tmp directories are allowed under /var")
    require(prefix.parent.is_dir(), "prefix parent must already exist")
    require(not prefix.exists() or (prefix.is_dir() and not any(prefix.iterdir())),
            "prefix already exists and is not empty; use a new task-local directory")
    python = Path(raw_python).absolute()
    require(python.is_file() and os.access(python, os.X_OK), "Python interpreter is not executable")
    compiler_name = shutil.which("cc")
    require(compiler_name is not None, "cc compiler is required; no compiler is installed automatically")
    compiler = Path(compiler_name).resolve(strict=True)
    compiler_hash = sha256_file(compiler)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("LD_")}
    environment.update({"LC_ALL": "C", "TMPDIR": str(prefix)})
    # Do not consult an enclosing checkout or private research path for source.
    if raw_archive:
        archive_input = Path(raw_archive)
        require(archive_input.is_absolute() and archive_input.is_file(), "archive must be an absolute regular file")
        with archive_input.open("rb") as stream:
            archive_bytes = stream.read(ARCHIVE_SIZE + 1)
    else:
        print("Downloading pinned SQLite archive from sqlite.org", file=sys.stderr, flush=True)
        opener = urllib.request.build_opener(OfficialRedirects())
        with opener.open(ARCHIVE_URL, timeout=30) as stream:
            archive_bytes = stream.read(ARCHIVE_SIZE + 1)
    # No tar parsing or extraction occurs before all three checks succeed.
    verify_bytes(archive_bytes, ARCHIVE_SIZE, ARCHIVE_SHA256, ARCHIVE_SHA3, "archive")
    prefix.mkdir(mode=0o700, exist_ok=True)
    for name in ("source", "lib", "bin"):
        (prefix / name).mkdir(mode=0o700)
    archive = prefix / "source" / ARCHIVE_NAME
    write_exclusive(archive, archive_bytes)
    with tarfile.open(archive, "r:gz") as tar:
        members = [member for member in tar.getmembers()
                   if member.name == "sqlite-autoconf-3530400/sqlite3.c"]
        require(len(members) == 1 and members[0].isfile() and members[0].size == SOURCE_SIZE,
                "archive lacks the unique expected regular amalgamation")
        with tar.extractfile(members[0]) as stream:
            source_bytes = stream.read(SOURCE_SIZE + 1)
    verify_bytes(source_bytes, SOURCE_SIZE, SOURCE_SHA256, SOURCE_SHA3, "sqlite3.c")
    source_text = source_bytes.decode("utf-8")
    require(re.findall(r'^#define SQLITE_VERSION\s+"([^"\n]+)"', source_text, re.MULTILINE) == [VERSION],
            "source version definition mismatch")
    require(re.findall(r'^#define SQLITE_SOURCE_ID\s+"([^"\n]+)"', source_text, re.MULTILINE) == [SOURCE_ID],
            "source ID definition mismatch")
    source = prefix / "source" / "sqlite3.c"
    write_exclusive(source, source_bytes)
    version_result = subprocess.run([str(compiler), "--version"], env=environment,
                                    capture_output=True, text=True, check=True, timeout=10)
    compiler_version = version_result.stdout.strip()
    require(compiler_version and len(compiler_version) <= 16384, "invalid compiler version output")
    library = prefix / "lib" / "libsqlite3.so.0"
    command = [str(compiler), *FLAGS[:6], str(source), *FLAGS[6:], "-o", str(library)]
    print("Building SQLite 3.53.4 with one compiler process", file=sys.stderr, flush=True)
    with (prefix / "build.log").open("xb") as log:
        subprocess.run(command, cwd=prefix, env=environment, stdout=log, stderr=subprocess.STDOUT,
                       check=True, timeout=600)
        log.flush()
        os.fsync(log.fileno())
    require(sha256_file(compiler) == compiler_hash, "compiler changed during provisioning")
    require(sha256_file(source) == SOURCE_SHA256, "source changed during compilation")
    library_hash = sha256_file(library)
    environment["LD_LIBRARY_PATH"] = str(prefix / "lib")
    result = subprocess.run([str(python), "-I", "-c", PROBE, str(library), library_hash, VERSION, SOURCE_ID],
                            env=environment, capture_output=True, text=True, check=True, timeout=30)
    attestation = json.loads(result.stdout)
    attestation.update({"schema_version": 1, "kind": "codex-grapher-sqlite-build",
                        "archive_sha256": ARCHIVE_SHA256, "source_sha256": SOURCE_SHA256,
                        "compiler_path": str(compiler), "compiler_sha256": compiler_hash,
                        "compiler_version": compiler_version, "compiler_flags": FLAGS})
    wrapper = ("#!/bin/sh\n"
               "# Loader settings apply only to this explicitly selected Python process.\n"
               "unset LD_PRELOAD LD_AUDIT\n"
               "LD_LIBRARY_PATH=" + shlex.quote(str(prefix / "lib")) + "\n"
               "export LD_LIBRARY_PATH\n"
               "exec " + shlex.quote(str(python)) + " \"$@\"\n")
    write_exclusive(prefix / "bin" / "python-sqlite", wrapper.encode(), 0o700)
    # Publish the attestation only after the actual selected Python passed the probe.
    data = (json.dumps(attestation, indent=2, sort_keys=True) + "\n").encode()
    write_exclusive(prefix / ".attestation.pending", data)
    os.rename(prefix / ".attestation.pending", prefix / "attestation.json")
    directory_fd = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    print(data.decode(), end="")


try:
    main()
except (OSError, RuntimeError, ValueError, tarfile.TarError, subprocess.SubprocessError) as exc:
    print("SQLite provisioning failed: " + str(exc), file=sys.stderr)
    if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
        print(exc.stderr, file=sys.stderr)
    sys.exit(1)
PY
