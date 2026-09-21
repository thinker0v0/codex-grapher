"""Current child-kernel checks before executing a role's command.

The privileged bootstrap supplies an internally derived mount plan and the fixed
seccomp policy digest. These checks do not establish trust against compromised
root code; the launcher's separate admission guard owns those code/context pins.
No provider process, candidate source, private key or authentication file is read.
"""
from __future__ import annotations

import ctypes
import errno
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any


_NAMESPACES = {"user": "user", "mount": "mnt", "pid": "pid", "ipc": "ipc",
               "net": "net", "uts": "uts"}
_CAPABILITIES = {"inheritable": "CapInh", "permitted": "CapPrm", "effective": "CapEff",
                 "bounding": "CapBnd", "ambient": "CapAmb"}
_MAX_MOUNTINFO_BYTES = 2 * 1024 * 1024
_MAX_MOUNTS = 4096
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_MASK = re.compile(r"[0-9a-fA-F]{1,16}\Z")
_DECIMAL = re.compile(r"[0-9]+\Z")
_ESCAPES = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}


def _deny(message: str) -> None:
    raise PermissionError("child boundary unavailable: " + message)


def _read_bounded(path: str, maximum: int) -> str:
    with Path(path).open("r", encoding="utf-8", errors="strict") as stream:
        value = stream.read(maximum + 1)
    if len(value.encode("utf-8")) > maximum:
        _deny("kernel observation exceeded its bound")
    return value


def _read_status() -> dict[str, str]:
    result = {}
    for line in _read_bounded("/proc/self/status", 128 * 1024).splitlines():
        if ":" not in line:
            _deny("malformed process status")
        key, value = line.split(":", 1)
        if not key or key in result:
            _deny("ambiguous process status")
        result[key] = value.strip()
    return result


def _read_namespaces() -> dict[str, int]:
    return {name: os.stat("/proc/self/ns/" + path).st_ino for name, path in _NAMESPACES.items()}


def _read_mountinfo() -> str:
    return _read_bounded("/proc/self/mountinfo", _MAX_MOUNTINFO_BYTES)


def _initial_uid_map() -> bool:
    return _read_bounded("/proc/self/uid_map", 4096).split() == ["0", "0", "4294967295"]


def _probe_unshare_zero() -> dict[str, int]:
    """Zero flags make this a non-effecting denial probe, even without seccomp."""
    library = ctypes.CDLL(None, use_errno=True)
    call = library.unshare
    call.argtypes = [ctypes.c_int]
    call.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = call(0)
    return {"returncode": result, "errno": ctypes.get_errno()}


def _integer(value: Any, name: str, *, minimum: int = 0, maximum: int = 2**64 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _deny("invalid " + name)
    return value


def _decimal(value: str, name: str, *, maximum: int = 2**64 - 1) -> int:
    if type(value) is not str or len(value) > 20 or not _DECIMAL.fullmatch(value):
        _deny("invalid " + name)
    return _integer(int(value), name, maximum=maximum)


def _namespace_values(value: Any) -> dict[str, int]:
    if type(value) is not dict or set(value) != set(_NAMESPACES):
        _deny("incomplete namespace observation")
    return {name: _integer(inode, "namespace inode", minimum=1) for name, inode in value.items()}


def _seccomp_values(status: dict[str, str]) -> dict[str, int]:
    return {"mode": _decimal(status["Seccomp"], "seccomp mode", maximum=2),
            "filters": _decimal(status["Seccomp_filters"], "seccomp filter count", maximum=4096)}


def capture_parent_boundary() -> dict[str, Any]:
    """Observe the explicit root bootstrap immediately before creating namespaces."""
    try:
        if os.geteuid() != 0 or not _initial_uid_map():
            _deny("parent is not the initial-domain root bootstrap")
        namespaces = _namespace_values(_read_namespaces())
        seccomp = _seccomp_values(_read_status())
        if seccomp["mode"] == 1 or (seccomp["mode"] == 0) != (seccomp["filters"] == 0):
            _deny("inconsistent parent seccomp state")
        return {"namespaces": namespaces, "seccomp": seccomp}
    except PermissionError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, OverflowError) as error:
        raise PermissionError("parent boundary observation unavailable") from error


def _unescape(value: str) -> str:
    result = []
    offset = 0
    while offset < len(value):
        if value[offset] != "\\":
            result.append(value[offset]); offset += 1
            continue
        escape = value[offset + 1:offset + 4]
        if escape not in _ESCAPES:
            _deny("invalid mountinfo escape")
        result.append(_ESCAPES[escape]); offset += 4
    return "".join(result)


def _mount_path(value: Any) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 4096 or "\0" in value:
        _deny("invalid mount destination")
    path = PurePosixPath(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        _deny("noncanonical mount destination")
    return value


def parse_mountinfo(text: str) -> list[dict[str, Any]]:
    """Parse only kernel mount identity/flags; never return host source paths."""
    try:
        if type(text) is not str or not text or len(text.encode("utf-8")) > _MAX_MOUNTINFO_BYTES:
            _deny("mountinfo exceeded its bound or is absent")
        lines = text.splitlines()
        if not 1 <= len(lines) <= _MAX_MOUNTS:
            _deny("mountinfo mount count exceeded its bound")
        result, identifiers = [], set()
        for line in lines:
            if line.count(" - ") != 1 or "\0" in line:
                _deny("malformed mountinfo separator")
            before, after = line.split(" - ", 1)
            left, right = before.split(" "), after.split(" ")
            if len(left) < 6 or len(right) != 3 or any(not field for field in left + right):
                _deny("malformed mountinfo fields")
            mount_id = _decimal(left[0], "mount ID")
            parent_id = _decimal(left[1], "mount parent ID")
            if mount_id == 0 or mount_id in identifiers:
                _deny("ambiguous mount ID")
            identifiers.add(mount_id)
            device = left[2].split(":")
            if len(device) != 2:
                _deny("invalid mount device")
            device_number = os.makedev(_decimal(device[0], "device major", maximum=2**32 - 1),
                                       _decimal(device[1], "device minor", maximum=2**32 - 1))
            _mount_path(_unescape(left[3]))
            destination = _mount_path(_unescape(left[4]))
            flags = left[5].split(",")
            if len(set(flags) & {"ro", "rw"}) != 1 or any(not flag for flag in flags):
                _deny("ambiguous mount permission flags")
            fstype = right[0]
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", fstype) is None:
                _deny("invalid mount filesystem type")
            # Validate escaping even in fields deliberately excluded from evidence.
            _unescape(right[1])
            result.append({"mount_id": mount_id, "parent_id": parent_id,
                           "device": device_number, "target": destination,
                           "readonly": "ro" in flags, "fstype": fstype})
        return result
    except PermissionError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError) as error:
        raise PermissionError("mountinfo observation unavailable") from error


def _validated_plan(value: Any) -> dict[str, dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= _MAX_MOUNTS:
        _deny("missing or oversized mount plan")
    result = {}
    source_fields = {"destination", "device", "inode", "readonly", "recursive"}
    kernel_fields = {"destination", "fstype", "readonly", "recursive"}
    for row in value:
        if type(row) is not dict or set(row) not in (source_fields, kernel_fields):
            _deny("invalid mount plan fields")
        destination = _mount_path(row["destination"])
        if destination == "/" or type(row["readonly"]) is not bool or type(row["recursive"]) is not bool:
            _deny("invalid mount plan authority")
        if set(row) == source_fields:
            _integer(row["device"], "planned device")
            _integer(row["inode"], "planned inode", minimum=1)
        elif ({"/proc": "proc", "/tmp": "tmpfs"}.get(destination) != row["fstype"]
              or row["readonly"] or row["recursive"]):
            _deny("invalid kernel mount plan")
        if destination in result and result[destination] != row:
            _deny("conflicting planned mount destination")
        result[destination] = dict(row)
    for destination, fstype in (("/proc", "proc"), ("/tmp", "tmpfs")):
        if result.get(destination, {}).get("fstype") != fstype:
            _deny("required kernel mount is absent from plan")
    return result


def _is_below(path: str, ancestor: str) -> bool:
    return path != ancestor and path.startswith(ancestor.rstrip("/") + "/")


def _effective_mounts(plan: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    mounts = parse_mountinfo(_read_mountinfo())
    root = os.stat("/")
    if not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_mode & 0o022:
        _deny("sandbox root is not root-owned and protected")
    seen, effective, mounted_targets = set(), [], {}
    for mount in mounts:
        target = mount["target"]
        exact = plan.get(target)
        ancestors = [row for destination, row in plan.items()
                     if row["recursive"] and _is_below(target, destination)]
        if target != "/" and exact is None and not ancestors:
            _deny("undeclared visible mount")
        if exact is not None:
            seen.add(target)
            if mount["readonly"] != exact["readonly"]:
                _deny("planned mount permission mismatch")
        if any(row["readonly"] for row in ancestors) and not mount["readonly"]:
            _deny("writable mount below recursive read-only authority")
        metadata = os.stat(target)
        if metadata.st_dev != mount["device"]:
            _deny("visible mount device differs from mounted target")
        if exact is not None:
            if "fstype" in exact:
                if mount["fstype"] != exact["fstype"]:
                    _deny("kernel mount filesystem mismatch")
            elif (metadata.st_dev, metadata.st_ino) != (exact["device"], exact["inode"]):
                _deny("mounted source identity changed")
        entry = {"destination": target, "readonly": mount["readonly"],
                 "fstype": mount["fstype"], "device": metadata.st_dev,
                 "inode": metadata.st_ino}
        if target in mounted_targets and mounted_targets[target] != entry:
            _deny("inconsistent stacked mount target")
        mounted_targets[target] = entry
        effective.append(entry)
    if seen != set(plan):
        _deny("planned mount is not visible")
    return sorted(effective, key=lambda row: (row["destination"], row["device"], row["inode"]))


def validate_child_boundary(
    observation: dict[str, Any], parent: dict[str, Any], *, expected_uid: int,
    expected_gid: int, network: bool, mount_plan: list[dict[str, Any]],
    seccomp_policy_sha256: str,
) -> dict[str, Any]:
    """Refuse exec unless current kernel state matches the root-derived boundary."""
    try:
        _integer(expected_uid, "expected UID", minimum=1, maximum=2**32 - 2)
        _integer(expected_gid, "expected GID", maximum=2**32 - 2)
        if type(network) is not bool or type(seccomp_policy_sha256) is not str or not _HEX64.fullmatch(seccomp_policy_sha256):
            _deny("invalid network policy or seccomp policy identity")
        if type(parent) is not dict or set(parent) != {"namespaces", "seccomp"}:
            _deny("invalid parent observation")
        parent_namespaces = _namespace_values(parent["namespaces"])
        parent_seccomp = parent["seccomp"]
        if type(parent_seccomp) is not dict or set(parent_seccomp) != {"mode", "filters"}:
            _deny("invalid parent seccomp observation")
        mode = _integer(parent_seccomp["mode"], "parent seccomp mode", maximum=2)
        filters = _integer(parent_seccomp["filters"], "parent seccomp filter count", maximum=4096)
        if mode == 1 or (mode == 0) != (filters == 0):
            _deny("inconsistent parent seccomp observation")
        if type(observation) is not dict:
            _deny("invalid child observation")
        _integer(observation["actual_uid"], "observed UID", minimum=1, maximum=2**32 - 2)
        _integer(observation["actual_gid"], "observed GID", maximum=2**32 - 2)
        if (observation["actual_uid"], observation["actual_gid"]) != (expected_uid, expected_gid):
            _deny("reported role identity mismatch")
        status = _read_status()
        uids = tuple(_decimal(value, "kernel UID", maximum=2**32 - 2) for value in status["Uid"].split())
        gids = tuple(_decimal(value, "kernel GID", maximum=2**32 - 2) for value in status["Gid"].split())
        if (os.getresuid() != (expected_uid,) * 3 or os.getresgid() != (expected_gid,) * 3
                or uids != (expected_uid,) * 4 or gids != (expected_gid,) * 4):
            _deny("kernel real/effective/saved/filesystem identity mismatch")
        if os.getgroups() or status["Groups"].split():
            _deny("supplementary role groups remain")
        caps = observation["capabilities"]
        if type(caps) is not dict or set(caps) != set(_CAPABILITIES):
            _deny("incomplete capability observation")
        for name, field in _CAPABILITIES.items():
            actual, reported = status[field], caps[name]
            if (type(reported) is not str or not _HEX_MASK.fullmatch(actual)
                    or not _HEX_MASK.fullmatch(reported) or int(actual, 16) or int(reported, 16)):
                _deny("role retained capabilities")
        if observation["no_new_privs"] is not True or status["NoNewPrivs"] != "1":
            _deny("no-new-privileges is absent")
        namespaces = _namespace_values(_read_namespaces())
        reported_ns = observation["namespaces"]
        if (type(reported_ns) is not dict or set(reported_ns) not in
                (set(_NAMESPACES), set(_NAMESPACES) - {"uts"})):
            _deny("incomplete reported namespace observation")
        for name, inode in reported_ns.items():
            if _integer(inode, "reported namespace inode", minimum=1) != namespaces[name]:
                _deny("reported namespace differs from current kernel")
        if not _initial_uid_map() or namespaces["user"] != parent_namespaces["user"]:
            _deny("initial user namespace was not retained")
        for name in ("mount", "pid", "ipc", "uts"):
            if namespaces[name] == parent_namespaces[name]:
                _deny("required private namespace was not created")
        if (namespaces["net"] == parent_namespaces["net"]) != network:
            _deny("network namespace differs from the fixed transport policy")
        seccomp = _seccomp_values(status)
        if seccomp["mode"] != 2 or seccomp["filters"] != filters + 1:
            _deny("fixed seccomp filter was not added")
        deny_probe = _probe_unshare_zero()
        if (type(deny_probe) is not dict or set(deny_probe) != {"returncode", "errno"}
                or type(deny_probe["returncode"]) is not int or type(deny_probe["errno"]) is not int
                or deny_probe != {"returncode": -1, "errno": errno.EPERM}):
            _deny("fixed seccomp syscall denial is absent")
        effective = _effective_mounts(_validated_plan(mount_plan))
        return {"parent_namespaces": parent_namespaces, "actual_namespaces": namespaces,
                "network_policy": "shared-transport" if network else "private-offline",
                "seccomp": {**seccomp, "policy_sha256": seccomp_policy_sha256, "deny_probe": dict(deny_probe)},
                "effective_mounts": effective}
    except PermissionError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError, KeyError, OverflowError, AttributeError) as error:
        raise PermissionError("child boundary observation unavailable") from error
