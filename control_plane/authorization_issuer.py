#!/usr/bin/env python3
"""Issue a short-lived, root-signed authorization for one exact task contract."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

try:
    from control_plane.task_controller import authorization_subject_hash, validate_contract
except ModuleNotFoundError:  # Installed beside the controller on the VPS.
    from task_controller import authorization_subject_hash, validate_contract


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def issue(contract: dict, private_key: Path, authorization_dir: Path, ttl_seconds: int) -> dict:
    if os.geteuid() != 0:
        raise PermissionError("authorization issuance requires root")
    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(seconds=ttl_seconds)
    authorization = contract.setdefault("authorization", {})
    authorization.update({
        "decision": "allow",
        "authorized_at": now.isoformat(),
        "expires_at": expires.isoformat(),
        "subject_sha256": "0" * 64,
        "evidence_sha256": "0" * 64,
        "signature_sha256": "0" * 64,
    })
    authorization["subject_sha256"] = authorization_subject_hash(contract)
    # Validate the completed shape before producing persistent evidence. The
    # final evidence/signature hashes are populated after signing, but their
    # zero placeholders already satisfy the typed digest fields.
    validate_contract(contract)
    envelope = {
        "decision": "allow",
        "policy_version": authorization["policy_version"],
        "subject_sha256": authorization["subject_sha256"],
        "requester_identity": contract["requester_identity"],
        "project_id": contract["project_id"],
        "builder_identity": contract["builder_identity"],
        "repo": contract["repo"],
        "base_sha": contract["base_sha"],
        "allowed_paths": contract["allowed_paths"],
        "allowed_tools": contract["allowed_tools"],
        "budget": contract["budget"],
        "authorized_at": authorization["authorized_at"],
        "expires_at": authorization["expires_at"],
    }
    authorization_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temp_name:
        temp_dir = Path(temp_name)
        envelope_temp = temp_dir / "authorization.json"
        signature_temp = temp_dir / "authorization.sig"
        envelope_temp.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n")
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key), "-in", str(envelope_temp), "-out", str(signature_temp)],
            check=True,
        )
        evidence_hash = sha256_file(envelope_temp)
        signature_hash = sha256_file(signature_temp)
        envelope_path = authorization_dir / f"{evidence_hash}.json"
        signature_path = authorization_dir / f"{evidence_hash}.sig"
        envelope_path.write_bytes(envelope_temp.read_bytes())
        signature_path.write_bytes(signature_temp.read_bytes())
    os.chmod(envelope_path, 0o440)
    os.chmod(signature_path, 0o440)
    authorization_gid = authorization_dir.stat().st_gid
    os.chown(envelope_path, 0, authorization_gid)
    os.chown(signature_path, 0, authorization_gid)
    authorization["evidence_sha256"] = evidence_hash
    authorization["signature_sha256"] = signature_hash
    validate_contract(contract)
    return contract


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-key", type=Path, default=Path("/etc/ai-ops/authorization-private.pem"))
    parser.add_argument("--authorization-dir", type=Path, required=True)
    parser.add_argument("--ttl-seconds", type=int, default=900)
    parser.add_argument("contract", type=Path)
    args = parser.parse_args()
    if not 30 <= args.ttl_seconds <= 1800:
        raise ValueError("authorization TTL must be between 30 and 1800 seconds")
    contract = json.loads(args.contract.read_text())
    print(json.dumps(issue(contract, args.private_key, args.authorization_dir, args.ttl_seconds), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
