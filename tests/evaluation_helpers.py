import base64
import hashlib
import subprocess
import tempfile
from pathlib import Path

from control_plane.project_integrator import SECTION_LIMITS, canonical, evaluation_ledger_hash, sha256_file


def generate_keypair(root: Path) -> tuple[Path, Path]:
    private_key = root / "evaluator-private.pem"
    public_key = root / "evaluator-public.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", private_key], check=True,
                   capture_output=True)
    subprocess.run(["openssl", "pkey", "-in", private_key, "-pubout", "-out", public_key], check=True,
                   capture_output=True)
    return private_key, public_key


def resign(evaluation: dict, private_key: Path, *, recompute_ledger: bool = True) -> dict:
    value = dict(evaluation)
    value.pop("signature", None)
    if recompute_ledger:
        value["ledger_hash"] = evaluation_ledger_hash(value)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        message = root / "evaluation.json"
        signature = root / "evaluation.sig"
        message.write_bytes(canonical(value))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private_key),
             "-in", str(message), "-out", str(signature)],
            check=True, capture_output=True,
        )
        value["signature"] = base64.b64encode(signature.read_bytes()).decode("ascii")
    return value


def make_evaluation(
    private_key: Path,
    evidence_manifest: Path,
    rubric: Path,
    *,
    task_id: str,
    contract_id: str,
    candidate_sha: str,
    artifact_id: str = f"sha256:{'a' * 64}",
    claim_id: str = f"claim:{'b' * 64}",
    previous_ledger_hash: str | None = None,
) -> dict:
    scores = {section: maximum for section, (_, maximum) in SECTION_LIMITS.items()}
    value = {
        "evaluation_id": f"evaluation-{task_id}",
        "task_id": task_id,
        "contract_id": contract_id,
        "artifact_id": artifact_id,
        "claim_id": claim_id,
        "evaluated_git_sha": candidate_sha,
        "evidence_manifest_sha256": sha256_file(evidence_manifest),
        "rubric_sha256": hashlib.sha256(rubric.read_bytes()).hexdigest(),
        "section_scores": scores,
        "mandatory_gates": {f"HG{i}": "PASS" for i in range(1, 12)},
        "total_score": sum(scores.values()),
        "verdict": "PASS",
        "evaluator_identity": "hermes-evaluator",
        "previous_ledger_hash": previous_ledger_hash,
        "ledger_hash": "0" * 64,
    }
    return resign(value, private_key)
