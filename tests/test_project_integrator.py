import concurrent.futures
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from control_plane.project_integrator import ProjectIntegrator
from tests.evaluation_helpers import generate_keypair, make_evaluation, resign


class ProjectIntegratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "-C", self.repo, "init", "-q"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", self.repo, "config", "user.name", "Integrator Test"], check=True)
        (self.repo / "src").mkdir()
        (self.repo / "src/base.txt").write_text("base\n")
        (self.repo / "forbidden\nsource.txt").write_text("tracked outside write set\n")
        self.commit("base")
        self.base = self.rev()
        (self.repo / "src/value.txt").write_text("verified value\n")
        self.commit("candidate")
        self.candidate = self.rev()
        subprocess.run(["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
                       check=True, capture_output=True)
        self.binding = self.root / "binding.json"
        self.binding.write_text(json.dumps({"repo": "codex_opensource", "base_sha": self.base}) + "\n")
        os.chmod(self.binding, 0o440)
        self.evidence = self.root / "evidence.json"
        self.evidence.write_text('{"tests":"pass"}\n')
        self.rubric = self.root / "RUBRIC.md"
        self.rubric.write_text("frozen rubric\n")
        self.private_key, self.public_key = generate_keypair(self.root)
        self.accepted_ref = "refs/ai-ops/accepted/opensource"
        self.integrator = ProjectIntegrator(
            self.repo, self.binding, self.public_key, self.rubric, self.accepted_ref
        )

    def tearDown(self):
        self.temp.cleanup()

    def commit(self, message):
        subprocess.run(["git", "-C", self.repo, "add", "."], check=True)
        subprocess.run(["git", "-C", self.repo, "commit", "-qm", message], check=True)

    def rev(self):
        return subprocess.run(
            ["git", "-C", self.repo, "rev-parse", "HEAD"], check=True,
            capture_output=True, text=True,
        ).stdout.strip()

    def evaluation(self, candidate=None):
        return make_evaluation(
            self.private_key, self.evidence, self.rubric,
            task_id="node-1", contract_id="eval-node-1-v1",
            candidate_sha=candidate or self.candidate,
        )

    def promote(self, candidate=None, evaluation=None):
        return self.integrator.promote(
            candidate or self.candidate, self.base, ["src/"],
            evaluation or self.evaluation(candidate), self.evidence,
            expected_task_id="node-1", expected_contract_id="eval-node-1-v1",
        )

    def test_atomic_ref_publication_binding_and_rollback(self):
        result = self.promote()
        self.assertEqual(result["base_sha"], self.candidate)
        self.assertEqual(result["integration_sha"], self.candidate)
        self.assertEqual(json.loads(self.binding.read_text()),
                         {"repo": "codex_opensource", "base_sha": self.candidate})
        self.assertEqual(
            subprocess.run(
                ["git", "-C", self.repo, "show", f"{self.accepted_ref}:src/value.txt"],
                check=True, capture_output=True, text=True,
            ).stdout,
            "verified value\n",
        )
        self.assertEqual(
            (self.root / "publications" / self.candidate / "src/value.txt").read_text(),
            "verified value\n",
        )
        self.assertEqual(self.rev(), self.base)
        self.assertEqual(self.integrator.rollback(self.candidate)["base_sha"], self.base)
        self.assertEqual(self.rev(), self.base)

    def test_failed_or_tampered_evaluation_cannot_change_binding_or_ref(self):
        before = self.binding.read_bytes()
        failed = self.evaluation()
        failed["verdict"] = "NOT_PASS"
        failed = resign(failed, self.private_key)
        with self.assertRaises(PermissionError):
            self.promote(evaluation=failed)
        tampered = self.evaluation()
        tampered["total_score"] = 95
        with self.assertRaises(PermissionError):
            self.promote(evaluation=tampered)
        self.assertEqual(self.binding.read_bytes(), before)
        self.assertNotEqual(
            subprocess.run(
                ["git", "-C", self.repo, "rev-parse", "--verify", self.accepted_ref],
                check=False, capture_output=True,
            ).returncode,
            0,
        )

    def test_section_minimum_wrong_task_and_broken_ledger_are_denied(self):
        low = self.evaluation()
        low["section_scores"]["tests_and_representative_evidence"] = 6
        low["total_score"] = sum(low["section_scores"].values())
        low = resign(low, self.private_key)
        with self.assertRaises(PermissionError):
            self.promote(evaluation=low)
        wrong_task = self.evaluation()
        wrong_task["task_id"] = "node-other"
        wrong_task = resign(wrong_task, self.private_key)
        with self.assertRaises(PermissionError):
            self.promote(evaluation=wrong_task)
        broken_ledger = self.evaluation()
        broken_ledger["ledger_hash"] = "f" * 64
        broken_ledger = resign(broken_ledger, self.private_key, recompute_ledger=False)
        with self.assertRaises(PermissionError):
            self.promote(evaluation=broken_ledger)

    def test_every_numeric_evaluation_field_rejects_nan_and_infinity(self):
        numeric_fields = ["total_score", *self.evaluation()["section_scores"]]
        for field in numeric_fields:
            for invalid in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(field=field, invalid=invalid):
                    evaluation = self.evaluation()
                    if field == "total_score":
                        evaluation[field] = invalid
                    else:
                        evaluation["section_scores"][field] = invalid
                        evaluation["total_score"] = sum(evaluation["section_scores"].values())
                    evaluation = resign(evaluation, self.private_key)
                    with self.assertRaises(PermissionError):
                        self.promote(evaluation=evaluation)

    def test_candidate_must_be_one_direct_non_merge_commit(self):
        subprocess.run(
            ["git", "-C", self.repo, "checkout", "--detach", "--force", self.candidate],
            check=True, capture_output=True,
        )
        (self.repo / "src/second.txt").write_text("hidden second commit\n")
        self.commit("second candidate commit")
        multiple = self.rev()
        subprocess.run(
            ["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
            check=True, capture_output=True,
        )
        with self.assertRaises(ValueError):
            self.promote(multiple, self.evaluation(multiple))

        subprocess.run(
            ["git", "-C", self.repo, "merge", "--no-ff", "-m", "merge candidate", self.candidate],
            check=True, capture_output=True,
        )
        merged = self.rev()
        subprocess.run(
            ["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
            check=True, capture_output=True,
        )
        with self.assertRaises(ValueError):
            self.promote(merged, self.evaluation(merged))

        self.assertIsNone(self.integrator._ref_sha(self.accepted_ref))
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)

    def test_untracked_workspace_bytes_block_promotion(self):
        (self.repo / "untracked.bin").write_bytes(b"not in candidate\n")
        with self.assertRaises(RuntimeError):
            self.promote()
        self.assertIsNone(self.integrator._ref_sha(self.accepted_ref))
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)

    def test_ignored_workspace_bytes_block_promotion(self):
        exclude = self.repo / ".git/info/exclude"
        with exclude.open("a", encoding="utf-8") as stream:
            stream.write("\nignored.cache\n")
        (self.repo / "ignored.cache").write_bytes(b"ignored but canonical workspace bytes\n")
        self.assertEqual(
            subprocess.run(
                ["git", "-C", self.repo, "status", "--porcelain"],
                check=True, capture_output=True, text=True,
            ).stdout,
            "",
        )
        with self.assertRaises(RuntimeError):
            self.promote()
        self.assertIsNone(self.integrator._ref_sha(self.accepted_ref))
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)

    def test_stale_binding_and_out_of_scope_candidate_are_denied(self):
        with self.assertRaises(RuntimeError):
            self.integrator.promote(
                self.candidate, "b" * 40, ["src/"], self.evaluation(), self.evidence,
                expected_task_id="node-1", expected_contract_id="eval-node-1-v1",
            )
        with self.assertRaises(PermissionError):
            self.integrator.promote(
                self.candidate, self.base, ["docs/"], self.evaluation(), self.evidence,
                expected_task_id="node-1", expected_contract_id="eval-node-1-v1",
            )

    def test_rename_from_forbidden_source_into_allowed_destination_is_denied(self):
        subprocess.run(
            ["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
            check=True, capture_output=True,
        )
        subprocess.run(
            [
                "git", "-C", self.repo, "mv", "forbidden\nsource.txt",
                "src/apparently\nallowed.txt",
            ],
            check=True, capture_output=True,
        )
        self.commit("adversarial write-set rename")
        renamed = self.rev()
        self.assertEqual(
            subprocess.run(
                [
                    "git", "-C", self.repo, "diff", "--name-status", "-z",
                    self.base, renamed,
                ],
                check=True, capture_output=True,
            ).stdout,
            b"R100\x00forbidden\nsource.txt\x00src/apparently\nallowed.txt\x00",
        )
        subprocess.run(
            ["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
            check=True, capture_output=True,
        )

        with self.assertRaises(PermissionError) as caught:
            self.promote(renamed, self.evaluation(renamed))
        self.assertIn("forbidden\nsource.txt", str(caught.exception))

        self.assertIsNone(self.integrator._ref_sha(self.accepted_ref))
        self.assertEqual(json.loads(self.binding.read_text())["base_sha"], self.base)

    def test_concurrent_candidates_use_compare_and_swap_exactly_once(self):
        subprocess.run(["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
                       check=True, capture_output=True)
        (self.repo / "src/alternative.txt").write_text("alternative\n")
        self.commit("alternative")
        alternative = self.rev()
        subprocess.run(["git", "-C", self.repo, "checkout", "--detach", "--force", self.base],
                       check=True, capture_output=True)
        first = ProjectIntegrator(self.repo, self.binding, self.public_key, self.rubric, self.accepted_ref)
        second = ProjectIntegrator(self.repo, self.binding, self.public_key, self.rubric, self.accepted_ref)

        def attempt(integrator, candidate):
            try:
                integrator.promote(
                    candidate, self.base, ["src/"], self.evaluation(candidate), self.evidence,
                    expected_task_id="node-1", expected_contract_id="eval-node-1-v1",
                )
                return "promoted"
            except RuntimeError:
                return "conflict"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda args: attempt(*args), [(first, self.candidate), (second, alternative)]))
        self.assertEqual(sorted(results), ["conflict", "promoted"])
        winner = json.loads(self.binding.read_text())["base_sha"]
        accepted = subprocess.run(
            ["git", "-C", self.repo, "rev-parse", self.accepted_ref], check=True,
            capture_output=True, text=True,
        ).stdout.strip()
        self.assertEqual(winner, accepted)
        self.assertIn(winner, {self.candidate, alternative})


if __name__ == "__main__":
    unittest.main()
