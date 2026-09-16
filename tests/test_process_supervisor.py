import os
import signal
import tempfile
import time
import unittest
from pathlib import Path

from control_plane.process_supervisor import supervise


def process_exists(pid):
    try:
        os.kill(pid, 0)
        fields = Path(f"/proc/{pid}/stat").read_text().split()
        return fields[2] != "Z"
    except ProcessLookupError:
        return False
    except FileNotFoundError:
        return False


class ProcessSupervisorTests(unittest.TestCase):
    def test_cancellation_terminates_process_group_and_descendant(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            pid_file = root / "pids"
            log = root / "events.jsonl"
            reads = 0

            def state_reader():
                nonlocal reads
                reads += 1
                return "CANCELLED" if reads >= 3 else "RUNNING"

            recorded = []
            command = [
                "/bin/bash", "-c",
                f"sleep 60 & child=$!; printf '%s %s' $$ $child >'{pid_file}'; wait",
            ]
            result = supervise(command, log, 10, 1000, state_reader, recorded.append, poll_seconds=0.05)
            parent, child = map(int, pid_file.read_text().split())
            time.sleep(0.1)
            self.assertEqual(result["reason"], "cancelled")
            self.assertEqual(result["exit_code"], 130)
            self.assertFalse(process_exists(parent))
            self.assertFalse(process_exists(child))
            self.assertEqual(recorded, [0])

    def test_controller_failure_state_terminates_process_group(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            log = root / "events.jsonl"
            reads = 0

            def state_reader():
                nonlocal reads
                reads += 1
                return "FAILED_PERMANENT" if reads >= 3 else "RUNNING"

            result = supervise(
                ["/bin/bash", "-c", "sleep 60"], log, 10, 1000,
                state_reader, lambda _: None, poll_seconds=0.05,
            )
            self.assertEqual(result["reason"], "controller_state_changed")
            self.assertEqual(result["exit_code"], 130)
            self.assertTrue(result["execution_quiesced"])

    def test_token_budget_stops_command(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            log = root / "events.jsonl"
            command = ["/bin/bash", "-c", "printf '%s\n' '{\"usage\":{\"total_tokens\":12}}'; sleep 60"]
            result = supervise(command, log, 10, 10, lambda: "RUNNING", lambda _: None, poll_seconds=0.05)
            self.assertEqual(result["reason"], "budget")
            self.assertEqual(result["exit_code"], 78)

    def test_term_ignoring_group_is_killed_and_cannot_write_late_artifact(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            log = root / "events.jsonl"
            sentinel = root / "late-artifact"
            command = [
                "/bin/bash", "-c",
                f"trap '' TERM; (trap '' TERM; sleep 1; touch '{sentinel}') & while true; do sleep 1; done",
            ]
            result = supervise(command, log, 0.15, 1000, lambda: "RUNNING", lambda _: None, poll_seconds=0.02)
            time.sleep(1.1)
            self.assertEqual(result["reason"], "timeout")
            self.assertTrue(result["execution_quiesced"])
            self.assertFalse(sentinel.exists())


if __name__ == "__main__":
    unittest.main()
