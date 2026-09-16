import tempfile
import unittest
from pathlib import Path

from control_plane.codex_usage import parse_jsonl


class CodexUsageTests(unittest.TestCase):
    def test_uses_largest_cumulative_usage_and_ignores_noise(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "events.jsonl"
            path.write_text(
                'not-json\n'
                '{"usage":{"input_tokens":10,"output_tokens":5}}\n'
                '{"event":{"usage":{"total_tokens":31}}}\n'
            )
            self.assertEqual(parse_jsonl(path), 31)


if __name__ == "__main__":
    unittest.main()
