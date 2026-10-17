import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from iam_auditor.cli import main


class CliTests(unittest.TestCase):
    def test_json_output_is_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(
                json.dumps(
                    {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
                ),
                encoding="utf-8",
            )
            output = io.StringIO()
            with redirect_stdout(output):
                result = main([str(policy), "--format", "json"])
            document = json.loads(output.getvalue())
            self.assertEqual(result, 0)
            self.assertEqual(document["findings"][0]["rule_id"], "IAM001")

    def test_strict_mode_returns_nonzero_for_findings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "policy.json"
            policy.write_text(
                json.dumps(
                    {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
                ),
                encoding="utf-8",
            )
            self.assertEqual(main([str(policy), "--strict"]), 1)

    def test_missing_file_returns_error_code(self) -> None:
        self.assertEqual(main(["/path/that/does/not/exist.json"]), 2)


if __name__ == "__main__":
    unittest.main()
