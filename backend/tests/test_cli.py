import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from app.cli import main


class CliTest(unittest.TestCase):
    def test_scan_writes_json_output_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo_path = root / "repo"
            repo_path.mkdir()
            (repo_path / "package.json").write_text(
                json.dumps({"name": "fixture-repo", "dependencies": {"left-pad": "1.3.0"}}),
                encoding="utf-8",
            )
            output_path = root / "reports" / "scan.json"
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "scan",
                        str(repo_path),
                        "--offline",
                        "--json",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertTrue(output_path.exists())

            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(report["repo_profile"]["repo_name"], "repo")
            self.assertIn("remediation_tasks", report)
            self.assertEqual(report["summary"]["deduped_remediation_tasks"], 0)


if __name__ == "__main__":
    unittest.main()
