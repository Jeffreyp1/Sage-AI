import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
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

    def test_scan_output_directory_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo_path = root / "repo"
            repo_path.mkdir()
            (repo_path / "package.json").write_text(
                json.dumps({"name": "fixture-repo", "dependencies": {"left-pad": "1.3.0"}}),
                encoding="utf-8",
            )
            output_path = root / "reports"
            output_path.mkdir()
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
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

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: unable to write output file:", stderr.getvalue())
            self.assertIn(str(output_path), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_summarize_report_writes_structured_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "summary.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "summarize-report",
                        str(report_path),
                        "--task-id",
                        "task-archive-utils",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "")

            summary = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(summary["blocked"])
            self.assertTrue(summary["validation"]["valid"])
            self.assertEqual(summary["request"]["finding_id"], "task-archive-utils")
            self.assertEqual(summary["request"]["package_name"], "archive-utils")
            self.assertEqual(summary["response"]["provider_name"], "mock-ai-provider")
            self.assertGreaterEqual(len(summary["request"]["evidence"]), 3)

    def test_summarize_report_uses_first_task_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "summary.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")

            exit_code = main(
                [
                    "summarize-report",
                    str(report_path),
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            summary = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["request"]["finding_id"], "task-archive-utils")

    def test_summarize_report_missing_file_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "summarize-report",
                        str(root / "missing.json"),
                        "--output",
                        str(root / "summary.json"),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertIn("Error: report file not found:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_summarize_report_malformed_json_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text("{not-json", encoding="utf-8")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "summarize-report",
                        str(report_path),
                        "--output",
                        str(root / "summary.json"),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertIn("Error: report file is not valid JSON:", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_summarize_report_no_tasks_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text(
                json.dumps({"remediation_tasks": []}),
                encoding="utf-8",
            )
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "summarize-report",
                        str(report_path),
                        "--output",
                        str(root / "summary.json"),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertIn("Error: report contains no remediation tasks", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_summarize_report_missing_task_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "summarize-report",
                        str(report_path),
                        "--task-id",
                        "does-not-exist",
                        "--output",
                        str(root / "summary.json"),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertIn("Error: remediation task not found: does-not-exist", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())


def scan_report_fixture():
    return {
        "repo_profile": {"repo_name": "payments-api"},
        "summary": {"deduped_remediation_tasks": 2},
        "remediation_tasks": [
            remediation_task_fixture("task-archive-utils", "archive-utils"),
            remediation_task_fixture("task-image-tool", "image-tool"),
        ],
    }


def remediation_task_fixture(task_id, package_name):
    return {
        "task_id": task_id,
        "repo": "payments-api",
        "package": {
            "name": package_name,
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "dependencies",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "CVE-2026-0001",
            "source_id": "GHSA-archive",
            "severity": "HIGH",
            "summary": "%s unsafe deserialization can affect archive parsing." % package_name,
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 78,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "rationale": ["Risk score 78 maps to P1_FIX_THIS_SPRINT."],
        },
        "evidence": [
            {
                "type": "lockfile_entry",
                "source": "package-lock.json",
                "claim": "%s@1.4.0 is installed in package-lock.json." % package_name,
            },
            {
                "type": "reachability",
                "source": "src/upload.ts",
                "claim": "%s is imported by the production upload route." % package_name,
            },
        ],
    }


if __name__ == "__main__":
    unittest.main()
