import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from app.cli import main
from app.schemas.report import REPORT_SCHEMA_VERSION


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
                        "--workspace-root",
                        str(root),
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
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: unable to write output file", stderr.getvalue())
            self.assertNotIn(str(output_path), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_scan_text_output_uses_sanitized_public_errors(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("app.cli.ScanService", return_value=RawErrorScanService()):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["scan", ".", "--workspace-root", "."])

        output = stdout.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("OSV query failed for archive-utils@2.1.4", output)
        self.assertNotIn("ghp_secret123", output)
        self.assertNotIn("/Users/auditor/private", output)

    def test_scan_malformed_manifest_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo_path = root / "repo"
            repo_path.mkdir()
            (repo_path / "package.json").write_text("{not-json", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "scan",
                        str(repo_path),
                        "--offline",
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: unable to scan repository:", stderr.getvalue())
            self.assertIn("Invalid JSON", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertNotIn("package.json", stderr.getvalue())
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

    def test_summarize_report_invalid_schema_returns_error_without_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "summary.json"
            report = scan_report_fixture()
            report.pop("schema_version")
            report_path.write_text(json.dumps(report), encoding="utf-8")
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

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(output_path.exists())
            self.assertIn("Error: report does not match public schema:", stderr.getvalue())
            self.assertIn("schema_version", stderr.getvalue())
            self.assertNotIn("input_value", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

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
            report = scan_report_fixture()
            report["remediation_tasks"] = []
            report["summary"]["deduped_remediation_tasks"] = 0
            report_path.write_text(json.dumps(report), encoding="utf-8")
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
            self.assertIn("Error: remediation task not found", stderr.getvalue())
            self.assertNotIn("does-not-exist", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_summarize_report_output_error_does_not_echo_output_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "private-token-output"
            output_path.mkdir()
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

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: unable to write summary output file", stderr.getvalue())
            self.assertNotIn(str(output_path), stderr.getvalue())
            self.assertNotIn("private-token-output", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_ai_context_bundle_writes_client_ai_case_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "bundle.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "ai-context-bundle",
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
            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(bundle["finding_id"], "task-archive-utils")
            self.assertEqual(bundle["ai_request"]["package_name"], "archive-utils")
            self.assertIn("Use only the evidence in this bundle", bundle["prompt"])
            self.assertIn("citations", bundle["expected_output_schema"]["required"])

    def test_ai_context_bundle_can_include_rag_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "bundle.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")

            exit_code = main(
                [
                    "ai-context-bundle",
                    str(report_path),
                    "--task-id",
                    "task-archive-utils",
                    "--include-rag",
                    "--top-k",
                    "5",
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            retrieved_evidence = [
                item
                for item in bundle["ai_request"]["evidence"]
                if item["metadata"].get("origin") == "retrieved_context"
            ]
            self.assertGreater(len(retrieved_evidence), 0)
            self.assertEqual(retrieved_evidence[0]["metadata"]["package"], "archive-utils")

    def test_ai_context_bundle_rejects_invalid_rag_top_k_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "bundle.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stderr = io.StringIO()

            with redirect_stderr(stderr):
                exit_code = main(
                    [
                        "ai-context-bundle",
                        str(report_path),
                        "--include-rag",
                        "--top-k",
                        "0",
                        "--output",
                        str(output_path),
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertFalse(output_path.exists())
            self.assertIn("Error: --top-k must be between 1 and 10", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_ai_context_bundle_rag_output_sanitizes_poisoned_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            output_path = root / "bundle.json"
            report = scan_report_fixture()
            report["scan_id"] = "/Users/auditor/private/repo"
            report["remediation_tasks"][0]["task_id"] = "secret.task-archive-utils"
            report["remediation_tasks"][0]["evidence"][0]["source"] = (
                "/Users/auditor/private/repo/package-lock.json"
            )
            report["remediation_tasks"][0]["evidence"][0]["claim"] = (
                "Proof-of-concept payload uses token=ghp_secret123."
            )
            report_path.write_text(json.dumps(report), encoding="utf-8")

            exit_code = main(
                [
                    "ai-context-bundle",
                    str(report_path),
                    "--task-id",
                    "secret.task-archive-utils",
                    "--include-rag",
                    "--output",
                    str(output_path),
                ]
            )

            self.assertEqual(exit_code, 0)
            bundle = json.loads(output_path.read_text(encoding="utf-8"))
            evidence_payload = json.dumps(bundle["ai_request"]["evidence"]).lower()
            finding_payload = json.dumps(bundle["finding"]).lower()
            encoded = evidence_payload + finding_payload
            self.assertNotIn("/users/", encoded)
            self.assertNotIn("private/repo", encoded)
            self.assertNotIn("secret.task", encoded)
            self.assertNotIn("ghp_secret123", encoded)
            self.assertNotIn("payload", encoded)

    def test_validate_ai_output_blocks_uncited_client_ai_response(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            bundle_path = root / "bundle.json"
            ai_output_path = root / "ai-output.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "ai-context-bundle",
                        str(report_path),
                        "--task-id",
                        "task-archive-utils",
                        "--output",
                        str(bundle_path),
                    ]
                ),
                0,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            request = bundle["ai_request"]
            evidence_id = request["evidence"][0]["id"]
            ai_output_path.write_text(
                json.dumps(uncited_ai_output(request, evidence_id)),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "validate-ai-output",
                        str(report_path),
                        str(ai_output_path),
                        "--task-id",
                        "task-archive-utils",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(stderr.getvalue(), "")
            result = json.loads(stdout.getvalue())
            self.assertFalse(result["passed"])
            self.assertTrue(result["blocked"])
            self.assertIn("matching citation", result["summary"])

    def test_validate_ai_output_accepts_cited_client_ai_response(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            bundle_path = root / "bundle.json"
            ai_output_path = root / "ai-output.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "ai-context-bundle",
                        str(report_path),
                        "--task-id",
                        "task-archive-utils",
                        "--output",
                        str(bundle_path),
                    ]
                ),
                0,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            request = bundle["ai_request"]
            evidence_id = request["evidence"][0]["id"]
            ai_output_path.write_text(
                json.dumps(cited_ai_output(request, evidence_id)),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "validate-ai-output",
                        str(report_path),
                        str(ai_output_path),
                        "--task-id",
                        "task-archive-utils",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["passed"])
            self.assertFalse(result["blocked"])

    def test_validate_ai_output_accepts_rag_context_bundle_citation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            bundle_path = root / "bundle.json"
            ai_output_path = root / "ai-output.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "ai-context-bundle",
                        str(report_path),
                        "--task-id",
                        "task-archive-utils",
                        "--include-rag",
                        "--output",
                        str(bundle_path),
                    ]
                ),
                0,
            )
            bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
            request = bundle["ai_request"]
            retrieved_evidence = [
                item
                for item in request["evidence"]
                if item["metadata"].get("origin") == "retrieved_context"
            ][0]
            ai_output_path.write_text(
                json.dumps(
                    {
                        "finding_id": request["finding_id"],
                        "package_name": request["package_name"],
                        "vulnerability_id": request["vulnerability_id"],
                        "priority": request["priority"],
                        "risk_score": request["risk_score"],
                        "summary": "archive-utils is supported by retrieved Sage evidence.",
                        "explanation": "The output cites retrieved evidence from the bundle.",
                        "citations": [
                            {
                                "claim_id": "claim-1",
                                "evidence_id": retrieved_evidence["id"],
                            }
                        ],
                        "claim_checks": [
                            {
                                "claim_id": "claim-1",
                                "claim": str(retrieved_evidence["content"]),
                                "disposition": "fact",
                                "evidence_ids": [retrieved_evidence["id"]],
                            }
                        ],
                        "provider_name": "client-ai",
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(
                    [
                        "validate-ai-output",
                        str(report_path),
                        str(ai_output_path),
                        "--task-id",
                        "task-archive-utils",
                        "--include-rag",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["passed"])
            self.assertFalse(result["blocked"])

    def test_ai_demo_runs_without_provider_api_key_and_writes_artifacts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "demo"
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["ai-demo", "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["validation"]["passed"])
            for filename in (
                "scan-report.json",
                "ai-context-bundle.json",
                "sample-ai-output.json",
                "ai-validation.json",
            ):
                self.assertTrue((output_dir / filename).exists(), filename)

    def test_validate_report_prints_summary_for_valid_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["validate-report", str(report_path)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stdout.getvalue(), "PASS public report validation with 0 finding(s)\n")
            self.assertEqual(stderr.getvalue(), "")

    def test_validate_report_json_returns_validator_output_for_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report["remediation_tasks"][0]["evidence"] = []
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["validate-report", str(report_path), "--json"])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stderr.getvalue(), "")
            result = json.loads(stdout.getvalue())
            self.assertFalse(result["passed"])
            self.assertEqual(result["finding_count"], 1)
            self.assertEqual(result["findings"][0]["code"], "missing_evidence")

    def test_validate_report_invalid_schema_returns_error_without_false_pass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report.pop("schema_version")
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["validate-report", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report does not match public schema:", stderr.getvalue())
            self.assertIn("schema_version", stderr.getvalue())
            self.assertNotIn("input_value", stderr.getvalue())
            self.assertNotIn("PASS", stdout.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_validate_report_schema_error_does_not_echo_unsafe_extra_field_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report["/Users/auditor/private-token"] = "value"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["validate-report", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            error_text = stderr.getvalue()
            self.assertIn("Error: report does not match public schema:", error_text)
            self.assertNotIn("/Users/auditor", error_text)
            self.assertNotIn("private-token", error_text)
            self.assertNotIn("Traceback", error_text)

    def test_validate_report_malformed_json_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text("{not-json", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["validate-report", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report file is not valid JSON:", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_validate_report_non_utf8_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_bytes(b"\xff\xfe\xfa")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["validate-report", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report file is not valid JSON:", stderr.getvalue())
            self.assertIn("scan.json", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_findings_lists_compact_rows_in_report_order(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path)])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            lines = stdout.getvalue().splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn("task-archive-utils", lines[0])
            self.assertIn("archive-utils", lines[0])
            self.assertIn("CVE-2026-0001", lines[0])
            self.assertIn("P1_FIX_THIS_SPRINT", lines[0])
            self.assertIn("78", lines[0])
            self.assertIn("2.2.0", lines[0])
            self.assertIn("task-image-tool", lines[1])

    def test_findings_limit_and_priority_filter_apply_before_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "findings",
                        str(report_path),
                        "--priority",
                        "P2_SCHEDULE_SOON",
                        "--limit",
                        "1",
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertEqual(
                stdout.getvalue().splitlines(),
                [
                    (
                        "task-image-tool | image-tool | CVE-2026-0002 | "
                        "P2_SCHEDULE_SOON | 42 | target 4.5.0"
                    )
                ],
            )

    def test_findings_json_returns_structured_compact_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "findings",
                        str(report_path),
                        "--priority",
                        "P2_SCHEDULE_SOON",
                        "--json",
                    ]
                )

            self.assertEqual(exit_code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["finding_count"], 1)
            self.assertEqual(
                result["findings"],
                [
                    {
                        "task_id": "task-image-tool",
                        "package_name": "image-tool",
                        "vulnerability_id": "CVE-2026-0002",
                        "priority": "P2_SCHEDULE_SOON",
                        "risk_score": 42,
                        "target_version": "4.5.0",
                    }
                ],
            )

    def test_findings_preserves_legitimate_token_named_packages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report["remediation_tasks"][0]["package"]["name"] = "jsonwebtoken"
            report["remediation_tasks"][0]["vulnerability"]["canonical_id"] = "CVE-2026-0001"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path), "--json"])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["findings"][0]["package_name"], "jsonwebtoken")

    def test_findings_preserves_legitimate_payload_and_cookie_package_names(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report["remediation_tasks"][0]["package"]["name"] = "payload-parser"
            report["remediation_tasks"][1]["package"]["name"] = "cookie"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path), "--json"])

            self.assertEqual(exit_code, 0)
            self.assertEqual(stderr.getvalue(), "")
            payload = json.loads(stdout.getvalue())
            package_names = [finding["package_name"] for finding in payload["findings"]]
            self.assertIn("payload-parser", package_names)
            self.assertIn("cookie", package_names)

    def test_findings_redacts_secret_like_identifiers_in_text_and_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            task = report["remediation_tasks"][0]
            task["task_id"] = "/Users/auditor/private-token/task"
            task["package"]["name"] = "private-token-package"
            task["vulnerability"]["canonical_id"] = "GHSA-secret-token"
            task["patch_plan"]["target_version"] = "2.2.0-secret"
            report["remediation_tasks"] = [task]
            report_path.write_text(json.dumps(report), encoding="utf-8")
            text_stdout = io.StringIO()
            json_stdout = io.StringIO()

            with redirect_stdout(text_stdout):
                text_exit_code = main(["findings", str(report_path)])
            with redirect_stdout(json_stdout):
                json_exit_code = main(["findings", str(report_path), "--json"])

            combined = text_stdout.getvalue() + json_stdout.getvalue()
            self.assertEqual(text_exit_code, 0)
            self.assertEqual(json_exit_code, 0)
            self.assertIn("[redacted", combined)
            self.assertNotIn("/Users/auditor", combined)
            self.assertNotIn("private-token", combined)
            self.assertNotIn("GHSA-secret-token", combined)
            self.assertNotIn("2.2.0-secret", combined)

    def test_findings_malformed_json_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_text("{not-json", encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report file is not valid JSON:", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_findings_non_utf8_returns_error_without_traceback(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report_path.write_bytes(b"\xff\xfe\xfa")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report file is not valid JSON:", stderr.getvalue())
            self.assertIn("scan.json", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_findings_invalid_schema_returns_error_without_unknown_rows(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report["remediation_tasks"][0]["package"].pop("name")
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report does not match public schema:", stderr.getvalue())
            self.assertIn("package", stderr.getvalue())
            self.assertNotIn("input_value", stderr.getvalue())
            self.assertNotIn("unknown", stdout.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_findings_invalid_schema_does_not_echo_path_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            report_path = root / "scan.json"
            report = scan_report_fixture()
            report["repo_profile"]["unexpected"] = str(root / "private-token")
            report_path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()

            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = main(["findings", str(report_path)])

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("Error: report does not match public schema:", stderr.getvalue())
            self.assertIn("repo_profile.unexpected", stderr.getvalue())
            self.assertNotIn("private-token", stderr.getvalue())
            self.assertNotIn(str(root), stderr.getvalue())


class RawErrorRepoProfile:
    repo_name = "repo"


class RawErrorScanResult:
    repo_profile = RawErrorRepoProfile()
    summary = {
        "packages": 1,
        "raw_alerts": 0,
        "deduped_remediation_tasks": 0,
        "release_blockers": 0,
    }
    errors = [
        "OSV query failed for archive-utils@2.1.4: token=ghp_secret123 from /Users/auditor/private/repo/package-lock.json"
    ]

    def to_dict(self):
        return {
            "repo_profile": {"repo_name": "repo"},
            "summary": self.summary,
            "errors": [
                "OSV query failed for archive-utils@2.1.4; vulnerability data may be incomplete."
            ]
        }


class RawErrorScanService:
    def scan_local(self, repo_path, *, workspace_root=None):
        return RawErrorScanResult()


def scan_report_fixture():
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_id": "scan-test-cli",
        "repo_profile": {"repo_name": "payments-api"},
        "packages": [],
        "vulnerabilities": [],
        "summary": {
            "complete": True,
            "scan_status": "complete",
            "packages": 2,
            "raw_alerts": 2,
            "deduped_remediation_tasks": 2,
            "release_blockers": 0,
            "recommended_sprint_fixes": 1,
            "safe_to_defer": 0,
            "needs_human_review": 0,
            "error_count": 0,
            "priority_counts": {"P1_FIX_THIS_SPRINT": 1, "P2_SCHEDULE_SOON": 1},
        },
        "remediation_tasks": [
            remediation_task_fixture("task-archive-utils", "archive-utils"),
            remediation_task_fixture("task-image-tool", "image-tool"),
        ],
        "errors": [],
    }


def remediation_task_fixture(task_id, package_name):
    risk_priority = "P1_FIX_THIS_SPRINT"
    risk_score = 78
    canonical_id = "CVE-2026-0001"
    target_version = "2.2.0"
    if task_id == "task-image-tool":
        risk_priority = "P2_SCHEDULE_SOON"
        risk_score = 42
        canonical_id = "CVE-2026-0002"
        target_version = "4.5.0"

    return {
        "task_id": task_id,
        "repo": "payments-api",
        "package": {
            "name": package_name,
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "dependencies",
            "is_direct": True,
            "parent_package": None,
        },
        "vulnerability": {
            "canonical_id": canonical_id,
            "source_id": "GHSA-archive",
            "aliases": ["GHSA-archive"],
            "severity": "HIGH",
            "summary": "%s unsafe deserialization can affect archive parsing." % package_name,
            "fixed_versions": [target_version],
        },
        "risk": {
            "priority": risk_priority,
            "risk_score": risk_score,
            "known_exploited": None,
            "epss_score": None,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "factors": {},
            "rationale": ["Risk score %s maps to %s." % (risk_score, risk_priority)],
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
        "patch_plan": {
            "recommended_action": "upgrade",
            "target_version": target_version,
            "patch_complexity": "low",
            "breaking_change_risk": "low",
            "steps": ["Upgrade %s to %s." % (package_name, target_version)],
            "test_plan": ["Run npm test."],
            "rollback_plan": ["Revert dependency bump."],
            "pr_description": "Upgrade %s." % package_name,
        },
        "test_plan": ["Run npm test."],
        "rollback_plan": ["Revert dependency bump."],
        "owner": None,
        "human_approval_required": True,
    }


def cited_ai_output(request, evidence_id):
    return {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded based on the cited evidence.",
        "explanation": "The explanation cites the evidence bundle.",
        "citations": [{"claim_id": "claim-1", "evidence_id": evidence_id}],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "client-ai",
    }


def uncited_ai_output(request, evidence_id):
    output = cited_ai_output(request, evidence_id)
    output["citations"] = []
    output["explanation"] = "The explanation omits the required citation object."
    return output


if __name__ == "__main__":
    unittest.main()
