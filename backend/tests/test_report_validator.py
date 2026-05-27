import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from copy import deepcopy
from pathlib import Path

from app.eval.report_validator import main, validate_json_file, validate_report


def clean_task():
    return {
        "task_id": "task_123",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "2.1.4",
            "dependency_type": "dependencies",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "CVE-2025-12345",
            "source_id": "GHSA-runtime",
            "aliases": ["GHSA-runtime"],
            "severity": "HIGH",
            "summary": "Archive parsing vulnerability",
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P0_RELEASE_BLOCKER",
            "risk_score": 95,
            "known_exploited": None,
            "epss_score": None,
            "runtime_scope": "production",
            "reachability": "possibly_reachable",
            "confidence": 0.8,
            "factors": {"production_runtime_path": 1.0},
            "rationale": ["Package is imported by the upload route."],
        },
        "evidence": [
            {
                "type": "lockfile",
                "source": "package-lock.json",
                "claim": "archive-utils@2.1.4 is installed",
            },
            {
                "type": "source_file",
                "source": "src/upload/receiptParser.ts",
                "claim": "archive-utils is imported by receipt parser",
            },
        ],
        "patch_plan": {
            "recommended_action": "upgrade",
            "target_version": "2.2.0",
            "steps": ["Update archive-utils from 2.1.4 to 2.2.0"],
        },
        "test_plan": ["npm test"],
        "rollback_plan": ["Revert dependency bump PR"],
        "owner": "@payments-platform",
    }


def clean_report():
    return {
        "schema_version": "v1",
        "scan_id": "scan_123",
        "repo_profile": {"repo_name": "payments-api"},
        "remediation_tasks": [clean_task()],
        "summary": {
            "complete": True,
            "scan_status": "complete",
            "packages": 1,
            "raw_alerts": 1,
            "deduped_remediation_tasks": 1,
            "release_blockers": 1,
            "recommended_sprint_fixes": 0,
            "safe_to_defer": 0,
            "needs_human_review": 0,
            "error_count": 0,
            "priority_counts": {"P0_RELEASE_BLOCKER": 1},
        },
        "errors": [],
    }


def finding_codes(result):
    return {finding["code"] for finding in result["findings"]}


def add_alias_overlap_duplicate(report):
    first = report["remediation_tasks"][0]
    first["vulnerability"]["canonical_id"] = "CVE-2025-11111"
    first["vulnerability"]["source_id"] = "GHSA-source-a"
    first["vulnerability"]["aliases"] = ["GHSA-SHARED-ALIAS"]
    duplicate = deepcopy(first)
    duplicate["vulnerability"]["canonical_id"] = "CVE-2025-22222"
    duplicate["vulnerability"]["source_id"] = "OSV-source-b"
    duplicate["vulnerability"]["aliases"] = ["ghsa-shared-alias"]
    report["remediation_tasks"].append(duplicate)


class ReportValidatorTest(unittest.TestCase):
    def test_passes_clean_public_report(self):
        result = validate_report(clean_report())

        self.assertTrue(result["passed"])
        self.assertEqual(result["finding_count"], 0)

    def test_allows_legitimate_payload_and_cookie_package_names(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["package"]["name"] = "payload-parser"
        report["packages"] = [
            {
                "name": "cookie",
                "current_version": "1.0.0",
                "ecosystem": "npm",
                "dependency_type": "dependencies",
                "is_direct": True,
            }
        ]

        result = validate_report(report)

        self.assertTrue(result["passed"])
        self.assertEqual(result["finding_count"], 0)

    def test_detects_scoped_private_package_in_freeform_text(self):
        report = clean_report()
        report["remediation_tasks"][0]["evidence"][0][
            "claim"
        ] = "Upgrade @private/token before release."

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("unsafe_public_text", finding_codes(result))

    def test_allows_safe_scoped_package_in_freeform_text(self):
        report = clean_report()
        report["remediation_tasks"][0]["evidence"][0][
            "claim"
        ] = "Review @safe/payload-parser before release."

        result = validate_report(report)

        self.assertTrue(result["passed"], json.dumps(result, sort_keys=True))
        self.assertEqual(result["finding_count"], 0)

    def test_detects_duplicate_task_identity(self):
        report = clean_report()
        report["remediation_tasks"].append(deepcopy(report["remediation_tasks"][0]))

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("duplicate_task", finding_codes(result))

    def test_detects_duplicate_task_identity_with_case_normalized_ids(self):
        report = clean_report()
        duplicate = deepcopy(report["remediation_tasks"][0])
        duplicate["vulnerability"]["canonical_id"] = "cve-2025-12345"
        report["remediation_tasks"].append(duplicate)

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("duplicate_task", finding_codes(result))

    def test_detects_duplicate_task_identity_with_overlapping_alias(self):
        report = clean_report()
        first = report["remediation_tasks"][0]
        first["vulnerability"]["canonical_id"] = "CVE-2025-11111"
        first["vulnerability"]["source_id"] = "GHSA-source-a"
        first["vulnerability"]["aliases"] = ["GHSA-SHARED-ALIAS"]
        duplicate = deepcopy(first)
        duplicate["vulnerability"]["canonical_id"] = "CVE-2025-22222"
        duplicate["vulnerability"]["source_id"] = "OSV-source-b"
        duplicate["vulnerability"]["aliases"] = ["ghsa-shared-alias"]
        report["remediation_tasks"].append(duplicate)

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("duplicate_task", finding_codes(result))

    def test_detects_duplicate_task_identity_with_canonical_alias_overlap(self):
        report = clean_report()
        first = report["remediation_tasks"][0]
        first["vulnerability"]["canonical_id"] = "CVE-2025-11111"
        first["vulnerability"]["source_id"] = "GHSA-source-a"
        first["vulnerability"]["aliases"] = []
        duplicate = deepcopy(first)
        duplicate["vulnerability"]["canonical_id"] = "GHSA-source-b"
        duplicate["vulnerability"]["source_id"] = "OSV-source-b"
        duplicate["vulnerability"]["aliases"] = ["cve-2025-11111"]
        report["remediation_tasks"].append(duplicate)

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("duplicate_task", finding_codes(result))

    def test_allows_same_alias_on_different_package(self):
        report = clean_report()
        duplicate = deepcopy(report["remediation_tasks"][0])
        duplicate["package"]["name"] = "other-archive-utils"
        duplicate["vulnerability"]["canonical_id"] = "CVE-2025-22222"
        duplicate["vulnerability"]["source_id"] = "OSV-source-b"
        duplicate["vulnerability"]["aliases"] = ["GHSA-runtime"]
        report["remediation_tasks"].append(duplicate)

        result = validate_report(report)

        self.assertTrue(result["passed"])

    def test_allows_same_alias_on_different_current_version(self):
        report = clean_report()
        duplicate = deepcopy(report["remediation_tasks"][0])
        duplicate["package"]["current_version"] = "2.1.5"
        duplicate["vulnerability"]["canonical_id"] = "CVE-2025-22222"
        duplicate["vulnerability"]["source_id"] = "OSV-source-b"
        duplicate["vulnerability"]["aliases"] = ["GHSA-runtime"]
        report["remediation_tasks"].append(duplicate)

        result = validate_report(report)

        self.assertTrue(result["passed"])

    def test_detects_downgrade_patch_target(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["patch_plan"]["target_version"] = "2.0.9"

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("downgrade_patch_target", finding_codes(result))

    def test_detects_prerelease_patch_target_downgrade(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["package"]["current_version"] = "1.0.0"
        task["vulnerability"]["fixed_versions"] = ["1.0.0-alpha.1"]
        task["patch_plan"]["target_version"] = "1.0.0-alpha.1"

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("downgrade_patch_target", finding_codes(result))

    def test_detects_non_review_priority_without_fix_or_target(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["vulnerability"]["fixed_versions"] = []
        task["patch_plan"]["target_version"] = None

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("missing_fix_or_target_version", finding_codes(result))

    def test_detects_non_review_priority_with_fixed_versions_but_no_patch_target(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["package"]["current_version"] = "6.5.2"
        task["vulnerability"]["fixed_versions"] = ["6.2.4"]
        task["patch_plan"]["target_version"] = None

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("missing_fix_or_target_version", finding_codes(result))

    def test_detects_p2_patch_target_below_current_version(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["package"]["current_version"] = "6.5.2"
        task["vulnerability"]["fixed_versions"] = ["6.2.4"]
        task["risk"]["priority"] = "P2"
        task["patch_plan"]["target_version"] = "6.2.4"

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("downgrade_patch_target", finding_codes(result))

    def test_detects_non_review_priority_with_invalid_patch_target(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["patch_plan"]["target_version"] = "latest"

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("invalid_patch_target_version", finding_codes(result))

    def test_allows_human_review_without_fix_or_target(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["risk"]["priority"] = "NEEDS_HUMAN_REVIEW"
        task["vulnerability"]["fixed_versions"] = []
        task["patch_plan"]["target_version"] = None

        result = validate_report(report)

        self.assertTrue(result["passed"])

    def test_detects_unsafe_public_text_and_forbidden_keys(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["vulnerability"]["summary"] = "PoC includes malicious payload notes."
        task["vulnerability"]["details"] = "Internal advisory details."
        task["raw"] = {"advisory": "internal"}

        result = validate_report(report)

        codes = finding_codes(result)
        self.assertIn("unsafe_public_text", codes)
        self.assertIn("forbidden_public_key", codes)

    def test_detects_local_path_and_secret_like_public_text(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["evidence"].append(
            {
                "type": "debug",
                "source": "/Users/auditor/private/repo/package-lock.json",
                "claim": "OSV token=ghp_secret123 was present in diagnostics.",
            }
        )

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("unsafe_public_text", finding_codes(result))

    def test_detects_local_path_variants_in_references_without_echoing_values(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        local_values = [
            "file:///Users/auditor/private/repo/package-lock.json",
            "https://scanner.local/report?path=/repos/private/payments/package.json",
            "C:/Users/auditor/private/repo/package-lock.json",
        ]
        for value in local_values:
            task["evidence"].append(
                {
                    "type": "reference",
                    "source": value,
                    "claim": "Reference was attached during validation.",
                }
            )

        result = validate_report(report)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("unsafe_public_text", finding_codes(result))
        for value in local_values:
            self.assertNotIn(value, text)

    def test_detects_unsafe_public_text_in_mapping_keys_without_echoing_key(self):
        report = clean_report()
        report["private-token-key"] = "safe value"

        result = validate_report(report)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("unsafe_public_text", finding_codes(result))
        self.assertNotIn("private-token-key", text)

    def test_forbidden_key_path_does_not_echo_unsafe_parent_key(self):
        report = clean_report()
        report["private-token-key"] = {"raw": "internal value"}

        result = validate_report(report)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("forbidden_public_key", finding_codes(result))
        self.assertNotIn("private-token-key", text)
        self.assertIn("<key>.raw", text)

    def test_detects_common_api_key_values(self):
        report = clean_report()
        report["errors"] = ["provider returned sk_live_51SecretValue"]

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("unsafe_public_text", finding_codes(result))

    def test_validate_report_rejects_schema_invalid_direct_input(self):
        result = validate_report({"remediation_tasks": []})

        self.assertFalse(result["passed"])
        self.assertIn("invalid_report_schema", finding_codes(result))

    def test_allows_already_redacted_secret_fragments(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["evidence"].append(
            {
                "type": "debug",
                "source": "debug-header",
                "claim": "Authorization: Bearer [redacted-secret]",
            }
        )

        result = validate_report(report)

        self.assertTrue(result["passed"])

    def test_detects_nested_unsafe_and_unsupported_text_outside_summary(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["evidence"].append(
            {
                "type": "analysis_note",
                "source": "src/upload/receiptParser.ts",
                "claim": "Confirmed exploitable through receipt upload.",
            }
        )
        task["patch_plan"]["steps"].append("Do not include exploit payload details in the PR.")

        result = validate_report(report)

        codes = finding_codes(result)
        self.assertFalse(result["passed"])
        self.assertIn("unsupported_claim_marker", codes)
        self.assertIn("unsafe_public_text", codes)
        self.assertIn(
            "remediation_tasks[0].evidence[2].claim",
            {finding["path"] for finding in result["findings"]},
        )
        self.assertIn(
            "remediation_tasks[0].patch_plan.steps[1]",
            {finding["path"] for finding in result["findings"]},
        )

    def test_detects_whitespace_only_evidence_as_missing(self):
        report = clean_report()
        report["remediation_tasks"][0]["evidence"] = [
            {"type": "lockfile", "source": "  ", "claim": "\t"}
        ]

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("missing_evidence", finding_codes(result))

    def test_wave_1_adversarial_reports_fail_expected_quality_gates(self):
        cases = [
            (
                "unsupported exploitability claim",
                lambda report: report["remediation_tasks"][0]["risk"].update(
                    {"rationale": ["This vulnerability is actively exploited in production."]}
                ),
                "unsupported_claim_marker",
            ),
            (
                "missing evidence",
                lambda report: report["remediation_tasks"][0].update({"evidence": []}),
                "missing_evidence",
            ),
            (
                "non-review task without patch target",
                lambda report: report["remediation_tasks"][0]["patch_plan"].update(
                    {"target_version": None}
                ),
                "missing_fix_or_target_version",
            ),
            (
                "duplicate alias overlap",
                add_alias_overlap_duplicate,
                "duplicate_task",
            ),
            (
                "unsafe text leakage",
                lambda report: report["remediation_tasks"][0]["test_plan"].append(
                    "Validate without proof-of-concept instructions."
                ),
                "unsafe_public_text",
            ),
        ]

        for name, mutate, expected_code in cases:
            with self.subTest(name=name):
                report = clean_report()
                mutate(report)

                result = validate_report(report)

                self.assertFalse(result["passed"])
                self.assertIn(expected_code, finding_codes(result))

    def test_detects_type_only_evidence_as_missing(self):
        report = clean_report()
        report["remediation_tasks"][0]["evidence"] = [{"type": "lockfile"}]

        result = validate_report(report)

        self.assertFalse(result["passed"])
        self.assertIn("missing_evidence", finding_codes(result))

    def test_detects_missing_evidence_missing_priority_and_unsupported_claim(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["evidence"] = []
        task["risk"].pop("priority")
        task["risk"]["rationale"] = ["This issue is confirmed exploitable in production."]

        result = validate_report(report)

        codes = finding_codes(result)
        self.assertIn("missing_evidence", codes)
        self.assertIn("missing_priority", codes)
        self.assertIn("unsupported_claim_marker", codes)

    def test_finding_messages_do_not_echo_raw_report_values(self):
        report = clean_report()
        task = report["remediation_tasks"][0]
        task["package"]["name"] = "private-token-package"
        task["package"]["current_version"] = "secret-version"
        task["vulnerability"]["canonical_id"] = "CVE-secret-token"
        task["vulnerability"]["summary"] = "malicious payload details"
        task["patch_plan"]["target_version"] = "token-secret-version"
        report["remediation_tasks"].append(deepcopy(task))

        result = validate_report(report)

        messages = " ".join(finding["message"] for finding in result["findings"])
        codes = finding_codes(result)
        self.assertFalse(result["passed"])
        self.assertIn("duplicate_task", codes)
        self.assertIn("invalid_patch_target_version", codes)
        self.assertIn("unsafe_public_text", codes)
        self.assertNotIn("private-token-package", messages)
        self.assertNotIn("secret-version", messages)
        self.assertNotIn("CVE-secret-token", messages)
        self.assertNotIn("token-secret-version", messages)
        self.assertNotIn("malicious payload", messages)

    def test_allows_negated_remote_exploitable_claim_but_blocks_positive_claim(self):
        report = clean_report()
        report["remediation_tasks"][0]["risk"]["rationale"] = [
            "This issue is not remotely exploitable based on retrieved evidence."
        ]

        negated_result = validate_report(report)

        self.assertTrue(negated_result["passed"])

        report["remediation_tasks"][0]["risk"]["rationale"] = [
            "This issue is not patched and remotely exploitable in production."
        ]

        positive_result = validate_report(report)

        self.assertFalse(positive_result["passed"])
        self.assertIn("unsupported_claim_marker", finding_codes(positive_result))

    def test_cli_prints_json_and_exits_nonzero_on_failure(self):
        report = clean_report()
        report["remediation_tasks"][0]["evidence"] = []

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                exit_code = main([str(path)])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["passed"])
        self.assertIn("missing_evidence", finding_codes(payload))

    def test_validate_json_file_does_not_leak_local_path_for_missing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing-report.json"

            result = validate_json_file(path)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("read_error", finding_codes(result))
        self.assertNotIn(temp_dir, text)
        self.assertNotIn(str(path), text)
        self.assertIn("missing-report.json", text)

    def test_validate_json_file_does_not_leak_local_path_for_invalid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad-report.json"
            path.write_text("{", encoding="utf-8")

            result = validate_json_file(path)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("invalid_json", finding_codes(result))
        self.assertNotIn(temp_dir, text)
        self.assertNotIn(str(path), text)
        self.assertIn("bad-report.json", text)

    def test_validate_json_file_does_not_leak_secret_like_filename(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "private-token-report.json"
            path.write_text("{", encoding="utf-8")

            result = validate_json_file(path)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("invalid_json", finding_codes(result))
        self.assertNotIn("private-token-report.json", text)
        self.assertNotIn("private-token", text)
        self.assertIn("report file", text)

    def test_validate_json_file_rejects_schema_invalid_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "report.json"
            report = clean_report()
            report.pop("schema_version", None)
            path.write_text(json.dumps(report), encoding="utf-8")

            result = validate_json_file(path)

        self.assertFalse(result["passed"])
        self.assertIn("invalid_report_schema", finding_codes(result))

    def test_validate_json_file_does_not_leak_local_path_for_non_utf8_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "binary-report.json"
            path.write_bytes(b"\xff\xfe\x00")

            result = validate_json_file(path)

        text = json.dumps(result)
        self.assertFalse(result["passed"])
        self.assertIn("read_error", finding_codes(result))
        self.assertNotIn(temp_dir, text)
        self.assertNotIn(str(path), text)
        self.assertIn("binary-report.json", text)


if __name__ == "__main__":
    unittest.main()
