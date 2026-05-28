import unittest

from app.eval.verifier import verify_report


def clean_task(package_name="archive-utils", priority="P0_RELEASE_BLOCKER"):
    return {
        "package": {
            "name": package_name,
            "dependency_type": "dependencies",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "CVE-2025-12345",
            "source_id": "GHSA-runtime",
            "aliases": ["GHSA-runtime"],
            "fixed_versions": ["2.2.0"],
            "summary": "Archive parsing vulnerability",
        },
        "risk": {
            "priority": priority,
            "reachability": "possibly_reachable",
            "runtime_scope": "production",
        },
        "evidence": [
            {"type": "lockfile", "source": "package-lock.json"},
            {"type": "source_file", "source": "src/upload/receiptParser.ts"},
        ],
        "patch_plan": {"target_version": "2.2.0"},
        "owner": "@payments-platform",
    }


class ReportVerifierTest(unittest.TestCase):
    def test_passes_clean_expected_report(self):
        case = {
            "case_id": "clean",
            "expected_findings": [
                {
                    "package": "archive-utils",
                    "canonical_id": "CVE-2025-12345",
                    "priority": "P0_RELEASE_BLOCKER",
                    "fixed_version": "2.2.0",
                    "dependency_type": "dependencies",
                    "is_direct": True,
                    "reachability": "possibly_reachable",
                    "runtime_scope": "production",
                    "owner": "@payments-platform",
                    "must_have_evidence_sources": ["src/upload/receiptParser.ts"],
                }
            ],
        }
        report = {"remediation_tasks": [clean_task()]}

        result = verify_report(case=case, report=report)

        self.assertTrue(result["passed"])
        self.assertEqual(result["scores"]["finding_count"], 0)

    def test_fails_missing_expected_finding(self):
        case = {
            "case_id": "missing",
            "expected_findings": [{"package": "archive-utils", "canonical_id": "CVE-2025-12345"}],
        }

        result = verify_report(case=case, report={"remediation_tasks": []})

        self.assertFalse(result["passed"])
        self.assertEqual(result["findings"][0]["code"], "missing_expected_finding")

    def test_fails_wrong_priority_and_missing_evidence(self):
        case = {
            "case_id": "bad_priority",
            "expected_findings": [
                {
                    "package": "archive-utils",
                    "canonical_id": "CVE-2025-12345",
                    "priority": "P0_RELEASE_BLOCKER",
                    "must_have_evidence_sources": ["src/routes/receipts.ts"],
                }
            ],
        }

        result = verify_report(
            case=case,
            report={"remediation_tasks": [clean_task(priority="P3_MONITOR_DEFER")]},
        )

        codes = {finding["code"] for finding in result["findings"]}
        self.assertIn("priority_mismatch", codes)
        self.assertIn("missing_evidence", codes)

    def test_fails_wrong_fixed_version(self):
        task = clean_task()
        task["vulnerability"]["fixed_versions"] = ["2.3.0"]
        task["patch_plan"]["target_version"] = "2.3.0"
        case = {
            "case_id": "bad_fixed_version",
            "expected_findings": [
                {
                    "package": "archive-utils",
                    "canonical_id": "CVE-2025-12345",
                    "fixed_version": "2.2.0",
                }
            ],
        }

        result = verify_report(case=case, report={"remediation_tasks": [task]})

        self.assertFalse(result["passed"])
        self.assertIn("fixed_version_mismatch", {finding["code"] for finding in result["findings"]})

    def test_fails_unsafe_output(self):
        task = clean_task()
        task["vulnerability"]["summary"] = "PoC uses malicious payload"
        case = {
            "case_id": "unsafe",
            "expected_findings": [{"package": "archive-utils", "canonical_id": "CVE-2025-12345"}],
        }

        result = verify_report(case=case, report={"remediation_tasks": [task]})

        self.assertFalse(result["passed"])
        self.assertIn("unsafe_string", {finding["code"] for finding in result["findings"]})
        messages = " ".join(finding["message"] for finding in result["findings"])
        self.assertNotIn("PoC uses malicious payload", messages)
        self.assertIn("unsafe marker", messages)

    def test_fails_local_path_variants_without_echoing_raw_values(self):
        task = clean_task()
        local_values = [
            "file:///Users/auditor/private/repo/package-lock.json",
            "https://scanner.local/report?path=/repos/private/payments/package.json",
            "C:/Users/auditor/private/repo/package-lock.json",
        ]
        task["evidence"].extend(
            {"type": "reference", "source": value} for value in local_values
        )
        case = {
            "case_id": "local_path_leak",
            "expected_findings": [{"package": "archive-utils", "canonical_id": "CVE-2025-12345"}],
        }

        result = verify_report(case=case, report={"remediation_tasks": [task]})

        messages = " ".join(finding["message"] for finding in result["findings"])
        self.assertFalse(result["passed"])
        self.assertIn("unsafe_string", {finding["code"] for finding in result["findings"]})
        self.assertIn("local_path", messages)
        self.assertIn("remediation_tasks[0].evidence", messages)
        for value in local_values:
            self.assertNotIn(value, messages)

    def test_allows_token_named_packages(self):
        case = {
            "case_id": "token_named_packages",
            "expected_findings": [
                {"package": "jsonwebtoken", "canonical_id": "CVE-2025-12345"},
                {"package": "csrf-token", "canonical_id": "CVE-2025-12345"},
            ],
            "allow_extra_findings": True,
        }
        report = {
            "remediation_tasks": [
                clean_task(package_name="jsonwebtoken"),
                clean_task(package_name="csrf-token"),
            ]
        }

        result = verify_report(case=case, report=report)

        self.assertTrue(result["passed"])

    def test_fails_unsupported_claim_marker(self):
        task = clean_task()
        task["risk"]["rationale"] = ["This vulnerability is confirmed exploitable."]
        case = {
            "case_id": "unsupported_claim",
            "expected_findings": [{"package": "archive-utils", "canonical_id": "CVE-2025-12345"}],
        }

        result = verify_report(case=case, report={"remediation_tasks": [task]})

        self.assertFalse(result["passed"])
        self.assertIn("unsupported_claim", {finding["code"] for finding in result["findings"]})


if __name__ == "__main__":
    unittest.main()
