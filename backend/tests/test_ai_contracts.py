from dataclasses import replace
import unittest

from app.ai.contracts import (
    AIFindingSummaryRequest,
    Citation,
    ClaimCheck,
    EvidenceItem,
    MockAIProvider,
    validate_finding_summary_response,
)


def finding_request() -> AIFindingSummaryRequest:
    return AIFindingSummaryRequest(
        finding_id="finding-1",
        package_name="archive-utils",
        vulnerability_id="CVE-2026-0001",
        priority="P0_RELEASE_BLOCKER",
        risk_score=82,
        severity="HIGH",
        evidence=[
            EvidenceItem(
                id="ev-advisory",
                kind="advisory",
                source="OSV",
                content="archive-utils before 2.2.0 is affected; fixed version is 2.2.0.",
            ),
            EvidenceItem(
                id="ev-reachability",
                kind="reachability",
                source="src/upload.js",
                content="archive-utils is imported by a production upload route.",
            ),
        ],
    )


class AIContractsTest(unittest.TestCase):
    def test_mock_provider_returns_deterministic_structured_response(self):
        request = finding_request()
        provider = MockAIProvider()

        first = provider.summarize_finding(request)
        second = provider.summarize_finding(request)

        self.assertEqual(first, second)
        self.assertEqual(first.priority, request.priority)
        self.assertEqual(first.risk_score, request.risk_score)
        self.assertEqual(
            [claim.disposition for claim in first.claim_checks],
            ["fact", "inference", "unknown"],
        )

    def test_validation_accepts_citations_to_provided_evidence_ids(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)

        result = validate_finding_summary_response(request, response)

        self.assertTrue(result.valid)
        self.assertFalse(result.blocked)
        self.assertEqual(result.errors, [])
        self.assertEqual(result.invalid_citation_ids, [])

    def test_validation_blocks_unknown_citation_evidence_ids(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            citations=[
                *response.citations,
                Citation(evidence_id="missing-evidence", claim_id="claim-fact-1"),
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(result.invalid_citation_ids, ["missing-evidence"])

    def test_validation_flags_unsupported_claims(self):
        request = finding_request()
        response = MockAIProvider(
            unsupported_claims=["This finding is confirmed in production without evidence."]
        ).summarize_finding(request)

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(result.unsupported_claim_ids, ["claim-unsupported-1"])

    def test_validation_rejects_disallowed_dispositions_before_evidence_checks(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            claim_checks=[
                ClaimCheck(
                    claim_id="claim-bad-disposition",
                    claim="This claim should not be accepted.",
                    disposition="unsupported",
                    evidence_ids=["missing-evidence"],
                )
            ],
            citations=[],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(
            result.errors[:3],
            [
                "Claim claim-bad-disposition uses disallowed disposition unsupported.",
                "Claim claim-bad-disposition references unknown evidence id missing-evidence.",
                "Claim claim-bad-disposition is unsupported.",
            ],
        )
        self.assertEqual(result.invalid_citation_ids, ["missing-evidence"])
        self.assertEqual(result.unsupported_claim_ids, ["claim-bad-disposition"])

    def test_validation_blocks_priority_and_risk_mutation(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(response, priority="P3_MONITOR_DEFER", risk_score=12)

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(result.mutated_fields, ["priority", "risk_score"])
        self.assertEqual(request.priority, "P0_RELEASE_BLOCKER")
        self.assertEqual(request.risk_score, 82)
        self.assertFalse(request.safety_constraints.may_change_priority)
        self.assertFalse(request.safety_constraints.may_change_risk_score)

    def test_validation_blocks_unsafe_text_in_citation_quote_note_and_errors(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            citations=[
                Citation(
                    evidence_id="ev-advisory",
                    claim_id="claim-fact-1",
                    quote="This quote includes proof of concept details.",
                    note="This note includes a malicious payload.",
                )
            ],
            errors=["Provider emitted exploit code."],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("AI response contains unsafe marker proof of concept.", result.errors)
        self.assertIn("AI response contains unsafe marker malicious payload.", result.errors)
        self.assertIn("AI response contains unsafe marker exploit code.", result.errors)

    def test_validation_blocks_scanner_owned_identity_mutation(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            finding_id="finding-2",
            package_name="different-package",
            vulnerability_id="CVE-2026-9999",
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(
            result.mutated_fields,
            ["finding_id", "package_name", "vulnerability_id"],
        )


if __name__ == "__main__":
    unittest.main()
