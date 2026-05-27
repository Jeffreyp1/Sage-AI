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

    def test_validation_blocks_fact_claim_without_matching_citation(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            citations=[],
            claim_checks=[
                ClaimCheck(
                    claim_id="claim-fact-1",
                    claim="archive-utils is affected.",
                    disposition="fact",
                    evidence_ids=["ev-advisory"],
                )
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(result.unsupported_claim_ids, ["claim-fact-1"])
        self.assertIn(
            "Claim claim-fact-1 evidence id ev-advisory has no matching citation.",
            result.errors,
        )

    def test_validation_blocks_inference_claim_with_mismatched_citation(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            citations=[
                Citation(
                    evidence_id="ev-reachability",
                    claim_id="claim-inference-1",
                )
            ],
            claim_checks=[
                ClaimCheck(
                    claim_id="claim-inference-1",
                    claim="The production upload route raises priority.",
                    disposition="inference",
                    evidence_ids=["ev-advisory"],
                )
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(result.unsupported_claim_ids, ["claim-inference-1"])
        self.assertIn(
            "Claim claim-inference-1 evidence id ev-advisory has no matching citation.",
            result.errors,
        )

    def test_validation_blocks_non_string_citation_identifiers_without_crashing(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            citations=[
                Citation(
                    evidence_id=["ev-advisory"],  # type: ignore[arg-type]
                    claim_id="claim-fact-1",
                ),
                Citation(
                    evidence_id="ev-advisory",
                    claim_id={"id": "claim-fact-1"},  # type: ignore[arg-type]
                ),
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("Citation evidence_id must be a string.", result.errors)
        self.assertIn("Citation claim_id must be a string.", result.errors)
        self.assertEqual(result.invalid_citation_ids, [])

    def test_validation_blocks_missing_citations(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(response, citations=None)  # type: ignore[arg-type]

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("AI response citations must be a list.", result.errors)

    def test_validation_blocks_malformed_citations(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            citations=[
                {
                    "evidence_id": "ev-advisory",
                    "claim_id": "claim-fact-1",
                }
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("AI response citations[0] must be a Citation.", result.errors)

    def test_validation_blocks_missing_claim_checks(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(response, claim_checks=None)  # type: ignore[arg-type]

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("AI response claim_checks must be a list.", result.errors)

    def test_validation_blocks_malformed_claim_checks(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            claim_checks=[
                {
                    "claim_id": "claim-fact-1",
                    "disposition": "fact",
                    "evidence_ids": ["ev-advisory"],
                }
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("AI response claim_checks[0] must be a ClaimCheck.", result.errors)

    def test_validation_blocks_claims_with_malformed_evidence_ids(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            claim_checks=[
                replace(response.claim_checks[0], evidence_ids=None),  # type: ignore[arg-type]
                replace(response.claim_checks[1], evidence_ids=42),  # type: ignore[arg-type]
            ],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("Claim claim-fact-1 evidence_ids must be a list.", result.errors)
        self.assertIn("Claim claim-inference-1 evidence_ids must be a list.", result.errors)

    def test_validation_blocks_non_string_claim_disposition_without_crashing(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            claim_checks=[
                ClaimCheck(
                    claim_id="claim-bad-disposition-list",
                    claim="This claim has a malformed disposition.",
                    disposition=["fact"],  # type: ignore[arg-type]
                    evidence_ids=["ev-advisory"],
                ),
                ClaimCheck(
                    claim_id="claim-bad-disposition-dict",
                    claim="This claim also has a malformed disposition.",
                    disposition={"value": "fact"},  # type: ignore[arg-type]
                    evidence_ids=["ev-advisory"],
                ),
            ],
            citations=[],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn(
            "Claim claim-bad-disposition-list disposition must be a string.",
            result.errors,
        )
        self.assertIn(
            "Claim claim-bad-disposition-dict disposition must be a string.",
            result.errors,
        )

    def test_validation_flags_unsupported_claims(self):
        request = finding_request()
        response = MockAIProvider(
            unsupported_claims=["This finding is confirmed in production without evidence."]
        ).summarize_finding(request)

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertEqual(result.unsupported_claim_ids, ["claim-unsupported-1"])

    def test_validation_blocks_non_string_unsupported_claim_ids_without_crashing(self):
        request = finding_request()
        response = MockAIProvider().summarize_finding(request)
        response = replace(
            response,
            claim_checks=[
                ClaimCheck(
                    claim_id=["claim-unsupported"],  # type: ignore[arg-type]
                    claim="This malformed claim should not crash validation.",
                    disposition="unsupported",
                    evidence_ids=[],
                ),
                ClaimCheck(
                    claim_id={"id": "claim-no-evidence"},  # type: ignore[arg-type]
                    claim="This malformed claim has no supporting evidence.",
                    disposition="fact",
                    evidence_ids=[],
                ),
            ],
            citations=[],
        )

        result = validate_finding_summary_response(request, response)

        self.assertFalse(result.valid)
        self.assertTrue(result.blocked)
        self.assertIn("Claim claim_id must be a string.", result.errors)
        self.assertIn("Claim ['claim-unsupported'] is unsupported.", result.errors)
        self.assertIn(
            "Claim {'id': 'claim-no-evidence'} has no supporting evidence.",
            result.errors,
        )
        self.assertEqual(result.unsupported_claim_ids, [])

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

    def test_validation_allows_poc_inside_scanner_owned_package_name(self):
        request = replace(finding_request(), package_name="poc-utils")
        response = MockAIProvider().summarize_finding(request)

        result = validate_finding_summary_response(request, response)

        self.assertTrue(result.valid)
        self.assertFalse(result.blocked)
        self.assertNotIn("AI response contains unsafe marker poc.", result.errors)

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
