from copy import deepcopy
from dataclasses import replace

import pytest

from app.ai.contracts import (
    AIFindingSummaryRequest,
    AIFindingSummaryResponse,
    Citation,
    ClaimCheck,
    MockAIProvider,
)
from app.services.ai_summary_service import (
    AISummaryService,
    build_finding_summary_request,
    retrieve_for_remediation_task,
)
from app.services.rag_types import EvidenceChunk
from app.services.trace_service import TraceService


def remediation_task() -> dict[str, object]:
    return {
        "task_id": "task_abc123",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "runtime",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "GHSA-1234-5678",
            "source_id": "CVE-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "severity": "HIGH",
            "summary": "archive-utils has unsafe deserialization that can lead to remote code execution.",
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 78,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "factors": ["High severity", "Production reachable"],
            "rationale": ["Risk score 78 maps to P1_FIX_THIS_SPRINT."],
        },
        "evidence": [
            {
                "type": "lockfile_entry",
                "source": "package-lock.json",
                "claim": "archive-utils@1.4.0 is installed in package-lock.json.",
            },
            {
                "type": "reachability",
                "source": "src/upload.ts",
                "claim": "archive-utils is imported by the production upload route.",
            },
        ],
        "patch_plan": {"target_version": "2.2.0"},
        "test_plan": ["npm test"],
        "rollback_plan": ["Revert package-lock.json"],
        "owner": "@security",
        "human_approval_required": True,
    }


def evidence_chunks() -> list[EvidenceChunk]:
    return [
        EvidenceChunk(
            chunk_id="chunk-advisory",
            source_type="advisory",
            content=(
                "GHSA-1234-5678 advisory for archive-utils: unsafe deserialization "
                "remote code execution. Fixed in 2.2.0."
            ),
            metadata={
                "repo_id": "payments-api",
                "package": "archive-utils",
                "path": "advisories/GHSA-1234-5678.md",
            },
        ),
        EvidenceChunk(
            chunk_id="chunk-reachable",
            source_type="reachability",
            content=(
                "archive-utils is imported by src/upload.ts in a production request path."
            ),
            metadata={
                "repo_id": "payments-api",
                "package": "archive-utils",
                "path": "src/upload.ts",
            },
        ),
        EvidenceChunk(
            chunk_id="chunk-other-package",
            source_type="advisory",
            content="frontend-widget has stored cross site scripting.",
            metadata={
                "repo_id": "payments-api",
                "package": "frontend-widget",
                "path": "frontend.md",
            },
        ),
        EvidenceChunk(
            chunk_id="chunk-other-repo",
            source_type="advisory",
            content="archive-utils appears in a documentation sample in another repository.",
            metadata={
                "repo_id": "docs-site",
                "package": "archive-utils",
                "path": "docs.md",
            },
        ),
    ]


class RetrievedCitationProvider:
    name = "retrieved-citation-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        retrieved = [
            item
            for item in request.evidence
            if item.metadata.get("origin") == "retrieved_context"
        ]
        evidence_id = retrieved[0].id
        claim_id = "claim-retrieved-1"
        return AIFindingSummaryResponse(
            finding_id=request.finding_id,
            package_name=request.package_name,
            vulnerability_id=request.vulnerability_id,
            priority=request.priority,
            risk_score=request.risk_score,
            summary="archive-utils is summarized from retrieved advisory evidence.",
            explanation="The finding is explained without changing triage fields.",
            citations=[Citation(evidence_id=evidence_id, claim_id=claim_id)],
            claim_checks=[
                ClaimCheck(
                    claim_id=claim_id,
                    claim="archive-utils has cited retrieved advisory context.",
                    disposition="fact",
                    evidence_ids=[evidence_id],
                    rationale="The claim cites a retrieved evidence item.",
                )
            ],
            provider_name=self.name,
        )


class MutatingPriorityProvider:
    name = "mutating-priority-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        response = MockAIProvider().summarize_finding(request)
        return replace(
            response,
            priority="P3_MONITOR_DEFER",
            risk_score=12,
            summary="This response tries to change triage values.",
            provider_name=self.name,
        )


class UnsupportedPublicProseProvider:
    name = "unsupported-public-prose-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        response = MockAIProvider().summarize_finding(request)
        return replace(
            response,
            summary="archive-utils is confirmed exploited in production.",
            explanation="Attackers are actively exfiltrating customer data.",
            provider_name=self.name,
        )


class FalseCitedFactProvider:
    name = "false-cited-fact-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        evidence_id = request.evidence[0].id
        claim_id = "claim-false-fact-1"
        false_claim = "archive-utils is confirmed exploited in production"
        return AIFindingSummaryResponse(
            finding_id=request.finding_id,
            package_name=request.package_name,
            vulnerability_id=request.vulnerability_id,
            priority=request.priority,
            risk_score=request.risk_score,
            summary="safe-looking summary",
            explanation="safe-looking explanation",
            citations=[Citation(evidence_id=evidence_id, claim_id=claim_id)],
            claim_checks=[
                ClaimCheck(
                    claim_id=claim_id,
                    claim=false_claim,
                    disposition="fact",
                    evidence_ids=[evidence_id],
                    rationale="The claim cites a real evidence item.",
                )
            ],
            provider_name=self.name,
        )


class MalformedProvider:
    name = "malformed-provider"

    def __init__(self, payload: object) -> None:
        self.payload = payload

    def summarize_finding(self, request: AIFindingSummaryRequest) -> object:
        return self.payload


class RawValidationLeakProvider:
    name = "raw-validation-leak-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        return AIFindingSummaryResponse(
            finding_id=request.finding_id,
            package_name=request.package_name,
            vulnerability_id=request.vulnerability_id,
            priority=request.priority,
            risk_score=request.risk_score,
            summary="safe-looking summary",
            explanation="safe-looking explanation",
            citations=[
                Citation(
                    evidence_id="token=secret-invalid-citation",
                    claim_id="claim-unsupported-secret",
                )
            ],
            claim_checks=[
                ClaimCheck(
                    claim_id="claim-unsupported-secret",
                    claim="secret unsupported claim",
                    disposition="unsupported",
                    evidence_ids=[],
                )
            ],
            provider_name=self.name,
        )


class AcceptedPublicLeakProvider:
    name = "accepted-public-leak-provider"
    raw_error = "provider-authored errors text must stay private"
    provider_claim_id = "confirmed exploited in production"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        evidence_id = request.evidence[0].id
        return AIFindingSummaryResponse(
            finding_id=request.finding_id,
            package_name=request.package_name,
            vulnerability_id=request.vulnerability_id,
            priority=request.priority,
            risk_score=request.risk_score,
            summary="safe-looking summary",
            explanation="safe-looking explanation",
            citations=[Citation(evidence_id=evidence_id, claim_id=self.provider_claim_id)],
            claim_checks=[
                ClaimCheck(
                    claim_id=self.provider_claim_id,
                    claim="archive-utils has cited package evidence.",
                    disposition="fact",
                    evidence_ids=[evidence_id],
                    rationale="The claim cites a real evidence item.",
                )
            ],
            provider_name=self.name,
            errors=[self.raw_error],
        )


def test_builds_deterministic_request_from_task_and_retrieved_evidence() -> None:
    task = remediation_task()
    retrieved = evidence_chunks()[:2]

    first = build_finding_summary_request(task, retrieved)
    second = build_finding_summary_request(task, retrieved)

    assert first == second
    assert first.finding_id == "task_abc123"
    assert first.package_name == "archive-utils"
    assert first.vulnerability_id == "GHSA-1234-5678"
    assert first.priority == "P1_FIX_THIS_SPRINT"
    assert first.risk_score == 78
    assert first.severity == "HIGH"
    assert [item.metadata["origin"] for item in first.evidence] == [
        "remediation_task",
        "remediation_task",
        "retrieved_context",
        "retrieved_context",
    ]
    assert len({item.id for item in first.evidence}) == len(first.evidence)


def test_retrieve_for_remediation_task_uses_metadata_filters_and_falls_back() -> None:
    filtered = retrieve_for_remediation_task(remediation_task(), evidence_chunks(), top_k=3)
    sparse_chunk = EvidenceChunk(
        chunk_id="chunk-sparse",
        source_type="advisory",
        content="archive-utils GHSA-1234-5678 unsafe deserialization fixed in 2.2.0.",
        metadata={"path": "advisory.md"},
    )

    sparse = retrieve_for_remediation_task(remediation_task(), [sparse_chunk], top_k=3)

    assert [result.chunk.chunk_id for result in filtered[:2]] == [
        "chunk-advisory",
        "chunk-reachable",
    ]
    assert "chunk-other-package" not in [
        result.chunk.chunk_id for result in filtered[:2]
    ]
    assert [result.chunk.chunk_id for result in sparse] == ["chunk-sparse"]


def test_retrieved_evidence_is_included_and_can_be_cited() -> None:
    result = AISummaryService(provider=RetrievedCitationProvider()).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    retrieved_ids = {
        item.id
        for item in result.request.evidence
        if item.metadata.get("origin") == "retrieved_context"
    }

    assert result.validation.valid
    assert not result.blocked
    assert result.response is not None
    assert result.response.citations[0].evidence_id in retrieved_ids
    assert result.retrieved_chunk_ids[0] == "chunk-advisory"


def test_priority_and_risk_mutation_is_blocked() -> None:
    result = AISummaryService(provider=MutatingPriorityProvider()).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    assert result.blocked
    assert not result.validation.valid
    assert result.validation.mutated_fields == ["priority", "risk_score"]
    assert result.response is None
    assert "AI response changed priority from P1_FIX_THIS_SPRINT to P3_MONITOR_DEFER." in (
        result.validation.errors
    )
    public_result = result.to_dict()
    assert public_result["validation"]["errors"] == [
        "AI response changed protected triage fields."
    ]
    assert "P3_MONITOR_DEFER" not in json_text(public_result)


def test_unsupported_claim_blocks_summary() -> None:
    provider = MockAIProvider(
        unsupported_claims=["The package is confirmed exploited in production."]
    )

    result = AISummaryService(provider=provider).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    assert result.blocked
    assert result.response is None
    assert result.validation.unsupported_claim_ids == ["claim-unsupported-1"]


def test_unsupported_public_summary_and_explanation_are_not_exposed() -> None:
    result = AISummaryService(
        provider=UnsupportedPublicProseProvider()
    ).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    assert not result.blocked
    assert result.response is not None
    public_text = "%s\n%s" % (result.response.summary, result.response.explanation)
    assert "confirmed exploited in production" not in public_text
    assert "exfiltrating customer data" not in public_text


def test_cited_false_fact_is_blocked_and_not_exposed_publicly() -> None:
    false_claim = "archive-utils is confirmed exploited in production"

    result = AISummaryService(provider=FalseCitedFactProvider()).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    public_result = result.to_dict()

    assert result.blocked
    assert result.response is None
    assert result.validation.unsupported_claim_ids == ["claim-false-fact-1"]
    assert false_claim not in json_text(public_result)


def test_blocked_provider_response_is_not_exposed_publicly() -> None:
    provider = MockAIProvider(
        unsupported_claims=["This blocked claim must not be exposed as accepted output."]
    )

    result = AISummaryService(provider=provider).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    assert result.blocked
    assert result.response is None
    assert result.validation.unsupported_claim_ids == ["claim-unsupported-1"]


def test_provider_failure_returns_blocked_result() -> None:
    provider = MockAIProvider(failure_message="provider unavailable")

    result = AISummaryService(provider=provider).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    assert result.blocked
    assert result.response is None
    assert result.validation.errors == ["AI provider failed."]
    assert result.validation.warnings == ["provider unavailable"]
    assert result.to_dict()["validation"]["errors"] == ["AI provider failed."]
    assert result.to_dict()["validation"]["warnings"] == []


@pytest.mark.parametrize(
    "payload",
    [
        "not structured output",
        {"summary": "dict output"},
        object(),
    ],
    ids=["string", "dict", "object"],
)
def test_malformed_provider_output_returns_blocked_trace_without_crashing(
    payload: object,
) -> None:
    trace_service = TraceService()

    result = AISummaryService(
        provider=MalformedProvider(payload),
        trace_service=trace_service,
    ).summarize_remediation_task(remediation_task(), evidence_chunks())

    records = trace_service.list_records()

    assert result.blocked
    assert result.response is None
    assert result.validation.errors == [
        "AI provider failed."
    ]
    assert result.validation.warnings == [
        "AI provider returned malformed finding summary response."
    ]
    assert len(records) == 1
    assert records[0]["validation_status"] == "blocked"
    assert records[0]["output_json"]["response"] is None
    assert records[0]["output_json"]["validation"]["errors"] == ["AI provider failed."]


def test_provider_failure_public_output_does_not_expose_raw_response_body() -> None:
    provider = MockAIProvider(
        failure_message="provider 500 body: token=secret malicious payload"
    )

    result = AISummaryService(provider=provider).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    public_text = json_text(result.to_dict())

    assert result.blocked
    assert result.validation.errors == ["AI provider failed."]
    assert "provider 500 body" not in public_text
    assert "secret" not in public_text
    assert "malicious payload" not in public_text


def test_blocked_public_validation_omits_raw_citation_and_claim_ids() -> None:
    result = AISummaryService(
        provider=RawValidationLeakProvider()
    ).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    public_result = result.to_dict()
    public_text = json_text(public_result)

    assert result.blocked
    assert result.validation.invalid_citation_ids == ["token=secret-invalid-citation"]
    assert result.validation.unsupported_claim_ids == ["claim-unsupported-secret"]
    assert public_result["validation"]["invalid_citation_ids"] == []
    assert public_result["validation"]["unsupported_claim_ids"] == []
    assert "token=secret-invalid-citation" not in public_text
    assert "claim-unsupported-secret" not in public_text


def test_accepted_public_output_remaps_provider_claim_ids() -> None:
    result = AISummaryService(
        provider=AcceptedPublicLeakProvider()
    ).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    public_result = result.to_dict()
    public_text = json_text(public_result)
    public_response = public_result["response"]
    public_claim_id = public_response["claim_checks"][0]["claim_id"]

    assert not result.blocked
    assert public_response is not None
    assert AcceptedPublicLeakProvider.provider_claim_id not in public_text
    assert public_claim_id.startswith("public-claim-")
    assert public_response["citations"][0]["claim_id"] == public_claim_id


def test_accepted_public_output_omits_provider_authored_errors() -> None:
    result = AISummaryService(
        provider=AcceptedPublicLeakProvider()
    ).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    public_result = result.to_dict()
    public_text = json_text(public_result)
    public_response = public_result["response"]

    assert not result.blocked
    assert public_response is not None
    assert public_response["errors"] == []
    assert AcceptedPublicLeakProvider.raw_error not in public_text


def test_valid_summary_keeps_sanitized_public_claim_ids_aligned() -> None:
    result = AISummaryService(provider=MockAIProvider()).summarize_remediation_task(
        remediation_task(),
        evidence_chunks(),
    )

    public_result = result.to_dict()
    public_response = public_result["response"]
    claim_ids = [claim["claim_id"] for claim in public_response["claim_checks"]]
    cited_claim_ids = [citation["claim_id"] for citation in public_response["citations"]]

    assert not result.blocked
    assert result.validation.valid
    assert all(claim_id.startswith("public-claim-") for claim_id in claim_ids)
    assert "claim-fact-1" not in json_text(public_result)
    assert set(cited_claim_ids).issubset(set(claim_ids))


def test_traces_record_validation_status() -> None:
    trace_service = TraceService()

    result = AISummaryService(
        provider=RetrievedCitationProvider(),
        trace_service=trace_service,
    ).summarize_remediation_task(remediation_task(), evidence_chunks())

    records = trace_service.list_records()

    assert not result.blocked
    assert len(records) == 1
    assert records[0]["event_type"] == "ai.finding_summary"
    assert records[0]["validation_status"] == "passed"
    assert records[0]["input_json"]["priority"] == "P1_FIX_THIS_SPRINT"
    assert records[0]["retrieved_context_json"][0]["chunk_id"] == "chunk-advisory"
    assert records[0]["output_json"]["validation"]["valid"] is True


def test_service_does_not_alter_task_priority_or_risk() -> None:
    task = remediation_task()
    original_task = deepcopy(task)

    result = AISummaryService(provider=MutatingPriorityProvider()).summarize_remediation_task(
        task,
        evidence_chunks(),
    )

    assert result.blocked
    assert task == original_task
    assert task["risk"]["priority"] == "P1_FIX_THIS_SPRINT"
    assert task["risk"]["risk_score"] == 78


def json_text(value: object) -> str:
    return repr(value)
