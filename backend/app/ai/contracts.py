"""Safe request and response contracts for future AI providers."""

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Dict, List, Literal, Optional, Protocol, Tuple


ClaimDisposition = Literal["fact", "inference", "unknown", "unsupported"]
UNSAFE_RESPONSE_MARKERS = (
    "exploit steps",
    "proof of concept",
    "proof-of-concept",
    "poc",
    "malicious payload",
    "exploit code",
)


class AIProviderError(RuntimeError):
    """Raised when an AI provider cannot return a structured response."""


@dataclass(frozen=True)
class AISafetyConstraints:
    """Non-negotiable rules every provider must observe for a request."""

    may_explain: bool = True
    may_change_priority: bool = False
    may_change_risk_score: bool = False
    allow_exploit_steps: bool = False
    required_claim_dispositions: Tuple[str, ...] = ("fact", "inference", "unknown")
    instructions: Tuple[str, ...] = (
        "Explain only from the supplied evidence.",
        "Do not change priority or risk score.",
        "Do not provide exploit steps or procedural abuse guidance.",
        "Label each claim as fact, inference, or unknown.",
    )


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    kind: str
    source: str
    content: str
    metadata: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id.strip():
            raise ValueError("evidence id is required")
        if not self.kind.strip():
            raise ValueError("evidence kind is required")
        if not self.source.strip():
            raise ValueError("evidence source is required")

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AIFindingSummaryRequest:
    finding_id: str
    package_name: str
    vulnerability_id: str
    priority: str
    risk_score: int
    severity: str
    evidence: List[EvidenceItem]
    safety_constraints: AISafetyConstraints = field(default_factory=AISafetyConstraints)

    def __post_init__(self) -> None:
        if not self.finding_id.strip():
            raise ValueError("finding id is required")
        if not self.package_name.strip():
            raise ValueError("package name is required")
        if not self.vulnerability_id.strip():
            raise ValueError("vulnerability id is required")
        if self.risk_score < 0 or self.risk_score > 100:
            raise ValueError("risk score must be between 0 and 100")
        evidence_ids = [item.id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence ids must be unique")

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class Citation:
    evidence_id: str
    claim_id: str
    quote: Optional[str] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ClaimCheck:
    claim_id: str
    claim: str
    disposition: ClaimDisposition
    evidence_ids: List[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AIFindingSummaryResponse:
    finding_id: str
    package_name: str
    vulnerability_id: str
    priority: str
    risk_score: int
    summary: str
    explanation: str
    citations: List[Citation]
    claim_checks: List[ClaimCheck]
    provider_name: str = "unknown"
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class AIResponseValidationResult:
    valid: bool
    blocked: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    invalid_citation_ids: List[str] = field(default_factory=list)
    unsupported_claim_ids: List[str] = field(default_factory=list)
    mutated_fields: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


class AIProvider(Protocol):
    name: str

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        """Return a structured, evidence-cited finding summary."""


class MockAIProvider:
    """Deterministic provider for contract tests and offline development."""

    name = "mock-ai-provider"

    def __init__(
        self,
        unsupported_claims: Optional[List[str]] = None,
        failure_message: Optional[str] = None,
    ) -> None:
        self.unsupported_claims = unsupported_claims or []
        self.failure_message = failure_message

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        if self.failure_message is not None:
            raise AIProviderError(self.failure_message)

        citations: List[Citation] = []
        claim_checks: List[ClaimCheck] = []
        evidence_id = first_evidence_id(request)

        fact_claim_id = "claim-fact-1"
        fact_claim = "%s is associated with %s." % (
            request.package_name,
            request.vulnerability_id,
        )
        fact_evidence_ids = [evidence_id] if evidence_id is not None else []
        claim_checks.append(
            ClaimCheck(
                claim_id=fact_claim_id,
                claim=fact_claim,
                disposition="fact" if evidence_id is not None else "unknown",
                evidence_ids=fact_evidence_ids,
                rationale="Grounded in the supplied finding evidence.",
            )
        )
        if evidence_id is not None:
            citations.append(
                Citation(
                    evidence_id=evidence_id,
                    claim_id=fact_claim_id,
                    quote=first_evidence_quote(request),
                    note="Primary finding evidence.",
                )
            )

        inference_claim_id = "claim-inference-1"
        inference_evidence_ids = [evidence_id] if evidence_id is not None else []
        claim_checks.append(
            ClaimCheck(
                claim_id=inference_claim_id,
                claim="Remediation review should focus on the cited advisory and reachability evidence.",
                disposition="inference" if evidence_id is not None else "unknown",
                evidence_ids=inference_evidence_ids,
                rationale="This recommendation is inferred from the provided evidence set.",
            )
        )
        if evidence_id is not None:
            citations.append(
                Citation(
                    evidence_id=evidence_id,
                    claim_id=inference_claim_id,
                    note="Supports the remediation-review inference.",
                )
            )

        claim_checks.append(
            ClaimCheck(
                claim_id="claim-unknown-1",
                claim="Details beyond the supplied evidence are unknown.",
                disposition="unknown",
                evidence_ids=[],
                rationale="The provider is constrained to the request evidence.",
            )
        )

        for index, claim in enumerate(self.unsupported_claims, start=1):
            claim_checks.append(
                ClaimCheck(
                    claim_id="claim-unsupported-%s" % index,
                    claim=claim,
                    disposition="unsupported",
                    evidence_ids=[],
                    rationale="Mock provider was configured to simulate an unsupported claim.",
                )
            )

        return AIFindingSummaryResponse(
            finding_id=request.finding_id,
            package_name=request.package_name,
            vulnerability_id=request.vulnerability_id,
            priority=request.priority,
            risk_score=request.risk_score,
            summary=(
                "%s remains %s with risk score %s for %s."
                % (
                    request.vulnerability_id,
                    request.priority,
                    request.risk_score,
                    request.package_name,
                )
            ),
            explanation="The summary is based only on supplied evidence and preserves triage values.",
            citations=citations,
            claim_checks=claim_checks,
            provider_name=self.name,
        )


def validate_finding_summary_response(
    request: AIFindingSummaryRequest,
    response: AIFindingSummaryResponse,
) -> AIResponseValidationResult:
    errors: List[str] = []
    warnings: List[str] = []
    invalid_citation_ids: List[str] = []
    unsupported_claim_ids: List[str] = []
    mutated_fields: List[str] = []

    evidence_ids = {item.id for item in request.evidence}
    claim_checks, claim_check_errors = valid_claim_checks(response.claim_checks)
    citations, citation_errors = valid_citations(response.citations)
    errors.extend(claim_check_errors)
    errors.extend(citation_errors)
    claim_ids = {claim.claim_id for claim in claim_checks}
    allowed_dispositions = set(request.safety_constraints.required_claim_dispositions)

    if response.finding_id != request.finding_id:
        mutated_fields.append("finding_id")
        errors.append(
            "AI response changed finding id from %s to %s."
            % (request.finding_id, response.finding_id)
        )
    if response.package_name != request.package_name:
        mutated_fields.append("package_name")
        errors.append(
            "AI response changed package name from %s to %s."
            % (request.package_name, response.package_name)
        )
    if response.vulnerability_id != request.vulnerability_id:
        mutated_fields.append("vulnerability_id")
        errors.append(
            "AI response changed vulnerability id from %s to %s."
            % (request.vulnerability_id, response.vulnerability_id)
        )
    if response.priority != request.priority:
        mutated_fields.append("priority")
        errors.append(
            "AI response changed priority from %s to %s." % (request.priority, response.priority)
        )
    if response.risk_score != request.risk_score:
        mutated_fields.append("risk_score")
        errors.append(
            "AI response changed risk score from %s to %s."
            % (request.risk_score, response.risk_score)
        )

    for citation in citations:
        if citation.evidence_id not in evidence_ids:
            invalid_citation_ids.append(citation.evidence_id)
            errors.append("Citation references unknown evidence id %s." % citation.evidence_id)
        if citation.claim_id not in claim_ids:
            errors.append("Citation references unknown claim id %s." % citation.claim_id)

    for claim in claim_checks:
        if claim.disposition not in allowed_dispositions:
            errors.append(
                "Claim %s uses disallowed disposition %s."
                % (claim.claim_id, claim.disposition)
            )

        claim_evidence_ids = valid_claim_evidence_ids(claim, errors)
        if claim_evidence_ids is None:
            continue

        invalid_evidence = sorted(set(claim_evidence_ids) - evidence_ids)
        for evidence_id in invalid_evidence:
            invalid_citation_ids.append(evidence_id)
            errors.append(
                "Claim %s references unknown evidence id %s." % (claim.claim_id, evidence_id)
            )

        if claim.disposition == "unsupported":
            unsupported_claim_ids.append(claim.claim_id)
            errors.append("Claim %s is unsupported." % claim.claim_id)
            continue

        if claim.disposition in {"fact", "inference"} and len(claim_evidence_ids) == 0:
            unsupported_claim_ids.append(claim.claim_id)
            errors.append("Claim %s has no supporting evidence." % claim.claim_id)

    if not request.safety_constraints.allow_exploit_steps:
        unsafe_markers = unsafe_response_markers(response)
        for marker in unsafe_markers:
            errors.append("AI response contains unsafe marker %s." % marker)

    deduped_invalid_citation_ids = dedupe_keep_order(invalid_citation_ids)
    deduped_unsupported_claim_ids = dedupe_keep_order(unsupported_claim_ids)
    blocked = (
        len(errors) > 0
        or len(deduped_invalid_citation_ids) > 0
        or len(deduped_unsupported_claim_ids) > 0
        or len(mutated_fields) > 0
    )
    return AIResponseValidationResult(
        valid=not blocked,
        blocked=blocked,
        errors=dedupe_keep_order(errors),
        warnings=warnings,
        invalid_citation_ids=deduped_invalid_citation_ids,
        unsupported_claim_ids=deduped_unsupported_claim_ids,
        mutated_fields=mutated_fields,
    )


def valid_claim_checks(value: object) -> Tuple[List[ClaimCheck], List[str]]:
    if not isinstance(value, list | tuple):
        return [], ["AI response claim_checks must be a list."]

    claim_checks: List[ClaimCheck] = []
    errors: List[str] = []
    for index, claim in enumerate(value):
        if isinstance(claim, ClaimCheck):
            claim_checks.append(claim)
            continue
        errors.append("AI response claim_checks[%s] must be a ClaimCheck." % index)
    return claim_checks, errors


def valid_citations(value: object) -> Tuple[List[Citation], List[str]]:
    if not isinstance(value, list | tuple):
        return [], ["AI response citations must be a list."]

    citations: List[Citation] = []
    errors: List[str] = []
    for index, citation in enumerate(value):
        if isinstance(citation, Citation):
            citations.append(citation)
            continue
        errors.append("AI response citations[%s] must be a Citation." % index)
    return citations, errors


def valid_claim_evidence_ids(
    claim: ClaimCheck,
    errors: List[str],
) -> Optional[List[str]]:
    if not isinstance(claim.evidence_ids, list | tuple | set):
        errors.append("Claim %s evidence_ids must be a list." % claim.claim_id)
        return None

    evidence_ids: List[str] = []
    for index, evidence_id in enumerate(claim.evidence_ids):
        if isinstance(evidence_id, str):
            evidence_ids.append(evidence_id)
            continue
        errors.append("Claim %s evidence_ids[%s] must be a string." % (claim.claim_id, index))
    return evidence_ids


def first_evidence_id(request: AIFindingSummaryRequest) -> Optional[str]:
    if len(request.evidence) == 0:
        return None
    return request.evidence[0].id


def first_evidence_quote(request: AIFindingSummaryRequest) -> Optional[str]:
    if len(request.evidence) == 0:
        return None
    content = request.evidence[0].content.strip()
    if len(content) <= 160:
        return content
    return content[:157].rstrip() + "..."


def unsafe_response_markers(response: AIFindingSummaryResponse) -> List[str]:
    response_text = "\n".join(public_response_strings(response)).lower()
    markers = []
    for marker in UNSAFE_RESPONSE_MARKERS:
        if marker in response_text:
            markers.append(marker)
    return markers


def public_response_strings(value: object) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, bool | int | float) or value is None:
        return []
    if is_dataclass(value) and not isinstance(value, type):
        return public_response_strings(asdict(value))
    if isinstance(value, dict):
        text_parts: List[str] = []
        for child in value.values():
            text_parts.extend(public_response_strings(child))
        return text_parts
    if isinstance(value, list | tuple | set):
        text_parts = []
        for child in value:
            text_parts.extend(public_response_strings(child))
        return text_parts
    return []


def dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    deduped = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
