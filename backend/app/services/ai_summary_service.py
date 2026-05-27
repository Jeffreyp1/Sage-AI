"""Safe AI summary orchestration for remediation findings."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from hashlib import blake2b

from app.ai.contracts import (
    AIFindingSummaryRequest,
    AIFindingSummaryResponse,
    AIProvider,
    AIResponseValidationResult,
    EvidenceItem,
    MockAIProvider,
    validate_finding_summary_response,
)
from app.services.public_safety import sanitize_text
from app.services.rag_retrieval import InMemoryEvidenceIndex
from app.services.rag_types import EvidenceChunk, EvidenceSearchResult
from app.services.trace_service import TraceService


MAX_EVIDENCE_CONTENT_LENGTH = 1200


@dataclass(frozen=True)
class AIFindingSummaryResult:
    request: AIFindingSummaryRequest
    response: AIFindingSummaryResponse | None
    validation: AIResponseValidationResult
    retrieved_chunk_ids: list[str]
    blocked: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "request": self.request.to_dict(),
            "response": (
                self.response.to_dict() if self.response is not None else None
            ),
            "validation": public_validation_dict(self.validation),
            "retrieved_chunk_ids": list(self.retrieved_chunk_ids),
            "blocked": self.blocked,
        }


class AISummaryService:
    """Build, call, and validate safe AI summaries without changing triage data."""

    def __init__(
        self,
        provider: AIProvider | None = None,
        trace_service: TraceService | None = None,
    ) -> None:
        self.provider = provider or MockAIProvider()
        self.trace_service = trace_service

    def summarize_remediation_task(
        self,
        task: Mapping[str, object],
        chunks: Iterable[EvidenceChunk],
        top_k: int = 5,
    ) -> AIFindingSummaryResult:
        retrieved_results = retrieve_for_remediation_task(task, chunks, top_k=top_k)
        retrieved_chunks = [result.chunk for result in retrieved_results]
        request = build_finding_summary_request(task, retrieved_chunks)
        response: AIFindingSummaryResponse | None = None

        try:
            candidate = self.provider.summarize_finding(request)
            if not isinstance(candidate, AIFindingSummaryResponse):
                raise TypeError(
                    "AI provider returned malformed finding summary response."
                )
            response = candidate
            validation = validate_finding_summary_response(request, response)
            if validation.blocked:
                response = None
            else:
                response = safe_public_response(request, response)
        except Exception as exc:
            response = None
            validation = provider_failure_validation(exc)

        result = AIFindingSummaryResult(
            request=request,
            response=response,
            validation=validation,
            retrieved_chunk_ids=[chunk.chunk_id for chunk in retrieved_chunks],
            blocked=validation.blocked,
        )
        self._trace_result(result, retrieved_results)
        return result

    def _trace_result(
        self,
        result: AIFindingSummaryResult,
        retrieved_results: list[EvidenceSearchResult],
    ) -> None:
        if self.trace_service is None:
            return

        validation_status = "blocked" if result.validation.blocked else "passed"
        self.trace_service.record_event(
            agent_name="ai-summary-service",
            event_type="ai.finding_summary",
            input_json=result.request.to_dict(),
            retrieved_context_json=[
                search_result.to_dict() for search_result in retrieved_results
            ],
            output_json={
                "response": (
                    result.response.to_dict()
                    if result.response is not None
                    else None
                ),
                "validation": public_validation_dict(result.validation),
            },
            model=provider_name(self.provider),
            validation_status=validation_status,
        )


def retrieve_for_remediation_task(
    task: Mapping[str, object],
    chunks: Iterable[EvidenceChunk],
    top_k: int = 5,
) -> list[EvidenceSearchResult]:
    chunk_list = list(chunks)
    if top_k <= 0 or len(chunk_list) == 0:
        return []

    query = remediation_task_query(task)
    index = InMemoryEvidenceIndex()
    index.add_chunks(chunk_list)

    filters = applicable_metadata_filters(task, chunk_list)
    attempts = filter_attempts(filters)
    results: list[EvidenceSearchResult] = []
    seen_chunk_ids: set[str] = set()
    for filters_for_attempt in attempts:
        for result in index.search(query, top_k=top_k, filters=filters_for_attempt):
            if result.chunk.chunk_id in seen_chunk_ids:
                continue
            seen_chunk_ids.add(result.chunk.chunk_id)
            results.append(result)
            if len(results) >= top_k:
                return results
    return results


def build_finding_summary_request(
    task: Mapping[str, object],
    retrieved_chunks: Iterable[EvidenceChunk],
) -> AIFindingSummaryRequest:
    package = mapping_value(task.get("package"))
    vulnerability = mapping_value(task.get("vulnerability"))
    risk = mapping_value(task.get("risk"))

    return AIFindingSummaryRequest(
        finding_id=string_value(task.get("task_id")) or stable_finding_id(task),
        package_name=required_string(package.get("name"), "package.name"),
        vulnerability_id=(
            required_string(
                vulnerability.get("canonical_id") or vulnerability.get("source_id"),
                "vulnerability.canonical_id",
            )
        ),
        priority=required_string(risk.get("priority"), "risk.priority"),
        risk_score=integer_value(risk.get("risk_score")),
        severity=string_value(vulnerability.get("severity")) or "UNKNOWN",
        evidence=evidence_items_for_task(task, retrieved_chunks),
    )


def evidence_items_for_task(
    task: Mapping[str, object],
    retrieved_chunks: Iterable[EvidenceChunk],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    used_ids: set[str] = set()

    evidence = list_value(task.get("evidence"))
    for index, value in enumerate(evidence):
        evidence_mapping = mapping_value(value)
        claim = string_value(evidence_mapping.get("claim"))
        if claim is None:
            continue
        base_id = stable_evidence_id(
            "task",
            [
                str(index),
                string_value(evidence_mapping.get("type")) or "evidence",
                string_value(evidence_mapping.get("source")) or "task",
                claim,
            ],
        )
        evidence_id = unique_id(base_id, used_ids)
        used_ids.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                kind=string_value(evidence_mapping.get("type")) or "finding_evidence",
                source=string_value(evidence_mapping.get("source")) or "remediation_task",
                content=truncate_content(claim),
                metadata={
                    "origin": "remediation_task",
                    "evidence_index": str(index),
                },
            )
        )

    for chunk in retrieved_chunks:
        base_id = stable_evidence_id("chunk", [chunk.chunk_id])
        evidence_id = unique_id(base_id, used_ids)
        used_ids.add(evidence_id)
        items.append(
            EvidenceItem(
                id=evidence_id,
                kind=chunk.source_type,
                source=chunk_source(chunk),
                content=truncate_content(chunk.content),
                metadata=chunk_metadata(chunk),
            )
        )

    return items


def remediation_task_query(task: Mapping[str, object]) -> str:
    package = mapping_value(task.get("package"))
    vulnerability = mapping_value(task.get("vulnerability"))
    risk = mapping_value(task.get("risk"))
    parts = [
        string_value(package.get("name")),
        string_value(package.get("ecosystem")),
        string_value(vulnerability.get("canonical_id")),
        string_value(vulnerability.get("source_id")),
        string_value(vulnerability.get("summary")),
        string_value(risk.get("priority")),
        string_value(risk.get("reachability")),
        string_value(risk.get("runtime_scope")),
        string_value(risk.get("confidence")),
    ]
    for evidence in list_value(task.get("evidence")):
        evidence_mapping = mapping_value(evidence)
        parts.append(string_value(evidence_mapping.get("claim")))
    return " ".join(part for part in parts if part is not None and part.strip() != "")


def applicable_metadata_filters(
    task: Mapping[str, object],
    chunks: list[EvidenceChunk],
) -> dict[str, object]:
    filters: dict[str, object] = {}
    package = mapping_value(task.get("package"))
    package_name = string_value(package.get("name"))
    repo_id = string_value(task.get("repo_id")) or string_value(task.get("repo"))

    if repo_id is not None and chunk_metadata_has_value(chunks, "repo_id", repo_id):
        filters["repo_id"] = repo_id
    if package_name is not None and chunk_metadata_has_value(chunks, "package", package_name):
        filters["package"] = package_name
    return filters


def filter_attempts(filters: Mapping[str, object]) -> list[dict[str, object] | None]:
    attempts: list[dict[str, object] | None] = []
    if len(filters) > 0:
        attempts.append(dict(filters))
    if "package" in filters and len(filters) > 1:
        attempts.append({"package": filters["package"]})
    if "repo_id" in filters and len(filters) > 1:
        attempts.append({"repo_id": filters["repo_id"]})
    attempts.append(None)
    return attempts


def provider_failure_validation(exc: Exception) -> AIResponseValidationResult:
    return AIResponseValidationResult(
        valid=False,
        blocked=True,
        errors=["AI provider failed."],
        warnings=[sanitize_text(str(exc)) or exc.__class__.__name__],
    )


def public_validation_dict(validation: AIResponseValidationResult) -> dict[str, object]:
    if not validation.blocked:
        return validation.to_dict()

    return {
        "valid": False,
        "blocked": True,
        "errors": public_validation_errors(validation),
        "warnings": [],
        "invalid_citation_ids": [],
        "unsupported_claim_ids": [],
        "mutated_fields": list(validation.mutated_fields),
    }


def public_validation_errors(validation: AIResponseValidationResult) -> list[str]:
    if any(error.startswith("AI provider failed") for error in validation.errors):
        return ["AI provider failed."]

    errors: list[str] = []
    if len(validation.mutated_fields) > 0:
        errors.append("AI response changed protected triage fields.")
    if len(validation.invalid_citation_ids) > 0:
        errors.append("AI response referenced unknown evidence.")
    if len(validation.unsupported_claim_ids) > 0:
        errors.append("AI response contained unsupported claims.")
    if has_unsafe_error(validation):
        errors.append("AI response contained unsafe text.")

    if len(errors) == 0 and len(validation.errors) > 0:
        errors.append("AI response failed validation.")
    return errors


def has_unsafe_error(validation: AIResponseValidationResult) -> bool:
    for error in validation.errors:
        if "unsafe marker" in error:
            return True
    return False


def safe_public_response(
    request: AIFindingSummaryRequest,
    response: AIFindingSummaryResponse,
) -> AIFindingSummaryResponse:
    return replace(
        response,
        finding_id=request.finding_id,
        package_name=request.package_name,
        vulnerability_id=request.vulnerability_id,
        priority=request.priority,
        risk_score=request.risk_score,
        summary=safe_public_summary(request),
        explanation=safe_public_explanation(response),
    )


def safe_public_summary(request: AIFindingSummaryRequest) -> str:
    return "%s remains %s with risk score %s for %s." % (
        request.vulnerability_id,
        request.priority,
        request.risk_score,
        request.package_name,
    )


def safe_public_explanation(response: AIFindingSummaryResponse) -> str:
    cited_claim_ids = {citation.claim_id for citation in response.citations}
    cited_claim_count = 0
    for claim in response.claim_checks:
        if claim.claim_id not in cited_claim_ids:
            continue
        if claim.disposition not in {"fact", "inference"}:
            continue
        if len(claim.evidence_ids) == 0:
            continue
        cited_claim_count += 1

    claim_count_text = "%s validated cited claims" % cited_claim_count
    if cited_claim_count == 1:
        claim_count_text = "1 validated cited claim"
    return (
        "The public explanation is based on %s from supplied evidence "
        "and preserves triage values."
    ) % claim_count_text


def chunk_metadata_has_value(
    chunks: list[EvidenceChunk],
    key: str,
    expected: object,
) -> bool:
    for chunk in chunks:
        if chunk.metadata.get(key) == expected:
            return True
    return False


def chunk_source(chunk: EvidenceChunk) -> str:
    for key in ("source", "path", "file_path", "url", "advisory_url"):
        value = string_value(chunk.metadata.get(key))
        if value is not None:
            return value
    return chunk.source_type


def chunk_metadata(chunk: EvidenceChunk) -> dict[str, str]:
    metadata: dict[str, str] = {
        "origin": "retrieved_context",
        "chunk_id": chunk.chunk_id,
        "source_type": chunk.source_type,
    }
    for key, value in sorted(chunk.metadata.items()):
        if value is None:
            continue
        if isinstance(value, str | int | float | bool):
            metadata[str(key)] = str(value)
            continue
        metadata[str(key)] = repr(value)
    return metadata


def stable_finding_id(task: Mapping[str, object]) -> str:
    package = mapping_value(task.get("package"))
    vulnerability = mapping_value(task.get("vulnerability"))
    return stable_evidence_id(
        "finding",
        [
            string_value(task.get("repo")) or "",
            string_value(package.get("name")) or "",
            string_value(vulnerability.get("canonical_id"))
            or string_value(vulnerability.get("source_id"))
            or "",
        ],
    )


def stable_evidence_id(prefix: str, values: list[str]) -> str:
    digest = blake2b("\n".join(values).encode("utf-8"), digest_size=6).hexdigest()
    return "ev-%s-%s" % (prefix, digest)


def unique_id(base_id: str, used_ids: set[str]) -> str:
    if base_id not in used_ids:
        return base_id
    suffix = 2
    while "%s-%s" % (base_id, suffix) in used_ids:
        suffix += 1
    return "%s-%s" % (base_id, suffix)


def truncate_content(value: str) -> str:
    stripped = value.strip()
    if len(stripped) <= MAX_EVIDENCE_CONTENT_LENGTH:
        return stripped
    return stripped[: MAX_EVIDENCE_CONTENT_LENGTH - 3].rstrip() + "..."


def mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def list_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def string_value(value: object) -> str | None:
    if isinstance(value, str):
        return value
    return None


def required_string(value: object, field_name: str) -> str:
    text = string_value(value)
    if text is None or text.strip() == "":
        raise ValueError("%s is required" % field_name)
    return text


def integer_value(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("risk.risk_score must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value)
    raise ValueError("risk.risk_score must be an integer")


def provider_name(provider: AIProvider) -> str:
    name = getattr(provider, "name", None)
    if isinstance(name, str) and name.strip() != "":
        return name
    return provider.__class__.__name__
