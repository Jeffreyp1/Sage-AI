"""Client-AI context bundles and output validation."""

from collections.abc import Iterable, Mapping

from app.ai.contracts import (
    AIFindingSummaryResponse,
    Citation,
    ClaimCheck,
    validate_finding_summary_response,
)
from app.services.ai_summary_service import build_finding_summary_request
from app.services.public_safety import sanitize_public_text, sanitize_public_value
from app.services.rag_types import EvidenceChunk


AI_CONTEXT_BUNDLE_SCHEMA_VERSION = "vulnsage.ai_context_bundle.v1"


class AIOutputParseError(ValueError):
    """Raised when a client AI response does not match the expected shape."""


def build_ai_context_bundle(
    task: Mapping[str, object],
    retrieved_chunks: Iterable[EvidenceChunk] = (),
) -> dict[str, object]:
    """Build a focused, safe case file for a client-provided AI assistant."""

    safe_task = mapping_value(sanitize_public_value(dict(task)))
    request = build_finding_summary_request(safe_task, retrieved_chunks)
    request_dict = request.to_dict()
    return {
        "schema_version": AI_CONTEXT_BUNDLE_SCHEMA_VERSION,
        "finding_id": request.finding_id,
        "finding": compact_finding(task),
        "ai_request": request_dict,
        "citation_rules": citation_rules(),
        "prompt": prompt_text(request_dict),
        "expected_output_schema": expected_output_schema(),
        "safety_constraints": request_dict["safety_constraints"],
    }


def validate_client_ai_output(
    task: Mapping[str, object],
    ai_output: Mapping[str, object],
    retrieved_chunks: Iterable[EvidenceChunk] = (),
) -> dict[str, object]:
    safe_task = mapping_value(sanitize_public_value(dict(task)))
    request = build_finding_summary_request(safe_task, retrieved_chunks)

    try:
        response = parse_ai_output(ai_output)
    except AIOutputParseError as error:
        message = sanitize_public_text(str(error))
        return {
            "passed": False,
            "blocked": True,
            "summary": "FAIL AI output validation: %s" % message,
            "validation": {
                "valid": False,
                "blocked": True,
                "errors": [message],
                "warnings": [],
                "invalid_citation_ids": [],
                "unsupported_claim_ids": [],
                "mutated_fields": [],
            },
        }

    validation = validate_finding_summary_response(request, response)
    validation_dict = public_validation_dict(validation.to_dict())
    return {
        "passed": validation.valid and not validation.blocked,
        "blocked": validation.blocked,
        "summary": validation_summary(validation_dict),
        "validation": validation_dict,
    }


def compact_finding(task: Mapping[str, object]) -> dict[str, object]:
    package = mapping_value(task.get("package"))
    vulnerability = mapping_value(task.get("vulnerability"))
    risk = mapping_value(task.get("risk"))
    patch_plan = mapping_value(task.get("patch_plan"))
    return mapping_value(
        sanitize_public_value(
            {
                "task_id": task.get("task_id"),
                "package_name": package.get("name"),
                "vulnerability_id": vulnerability.get("canonical_id")
                or vulnerability.get("source_id"),
                "severity": vulnerability.get("severity"),
                "priority": risk.get("priority"),
                "risk_score": risk.get("risk_score"),
                "target_version": patch_plan.get("target_version"),
            }
        )
    )


def citation_rules() -> list[str]:
    return [
        "Use only the evidence in this bundle.",
        "Every fact or inference claim must cite matching evidence IDs.",
        "Use unknown when the bundle does not prove a claim.",
        "Do not change priority, risk score, package, vulnerability, or finding IDs.",
        "Do not include exploit steps, payloads, or offensive instructions.",
    ]


def prompt_text(ai_request: Mapping[str, object]) -> str:
    return "\n".join(
        [
            "You are a defensive AppSec assistant reviewing one dependency finding.",
            "Use only the evidence in this bundle.",
            "Return JSON matching expected_output_schema exactly.",
            "Every fact or inference claim must include claim_checks.evidence_ids and a matching citation.",
            "Say unknown when evidence is missing.",
            "Finding: %s for %s, priority %s, risk score %s."
            % (
                sanitize_public_text(str(ai_request.get("vulnerability_id", "unknown"))),
                sanitize_public_text(str(ai_request.get("package_name", "unknown"))),
                sanitize_public_text(str(ai_request.get("priority", "unknown"))),
                sanitize_public_text(str(ai_request.get("risk_score", "unknown"))),
            ),
        ]
    )


def expected_output_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "finding_id",
            "package_name",
            "vulnerability_id",
            "priority",
            "risk_score",
            "summary",
            "explanation",
            "citations",
            "claim_checks",
            "provider_name",
        ],
        "properties": {
            "finding_id": {"type": "string"},
            "package_name": {"type": "string"},
            "vulnerability_id": {"type": "string"},
            "priority": {"type": "string"},
            "risk_score": {"type": "integer"},
            "summary": {"type": "string"},
            "explanation": {"type": "string"},
            "citations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["claim_id", "evidence_id"],
                },
            },
            "claim_checks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["claim_id", "claim", "disposition", "evidence_ids"],
                },
            },
            "provider_name": {"type": "string"},
            "errors": {"type": "array", "items": {"type": "string"}},
        },
    }


def parse_ai_output(value: Mapping[str, object]) -> AIFindingSummaryResponse:
    return AIFindingSummaryResponse(
        finding_id=required_string(value, "finding_id"),
        package_name=required_string(value, "package_name"),
        vulnerability_id=required_string(value, "vulnerability_id"),
        priority=required_string(value, "priority"),
        risk_score=required_int(value, "risk_score"),
        summary=required_string(value, "summary"),
        explanation=required_string(value, "explanation"),
        citations=parse_citations(value.get("citations")),
        claim_checks=parse_claim_checks(value.get("claim_checks")),
        provider_name=required_string(value, "provider_name"),
        errors=optional_string_list(value.get("errors"), "errors"),
    )


def parse_citations(value: object) -> list[Citation]:
    if not isinstance(value, list):
        raise AIOutputParseError("AI output citations must be a list.")

    citations: list[Citation] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise AIOutputParseError("AI output citations[%s] must be an object." % index)
        citations.append(
            Citation(
                evidence_id=required_string(item, "evidence_id"),
                claim_id=required_string(item, "claim_id"),
                quote=optional_string(item.get("quote"), "quote"),
                note=optional_string(item.get("note"), "note"),
            )
        )
    return citations


def parse_claim_checks(value: object) -> list[ClaimCheck]:
    if not isinstance(value, list):
        raise AIOutputParseError("AI output claim_checks must be a list.")

    claims: list[ClaimCheck] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise AIOutputParseError("AI output claim_checks[%s] must be an object." % index)
        claims.append(
            ClaimCheck(
                claim_id=required_string(item, "claim_id"),
                claim=required_string(item, "claim"),
                disposition=required_string(item, "disposition"),
                evidence_ids=required_string_list(item.get("evidence_ids"), "evidence_ids"),
                rationale=optional_string(item.get("rationale"), "rationale") or "",
            )
        )
    return claims


def public_validation_dict(value: Mapping[str, object]) -> dict[str, object]:
    return mapping_value(sanitize_public_value(dict(value)))


def validation_summary(validation: Mapping[str, object]) -> str:
    if validation.get("blocked") is not True:
        return "PASS AI output validation with 0 finding(s)"

    errors = validation.get("errors")
    if isinstance(errors, list) and len(errors) > 0:
        first_error = errors[0]
        if isinstance(first_error, str):
            return "FAIL AI output validation: %s" % first_error
    return "FAIL AI output validation"


def required_string(value: Mapping[str, object], key: str) -> str:
    raw = value.get(key)
    if not isinstance(raw, str) or raw.strip() == "":
        raise AIOutputParseError("AI output %s must be a non-empty string." % key)
    return sanitize_public_text(raw).strip()


def required_int(value: Mapping[str, object], key: str) -> int:
    raw = value.get(key)
    if not isinstance(raw, int) or isinstance(raw, bool):
        raise AIOutputParseError("AI output %s must be an integer." % key)
    return raw


def required_string_list(value: object, key: str) -> list[str]:
    if not isinstance(value, list):
        raise AIOutputParseError("AI output %s must be a list." % key)

    output: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or item.strip() == "":
            raise AIOutputParseError("AI output %s[%s] must be a string." % (key, index))
        output.append(sanitize_public_text(item).strip())
    return output


def optional_string_list(value: object, key: str) -> list[str]:
    if value is None:
        return []
    return required_string_list(value, key)


def optional_string(value: object, key: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise AIOutputParseError("AI output %s must be a string." % key)
    return sanitize_public_text(value).strip()


def mapping_value(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}
