"""Deterministic guardrail audit for AI-generated security explanations."""

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
import re

from app.ai.contracts import UNSAFE_RESPONSE_MARKERS, unsafe_marker_found


CONCRETE_DISPOSITIONS = {"fact", "inference"}
UNKNOWN_DISPOSITIONS = {"unknown", "unsupported"}
CONSERVATIVE_UNKNOWN_PATTERNS = (
    re.compile(r"\bunknown\b", re.IGNORECASE),
    re.compile(r"\bneeds?[\s._-]+human[\s._-]+review\b", re.IGNORECASE),
    re.compile(r"\brequires?[\s._-]+human[\s._-]+review\b", re.IGNORECASE),
    re.compile(r"\bmanual[\s._-]+review\b", re.IGNORECASE),
    re.compile(r"\binsufficient[\s._-]+evidence\b", re.IGNORECASE),
    re.compile(r"\bnot[\s._-]+enough[\s._-]+evidence\b", re.IGNORECASE),
    re.compile(r"\b(?:can(?:not|'t)|unable[\s._-]+to)[\s._-]+determine\b", re.IGNORECASE),
)
FACTUAL_PROSE_PATTERNS = (
    re.compile(r"\b\d+\.\d+(?:\.\d+)?\b", re.IGNORECASE),
    re.compile(r"\b(?:CVE|GHSA|OSV)-[A-Za-z0-9-]+\b", re.IGNORECASE),
    re.compile(
        r"\b(?:is|are|was|were)[\s._-]+"
        r"(?:installed|present|used|reachable|affected|vulnerable|exploitable|fixed)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:has|have|uses|contains|includes|imports|depends)[\s._-]+", re.IGNORECASE),
    re.compile(r"\b(?:detected|found|appears)[\s._-]+in\b", re.IGNORECASE),
)
ACTION_PROSE_PATTERNS = (
    re.compile(r"\b(?:upgrade|install|update|patch|fix|remediate|deploy)\b", re.IGNORECASE),
    re.compile(r"\bsafe[\s._-]+to[\s._-]+ignore\b", re.IGNORECASE),
    re.compile(r"\bbefore[\s._-]+release\b", re.IGNORECASE),
    re.compile(r"\bblock[\s._-]+release\b", re.IGNORECASE),
    re.compile(r"\brelease[\s._-]+blocker\b", re.IGNORECASE),
)
OVERCONFIDENT_PATTERNS = (
    re.compile(r"\bguaranteed\b", re.IGNORECASE),
    re.compile(r"\bwill[\s._-]+fix\b", re.IGNORECASE),
    re.compile(r"\bdefinitely[\s._-]+fix(?:es)?\b", re.IGNORECASE),
    re.compile(r"\bsafe[\s._-]+to[\s._-]+ignore\b", re.IGNORECASE),
    re.compile(r"\bno[\s._-]+risk\b", re.IGNORECASE),
    re.compile(r"\bfully[\s._-]+remediates?\b", re.IGNORECASE),
    re.compile(
        r"\binstall\b.{0,80}\band\b.{0,40}\bfix(?:es)?[\s._-]+everything\b",
        re.IGNORECASE,
    ),
)


@dataclass(frozen=True)
class AuditFinding:
    severity: str
    code: str
    message: str
    path: str
    claim_id: str | None = None

    def to_dict(self) -> dict[str, str]:
        value = asdict(self)
        if self.claim_id is None:
            value.pop("claim_id")
        return value


def audit_ai_claims(ai_output: object) -> dict[str, object]:
    """Audit structured AI output for unsupported or unsafe claim language."""

    findings: list[AuditFinding] = []
    warnings: list[str] = []
    blocked_claim_ids: list[str] = []

    if not isinstance(ai_output, Mapping):
        findings.append(
            AuditFinding(
                severity="critical",
                code="invalid_ai_output",
                message="AI output must be a JSON object.",
                path="$",
            )
        )
        return build_result(findings, blocked_claim_ids, warnings)

    citations = citation_pairs(ai_output.get("citations"), findings)
    claims = extract_claims(ai_output, findings)
    if len(claims) == 0:
        warnings.append("AI output did not include auditable claims.")
        findings.extend(missing_auditable_claim_findings(ai_output))
    elif not has_supported_concrete_claim(claims):
        findings.extend(unaudited_factual_or_action_findings(ai_output))

    findings.extend(unsafe_wording_findings(ai_output))
    findings.extend(overconfident_language_findings(ai_output))

    for claim in claims:
        disposition = claim.disposition
        if disposition == "unsupported":
            blocked_claim_ids.append(claim.claim_id)
            findings.append(
                AuditFinding(
                    severity="critical",
                    code="unsupported_claim",
                    message="Claims marked unsupported must be blocked.",
                    path=claim.path,
                    claim_id=claim.claim_id,
                )
            )
            continue
        if disposition not in CONCRETE_DISPOSITIONS:
            continue

        if len(claim.evidence_ids) == 0:
            blocked_claim_ids.append(claim.claim_id)
            findings.append(
                AuditFinding(
                    severity="critical",
                    code="missing_claim_evidence",
                    message="Fact and inference claims must include evidence IDs.",
                    path=claim.path,
                    claim_id=claim.claim_id,
                )
            )
            continue

        missing_citations = [
            evidence_id
            for evidence_id in claim.evidence_ids
            if (claim.claim_id, evidence_id) not in citations
        ]
        if len(missing_citations) == 0:
            continue

        blocked_claim_ids.append(claim.claim_id)
        findings.append(
            AuditFinding(
                severity="critical",
                code="missing_matching_citation",
                message="Claim evidence IDs must have matching citation entries.",
                path=claim.path,
                claim_id=claim.claim_id,
            )
        )

    return build_result(findings, blocked_claim_ids, warnings)


@dataclass(frozen=True)
class AuditClaim:
    claim_id: str
    text: str
    disposition: str
    evidence_ids: list[str]
    path: str


def extract_claims(
    ai_output: Mapping[object, object],
    findings: list[AuditFinding],
) -> list[AuditClaim]:
    raw_claims = ai_output.get("claims")
    if raw_claims is None:
        raw_claims = ai_output.get("claim_checks")
        path = "claim_checks"
    else:
        path = "claims"

    if raw_claims is None:
        return []
    if not isinstance(raw_claims, list):
        findings.append(
            AuditFinding(
                severity="critical",
                code="invalid_claims",
                message="AI output claims must be a list.",
                path=path,
            )
        )
        return []

    claims: list[AuditClaim] = []
    for index, item in enumerate(raw_claims):
        item_path = "%s[%s]" % (path, index)
        if not isinstance(item, Mapping):
            findings.append(
                AuditFinding(
                    severity="critical",
                    code="invalid_claim",
                    message="Claim must be a JSON object.",
                    path=item_path,
                )
            )
            continue

        claim_id = optional_text(item.get("claim_id")) or "claim-%s" % (index + 1)
        disposition = claim_disposition(item)
        evidence_ids = string_list(item.get("evidence_ids"))
        claims.append(
            AuditClaim(
                claim_id=claim_id,
                text=optional_text(item.get("text")) or optional_text(item.get("claim")) or "",
                disposition=disposition,
                evidence_ids=evidence_ids,
                path=item_path,
            )
        )
    return claims


def claim_disposition(claim: Mapping[object, object]) -> str:
    raw = optional_text(claim.get("type")) or optional_text(claim.get("disposition"))
    if raw is None:
        return "fact"
    normalized = raw.strip().casefold()
    if normalized in CONCRETE_DISPOSITIONS | UNKNOWN_DISPOSITIONS:
        return normalized
    return "fact"


def citation_pairs(value: object, findings: list[AuditFinding]) -> set[tuple[str, str]]:
    if value is None:
        return set()
    if not isinstance(value, list):
        findings.append(
            AuditFinding(
                severity="critical",
                code="invalid_citations",
                message="AI output citations must be a list.",
                path="citations",
            )
        )
        return set()

    pairs: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            findings.append(
                AuditFinding(
                    severity="critical",
                    code="invalid_citation",
                    message="Citation must be a JSON object.",
                    path="citations[%s]" % index,
                )
            )
            continue

        claim_id = optional_text(item.get("claim_id"))
        evidence_id = optional_text(item.get("evidence_id"))
        if claim_id is None or evidence_id is None:
            findings.append(
                AuditFinding(
                    severity="critical",
                    code="invalid_citation",
                    message="Citation must include claim_id and evidence_id.",
                    path="citations[%s]" % index,
                )
            )
            continue
        pairs.add((claim_id, evidence_id))
    return pairs


def unsafe_wording_findings(ai_output: Mapping[object, object]) -> list[AuditFinding]:
    text = "\n".join(generated_strings(ai_output)).casefold()
    markers = [
        marker
        for marker in UNSAFE_RESPONSE_MARKERS
        if unsafe_marker_found(marker, text)
    ]
    if len(markers) == 0:
        return []
    return [
        AuditFinding(
            severity="critical",
            code="unsafe_offensive_wording",
            message="AI output contains unsafe offensive wording.",
            path="$",
        )
    ]


def missing_auditable_claim_findings(ai_output: Mapping[object, object]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for path, text in generated_claim_language_with_paths(ai_output):
        if is_conservative_unknown_prose(text):
            continue
        findings.append(
            AuditFinding(
                severity="critical",
                code="missing_auditable_claims",
                message="Generated prose with factual content must include auditable claims.",
                path=path,
            )
        )
    return findings


def has_supported_concrete_claim(claims: list[AuditClaim]) -> bool:
    for claim in claims:
        if claim.disposition not in CONCRETE_DISPOSITIONS:
            continue
        if len(claim.evidence_ids) == 0:
            continue
        return True
    return False


def unaudited_factual_or_action_findings(ai_output: Mapping[object, object]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for path, text in generated_claim_language_with_paths(ai_output):
        if is_conservative_unknown_prose(text):
            continue
        if not has_factual_or_action_signal(text):
            continue
        findings.append(
            AuditFinding(
                severity="critical",
                code="missing_auditable_claims",
                message="Generated prose with factual content must include auditable claims.",
                path=path,
            )
        )
    return findings


def has_factual_or_action_signal(value: str) -> bool:
    has_factual_signal = any(
        pattern.search(value) is not None for pattern in FACTUAL_PROSE_PATTERNS
    )
    has_action_signal = any(
        pattern.search(value) is not None for pattern in ACTION_PROSE_PATTERNS
    )
    return has_factual_signal or has_action_signal


def is_conservative_unknown_prose(value: str) -> bool:
    has_conservative_marker = any(
        pattern.search(value) is not None for pattern in CONSERVATIVE_UNKNOWN_PATTERNS
    )
    return has_conservative_marker and not has_factual_or_action_signal(value)


def overconfident_language_findings(ai_output: Mapping[object, object]) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    for path, text in generated_strings_with_paths(ai_output):
        if not has_overconfident_language(text):
            continue
        findings.append(
            AuditFinding(
                severity="critical",
                code="overconfident_fix_language",
                message="AI output overpromises remediation certainty or risk absence.",
                path=path,
            )
        )
    return findings


def has_overconfident_language(value: str) -> bool:
    return any(pattern.search(value) is not None for pattern in OVERCONFIDENT_PATTERNS)


def generated_strings(value: Mapping[object, object]) -> list[str]:
    return [text for _, text in generated_strings_with_paths(value)]


def generated_prose_with_paths(value: Mapping[object, object]) -> Iterable[tuple[str, str]]:
    for key in ("summary", "recommendation", "explanation"):
        yield from strings_from_value(value.get(key), key)


def generated_claim_language_with_paths(value: Mapping[object, object]) -> Iterable[tuple[str, str]]:
    yield from generated_prose_with_paths(value)

    raw_claims = value.get("claims")
    claims_path = "claims"
    if raw_claims is None:
        raw_claims = value.get("claim_checks")
        claims_path = "claim_checks"

    for index, claim in enumerate(list_value(raw_claims)):
        claim_mapping = mapping_value(claim)
        yield from strings_from_value(claim_mapping.get("text"), "%s[%s].text" % (claims_path, index))
        yield from strings_from_value(claim_mapping.get("claim"), "%s[%s].claim" % (claims_path, index))
        yield from strings_from_value(
            claim_mapping.get("rationale"),
            "%s[%s].rationale" % (claims_path, index),
        )


def generated_strings_with_paths(value: Mapping[object, object]) -> Iterable[tuple[str, str]]:
    yield from generated_prose_with_paths(value)
    yield from strings_from_value(value.get("errors"), "errors")

    for index, citation in enumerate(list_value(value.get("citations"))):
        citation_mapping = mapping_value(citation)
        yield from strings_from_value(citation_mapping.get("quote"), "citations[%s].quote" % index)
        yield from strings_from_value(citation_mapping.get("note"), "citations[%s].note" % index)

    raw_claims = value.get("claims")
    claims_path = "claims"
    if raw_claims is None:
        raw_claims = value.get("claim_checks")
        claims_path = "claim_checks"

    for index, claim in enumerate(list_value(raw_claims)):
        claim_mapping = mapping_value(claim)
        yield from strings_from_value(claim_mapping.get("text"), "%s[%s].text" % (claims_path, index))
        yield from strings_from_value(claim_mapping.get("claim"), "%s[%s].claim" % (claims_path, index))
        yield from strings_from_value(
            claim_mapping.get("rationale"),
            "%s[%s].rationale" % (claims_path, index),
        )


def strings_from_value(value: object, path: str) -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings_from_value(item, "%s[%s]" % (path, index))


def mapping_value(value: object) -> dict[object, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def list_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip() != ""]


def optional_text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text == "":
        return None
    return text


def build_result(
    findings: list[AuditFinding],
    blocked_claim_ids: list[str],
    warnings: list[str],
) -> dict[str, object]:
    deduped_findings = dedupe_findings(findings)
    passed = len(deduped_findings) == 0
    return {
        "passed": passed,
        "score": audit_score(deduped_findings),
        "findings": [finding.to_dict() for finding in deduped_findings],
        "blocked_claims": [
            {"claim_id": claim_id} for claim_id in dedupe_keep_order(blocked_claim_ids)
        ],
        "warnings": dedupe_keep_order(warnings),
    }


def audit_score(findings: list[AuditFinding]) -> int:
    score = 100
    for finding in findings:
        if finding.severity == "critical":
            score -= 40
        elif finding.severity == "high":
            score -= 25
        else:
            score -= 10
    return max(score, 0)


def dedupe_findings(findings: list[AuditFinding]) -> list[AuditFinding]:
    seen: set[tuple[str, str, str | None]] = set()
    deduped: list[AuditFinding] = []
    for finding in findings:
        key = (finding.code, finding.path, finding.claim_id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
