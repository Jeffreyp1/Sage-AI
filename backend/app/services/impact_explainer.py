"""Standalone library service for future MCP/report impact explanation wiring."""

import re
from collections.abc import Mapping, Sequence

from app.services.public_safety import contains_public_leak_text, sanitize_public_value


ImpactExplanation = dict[str, list[str]]

CONFIDENTIALITY_KEYWORDS = (
    "credential",
    "credentials",
    "cross-site scripting",
    "cwe-79",
    "data exposure",
    "deserialization",
    "disclosure",
    "exfiltration",
    "information leak",
    "leak",
    "secret",
    "xss",
)
INTEGRITY_KEYWORDS = (
    "bypass",
    "command injection",
    "cross-site scripting",
    "cwe-79",
    "deserialization",
    "html",
    "injection",
    "prototype pollution",
    "remote code execution",
    "rce",
    "tamper",
    "xss",
)
AVAILABILITY_KEYWORDS = (
    "availability",
    "crash",
    "denial of service",
    "denial-of-service",
    "dos",
    "infinite loop",
    "resource exhaustion",
)

UNKNOWN_VALUES = {"", "unknown", "not_evaluated", "not evaluated", "none", "null"}
UNSAFE_DETAIL_PATTERN = re.compile(
    r"(<\s*/?\s*script\b|https?://\S+|\b(?:curl|wget|bash|sh|python|node)\b\s+(?:-|https?://|\S))",
    re.IGNORECASE,
)
KNOWN_EXPLOITED_PATTERN = re.compile(
    r"\b(?:known[-\s]+exploited|actively[-\s]+exploited)\b",
    re.IGNORECASE,
)
NEGATED_KNOWN_EXPLOITED_PATTERN = re.compile(
    r"\b(?:no|not|never|without)\b[^.?!;]{0,80}\b(?:known[-\s]+exploited|actively[-\s]+exploited)\b"
    r"|\b(?:known[-\s]+exploited|actively[-\s]+exploited)\b[^.?!;]{0,80}\b(?:not|unknown|unconfirmed|not confirmed|false|absent)\b",
    re.IGNORECASE,
)


def explain_possible_impact(task: object) -> dict[str, list[str]]:
    """Return conservative impact context for a remediation task-like dict."""

    task_context = mapping_value(task)
    package = mapping_value(task_context.get("package"))
    vulnerability = mapping_value(task_context.get("vulnerability"))
    risk = mapping_value(task_context.get("risk"))
    evidence = sequence_value(task_context.get("evidence"))
    context_notes = invalid_context_notes(task_context)

    if has_invalid_core_context(context_notes):
        categories = ["unknown"]
    else:
        categories = classify_impact_categories(package, vulnerability, risk)
    result = {
        "impact_categories": categories,
        "confirmed_facts": confirmed_facts(task_context, package, vulnerability, risk, evidence),
        "possible_impacts": possible_impacts(categories, package, vulnerability, risk, evidence),
        "unknowns": unknowns(vulnerability, risk, evidence, context_notes),
        "human_review_notes": human_review_notes(vulnerability, risk, evidence, context_notes),
    }
    return sanitize_result(result)


def classify_impact_categories(
    package: Mapping[str, object],
    vulnerability: Mapping[str, object],
    risk: Mapping[str, object],
) -> list[str]:
    text = searchable_text(package, vulnerability)
    categories = []
    if contains_keyword(text, CONFIDENTIALITY_KEYWORDS):
        categories.append("confidentiality")
    if contains_keyword(text, INTEGRITY_KEYWORDS):
        categories.append("integrity")
    if contains_keyword(text, AVAILABILITY_KEYWORDS):
        categories.append("availability")
    if is_supply_chain_context(package):
        categories.append("supply_chain")
    if is_operational_context(risk, categories):
        categories.append("operational")
    if len(categories) == 0:
        categories.append("operational")
    return categories


def confirmed_facts(
    task: Mapping[str, object],
    package: Mapping[str, object],
    vulnerability: Mapping[str, object],
    risk: Mapping[str, object],
    evidence: Sequence[object],
) -> list[str]:
    facts = []
    package_name = text_value(package.get("name"))
    ecosystem = text_value(package.get("ecosystem"))
    current_version = text_value(package.get("current_version"))
    dependency_type = text_value(package.get("dependency_type"))
    direct_text = direct_dependency_text(package.get("is_direct"))
    if package_name is not None:
        facts.append(
            package_fact(package_name, current_version, direct_text, ecosystem, dependency_type)
        )

    canonical_id = text_value(vulnerability.get("canonical_id"))
    if canonical_id is not None:
        facts.append("Vulnerability identifier is %s." % canonical_id)

    severity = text_value(vulnerability.get("severity"))
    if severity is not None and not is_unknown(severity):
        facts.append("Severity is %s." % severity.upper())

    summary = text_value(vulnerability.get("summary"))
    if summary is not None:
        facts.append(
            safe_fact_sentence(
                summary,
                "Vulnerability summary contained unsafe technical detail and was redacted.",
                "Vulnerability summary says: %s" % summary,
            )
        )

    fixed_versions = list_text_values(vulnerability.get("fixed_versions"))
    if len(fixed_versions) > 0:
        facts.append("A fixed version is listed: %s." % ", ".join(fixed_versions))

    runtime_scope = text_value(risk.get("runtime_scope"))
    if runtime_scope is not None and not is_unknown(runtime_scope):
        facts.append("Runtime scope is %s." % runtime_scope)

    reachability = text_value(risk.get("reachability"))
    if reachability is not None and not is_unknown(reachability):
        facts.append("Reachability is %s." % reachability)

    priority = text_value(risk.get("priority")) or text_value(task.get("priority"))
    if priority is not None and not is_unknown(priority):
        facts.append("Priority is %s." % priority)

    risk_score = risk.get("risk_score", task.get("risk_score"))
    if isinstance(risk_score, int | float):
        facts.append("Risk score is %s." % int(risk_score))

    if known_exploited_confirmed(risk, evidence):
        facts.append("Known exploited status is confirmed by provided report evidence.")

    evidence_facts = evidence_claim_facts(evidence)
    facts.extend(evidence_facts)
    return dedupe(facts)


def package_fact(
    name: str,
    version: str | None,
    direct_text: str | None,
    ecosystem: str | None,
    dependency_type: str | None,
) -> str:
    parts = [name]
    if version is not None:
        parts.append(version)
    suffix_parts = []
    if direct_text is not None:
        suffix_parts.append(direct_text)
    if ecosystem is not None:
        suffix_parts.append(ecosystem)
    if dependency_type is not None:
        suffix_parts.append(dependency_label(dependency_type))
    if len(suffix_parts) == 0:
        return "Package %s is present." % " ".join(parts)
    return "Package %s is present as a %s." % (" ".join(parts), " ".join(suffix_parts))


def dependency_label(value: str) -> str:
    if value == "dependencies":
        return "dependency"
    return value


def possible_impacts(
    categories: Sequence[str],
    package: Mapping[str, object],
    vulnerability: Mapping[str, object],
    risk: Mapping[str, object],
    evidence: Sequence[object],
) -> list[str]:
    package_name = text_value(package.get("name")) or "the affected package"
    severity = text_value(vulnerability.get("severity"))
    runtime_scope = text_value(risk.get("runtime_scope"))
    impacts = []
    if "confidentiality" in categories:
        impacts.append(
            "%s may affect data confidentiality if the vulnerable behavior is reachable."
            % package_name
        )
    if "integrity" in categories:
        impacts.append(
            "%s could affect data integrity or trust boundaries depending on how it is used."
            % package_name
        )
    if "availability" in categories:
        impacts.append(
            "%s may affect service availability if affected code paths process untrusted or high-volume input."
            % package_name
        )
    if "supply_chain" in categories:
        impacts.append(
            "Dependency context can increase supply-chain review risk, especially when ownership or runtime use is unclear."
        )
    if "operational" in categories:
        impacts.append(
            "Operational risk may increase when severity, runtime scope, or reachability needs human validation."
        )
    if known_text(severity) in {"CRITICAL", "HIGH"} and known_text(runtime_scope) == "PRODUCTION":
        impacts.append(
            "High-severity production findings could increase release or incident-review urgency."
        )
    if known_exploited_confirmed(risk, evidence):
        impacts.append(
            "Confirmed known exploited status can increase urgency, but local runtime exposure still needs review."
        )
    return dedupe(impacts)


def unknowns(
    vulnerability: Mapping[str, object],
    risk: Mapping[str, object],
    evidence: Sequence[object],
    context_notes: Sequence[str],
) -> list[str]:
    values = list(context_notes)
    severity = text_value(vulnerability.get("severity"))
    if severity is None or is_unknown(severity):
        values.append("Severity is unknown.")
    runtime_scope = text_value(risk.get("runtime_scope"))
    if runtime_scope is None or is_unknown(runtime_scope):
        values.append("Runtime scope is unknown.")
    reachability = text_value(risk.get("reachability"))
    if reachability is None or is_unknown(reachability):
        values.append("Runtime reachability is unknown.")
    if not known_exploited_confirmed(risk, evidence):
        values.append("Known exploited status is not confirmed by the provided evidence.")
    fixed_versions = list_text_values(vulnerability.get("fixed_versions"))
    if len(fixed_versions) == 0:
        values.append("Fixed version availability is unknown.")
    values.append("Exploitability is unknown without validated report evidence.")
    return dedupe(values)


def human_review_notes(
    vulnerability: Mapping[str, object],
    risk: Mapping[str, object],
    evidence: Sequence[object],
    context_notes: Sequence[str],
) -> list[str]:
    notes = [
        "Verify whether the package is used in the relevant runtime path.",
        "Review fixed versions, changelog, and tests before changing dependency versions.",
        "Check whether compensating controls or deployment context reduce practical risk.",
    ]
    if has_invalid_core_context(context_notes):
        notes.append("Human review is required because input context is missing or malformed.")
    if known_exploited_confirmed(risk, evidence):
        notes.append("Confirm the known-exploited source and whether the deployed service is exposed.")
    elif risk.get("known_exploited") is True:
        notes.append("Review the reported known-exploited flag against a cited advisory or evidence item.")
    if len(list_text_values(vulnerability.get("fixed_versions"))) == 0:
        notes.append("Review upstream advisories for fixed-version status and mitigation notes.")
    return notes


def evidence_claim_facts(evidence: Sequence[object]) -> list[str]:
    facts = []
    for item in evidence:
        evidence_item = mapping_value(item)
        claim = text_value(evidence_item.get("claim"))
        source = text_value(evidence_item.get("source"))
        if claim is None:
            continue
        if contains_unsafe_detail(claim):
            if source is None:
                facts.append("Report evidence contained unsafe technical detail and was redacted.")
            else:
                facts.append(
                    "Report evidence from %s contained unsafe technical detail and was redacted."
                    % source
                )
            continue
        if source is None:
            facts.append("Report evidence states: %s" % claim)
        else:
            facts.append("Report evidence from %s states: %s" % (source, claim))
    return facts


def known_exploited_confirmed(
    risk: Mapping[str, object],
    evidence: Sequence[object],
) -> bool:
    if risk_known_exploited_has_validated_source(risk):
        return True
    for item in evidence:
        evidence_item = mapping_value(item)
        claim = text_value(evidence_item.get("claim"))
        if claim is not None and mentions_known_exploited(claim):
            return True
    return False


def risk_known_exploited_has_validated_source(risk: Mapping[str, object]) -> bool:
    if risk.get("known_exploited") is not True:
        return False
    source_fields = (
        "known_exploited_source",
        "known_exploited_evidence",
        "known_exploited_reference",
    )
    return any(text_value(risk.get(field)) is not None for field in source_fields)


def mentions_known_exploited(value: str) -> bool:
    for sentence in re.split(r"(?<=[.?!;])\s+", value):
        if KNOWN_EXPLOITED_PATTERN.search(sentence) is None:
            continue
        if NEGATED_KNOWN_EXPLOITED_PATTERN.search(sentence) is not None:
            continue
        return True
    return False


def is_supply_chain_context(package: Mapping[str, object]) -> bool:
    if len(package) == 0:
        return False
    dependency_type = text_value(package.get("dependency_type"))
    is_direct = package.get("is_direct")
    if is_direct is False:
        return True
    if dependency_type is None:
        return True
    return dependency_type in {"devDependency", "transitive", "peerDependency"}


def is_operational_context(risk: Mapping[str, object], categories: Sequence[str]) -> bool:
    priority = text_value(risk.get("priority"))
    runtime_scope = text_value(risk.get("runtime_scope"))
    reachability = text_value(risk.get("reachability"))
    if "availability" in categories:
        return True
    if priority in {"P0_RELEASE_BLOCKER", "P1_FIX_THIS_SPRINT", "NEEDS_HUMAN_REVIEW"}:
        return True
    if runtime_scope in {"production", "runtime", "unknown"}:
        return True
    return reachability in {"reachable", "possibly_reachable", "likely_reachable", "unknown"}


def searchable_text(
    package: Mapping[str, object],
    vulnerability: Mapping[str, object],
) -> str:
    values = []
    for key in ("name", "ecosystem", "dependency_type"):
        value = text_value(package.get(key))
        if value is not None:
            values.append(value)
    for key in ("canonical_id", "source_id", "severity", "summary"):
        value = text_value(vulnerability.get(key))
        if value is not None:
            values.append(value)
    references = sequence_value(vulnerability.get("references"))
    for item in references:
        reference = mapping_value(item)
        for key in ("type", "url"):
            value = text_value(reference.get(key))
            if value is not None:
                values.append(value)
    return " ".join(values).lower()


def contains_keyword(text: str, keywords: Sequence[str]) -> bool:
    return any(keyword in text for keyword in keywords)


def invalid_context_notes(task: Mapping[str, object]) -> list[str]:
    notes = []
    invalid_core = False
    if not isinstance(task.get("package"), Mapping) or len(mapping_value(task.get("package"))) == 0:
        invalid_core = True
        notes.append("Package context is missing or invalid.")
    if not isinstance(task.get("vulnerability"), Mapping) or len(
        mapping_value(task.get("vulnerability"))
    ) == 0:
        invalid_core = True
        notes.append("Vulnerability context is missing or invalid.")
    if "risk" in task and not isinstance(task.get("risk"), Mapping):
        notes.append("Risk context is malformed.")
    if "evidence" in task and not isinstance(task.get("evidence"), list | tuple):
        notes.append("Evidence context is malformed.")
    if invalid_core:
        return ["Input context is missing or malformed.", *notes]
    return notes


def has_invalid_core_context(context_notes: Sequence[str]) -> bool:
    return "Input context is missing or malformed." in context_notes


def safe_fact_sentence(value: str, unsafe_message: str, safe_message: str) -> str:
    if contains_unsafe_detail(value):
        return unsafe_message
    return safe_message


def contains_unsafe_detail(value: str) -> bool:
    return contains_public_leak_text(value) or UNSAFE_DETAIL_PATTERN.search(value) is not None


def sanitize_result(result: dict[str, list[str]]) -> dict[str, list[str]]:
    sanitized = sanitize_public_value(result)
    if not isinstance(sanitized, dict):
        return result
    clean_result: dict[str, list[str]] = {}
    for key, value in sanitized.items():
        if not isinstance(key, str):
            continue
        clean_result[key] = [str(item) for item in sequence_value(value)]
    return clean_result


def mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def sequence_value(value: object) -> Sequence[object]:
    if isinstance(value, list | tuple):
        return value
    return []


def text_value(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return None
        return stripped
    if isinstance(value, int | float | bool):
        return str(value)
    return None


def list_text_values(value: object) -> list[str]:
    if isinstance(value, str):
        text = text_value(value)
        return [] if text is None else [text]
    if not isinstance(value, list | tuple):
        return []
    values = []
    for item in value:
        text = text_value(item)
        if text is not None:
            values.append(text)
    return values


def direct_dependency_text(value: object) -> str | None:
    if value is True:
        return "direct"
    if value is False:
        return "transitive"
    return None


def is_unknown(value: str) -> bool:
    return value.strip().lower() in UNKNOWN_VALUES


def known_text(value: str | None) -> str | None:
    if value is None or is_unknown(value):
        return None
    return value.upper()


def dedupe(values: Sequence[str]) -> list[str]:
    result = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
