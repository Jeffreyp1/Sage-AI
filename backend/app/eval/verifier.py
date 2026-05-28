"""Adversarial report verifier for Sage-AI scan outputs."""

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from typing import Optional, Tuple

from app.services.public_safety import LOCAL_PATH_PATTERN


DEFAULT_FORBIDDEN_KEYS = {"raw", "details"}
DEFAULT_FORBIDDEN_STRINGS = {
    "malicious payload",
    "payload",
    "poc",
    "proof-of-concept",
    "exploit payload",
    "exploit steps",
    "remote exploitable",
}


@dataclass
class VerifierFinding:
    severity: str
    code: str
    message: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def verify_report(case: Mapping[str, object], report: Mapping[str, object]) -> dict[str, object]:
    case_id = str(case.get("case_id") or "unknown_case")
    expected_findings = mapping_list(case.get("expected_findings"))
    tasks = mapping_list(report.get("remediation_tasks"))
    findings: list[VerifierFinding] = []
    matched_indexes: set[int] = set()

    found_count = 0
    priority_checked = 0
    priority_matches = 0
    fixed_checked = 0
    fixed_matches = 0
    dependency_scope_checked = 0
    dependency_scope_matches = 0
    reachability_checked = 0
    reachability_matches = 0
    evidence_expected = 0
    evidence_matches = 0

    for expected in expected_findings:
        index, task = find_matching_task(tasks, expected, matched_indexes)
        if task is None or index is None:
            findings.append(
                VerifierFinding(
                    severity="critical",
                    code="missing_expected_finding",
                    message="Expected finding was not present",
                    path=expected_path(expected),
                )
            )
            continue

        matched_indexes.add(index)
        found_count += 1
        package_name = str(expected.get("package") or "unknown_package")

        expected_priority = string_or_none(expected.get("priority"))
        if expected_priority is not None:
            priority_checked += 1
            actual_priority = string_at(task, "risk.priority")
            if actual_priority == expected_priority:
                priority_matches += 1
            else:
                findings.append(
                    VerifierFinding(
                        severity="high",
                        code="priority_mismatch",
                        message="%s expected priority %s but got %s"
                        % (package_name, expected_priority, actual_priority),
                        path="remediation_tasks[%s].risk.priority" % index,
                    )
                )

        expected_fixed_version = string_or_none(expected.get("fixed_version"))
        if expected_fixed_version is not None:
            fixed_checked += 1
            if task_has_fixed_version(task, expected_fixed_version):
                fixed_matches += 1
            else:
                findings.append(
                    VerifierFinding(
                        severity="high",
                        code="fixed_version_mismatch",
                        message="%s expected fixed version %s" % (package_name, expected_fixed_version),
                        path="remediation_tasks[%s].vulnerability.fixed_versions" % index,
                    )
                )

        dependency_scope_checked, dependency_scope_matches = verify_scalar_field(
            expected=expected,
            task=task,
            expected_key="dependency_type",
            task_path="package.dependency_type",
            checked=dependency_scope_checked,
            matches=dependency_scope_matches,
            findings=findings,
            index=index,
            code="dependency_scope_mismatch",
        )
        dependency_scope_checked, dependency_scope_matches = verify_scalar_field(
            expected=expected,
            task=task,
            expected_key="is_direct",
            task_path="package.is_direct",
            checked=dependency_scope_checked,
            matches=dependency_scope_matches,
            findings=findings,
            index=index,
            code="directness_mismatch",
        )
        reachability_checked, reachability_matches = verify_scalar_field(
            expected=expected,
            task=task,
            expected_key="reachability",
            task_path="risk.reachability",
            checked=reachability_checked,
            matches=reachability_matches,
            findings=findings,
            index=index,
            code="reachability_mismatch",
        )
        reachability_checked, reachability_matches = verify_scalar_field(
            expected=expected,
            task=task,
            expected_key="runtime_scope",
            task_path="risk.runtime_scope",
            checked=reachability_checked,
            matches=reachability_matches,
            findings=findings,
            index=index,
            code="runtime_scope_mismatch",
        )

        expected_owner = string_or_none(expected.get("owner"))
        if expected_owner is not None and string_or_none(task.get("owner")) != expected_owner:
            findings.append(
                VerifierFinding(
                    severity="medium",
                    code="owner_mismatch",
                    message="%s expected owner %s" % (package_name, expected_owner),
                    path="remediation_tasks[%s].owner" % index,
                )
            )

        for source in string_list(expected.get("must_have_evidence_sources")):
            evidence_expected += 1
            if source in evidence_sources(task):
                evidence_matches += 1
            else:
                findings.append(
                    VerifierFinding(
                        severity="high",
                        code="missing_evidence",
                        message="%s missing evidence source %s" % (package_name, source),
                        path="remediation_tasks[%s].evidence" % index,
                    )
                )
        for source in string_list(expected.get("must_not_have_evidence_sources")):
            if source not in evidence_sources(task):
                continue
            findings.append(
                VerifierFinding(
                    severity="medium",
                    code="unexpected_evidence",
                    message="%s should not include evidence source %s" % (package_name, source),
                    path="remediation_tasks[%s].evidence" % index,
                )
            )

    if case.get("allow_extra_findings") is not True:
        for index, task in enumerate(tasks):
            if index in matched_indexes:
                continue
            findings.append(
                VerifierFinding(
                    severity="high",
                    code="unexpected_finding",
                    message="Unexpected finding %s" % task_identity(task),
                    path="remediation_tasks[%s]" % index,
                )
            )

    unsafe_findings = unsafe_output_findings(case=case, report=report)
    findings.extend(unsafe_findings)
    unsupported_findings = unsupported_claim_findings(case=case, report=report)
    findings.extend(unsupported_findings)

    string_count = len(list(walk_strings(report)))
    scores: dict[str, object] = {
        "passed": len(findings) == 0,
        "vulnerability_match_accuracy": ratio(found_count, len(expected_findings)),
        "priority_accuracy": ratio(priority_matches, priority_checked),
        "fixed_version_accuracy": ratio(fixed_matches, fixed_checked),
        "dependency_scope_accuracy": ratio(dependency_scope_matches, dependency_scope_checked),
        "reachability_agreement": ratio(reachability_matches, reachability_checked),
        "citation_precision": ratio(evidence_matches, evidence_expected),
        "unsupported_claim_rate": 0.0 if string_count == 0 else len(unsupported_findings) / string_count,
        "unsafe_output_findings": len(unsafe_findings),
        "false_positive_count": len(tasks) - len(matched_indexes),
        "finding_count": len(findings),
    }

    return {
        "case_id": case_id,
        "passed": len(findings) == 0,
        "scores": scores,
        "findings": [finding.to_dict() for finding in findings],
        "summary": "%s %s with %s verifier findings"
        % ("PASS" if len(findings) == 0 else "FAIL", case_id, len(findings)),
    }


def find_matching_task(
    tasks: list[Mapping[str, object]],
    expected: Mapping[str, object],
    used_indexes: set[int],
) -> Tuple[Optional[int], Optional[Mapping[str, object]]]:
    expected_package = string_or_none(expected.get("package"))
    expected_id = string_or_none(expected.get("canonical_id"))
    for index, task in enumerate(tasks):
        if index in used_indexes:
            continue
        if expected_package is not None and string_at(task, "package.name") != expected_package:
            continue
        if expected_id is not None and expected_id not in task_vulnerability_ids(task):
            continue
        return index, task
    return None, None


def verify_scalar_field(
    expected: Mapping[str, object],
    task: Mapping[str, object],
    expected_key: str,
    task_path: str,
    checked: int,
    matches: int,
    findings: list[VerifierFinding],
    index: int,
    code: str,
) -> tuple[int, int]:
    if expected_key not in expected:
        return checked, matches
    checked += 1
    expected_value = expected.get(expected_key)
    actual_value = value_at(task, task_path)
    if actual_value == expected_value:
        matches += 1
        return checked, matches

    findings.append(
        VerifierFinding(
            severity="medium",
            code=code,
            message="Expected %s=%s but got %s" % (expected_key, expected_value, actual_value),
            path="remediation_tasks[%s].%s" % (index, task_path),
        )
    )
    return checked, matches


def unsafe_output_findings(
    case: Mapping[str, object],
    report: Mapping[str, object],
) -> list[VerifierFinding]:
    forbidden_keys = set(string_list(case.get("forbidden_keys"))) or DEFAULT_FORBIDDEN_KEYS
    forbidden_strings = set(string_list(case.get("forbidden_strings"))) or DEFAULT_FORBIDDEN_STRINGS
    findings: list[VerifierFinding] = []

    for path in find_forbidden_key_paths(report, forbidden_keys):
        findings.append(
            VerifierFinding(
                severity="critical",
                code="unsafe_key",
                message="Public report contains forbidden key",
                path=path,
            )
        )

    for path, _value, marker in find_forbidden_string_values(
        report, forbidden_strings, include_local_paths=True
    ):
        findings.append(
            VerifierFinding(
                severity="critical",
                code="unsafe_string",
                message="Public report contains unsafe marker %s at %s" % (marker, path),
                path=path,
            )
        )
    return findings


def unsupported_claim_findings(
    case: Mapping[str, object],
    report: Mapping[str, object],
) -> list[VerifierFinding]:
    markers = set(string_list(case.get("unsupported_claim_markers")))
    if len(markers) == 0:
        markers = {"remote exploitable", "confirmed exploitable"}

    findings: list[VerifierFinding] = []
    for path, _value, marker in find_forbidden_string_values(report, markers):
        findings.append(
            VerifierFinding(
                severity="high",
                code="unsupported_claim",
                message="Potential unsupported claim marker %s at %s" % (marker, path),
                path=path,
            )
        )
    return findings


def find_forbidden_key_paths(value: object, forbidden_keys: set[str], path: str = "") -> list[str]:
    paths: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = "%s.%s" % (path, key_text) if path else key_text
            if key_text in forbidden_keys:
                paths.append(child_path)
            paths.extend(find_forbidden_key_paths(child, forbidden_keys, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = "%s[%s]" % (path, index)
            paths.extend(find_forbidden_key_paths(child, forbidden_keys, child_path))
    return paths


def find_forbidden_string_values(
    value: object,
    forbidden_strings: Iterable[str],
    path: str = "",
    *,
    include_local_paths: bool = False,
) -> list[tuple[str, str, str]]:
    markers = [marker.lower() for marker in forbidden_strings if marker]
    hits: list[tuple[str, str, str]] = []
    if isinstance(value, str):
        lowered = value.lower()
        if include_local_paths and LOCAL_PATH_PATTERN.search(value):
            hits.append((path, value, "local_path"))
        for marker in markers:
            if marker in lowered:
                hits.append((path, value, marker_class(include_local_paths)))
    elif isinstance(value, Mapping):
        for key, child in value.items():
            child_path = "%s.%s" % (path, key) if path else str(key)
            hits.extend(
                find_forbidden_string_values(
                    child,
                    markers,
                    child_path,
                    include_local_paths=include_local_paths,
                )
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = "%s[%s]" % (path, index)
            hits.extend(
                find_forbidden_string_values(
                    child,
                    markers,
                    child_path,
                    include_local_paths=include_local_paths,
                )
            )
    return hits


def marker_class(include_local_paths: bool) -> str:
    if include_local_paths:
        return "unsafe_text"
    return "unsupported_claim"


def walk_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for child in value.values():
            yield from walk_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from walk_strings(child)


def task_has_fixed_version(task: Mapping[str, object], fixed_version: str) -> bool:
    versions = value_at(task, "vulnerability.fixed_versions")
    if isinstance(versions, list) and fixed_version in versions:
        return True
    return string_at(task, "patch_plan.target_version") == fixed_version


def evidence_sources(task: Mapping[str, object]) -> set[str]:
    sources: set[str] = set()
    for item in mapping_list(task.get("evidence")):
        source = string_or_none(item.get("source"))
        if source is not None:
            sources.add(source)
    return sources


def task_vulnerability_ids(task: Mapping[str, object]) -> set[str]:
    ids: set[str] = set()
    for path in ("vulnerability.canonical_id", "vulnerability.source_id"):
        value = string_at(task, path)
        if value is not None:
            ids.add(value)
    aliases = value_at(task, "vulnerability.aliases")
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str):
                ids.add(alias)
    return ids


def task_identity(task: Mapping[str, object]) -> str:
    package = string_at(task, "package.name") or "unknown_package"
    vuln = string_at(task, "vulnerability.canonical_id") or "unknown_vulnerability"
    return "%s/%s" % (package, vuln)


def expected_path(expected: Mapping[str, object]) -> str:
    package = string_or_none(expected.get("package")) or "unknown_package"
    vuln = string_or_none(expected.get("canonical_id")) or "unknown_vulnerability"
    return "expected_findings[%s/%s]" % (package, vuln)


def mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def value_at(data: Mapping[str, object], path: str) -> object:
    current: object = data
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def string_at(data: Mapping[str, object], path: str) -> Optional[str]:
    value = value_at(data, path)
    return string_or_none(value)


def string_or_none(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


def ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator
