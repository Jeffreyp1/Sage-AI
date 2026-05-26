"""Quality gate for public scan reports.

The validator operates on the public report dictionary produced by the scanner
or on the same payload serialized as JSON by the CLI below.
"""

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys
from typing import Optional

from app.services.public_safety import UNSAFE_PUBLIC_PATTERN


FORBIDDEN_PUBLIC_KEYS = {"raw", "details"}
HUMAN_REVIEW_PRIORITY = "NEEDS_HUMAN_REVIEW"
UNSUPPORTED_CLAIM_MARKERS = (
    "remote exploitable",
    "confirmed exploitable",
    "actively exploited",
)
TaskList = list[tuple[int, Mapping[object, object]]]


@dataclass(frozen=True)
class ValidationFinding:
    severity: str
    code: str
    message: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def validate_report(report: object) -> dict[str, object]:
    """Validate a public scan report dictionary."""
    findings: list[ValidationFinding] = []

    if not isinstance(report, Mapping):
        findings.append(
            ValidationFinding(
                severity="critical",
                code="invalid_report",
                message="Report must be a JSON object",
                path="$",
            )
        )
        return build_result(findings)

    findings.extend(forbidden_key_findings(report))
    findings.extend(unsafe_public_text_findings(report))
    findings.extend(unsupported_claim_findings(report))

    tasks_value = report.get("remediation_tasks")
    tasks, task_findings = remediation_tasks(tasks_value)
    findings.extend(task_findings)
    findings.extend(duplicate_task_findings(tasks))

    for index, task in tasks:
        findings.extend(task_quality_findings(task, index))

    return build_result(findings)


def build_result(findings: list[ValidationFinding]) -> dict[str, object]:
    passed = len(findings) == 0
    return {
        "passed": passed,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
        "summary": "%s public report validation with %s finding(s)"
        % ("PASS" if passed else "FAIL", len(findings)),
    }


def remediation_tasks(value: object) -> tuple[TaskList, list[ValidationFinding]]:
    if not isinstance(value, list):
        return [], [
            ValidationFinding(
                severity="critical",
                code="invalid_remediation_tasks",
                message="Report must include remediation_tasks as a list",
                path="remediation_tasks",
            )
        ]

    tasks: list[tuple[int, Mapping[object, object]]] = []
    findings: list[ValidationFinding] = []
    for index, item in enumerate(value):
        if isinstance(item, Mapping):
            tasks.append((index, item))
            continue
        findings.append(
            ValidationFinding(
                severity="critical",
                code="invalid_remediation_task",
                message="Remediation task must be a JSON object",
                path="remediation_tasks[%s]" % index,
            )
        )
    return tasks, findings


def duplicate_task_findings(tasks: TaskList) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    seen: dict[tuple[str, str, str], int] = {}

    for index, task in tasks:
        package_name = string_at(task, "package.name")
        current_version = string_at(task, "package.current_version")
        canonical_id = string_at(task, "vulnerability.canonical_id")
        if package_name is None or current_version is None or canonical_id is None:
            continue

        key = (package_name, current_version, canonical_id)
        first_index = seen.get(key)
        if first_index is None:
            seen[key] = index
            continue

        findings.append(
            ValidationFinding(
                severity="critical",
                code="duplicate_task",
                message=(
                    "Duplicate remediation task for %s@%s %s; first occurrence is "
                    "remediation_tasks[%s]"
                )
                % (package_name, current_version, canonical_id, first_index),
                path="remediation_tasks[%s]" % index,
            )
        )

    return findings


def task_quality_findings(task: Mapping[object, object], index: int) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    path = "remediation_tasks[%s]" % index

    priority = string_at(task, "risk.priority")
    if priority is None or priority.strip() == "":
        findings.append(
            ValidationFinding(
                severity="critical",
                code="missing_priority",
                message="Remediation task is missing risk.priority",
                path="%s.risk.priority" % path,
            )
        )

    if not has_meaningful_evidence(task.get("evidence")):
        findings.append(
            ValidationFinding(
                severity="critical",
                code="missing_evidence",
                message="Remediation task must include evidence",
                path="%s.evidence" % path,
            )
        )

    current_version = string_at(task, "package.current_version")
    target_version = string_at(task, "patch_plan.target_version")
    if is_downgrade(current_version, target_version):
        findings.append(
            ValidationFinding(
                severity="critical",
                code="downgrade_patch_target",
                message="Patch target %s is older than current version %s"
                % (target_version, current_version),
                path="%s.patch_plan.target_version" % path,
            )
        )

    if priority is not None and priority != HUMAN_REVIEW_PRIORITY and not has_fix_or_target(task):
        findings.append(
            ValidationFinding(
                severity="critical",
                code="missing_fix_or_target_version",
                message=(
                    "Non-review remediation task must include vulnerability.fixed_versions or "
                    "patch_plan.target_version"
                ),
                path=path,
            )
        )

    return findings


def has_meaningful_evidence(value: object) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        if isinstance(item, str) and item.strip() != "":
            return True
        if not isinstance(item, Mapping):
            continue
        for field_name in ("source", "claim", "type"):
            field_value = item.get(field_name)
            if isinstance(field_value, str) and field_value.strip() != "":
                return True
    return False


def has_fix_or_target(task: Mapping[object, object]) -> bool:
    target_version = string_at(task, "patch_plan.target_version")
    if target_version is not None and target_version.strip() != "":
        return True

    fixed_versions = value_at(task, "vulnerability.fixed_versions")
    if not isinstance(fixed_versions, list):
        return False
    for version in fixed_versions:
        if isinstance(version, str) and version.strip() != "":
            return True
    return False


def forbidden_key_findings(report: Mapping[object, object]) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    for path, key in forbidden_key_paths(report, FORBIDDEN_PUBLIC_KEYS):
        findings.append(
            ValidationFinding(
                severity="critical",
                code="forbidden_public_key",
                message="Public report contains forbidden key %s" % key,
                path=path,
            )
        )
    return findings


def forbidden_key_paths(
    value: object,
    forbidden_keys: set[str],
    path: str = "",
) -> Iterable[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = "%s.%s" % (path, key_text) if path else key_text
            if key_text.lower() in forbidden_keys:
                yield child_path, key_text
            yield from forbidden_key_paths(child, forbidden_keys, child_path)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            child_path = "%s[%s]" % (path, index)
            yield from forbidden_key_paths(child, forbidden_keys, child_path)


def unsafe_public_text_findings(report: Mapping[object, object]) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    for path, value in walk_strings_with_paths(report):
        match = UNSAFE_PUBLIC_PATTERN.search(value)
        if match is None:
            continue
        findings.append(
            ValidationFinding(
                severity="critical",
                code="unsafe_public_text",
                message="Public report contains unsafe text marker %s" % match.group(0),
                path=path,
            )
        )
    return findings


def unsupported_claim_findings(report: Mapping[object, object]) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    markers = [marker.lower() for marker in UNSUPPORTED_CLAIM_MARKERS]
    for path, value in walk_strings_with_paths(report):
        lowered = value.lower()
        for marker in markers:
            if marker not in lowered:
                continue
            findings.append(
                ValidationFinding(
                    severity="high",
                    code="unsupported_claim_marker",
                    message="Public report contains unsupported claim marker %s" % marker,
                    path=path,
                )
            )
    return findings


def walk_strings_with_paths(value: object, path: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = "%s.%s" % (path, key_text) if path else key_text
            yield from walk_strings_with_paths(child, child_path)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            child_path = "%s[%s]" % (path, index)
            yield from walk_strings_with_paths(child, child_path)


def is_downgrade(current_version: Optional[str], target_version: Optional[str]) -> bool:
    if current_version is None or target_version is None:
        return False
    current_key = version_key(current_version)
    target_key = version_key(target_version)
    if current_key is None or target_key is None:
        return False
    return target_key < current_key


def version_key(version: str) -> Optional[tuple[int, ...]]:
    clean = version.strip().lstrip("v")
    if clean == "":
        return None
    clean = clean.split("-", 1)[0]
    clean = clean.split("+", 1)[0]
    parts = clean.split(".")
    numbers: list[int] = []
    for part in parts:
        if part == "":
            return None
        if not part.isdigit():
            return None
        numbers.append(int(part))
    if len(numbers) == 0:
        return None
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)


def value_at(data: Mapping[object, object], path: str) -> object:
    current: object = data
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current


def string_at(data: Mapping[object, object], path: str) -> Optional[str]:
    value = value_at(data, path)
    if not isinstance(value, str):
        return None
    return value


def validate_json_file(path: Path) -> dict[str, object]:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        return build_result(
            [
                ValidationFinding(
                    severity="critical",
                    code="read_error",
                    message=str(exc),
                    path=str(path),
                )
            ]
        )
    except json.JSONDecodeError as exc:
        return build_result(
            [
                ValidationFinding(
                    severity="critical",
                    code="invalid_json",
                    message=str(exc),
                    path=str(path),
                )
            ]
        )
    return validate_report(report)


def main(argv: Optional[list[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        result = build_result(
            [
                ValidationFinding(
                    severity="critical",
                    code="usage_error",
                    message="Usage: python3 -m app.eval.report_validator path.json",
                    path="$",
                )
            ]
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 2

    result = validate_json_file(Path(args[0]))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
