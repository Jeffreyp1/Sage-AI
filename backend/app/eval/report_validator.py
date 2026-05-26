"""Quality gate for public scan reports.

The validator operates on the public report dictionary produced by the scanner
or on the same payload serialized as JSON by the CLI below.
"""

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys
from typing import Optional

from app.services.public_safety import UNSAFE_PUBLIC_PATTERN


FORBIDDEN_PUBLIC_KEYS = {"raw", "details"}
HUMAN_REVIEW_PRIORITY = "NEEDS_HUMAN_REVIEW"
UNSUPPORTED_CLAIM_MARKERS = (
    "remote exploitable",
    "remotely exploitable",
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


@dataclass(frozen=True)
class ParsedVersion:
    release: tuple[int, ...]
    prerelease: Optional[tuple[str, ...]]


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

        key = duplicate_task_key(package_name, current_version, canonical_id)
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

    if priority is not None and priority != HUMAN_REVIEW_PRIORITY:
        findings.extend(non_review_patch_target_findings(target_version, path))

    return findings


def has_meaningful_evidence(value: object) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        if isinstance(item, str) and item.strip() != "":
            return True
        if not isinstance(item, Mapping):
            continue
        for field_name in ("source", "claim"):
            field_value = item.get(field_name)
            if isinstance(field_value, str) and field_value.strip() != "":
                return True
    return False


def non_review_patch_target_findings(
    target_version: Optional[str], task_path: str
) -> list[ValidationFinding]:
    target_path = "%s.patch_plan.target_version" % task_path
    if target_version is None or target_version.strip() == "":
        return [
            ValidationFinding(
                severity="critical",
                code="missing_fix_or_target_version",
                message="Non-review remediation task must include patch_plan.target_version",
                path=target_path,
            )
        ]

    if parse_version(target_version) is None:
        return [
            ValidationFinding(
                severity="critical",
                code="invalid_patch_target_version",
                message="Patch target %s is not a valid semantic version" % target_version,
                path=target_path,
            )
        ]

    return []


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
    marker_patterns = [
        (marker, unsupported_claim_pattern(marker)) for marker in UNSUPPORTED_CLAIM_MARKERS
    ]
    for path, value in walk_strings_with_paths(report):
        for marker, pattern in marker_patterns:
            for match in pattern.finditer(value):
                if is_negated_claim(value, match.start()):
                    continue
                findings.append(
                    ValidationFinding(
                        severity="high",
                        code="unsupported_claim_marker",
                        message="Public report contains unsupported claim marker %s" % marker,
                        path=path,
                    )
                )
                break
    return findings


def unsupported_claim_pattern(marker: str) -> re.Pattern[str]:
    parts = [re.escape(part) for part in marker.split()]
    phrase = r"[\s._-]+".join(parts)
    return re.compile(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % phrase, re.IGNORECASE)


def is_negated_claim(value: str, marker_start: int) -> bool:
    prefix = value[:marker_start]
    words = re.findall(r"[A-Za-z]+", prefix.lower())
    if len(words) == 0:
        return False

    if len(words) >= 2 and words[-2:] == ["not", "only"]:
        return False
    return words[-1] in {"not", "never", "no", "without"}


def duplicate_task_key(
    package_name: str, current_version: str, canonical_id: str
) -> tuple[str, str, str]:
    return (
        package_name.strip().casefold(),
        current_version.strip(),
        canonical_id.strip().casefold(),
    )


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
    current = parse_version(current_version)
    target = parse_version(target_version)
    if current is None or target is None:
        return False
    return compare_versions(target, current) < 0


def parse_version(version: str) -> Optional[ParsedVersion]:
    clean = version.strip().lstrip("v")
    if clean == "":
        return None
    clean = clean.split("+", 1)[0]
    release_text, prerelease_text = split_prerelease(clean)
    parts = release_text.split(".")
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
    prerelease = parse_prerelease(prerelease_text)
    if prerelease_text is not None and prerelease is None:
        return None
    return ParsedVersion(release=tuple(numbers), prerelease=prerelease)


def split_prerelease(version: str) -> tuple[str, Optional[str]]:
    if "-" not in version:
        return version, None
    release_text, prerelease_text = version.split("-", 1)
    return release_text, prerelease_text


def parse_prerelease(value: Optional[str]) -> Optional[tuple[str, ...]]:
    if value is None:
        return None
    identifiers = tuple(value.split("."))
    if len(identifiers) == 0:
        return None
    for identifier in identifiers:
        if identifier == "":
            return None
        if re.fullmatch(r"[0-9A-Za-z-]+", identifier) is None:
            return None
    return identifiers


def compare_versions(left: ParsedVersion, right: ParsedVersion) -> int:
    if left.release < right.release:
        return -1
    if left.release > right.release:
        return 1
    return compare_prerelease(left.prerelease, right.prerelease)


def compare_prerelease(
    left: Optional[tuple[str, ...]], right: Optional[tuple[str, ...]]
) -> int:
    if left is None and right is None:
        return 0
    if left is None:
        return 1
    if right is None:
        return -1

    for left_part, right_part in zip(left, right):
        part_result = compare_prerelease_part(left_part, right_part)
        if part_result != 0:
            return part_result
    if len(left) < len(right):
        return -1
    if len(left) > len(right):
        return 1
    return 0


def compare_prerelease_part(left: str, right: str) -> int:
    left_is_number = left.isdigit()
    right_is_number = right.isdigit()
    if left_is_number and right_is_number:
        left_number = int(left)
        right_number = int(right)
        if left_number < right_number:
            return -1
        if left_number > right_number:
            return 1
        return 0
    if left_is_number:
        return -1
    if right_is_number:
        return 1
    if left < right:
        return -1
    if left > right:
        return 1
    return 0


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
