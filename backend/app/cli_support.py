"""Shared helpers for Sage AI CLI commands."""

import json
from collections.abc import Mapping
from pathlib import Path

from pydantic import ValidationError

from app.schemas.report import RemediationTaskSchema, ScanReport
from app.services.public_safety import (
    safe_display_name,
    sanitize_public_identifier,
    sanitize_public_text,
)
from app.services.trace_service import redact_secret_text


class CliError(RuntimeError):
    pass


def read_json_value(path: Path) -> object:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as error:
        raise CliError("report file not found: %s" % display_path(path)) from error
    except UnicodeDecodeError as error:
        raise CliError(
            "report file is not valid JSON: %s: invalid UTF-8"
            % display_path(path)
        ) from error
    except OSError as error:
        raise CliError(
            "unable to read report file: %s: %s"
            % (display_path(path), error.strerror or "read failed")
        ) from error

    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise CliError(
            "report file is not valid JSON: %s:%s: %s"
            % (display_path(path), error.lineno, error.msg)
        ) from error


def display_path(path: Path) -> str:
    return safe_display_name(path.name, fallback="report file")


def read_report_json(path: Path) -> dict[str, object]:
    data = read_json_value(path)
    if not isinstance(data, dict):
        raise CliError("report JSON must be an object")
    return data


def read_mapping_json(path: Path, label: str) -> dict[str, object]:
    data = read_json_value(path)
    if not isinstance(data, dict):
        raise CliError("%s must be an object" % label)
    return data


def read_scan_report(path: Path) -> ScanReport:
    data = read_report_json(path)
    try:
        return ScanReport.model_validate(data)
    except ValidationError as error:
        raise CliError(
            "report does not match public schema: %s" % validation_error_summary(error)
        ) from error


def validation_error_summary(error: ValidationError) -> str:
    summaries: list[str] = []
    for item in error.errors():
        location = ".".join(
            public_validation_location_part(part) for part in item.get("loc", ())
        ) or "body"
        error_type = str(item.get("type", "validation_error"))
        summaries.append("%s:%s" % (location, error_type))
    if len(summaries) == 0:
        return "validation_error"
    return "; ".join(summaries)


def public_validation_location_part(value: object) -> str:
    text = sanitize_public_text(str(value)).strip()
    if text == "" or "[redacted" in text:
        return "<field>"
    return text


def select_remediation_task(
    report: Mapping[str, object],
    task_id: str | None,
) -> Mapping[str, object]:
    tasks = report.get("remediation_tasks")
    if not isinstance(tasks, list) or len(tasks) == 0:
        raise CliError("report contains no remediation tasks")

    if task_id is None:
        first_task = tasks[0]
        if not isinstance(first_task, Mapping):
            raise CliError("first remediation task must be an object")
        return first_task

    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        if task.get("task_id") == task_id:
            return task
    raise CliError("remediation task not found")


def compact_findings_from_report(
    report: ScanReport,
    limit: int | None,
    priority: str | None,
) -> list[dict[str, object]]:
    if limit is not None and limit < 1:
        raise CliError("--limit must be 1 or greater")

    findings: list[dict[str, object]] = []
    for task in report.remediation_tasks:
        finding = compact_finding_from_task(task)
        if priority is not None and finding["priority"] != priority:
            continue
        findings.append(finding)
        if limit is not None and len(findings) >= limit:
            break
    return findings


def compact_finding_from_task(task: RemediationTaskSchema) -> dict[str, object]:
    finding: dict[str, object] = {
        "task_id": safe_cli_output_text(task.task_id),
        "package_name": safe_cli_identifier_text(task.package.name),
        "vulnerability_id": safe_cli_output_text(task.vulnerability.canonical_id),
        "priority": safe_cli_output_text(task.risk.priority),
        "risk_score": task.risk.risk_score,
    }
    if task.patch_plan.target_version is not None:
        finding["target_version"] = safe_cli_output_text(task.patch_plan.target_version)
    return finding


def format_compact_finding(finding: Mapping[str, object]) -> str:
    fields = [
        str(finding["task_id"]),
        str(finding["package_name"]),
        str(finding["vulnerability_id"]),
        str(finding["priority"]),
        str(finding["risk_score"]),
    ]
    target_version = string_value(finding.get("target_version"))
    if target_version is not None:
        fields.append("target %s" % target_version)
    return " | ".join(fields)


def mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def string_from_mapping(value: object, key: str) -> str | None:
    return string_value(mapping_value(value).get(key))


def string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip() != "":
        return value
    return None


def safe_cli_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    safe_value = safe_cli_value(value)
    if isinstance(safe_value, Mapping):
        return safe_value
    return {}


def safe_cli_value(value: object) -> object:
    if isinstance(value, str):
        return safe_cli_output_text(value)
    if isinstance(value, list):
        return [safe_cli_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): safe_cli_value(child) for key, child in value.items()}
    return value


def safe_cli_output_text(value: str) -> str:
    return sanitize_public_text(redact_secret_text(value)).strip()


def safe_cli_identifier_text(value: str) -> str:
    return sanitize_public_identifier(redact_secret_text(value)).strip()


def write_json_output(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
