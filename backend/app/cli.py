"""Command line interface for VulnSage AI."""

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Optional

from pydantic import ValidationError

from app.ai.contracts import MockAIProvider
from app.eval.report_validator import validate_report
from app.schemas.report import RemediationTaskSchema, ScanReport
from app.services.ai_context_bundle import build_ai_context_bundle, validate_client_ai_output
from app.services.ai_summary_service import AISummaryService
from app.services.path_policy import PathPolicyError
from app.services.public_safety import (
    safe_display_name,
    sanitize_public_identifier,
    sanitize_public_text,
)
from app.services.rag_types import EvidenceChunk
from app.services.scan_service import ScanService
from app.services.trace_service import redact_secret_text

class OfflineOsvClient:
    def query(self, package_name: str, version: Optional[str], ecosystem: str):
        return []


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnsage")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a local repository.")
    scan_parser.add_argument("path", help="Path to a local repository.")
    scan_parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    scan_parser.add_argument(
        "--offline",
        action="store_true",
        help="Parse the repository without querying OSV.",
    )
    scan_parser.add_argument(
        "--output",
        help="Write structured JSON output to this file.",
    )
    scan_parser.add_argument(
        "--workspace-root",
        help="Restrict the scan path to this workspace root.",
    )
    summary_parser = subparsers.add_parser(
        "summarize-report",
        help="Generate a deterministic AI summary for one remediation task.",
    )
    summary_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    summary_parser.add_argument(
        "--output",
        required=True,
        help="Write structured summary JSON output to this file.",
    )
    summary_parser.add_argument(
        "--task-id",
        help="Summarize the remediation task with this task_id. Defaults to the first task.",
    )
    context_parser = subparsers.add_parser(
        "ai-context-bundle",
        help="Write a focused client-AI context bundle for one remediation task.",
    )
    context_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    context_parser.add_argument(
        "--output",
        required=True,
        help="Write structured AI context bundle JSON output to this file.",
    )
    context_parser.add_argument(
        "--task-id",
        help="Build context for this remediation task. Defaults to the first task.",
    )
    validate_ai_parser = subparsers.add_parser(
        "validate-ai-output",
        help="Validate a client AI JSON response against one remediation task.",
    )
    validate_ai_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    validate_ai_parser.add_argument("ai_output_json", help="Path to a client AI output JSON file.")
    validate_ai_parser.add_argument(
        "--task-id",
        help="Validate against this remediation task. Defaults to the first task.",
    )
    validate_ai_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured validator output.",
    )
    ai_demo_parser = subparsers.add_parser(
        "ai-demo",
        help="Run the no-key AI MVP demo and write all proof artifacts.",
    )
    ai_demo_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory where demo artifacts should be written.",
    )
    validate_parser = subparsers.add_parser(
        "validate-report",
        help="Validate a public scan report JSON file.",
    )
    validate_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured validator output.",
    )
    findings_parser = subparsers.add_parser(
        "findings",
        help="List compact findings from a scan report JSON file.",
    )
    findings_parser.add_argument("report_json", help="Path to a scan report JSON file.")
    findings_parser.add_argument(
        "--limit",
        type=int,
        help="Limit the number of findings printed.",
    )
    findings_parser.add_argument(
        "--priority",
        help="Only include findings with this priority.",
    )
    findings_parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured JSON output.",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        client = OfflineOsvClient() if args.offline else None
        try:
            result = ScanService(osv_client=client).scan_local(
                args.path,
                workspace_root=args.workspace_root,
            )
        except PathPolicyError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1
        except ValueError as error:
            print("Error: unable to scan repository: %s" % error, file=sys.stderr)
            return 1
        public_result = result.to_dict()
        if args.output:
            output_path = Path(args.output)
            try:
                write_json_output(output_path, public_result)
            except OSError:
                print("Error: unable to write output file", file=sys.stderr)
                return 1
            return 0
        if args.json:
            print(json.dumps(public_result, indent=2, sort_keys=True))
        else:
            repo_profile = mapping_value(public_result.get("repo_profile"))
            summary = mapping_value(public_result.get("summary"))
            errors = public_result.get("errors")
            print("Scan complete: %s" % (repo_profile.get("repo_name") or "repo"))
            print("Packages: %s" % summary["packages"])
            print("Raw alerts: %s" % summary["raw_alerts"])
            print("Deduped remediation tasks: %s" % summary["deduped_remediation_tasks"])
            print("Release blockers: %s" % summary["release_blockers"])
            if isinstance(errors, list) and len(errors) > 0:
                print("Errors:")
                for error in errors:
                    print("- %s" % error)
        return 0
    if args.command == "summarize-report":
        try:
            report_model = read_scan_report(Path(args.report_json))
            report = report_model.model_dump(mode="json")
            task = select_remediation_task(report, args.task_id)
            task = safe_cli_mapping(task)
            chunks = evidence_chunks_from_task(task)
            result = AISummaryService(provider=MockAIProvider()).summarize_remediation_task(
                task,
                chunks,
            )
            write_json_output(Path(args.output), result.to_dict())
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1
        except OSError:
            print("Error: unable to write summary output file", file=sys.stderr)
            return 1
        except ValueError as error:
            print("Error: unable to summarize report: %s" % error, file=sys.stderr)
            return 1
        return 0
    if args.command == "ai-context-bundle":
        try:
            report_model = read_scan_report(Path(args.report_json))
            report = report_model.model_dump(mode="json")
            task = select_remediation_task(report, args.task_id)
            bundle = build_ai_context_bundle(safe_cli_mapping(task))
            write_json_output(Path(args.output), bundle)
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1
        except OSError:
            print("Error: unable to write AI context bundle output file", file=sys.stderr)
            return 1
        except ValueError as error:
            print("Error: unable to build AI context bundle: %s" % error, file=sys.stderr)
            return 1
        return 0
    if args.command == "validate-ai-output":
        try:
            report_model = read_scan_report(Path(args.report_json))
            report = report_model.model_dump(mode="json")
            task = select_remediation_task(report, args.task_id)
            ai_output = read_mapping_json(Path(args.ai_output_json), "AI output JSON")
            result = validate_client_ai_output(safe_cli_mapping(task), ai_output)
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1
        except ValueError as error:
            print("Error: unable to validate AI output: %s" % error, file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(result["summary"])
        return 0 if result["passed"] is True else 1
    if args.command == "ai-demo":
        try:
            result = run_ai_demo(Path(args.output_dir))
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1
        except OSError:
            print("Error: unable to write AI demo artifacts", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["validation"]["passed"] is True else 1
    if args.command == "validate-report":
        try:
            report = read_scan_report(Path(args.report_json))
            result = validate_report(report.model_dump(mode="json"))
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1

        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True))
        else:
            print(result["summary"])
        return 0 if result["passed"] is True else 1
    if args.command == "findings":
        try:
            report = read_scan_report(Path(args.report_json))
            findings = compact_findings_from_report(
                report,
                limit=args.limit,
                priority=args.priority,
            )
        except CliError as error:
            print("Error: %s" % error, file=sys.stderr)
            return 1

        if args.json:
            print(
                json.dumps(
                    {"finding_count": len(findings), "findings": findings},
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            for finding in findings:
                print(format_compact_finding(finding))
        return 0

    parser.print_help()
    return 1


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
        data = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CliError(
            "report file is not valid JSON: %s:%s: %s"
            % (display_path(path), error.lineno, error.msg)
        ) from error

    return data


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


def evidence_chunks_from_task(task: Mapping[str, object]) -> list[EvidenceChunk]:
    chunks: list[EvidenceChunk] = []
    package_name = string_from_mapping(task.get("package"), "name")
    repo_id = string_value(task.get("repo_id")) or string_value(task.get("repo"))

    vulnerability = mapping_value(task.get("vulnerability"))
    advisory_text = advisory_content(vulnerability)
    if advisory_text is not None:
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-advisory",
                source_type="advisory",
                content=advisory_text,
                metadata=chunk_metadata(
                    repo_id=repo_id,
                    package_name=package_name,
                    source="vulnerability",
                ),
            )
        )

    risk_text = risk_content(mapping_value(task.get("risk")))
    if risk_text is not None:
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-risk",
                source_type="risk",
                content=risk_text,
                metadata=chunk_metadata(
                    repo_id=repo_id,
                    package_name=package_name,
                    source="risk",
                ),
            )
        )

    evidence = task.get("evidence")
    if isinstance(evidence, list):
        for index, item in enumerate(evidence):
            if not isinstance(item, Mapping):
                continue
            claim = string_value(item.get("claim"))
            if claim is None or claim.strip() == "":
                continue
            chunks.append(
                EvidenceChunk(
                    chunk_id="cli-evidence-%s" % (index + 1),
                    source_type=string_value(item.get("type")) or "task_evidence",
                    content=claim,
                    metadata=chunk_metadata(
                        repo_id=repo_id,
                        package_name=package_name,
                        source=string_value(item.get("source")) or "remediation_task",
                    ),
                )
            )
    return chunks


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


def advisory_content(vulnerability: Mapping[str, object]) -> str | None:
    fields = [
        ("Vulnerability", vulnerability.get("canonical_id") or vulnerability.get("source_id")),
        ("Severity", vulnerability.get("severity")),
        ("Summary", vulnerability.get("summary")),
        ("Fixed versions", vulnerability.get("fixed_versions")),
    ]
    return content_from_fields(fields)


def risk_content(risk: Mapping[str, object]) -> str | None:
    fields = [
        ("Priority", risk.get("priority")),
        ("Risk score", risk.get("risk_score")),
        ("Reachability", risk.get("reachability")),
        ("Runtime scope", risk.get("runtime_scope")),
        ("Confidence", risk.get("confidence")),
        ("Rationale", risk.get("rationale")),
    ]
    return content_from_fields(fields)


def content_from_fields(fields: list[tuple[str, object]]) -> str | None:
    lines: list[str] = []
    for label, value in fields:
        text = field_text(value)
        if text is None:
            continue
        lines.append("%s: %s" % (label, text))
    if len(lines) == 0:
        return None
    return "\n".join(lines)


def field_text(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped != "" else None
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            text = field_text(item)
            if text is not None:
                items.append(text)
        if len(items) == 0:
            return None
        return ", ".join(items)
    return None


def chunk_metadata(
    repo_id: str | None,
    package_name: str | None,
    source: str,
) -> dict[str, object]:
    metadata: dict[str, object] = {"source": source}
    if repo_id is not None:
        metadata["repo_id"] = repo_id
    if package_name is not None:
        metadata["package"] = package_name
    return metadata


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


def run_ai_demo(output_dir: Path) -> dict[str, object]:
    from app.eval.generate_demo_report import DEFAULT_REPO_PATH, generate_report

    report = generate_report(repo_path=DEFAULT_REPO_PATH)
    report_model = ScanReport.model_validate(report)
    report_payload = report_model.model_dump(mode="json")
    task = select_remediation_task(report_payload, None)
    bundle = build_ai_context_bundle(safe_cli_mapping(task))
    sample_output = sample_ai_output_from_bundle(bundle)
    validation = validate_client_ai_output(safe_cli_mapping(task), sample_output)

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "scan_report": "scan-report.json",
        "ai_context_bundle": "ai-context-bundle.json",
        "sample_ai_output": "sample-ai-output.json",
        "ai_validation": "ai-validation.json",
    }
    write_json_output(output_dir / artifacts["scan_report"], report_payload)
    write_json_output(output_dir / artifacts["ai_context_bundle"], bundle)
    write_json_output(output_dir / artifacts["sample_ai_output"], sample_output)
    write_json_output(output_dir / artifacts["ai_validation"], validation)
    return {
        "artifacts": artifacts,
        "validation": validation,
    }


def sample_ai_output_from_bundle(bundle: Mapping[str, object]) -> dict[str, object]:
    request = mapping_value(bundle.get("ai_request"))
    evidence = request.get("evidence")
    if not isinstance(evidence, list) or len(evidence) == 0:
        raise CliError("AI context bundle contains no evidence")
    first_evidence = mapping_value(evidence[0])
    evidence_id = string_value(first_evidence.get("id"))
    if evidence_id is None:
        raise CliError("AI context bundle evidence is missing an id")
    return {
        "finding_id": string_value(request.get("finding_id")) or "unknown",
        "package_name": string_value(request.get("package_name")) or "unknown",
        "vulnerability_id": string_value(request.get("vulnerability_id")) or "unknown",
        "priority": string_value(request.get("priority")) or "unknown",
        "risk_score": int(request.get("risk_score") or 0),
        "summary": "This finding should be reviewed using the cited Sage evidence.",
        "explanation": "The response is intentionally limited to the provided context bundle.",
        "citations": [
            {
                "claim_id": "claim-1",
                "evidence_id": evidence_id,
                "note": "Supports the sample client-AI response.",
            }
        ],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "This finding should be reviewed using Sage evidence.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "sample-client-ai",
    }


def write_json_output(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
