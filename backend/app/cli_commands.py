"""Command handlers for the VulnSage CLI."""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from app.ai.contracts import MockAIProvider
from app.cli_ai_demo import AIDemoError, run_ai_demo, run_ai_upgrade_demo
from app.cli_evidence import evidence_chunks_from_task
from app.cli_support import (
    CliError,
    compact_findings_from_report,
    format_compact_finding,
    mapping_value,
    read_mapping_json,
    read_scan_report,
    safe_cli_mapping,
    select_remediation_task,
    write_json_output,
)
from app.eval.report_validator import validate_report
from app.services.ai_context_bundle import build_ai_context_bundle, validate_client_ai_output
from app.services.ai_summary_service import AISummaryService
from app.services.path_policy import PathPolicyError
from app.services.rag_types import EvidenceChunk
from app.services.report_evidence_index import retrieved_chunks_for_task
from app.services.scan_service import ScanService


class OfflineOsvClient:
    def query(self, package_name: str, version: Optional[str], ecosystem: str):
        return []


def handle_scan(args: argparse.Namespace) -> int:
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
        try:
            write_json_output(Path(args.output), public_result)
        except OSError:
            print("Error: unable to write output file", file=sys.stderr)
            return 1
        return 0

    if args.json:
        print(json.dumps(public_result, indent=2, sort_keys=True))
        return 0

    print_scan_summary(public_result)
    return 0


def print_scan_summary(public_result: dict[str, object]) -> None:
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


def handle_summarize_report(args: argparse.Namespace) -> int:
    try:
        report_model = read_scan_report(Path(args.report_json))
        report = report_model.model_dump(mode="json")
        task = safe_cli_mapping(select_remediation_task(report, args.task_id))
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


def handle_ai_context_bundle(args: argparse.Namespace) -> int:
    try:
        report_model = read_scan_report(Path(args.report_json))
        report = report_model.model_dump(mode="json")
        task = safe_cli_mapping(select_remediation_task(report, args.task_id))
        retrieved_chunks = resolve_retrieved_chunks(report, task, args.include_rag, args.top_k)
        bundle = build_ai_context_bundle(task, retrieved_chunks=retrieved_chunks)
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


def handle_validate_ai_output(args: argparse.Namespace) -> int:
    try:
        report_model = read_scan_report(Path(args.report_json))
        report = report_model.model_dump(mode="json")
        task = safe_cli_mapping(select_remediation_task(report, args.task_id))
        ai_output = read_mapping_json(Path(args.ai_output_json), "AI output JSON")
        retrieved_chunks = resolve_retrieved_chunks(report, task, args.include_rag, args.top_k)
        result = validate_client_ai_output(
            task,
            ai_output,
            retrieved_chunks=retrieved_chunks,
        )
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


def resolve_retrieved_chunks(
    report: dict[str, object],
    task: object,
    include_rag: bool,
    top_k: int,
) -> list[EvidenceChunk]:
    if not include_rag:
        return []
    if top_k < 1 or top_k > 10:
        raise CliError("--top-k must be between 1 and 10")
    return retrieved_chunks_for_task(report, safe_cli_mapping(mapping_value(task)), top_k=top_k)


def handle_ai_demo(args: argparse.Namespace) -> int:
    try:
        result = run_ai_demo(Path(args.output_dir))
    except AIDemoError as error:
        print("Error: %s" % error, file=sys.stderr)
        return 1
    except OSError:
        print("Error: unable to write AI demo artifacts", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation"]["passed"] is True else 1


def handle_ai_upgrade_demo(args: argparse.Namespace) -> int:
    try:
        result = run_ai_upgrade_demo(Path(args.output_dir))
    except AIDemoError as error:
        print("Error: %s" % error, file=sys.stderr)
        return 1
    except OSError:
        print("Error: unable to write AI upgrade demo artifacts", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["validation"]["passed"] is True else 1


def handle_validate_report(args: argparse.Namespace) -> int:
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


def handle_findings(args: argparse.Namespace) -> int:
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
        print(json.dumps({"finding_count": len(findings), "findings": findings}, indent=2, sort_keys=True))
    else:
        for finding in findings:
            print(format_compact_finding(finding))
    return 0


COMMAND_HANDLERS = {
    "scan": handle_scan,
    "summarize-report": handle_summarize_report,
    "ai-context-bundle": handle_ai_context_bundle,
    "validate-ai-output": handle_validate_ai_output,
    "ai-demo": handle_ai_demo,
    "ai-upgrade-demo": handle_ai_upgrade_demo,
    "validate-report": handle_validate_report,
    "findings": handle_findings,
}
