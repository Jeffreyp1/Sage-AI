"""No-key AI demo artifact generation for the CLI."""

from collections.abc import Mapping
from pathlib import Path

from app.agents.triage_graph import TriageGraph
from app.cli_support import mapping_value, safe_cli_mapping, string_value, write_json_output
from app.eval.generate_demo_report import DEFAULT_REPO_PATH, generate_report
from app.schemas.report import ScanReport
from app.services.ai_context_bundle import build_ai_context_bundle, validate_client_ai_output
from app.services.report_evidence_index import retrieved_chunks_for_task
from app.services.trace_service import TraceService


class AIDemoError(RuntimeError):
    """Raised when the deterministic AI demo cannot build valid artifacts."""


def run_ai_demo(output_dir: Path) -> dict[str, object]:
    report_payload = demo_report_payload()
    task = first_remediation_task(report_payload)
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


def run_ai_upgrade_demo(output_dir: Path) -> dict[str, object]:
    report_payload = demo_report_payload()
    task = safe_cli_mapping(first_remediation_task(report_payload))
    retrieved_chunks = retrieved_chunks_for_task(report_payload, task, top_k=5)
    bundle = build_ai_context_bundle(task, retrieved_chunks=retrieved_chunks)
    sample_output = sample_ai_output_from_bundle(bundle)
    validation = validate_client_ai_output(
        task,
        sample_output,
        retrieved_chunks=retrieved_chunks,
    )

    trace_service = TraceService()
    workflow_state = TriageGraph(trace_service=trace_service).run_with_client_ai(
        remediation_task=task,
        evidence_chunks=retrieved_chunks,
        ai_output=sample_output,
    )
    orchestration_trace = {
        "workflow_state": workflow_state.to_dict(),
        "trace_records": deterministic_trace_records(trace_service.list_records()),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "scan_report": "scan-report.json",
        "rag_ai_context_bundle": "rag-ai-context-bundle.json",
        "sample_ai_output": "sample-ai-output.json",
        "client_ai_validation": "client-ai-validation.json",
        "orchestration_trace": "orchestration-trace.json",
    }
    write_json_output(output_dir / artifacts["scan_report"], report_payload)
    write_json_output(output_dir / artifacts["rag_ai_context_bundle"], bundle)
    write_json_output(output_dir / artifacts["sample_ai_output"], sample_output)
    write_json_output(output_dir / artifacts["client_ai_validation"], validation)
    write_json_output(output_dir / artifacts["orchestration_trace"], orchestration_trace)
    return {
        "artifacts": artifacts,
        "validation": validation,
        "workflow_state": orchestration_trace["workflow_state"],
    }


def demo_report_payload() -> dict[str, object]:
    report = generate_report(repo_path=DEFAULT_REPO_PATH)
    report_model = ScanReport.model_validate(report)
    return report_model.model_dump(mode="json")


def first_remediation_task(report: Mapping[str, object]) -> Mapping[str, object]:
    tasks = report.get("remediation_tasks")
    if not isinstance(tasks, list) or len(tasks) == 0:
        raise AIDemoError("demo report contains no remediation tasks")

    first_task = tasks[0]
    if not isinstance(first_task, Mapping):
        raise AIDemoError("first demo remediation task must be an object")
    return first_task


def sample_ai_output_from_bundle(bundle: Mapping[str, object]) -> dict[str, object]:
    request = mapping_value(bundle.get("ai_request"))
    evidence = request.get("evidence")
    if not isinstance(evidence, list) or len(evidence) == 0:
        raise AIDemoError("AI context bundle contains no evidence")

    first_evidence = sample_evidence_item(evidence)
    evidence_id = string_value(first_evidence.get("id"))
    if evidence_id is None:
        raise AIDemoError("AI context bundle evidence is missing an id")

    claim = string_value(first_evidence.get("content")) or (
        "This finding should be reviewed using Sage evidence."
    )
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
                "claim": claim,
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "sample-client-ai",
    }


def sample_evidence_item(evidence: list[object]) -> Mapping[str, object]:
    for item in evidence:
        evidence_item = mapping_value(item)
        metadata = mapping_value(evidence_item.get("metadata"))
        if metadata.get("origin") == "retrieved_context":
            return evidence_item
    return mapping_value(evidence[0])


def deterministic_trace_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    deterministic: list[dict[str, object]] = []
    for index, record in enumerate(records, start=1):
        stable_record = dict(record)
        stable_record["trace_id"] = "demo-trace-%03d" % index
        deterministic.append(stable_record)
    return deterministic
