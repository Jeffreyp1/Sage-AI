"""SDK-free MCP-ready tool handlers for local Sage AI scans."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from app.eval.report_validator import validate_report as validate_public_report
from app.mcp.contracts import (
    AIContextBundleInput,
    AIContextBundleOutput,
    CompactFinding,
    ExplainTopRisksInput,
    ExplainTopRisksOutput,
    FindingEvidenceOutput,
    FindingInput,
    FindingOutput,
    GetVulnerabilityBriefOutput,
    ListFindingsInput,
    ListFindingsOutput,
    RemediationContextOutput,
    ScanCurrentRepoInput,
    ScanRepoInput,
    ScanRepoOutput,
    ValidateAIOutputInput,
    ValidateAIOutputOutput,
    ValidateReportInput,
    ValidateReportOutput,
    ToolContract,
    tool_contracts,
)
from app.mcp.store import FileReportStore, ReportStoreError
from app.schemas.report import RemediationTaskSchema, ScanReport
from app.services.ai_context_bundle import build_ai_context_bundle, validate_client_ai_output
from app.services.ai_summary_service import evidence_items_for_task
from app.services.path_policy import PathPolicyError, resolve_existing_workspace, resolve_repo_path
from app.services.public_safety import (
    sanitize_public_identifier,
    sanitize_public_text,
    sanitize_public_value,
)
from app.services.report_evidence_index import retrieved_chunks_for_task
from app.services.rag_types import EvidenceChunk
from app.services.scan_service import ScanService


ModelT = TypeVar("ModelT", bound=BaseModel)


class ToolHandlerError(RuntimeError):
    """Raised for controlled MCP tool validation and execution failures."""


class ScanResultLike(Protocol):
    scan_id: str

    def to_dict(self) -> dict[str, object]:
        ...


class ScanServiceLike(Protocol):
    def scan_local(
        self,
        repo_path: str,
        *,
        workspace_root: str | Path | None = None,
    ) -> ScanResultLike:
        ...


class OfflineOsvClient:
    def query(
        self,
        package_name: str,
        version: str | None,
        ecosystem: str,
    ) -> list[dict[str, object]]:
        return []


class McpToolHandlers:
    """Validate tool calls, execute local scan operations, and validate outputs."""

    def __init__(
        self,
        *,
        workspace_root: str | Path | None = None,
        storage_dir: str | Path | None = None,
        scan_service: ScanServiceLike | None = None,
    ) -> None:
        try:
            self.workspace_root = resolve_existing_workspace(workspace_root)
        except PathPolicyError as error:
            raise ToolHandlerError(str(error)) from error

        reports_dir = (
            self.workspace_root / ".vulnsage-mcp-reports"
            if storage_dir is None
            else Path(storage_dir)
        )
        try:
            self.report_store = FileReportStore(
                reports_dir,
                allowed_root=self.workspace_root,
            )
        except ReportStoreError as error:
            raise ToolHandlerError(str(error)) from error
        self.scan_service = scan_service
        self.contracts = {contract.name: contract for contract in tool_contracts()}
        self.handlers: dict[str, Callable[[BaseModel], BaseModel]] = {
            "scan_repo": self._scan_repo,
            "scan_current_repo": self._scan_current_repo,
            "list_findings": self._list_findings,
            "get_finding": self._get_finding,
            "get_finding_evidence": self._get_finding_evidence,
            "get_vulnerability_brief": self._get_vulnerability_brief,
            "explain_top_risks": self._explain_top_risks,
            "get_remediation_context": self._get_remediation_context,
            "get_ai_context_bundle": self._get_ai_context_bundle,
            "validate_ai_output": self._validate_ai_output,
            "validate_report": self._validate_report,
        }

    def list_tools(self) -> list[dict[str, object]]:
        tools: list[dict[str, object]] = []
        for contract in tool_contracts():
            tools.append(
                {
                    "name": contract.name,
                    "description": contract.description,
                    "inputSchema": contract.input_model.model_json_schema(),
                }
            )
        return tools

    def call_tool(
        self,
        name: str,
        arguments: Mapping[str, object] | None = None,
    ) -> BaseModel:
        contract = self.contracts.get(name)
        handler = self.handlers.get(name)
        if contract is None or handler is None:
            raise ToolHandlerError("Unknown MCP tool")

        input_model = self._validate_input(contract, arguments)
        output = handler(input_model)
        return self._validate_output(contract, output)

    def call_tool_dict(
        self,
        name: str,
        arguments: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        output = self.call_tool(name, arguments)
        return output.model_dump(mode="json")

    def _validate_input(
        self,
        contract: ToolContract,
        arguments: Mapping[str, object] | None,
    ) -> BaseModel:
        payload = {} if arguments is None else dict(arguments)
        try:
            return contract.input_model.model_validate(payload)
        except ValidationError as error:
            raise ToolHandlerError(
                "Invalid input for %s: %s"
                % (contract.name, validation_error_summary(error))
            ) from error

    def _validate_output(self, contract: ToolContract, output: BaseModel) -> BaseModel:
        try:
            return contract.output_model.model_validate(output)
        except ValidationError as error:
            raise ToolHandlerError(
                "Invalid output for %s: %s"
                % (contract.name, validation_error_summary(error))
            ) from error

    def _resolve_repo_path(self, requested_path: str | Path) -> Path:
        try:
            return resolve_repo_path(requested_path, workspace_root=self.workspace_root)
        except PathPolicyError as error:
            raise ToolHandlerError(str(error)) from error

    def _scan_repo(self, model: BaseModel) -> ScanRepoOutput:
        request = as_model(model, ScanRepoInput)
        repo_path = self._resolve_repo_path(request.repo_path)
        return self._scan_path(
            repo_path,
            offline=request.offline,
            max_findings=request.max_findings,
        )

    def _scan_current_repo(self, model: BaseModel) -> ScanRepoOutput:
        request = as_model(model, ScanCurrentRepoInput)
        repo_path = self._resolve_repo_path(".")
        return self._scan_path(
            repo_path,
            offline=request.offline,
            max_findings=request.max_findings,
        )

    def _scan_path(
        self,
        repo_path: Path,
        *,
        offline: bool,
        max_findings: int,
    ) -> ScanRepoOutput:
        service = self._scan_service(offline=offline)
        try:
            result = service.scan_local(str(repo_path), workspace_root=self.workspace_root)
            report = ScanReport.model_validate(result.to_dict())
        except ValidationError as error:
            raise ToolHandlerError("Scan produced an invalid public report") from error
        except PathPolicyError as error:
            raise ToolHandlerError(str(error)) from error
        except ValueError as error:
            raise ToolHandlerError(str(error)) from error

        try:
            report_path = self.report_store.save(report)
        except ReportStoreError as error:
            raise ToolHandlerError(str(error)) from error

        summary = report.summary
        return ScanRepoOutput(
            schema_version=report.schema_version,
            scan_id=report.scan_id,
            complete=summary.complete,
            scan_status=summary.scan_status,
            error_count=summary.error_count,
            summary=summary,
            top_findings=compact_findings(report, limit=max_findings),
            report_path=report_path.name,
        )

    def _list_findings(self, model: BaseModel) -> ListFindingsOutput:
        request = as_model(model, ListFindingsInput)
        report = self._load_report(request.scan_id)
        return ListFindingsOutput(
            scan_id=report.scan_id,
            findings=compact_findings(report, limit=request.limit),
        )

    def _get_finding(self, model: BaseModel) -> FindingOutput:
        request = as_model(model, FindingInput)
        report = self._load_report(request.scan_id)
        finding = find_task(report, request.task_id)
        return FindingOutput(scan_id=report.scan_id, finding=sanitized_finding(finding))

    def _get_finding_evidence(self, model: BaseModel) -> FindingEvidenceOutput:
        request = as_model(model, FindingInput)
        report = self._load_report(request.scan_id)
        finding = find_task(report, request.task_id)
        evidence = [evidence_item(item) for item in finding.evidence]
        return FindingEvidenceOutput(
            scan_id=report.scan_id,
            task_id=safe_text(finding.task_id),
            evidence=evidence,
        )

    def _get_vulnerability_brief(self, model: BaseModel) -> GetVulnerabilityBriefOutput:
        request = as_model(model, FindingInput)
        report = self._load_report(request.scan_id)
        finding = find_task(report, request.task_id)
        return GetVulnerabilityBriefOutput(
            scan_id=report.scan_id,
            task_id=safe_text(finding.task_id),
            brief=vulnerability_brief(finding),
            evidence=evidence_items_with_ids(finding),
            risk_rationale=safe_text_list(finding.risk.rationale),
        )

    def _explain_top_risks(self, model: BaseModel) -> ExplainTopRisksOutput:
        request = as_model(model, ExplainTopRisksInput)
        report = self._load_report(request.scan_id)
        findings: list[dict[str, object]] = []
        for task in report.remediation_tasks[: request.limit]:
            compact = sanitized_compact_finding(task)
            findings.append(
                {
                    "task_id": compact.task_id,
                    "package_name": compact.package_name,
                    "vulnerability_id": compact.vulnerability_id,
                    "priority": compact.priority,
                    "risk_score": compact.risk_score,
                    "evidence_ids": evidence_ids_for_task(task),
                }
            )
        return ExplainTopRisksOutput(scan_id=report.scan_id, findings=findings)

    def _get_remediation_context(self, model: BaseModel) -> RemediationContextOutput:
        request = as_model(model, FindingInput)
        report = self._load_report(request.scan_id)
        finding = find_task(report, request.task_id)
        compact = sanitized_compact_finding(finding)
        context = remediation_context_markdown(finding)
        return RemediationContextOutput(
            scan_id=report.scan_id,
            task_id=safe_text(finding.task_id),
            context_markdown=context,
            finding=compact,
            evidence_count=len(finding.evidence),
        )

    def _get_ai_context_bundle(self, model: BaseModel) -> AIContextBundleOutput:
        request = as_model(model, AIContextBundleInput)
        report = self._load_report(request.scan_id)
        finding = find_task(report, request.task_id)
        report_payload = report.model_dump(mode="json")
        finding_payload = finding.model_dump(mode="json")
        retrieved_chunks: list[EvidenceChunk] = []
        if request.include_rag:
            retrieved_chunks = retrieved_chunks_for_task(
                report_payload,
                finding_payload,
                top_k=request.top_k,
            )
        bundle = build_ai_context_bundle(finding_payload, retrieved_chunks=retrieved_chunks)
        return AIContextBundleOutput(
            scan_id=report.scan_id,
            task_id=safe_text(finding.task_id),
            bundle=bundle,
        )

    def _validate_ai_output(self, model: BaseModel) -> ValidateAIOutputOutput:
        request = as_model(model, ValidateAIOutputInput)
        report = self._load_report(request.scan_id)
        finding = find_task(report, request.task_id)
        report_payload = report.model_dump(mode="json")
        finding_payload = finding.model_dump(mode="json")
        retrieved_chunks: list[EvidenceChunk] = []
        if request.include_rag:
            retrieved_chunks = retrieved_chunks_for_task(
                report_payload,
                finding_payload,
                top_k=request.top_k,
            )
        result = validate_client_ai_output(
            finding_payload,
            request.ai_output,
            retrieved_chunks=retrieved_chunks,
        )
        return ValidateAIOutputOutput(
            scan_id=report.scan_id,
            task_id=safe_text(finding.task_id),
            passed=bool(result["passed"]),
            blocked=bool(result["blocked"]),
            blocked_by=safe_optional_text(result.get("blocked_by")),
            blocked_subject=safe_text(result.get("blocked_subject")),
            scan_failed=bool(result.get("scan_failed")),
            user_message=safe_text(result.get("user_message")),
            summary=str(result["summary"]),
            validation=mapping_value(result.get("validation")),
        )

    def _validate_report(self, model: BaseModel) -> ValidateReportOutput:
        request = as_model(model, ValidateReportInput)
        try:
            report = self.report_store.load_path(request.report_path)
        except ReportStoreError as error:
            raise ToolHandlerError(str(error)) from error
        result = validate_public_report(report.model_dump(mode="json"))
        return ValidateReportOutput.model_validate(result)

    def _load_report(self, scan_id: str) -> ScanReport:
        try:
            return self.report_store.load(scan_id)
        except ReportStoreError as error:
            raise ToolHandlerError(str(error)) from error

    def _scan_service(self, *, offline: bool) -> ScanServiceLike:
        if self.scan_service is not None:
            return self.scan_service
        if offline:
            return ScanService(osv_client=OfflineOsvClient())
        return ScanService()


def as_model(model: BaseModel, expected_type: type[ModelT]) -> ModelT:
    if not isinstance(model, expected_type):
        raise ToolHandlerError("Internal handler received wrong input model")
    return model


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


def compact_findings(report: ScanReport, *, limit: int) -> list[CompactFinding]:
    findings: list[CompactFinding] = []
    for task in report.remediation_tasks[:limit]:
        findings.append(sanitized_compact_finding(task))
    return findings


def compact_finding(task: RemediationTaskSchema) -> CompactFinding:
    return CompactFinding(
        task_id=task.task_id,
        package_name=task.package.name,
        vulnerability_id=task.vulnerability.canonical_id,
        priority=task.risk.priority,
        risk_score=task.risk.risk_score,
        severity=task.vulnerability.severity,
        target_version=task.patch_plan.target_version,
    )


def sanitized_compact_finding(task: RemediationTaskSchema) -> CompactFinding:
    finding = compact_finding(task)
    return CompactFinding(
        task_id=safe_text(finding.task_id),
        package_name=safe_identifier_text(finding.package_name),
        vulnerability_id=safe_text(finding.vulnerability_id),
        priority=safe_text(finding.priority),
        risk_score=finding.risk_score,
        severity=safe_optional_text(finding.severity),
        target_version=safe_optional_text(finding.target_version),
    )


def find_task(report: ScanReport, task_id: str) -> RemediationTaskSchema:
    for task in report.remediation_tasks:
        if task.task_id == task_id:
            return task
    raise ToolHandlerError("Finding not found")


def sanitized_finding(task: RemediationTaskSchema) -> RemediationTaskSchema:
    payload = sanitize_public_value(task.model_dump(mode="json"))
    return RemediationTaskSchema.model_validate(payload)


def vulnerability_brief(task: RemediationTaskSchema) -> dict[str, object]:
    brief: dict[str, object] = {
        "task_id": safe_text(task.task_id),
        "package_name": safe_identifier_text(task.package.name),
        "vulnerability_id": safe_text(task.vulnerability.canonical_id),
        "priority": safe_text(task.risk.priority),
        "risk_score": task.risk.risk_score,
    }
    optional_values = {
        "severity": task.vulnerability.severity,
        "current_version": task.package.current_version,
        "target_version": task.patch_plan.target_version,
        "summary": task.vulnerability.summary,
        "recommended_action": task.patch_plan.recommended_action,
    }
    for key, value in optional_values.items():
        if value is not None:
            brief[key] = safe_text(value)
    return brief


def evidence_items_with_ids(task: RemediationTaskSchema) -> list[dict[str, str]]:
    request_evidence = evidence_items_for_task(task.model_dump(mode="json"), ())
    evidence: list[dict[str, str]] = []
    for item, request_item in zip(task.evidence, request_evidence, strict=False):
        output = evidence_item(item)
        output["id"] = safe_text(request_item.id)
        evidence.append(output)
    return evidence


def evidence_ids_for_task(task: RemediationTaskSchema) -> list[str]:
    return [item["id"] for item in evidence_items_with_ids(task)]


def evidence_item(item: BaseModel) -> dict[str, str]:
    payload = item.model_dump(mode="json", exclude_none=True)
    output: dict[str, str] = {}
    for key, value in payload.items():
        if isinstance(value, str):
            output[key] = safe_text(value)
    return output


def remediation_context_markdown(task: RemediationTaskSchema) -> str:
    lines = [
        "# Remediation Context",
        "",
        "- Package: %s" % safe_identifier_text(task.package.name),
        "- Vulnerability: %s" % safe_text(task.vulnerability.canonical_id),
        "- Priority: %s (%s/100)" % (safe_text(task.risk.priority), task.risk.risk_score),
    ]
    if task.vulnerability.severity is not None:
        lines.append("- Severity: %s" % safe_text(task.vulnerability.severity))
    if task.package.current_version is not None:
        lines.append("- Current version: %s" % safe_text(task.package.current_version))
    if task.patch_plan.target_version is not None:
        lines.append("- Target version: %s" % safe_text(task.patch_plan.target_version))
    if task.vulnerability.summary is not None:
        lines.extend(["", "## Summary", safe_text(task.vulnerability.summary)])

    lines.extend(["", "## Evidence"])
    for item in task.evidence[:5]:
        source = safe_text(item.source)
        claim = safe_text(item.claim)
        lines.append("- %s: %s" % (source, claim))

    if len(task.evidence) == 0:
        lines.append("- No evidence items were recorded in the scan report.")

    return "\n".join(lines)


def mapping_value(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def safe_text_list(values: list[str]) -> list[str]:
    return [safe_text(value) for value in values]


def safe_text(value: str) -> str:
    return sanitize_public_text(value).strip()


def safe_identifier_text(value: str) -> str:
    return sanitize_public_identifier(value).strip()


def safe_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    return safe_text(value)
