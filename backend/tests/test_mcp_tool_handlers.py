import json
from pathlib import Path

import pytest

from app.mcp.contracts import (
    AIContextBundleOutput,
    FindingEvidenceOutput,
    FindingOutput,
    ListFindingsOutput,
    RemediationContextOutput,
    ScanRepoOutput,
    ValidateAIOutputOutput,
    ValidateReportOutput,
)
from app.mcp.handlers import McpToolHandlers, ToolHandlerError
from app.mcp.store import FileReportStore, ReportStoreError
from app.schemas.report import REPORT_SCHEMA_VERSION


class FakeScanResult:
    scan_id = "scan-test-001"

    def __init__(self, report: dict[str, object]) -> None:
        self._report = report

    def to_dict(self) -> dict[str, object]:
        return self._report


class RecordingScanService:
    def __init__(self, report: dict[str, object]) -> None:
        self.report = report
        self.calls: list[tuple[str, Path | None]] = []

    def scan_local(
        self,
        repo_path: str,
        *,
        workspace_root: str | Path | None = None,
    ) -> FakeScanResult:
        root_path = None if workspace_root is None else Path(workspace_root)
        self.calls.append((repo_path, root_path))
        return FakeScanResult(self.report)


class FailingScanService:
    def scan_local(
        self,
        repo_path: str,
        *,
        workspace_root: str | Path | None = None,
    ) -> FakeScanResult:
        raise AssertionError("scan service should not be called")


def test_scan_repo_persists_report_and_followup_tools_return_validated_models(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    service = RecordingScanService(scan_report_fixture())
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=service,
    )

    scan = handlers.call_tool(
        "scan_repo",
        {"repo_path": "payments-api", "offline": True, "max_findings": 1},
    )

    assert isinstance(scan, ScanRepoOutput)
    assert scan.scan_id == "scan-test-001"
    assert scan.report_path == "scan-test-001.json"
    assert not Path(scan.report_path).is_absolute()
    assert (storage / scan.report_path).exists()
    assert len(scan.top_findings) == 1
    assert scan.top_findings[0].package_name == "archive-utils"
    assert service.calls == [(str(repo.resolve()), workspace.resolve())]

    listed = handlers.call_tool(
        "list_findings",
        {"scan_id": scan.scan_id, "limit": 10},
    )
    assert isinstance(listed, ListFindingsOutput)
    assert [finding.task_id for finding in listed.findings] == [
        "task-archive-utils",
        "task-image-tool",
    ]

    finding = handlers.call_tool(
        "get_finding",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )
    assert isinstance(finding, FindingOutput)
    assert finding.finding.package.name == "archive-utils"

    evidence = handlers.call_tool(
        "get_finding_evidence",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )
    assert isinstance(evidence, FindingEvidenceOutput)
    assert evidence.evidence == [
        {
            "type": "lockfile_entry",
            "source": "package-lock.json",
            "claim": "archive-utils@1.4.0 is installed in package-lock.json.",
        },
        {
            "type": "reachability",
            "source": "src/upload.ts",
            "claim": "archive-utils is imported by the production upload route.",
        },
    ]

    validation = handlers.call_tool(
        "validate_report",
        {"report_path": scan.report_path},
    )
    assert isinstance(validation, ValidateReportOutput)
    assert validation.passed is True
    assert validation.finding_count == 0


def test_list_findings_and_get_finding_sanitize_stored_report_values(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    report = scan_report_fixture(
        evidence_claim="PoC demonstrates malicious payload handling in uploads.",
        summary="Archive parser PoC with malicious payload details.",
    )
    task = report["remediation_tasks"][0]
    task["package"]["name"] = "proof-of-concept-payload-lib"
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(report),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    listed = handlers.call_tool("list_findings", {"scan_id": scan.scan_id})
    finding = handlers.call_tool(
        "get_finding",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )

    serialized = json.dumps(
        {
            "listed": listed.model_dump(mode="json"),
            "finding": finding.model_dump(mode="json"),
        }
    ).lower()
    assert "[redacted]" in serialized
    assert "proof-of-concept-payload-lib" not in serialized
    assert "malicious payload" not in serialized
    assert "poc" not in serialized


def test_list_findings_preserves_legitimate_payload_and_cookie_package_names(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    report = scan_report_fixture()
    report["remediation_tasks"][0]["package"]["name"] = "payload-parser"
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(report),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    listed = handlers.call_tool("list_findings", {"scan_id": scan.scan_id})
    finding = handlers.call_tool(
        "get_finding",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )

    assert listed.findings[0].package_name == "payload-parser"
    assert finding.finding.package.name == "payload-parser"


def test_scan_repo_rejects_workspace_escape_before_scanning(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    outside.mkdir()
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError, match="outside the allowed workspace"):
        handlers.call_tool("scan_repo", {"repo_path": "../outside"})


def test_input_validation_error_does_not_echo_unsafe_extra_field_name(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError) as caught:
        handlers.call_tool(
            "scan_repo",
            {
                "repo_path": "payments-api",
                "/Users/auditor/private-token": "value",
            },
        )

    message = str(caught.value)
    assert "Invalid input for scan_repo" in message
    assert "/Users/auditor" not in message
    assert "private-token" not in message


def test_report_store_rejects_unknown_scan_and_report_path_escape(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError, match="Scan report not found"):
        handlers.call_tool("list_findings", {"scan_id": "scan-missing"})

    outside_report = tmp_path / "outside-report.json"
    outside_report.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
    with pytest.raises(ToolHandlerError, match="store-relative"):
        handlers.call_tool("validate_report", {"report_path": str(outside_report)})


def test_list_findings_rejects_unsafe_scan_id_without_echoing_value(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    unsafe_scan_id = "/Users/example/private-token"
    with pytest.raises(ToolHandlerError) as caught:
        handlers.call_tool("list_findings", {"scan_id": unsafe_scan_id})

    message = str(caught.value)
    assert "Scan id is not safe for local report storage" in message
    assert "private-token" not in message
    assert "/Users/example" not in message


def test_load_by_scan_id_rejects_report_file_symlink_escape(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    outside = tmp_path / "outside"
    workspace.mkdir()
    storage.mkdir()
    outside.mkdir()
    outside_report = outside / "scan-escape.json"
    outside_report.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
    (storage / "scan-escape.json").symlink_to(outside_report)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError, match="outside the report store"):
        handlers.call_tool("list_findings", {"scan_id": "scan-escape"})


def test_list_findings_missing_scan_does_not_echo_scan_id(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError) as caught:
        handlers.call_tool("list_findings", {"scan_id": "safe-but-sensitive-id"})

    message = str(caught.value)
    assert message == "Scan report not found"
    assert "safe-but-sensitive-id" not in message


def test_validate_report_requires_store_relative_report_path(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    storage.mkdir()
    report_path = storage / "scan-test-001.json"
    report_path.write_text(json.dumps(scan_report_fixture()), encoding="utf-8")
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError, match="store-relative"):
        handlers.call_tool("validate_report", {"report_path": str(report_path)})


def test_validate_report_rejects_schema_invalid_report_before_quality_pass(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )
    report = scan_report_fixture()
    report.pop("schema_version")
    report_path = storage / "schema-invalid.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ToolHandlerError, match="Stored scan report is invalid"):
        handlers.call_tool("validate_report", {"report_path": report_path.name})


def test_default_report_store_rejects_symlink_escape_from_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside-reports"
    workspace.mkdir()
    outside.mkdir()
    (workspace / ".vulnsage-mcp-reports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ToolHandlerError, match="outside the allowed workspace"):
        McpToolHandlers(
            workspace_root=workspace,
            scan_service=FailingScanService(),
        )


def test_custom_report_store_outside_workspace_is_rejected(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside-reports"
    workspace.mkdir()
    outside.mkdir()

    with pytest.raises(ToolHandlerError, match="outside the allowed workspace"):
        McpToolHandlers(
            workspace_root=workspace,
            storage_dir=outside,
            scan_service=FailingScanService(),
        )


def test_report_store_rejects_outside_storage_dir_before_creating_it(tmp_path):
    workspace = tmp_path / "workspace"
    outside_storage = tmp_path / "outside" / "reports"
    workspace.mkdir()

    with pytest.raises(ReportStoreError, match="outside"):
        FileReportStore(outside_storage, allowed_root=workspace)

    assert not outside_storage.exists()


def test_scan_repo_does_not_write_through_existing_report_symlink(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    outside = tmp_path / "outside"
    repo.mkdir(parents=True)
    storage.mkdir()
    outside.mkdir()
    outside_report = outside / "secret-report.json"
    outside_report.write_text("keep me", encoding="utf-8")
    (storage / "scan-test-001.json").symlink_to(outside_report)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )

    with pytest.raises(ToolHandlerError, match="Unable to write scan report"):
        handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    assert outside_report.read_text(encoding="utf-8") == "keep me"


def test_dot_segment_scan_ids_are_rejected_before_report_lookup(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    for scan_id in [".", "..", ".hidden", "scan..hidden"]:
        with pytest.raises(ToolHandlerError, match="Scan id is not safe"):
            handlers.call_tool("list_findings", {"scan_id": scan_id})


def test_report_store_file_path_failure_becomes_tool_handler_error(tmp_path):
    workspace = tmp_path / "workspace"
    storage_file = workspace / "mcp-reports"
    workspace.mkdir()
    storage_file.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ToolHandlerError, match="Unable to initialize report store"):
        McpToolHandlers(
            workspace_root=workspace,
            storage_dir=storage_file,
            scan_service=FailingScanService(),
        )


def test_remediation_context_is_compact_and_redacts_exploit_payload_text(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    report = scan_report_fixture(
        evidence_claim="PoC demonstrates malicious payload handling in uploads.",
        summary="Archive parser PoC with exploit payload details.",
    )
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(report),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    context = handlers.call_tool(
        "get_remediation_context",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )

    assert isinstance(context, RemediationContextOutput)
    assert context.evidence_count == 2
    assert "archive-utils" in context.context_markdown
    assert len(context.context_markdown) < 2000
    lowered = context.context_markdown.lower()
    assert "poc" not in lowered
    assert "malicious payload" not in lowered
    assert "exploit payload" not in lowered


def test_ai_context_bundle_and_validation_tools_support_client_ai_flow(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    bundle_output = handlers.call_tool(
        "get_ai_context_bundle",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )

    assert isinstance(bundle_output, AIContextBundleOutput)
    bundle = bundle_output.bundle
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    assert "Use only the evidence in this bundle" in bundle["prompt"]

    validation = handlers.call_tool(
        "validate_ai_output",
        {
            "scan_id": scan.scan_id,
            "task_id": "task-archive-utils",
            "ai_output": {
                "finding_id": request["finding_id"],
                "package_name": request["package_name"],
                "vulnerability_id": request["vulnerability_id"],
                "priority": request["priority"],
                "risk_score": request["risk_score"],
                "summary": "archive-utils should be upgraded.",
                "explanation": "This answer cites the evidence bundle.",
                "citations": [{"claim_id": "claim-1", "evidence_id": evidence_id}],
                "claim_checks": [
                    {
                        "claim_id": "claim-1",
                        "claim": "archive-utils should be upgraded.",
                        "disposition": "fact",
                        "evidence_ids": [evidence_id],
                    }
                ],
                "provider_name": "client-ai",
            },
        },
    )

    assert isinstance(validation, ValidateAIOutputOutput)
    assert validation.passed is True
    assert validation.blocked is False


def test_ai_context_bundle_can_include_rag_evidence_from_stored_report(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    bundle_output = handlers.call_tool(
        "get_ai_context_bundle",
        {
            "scan_id": scan.scan_id,
            "task_id": "task-archive-utils",
            "include_rag": True,
            "top_k": 5,
        },
    )

    evidence = bundle_output.bundle["ai_request"]["evidence"]
    retrieved_evidence = [
        item for item in evidence if item["metadata"].get("origin") == "retrieved_context"
    ]
    assert len(evidence) > 2
    assert len(retrieved_evidence) > 0
    assert retrieved_evidence[0]["metadata"]["package"] == "archive-utils"
    assert retrieved_evidence[0]["metadata"]["vulnerability_id"] == "CVE-2026-0001"


def test_validate_ai_output_accepts_rag_evidence_from_stored_report(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})
    bundle_output = handlers.call_tool(
        "get_ai_context_bundle",
        {
            "scan_id": scan.scan_id,
            "task_id": "task-archive-utils",
            "include_rag": True,
        },
    )
    request = bundle_output.bundle["ai_request"]
    retrieved_evidence = [
        item
        for item in request["evidence"]
        if item["metadata"].get("origin") == "retrieved_context"
    ][0]

    validation = handlers.call_tool(
        "validate_ai_output",
        {
            "scan_id": scan.scan_id,
            "task_id": "task-archive-utils",
            "include_rag": True,
            "ai_output": {
                "finding_id": request["finding_id"],
                "package_name": request["package_name"],
                "vulnerability_id": request["vulnerability_id"],
                "priority": request["priority"],
                "risk_score": request["risk_score"],
                "summary": "archive-utils is supported by retrieved Sage evidence.",
                "explanation": "The output cites a retrieved evidence item from the bundle.",
                "citations": [
                    {"claim_id": "claim-1", "evidence_id": retrieved_evidence["id"]}
                ],
                "claim_checks": [
                    {
                        "claim_id": "claim-1",
                        "claim": str(retrieved_evidence["content"]),
                        "disposition": "fact",
                        "evidence_ids": [retrieved_evidence["id"]],
                    }
                ],
                "provider_name": "client-ai",
            },
        },
    )

    assert validation.passed is True
    assert validation.blocked is False


def test_validate_ai_output_blocks_uncited_client_ai_claims(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})
    bundle_output = handlers.call_tool(
        "get_ai_context_bundle",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )
    request = bundle_output.bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]

    validation = handlers.call_tool(
        "validate_ai_output",
        {
            "scan_id": scan.scan_id,
            "task_id": "task-archive-utils",
            "ai_output": {
                "finding_id": request["finding_id"],
                "package_name": request["package_name"],
                "vulnerability_id": request["vulnerability_id"],
                "priority": request["priority"],
                "risk_score": request["risk_score"],
                "summary": "archive-utils should be upgraded.",
                "explanation": "This answer lacks matching citations.",
                "citations": [],
                "claim_checks": [
                    {
                        "claim_id": "claim-1",
                        "claim": "archive-utils should be upgraded.",
                        "disposition": "fact",
                        "evidence_ids": [evidence_id],
                    }
                ],
                "provider_name": "client-ai",
            },
        },
    )

    assert isinstance(validation, ValidateAIOutputOutput)
    assert validation.passed is False
    assert validation.blocked is True
    assert "matching citation" in validation.summary


def test_remediation_context_sanitizes_compact_finding_values(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    report = scan_report_fixture()
    task = report["remediation_tasks"][0]
    task["package"]["name"] = "proof-of-concept-payload-lib"
    task["vulnerability"]["canonical_id"] = "CVE-payload-2026-0001"
    task["vulnerability"]["severity"] = "HIGH payload"
    task["patch_plan"]["target_version"] = "2.2.0-poc"
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(report),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    context = handlers.call_tool(
        "get_remediation_context",
        {"scan_id": scan.scan_id, "task_id": "task-archive-utils"},
    )

    serialized_finding = json.dumps(context.finding.model_dump(mode="json")).lower()
    assert "[redacted]" in serialized_finding
    assert "payload" not in serialized_finding
    assert "poc" not in serialized_finding
    assert "proof-of-concept" not in serialized_finding


def test_evidence_and_remediation_context_redact_unsafe_stored_task_ids(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    unsafe_task_id = "/Users/auditor/repo/private-token"
    report = scan_report_fixture()
    report["remediation_tasks"][0]["task_id"] = unsafe_task_id
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(report),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    evidence = handlers.call_tool(
        "get_finding_evidence",
        {"scan_id": scan.scan_id, "task_id": unsafe_task_id},
    )
    context = handlers.call_tool(
        "get_remediation_context",
        {"scan_id": scan.scan_id, "task_id": unsafe_task_id},
    )

    assert evidence.task_id == "[redacted-path]"
    assert context.task_id == "[redacted-path]"
    serialized = json.dumps(
        {
            "evidence": evidence.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
        }
    )
    assert "/Users/auditor" not in serialized
    assert "private-token" not in serialized


def test_validate_report_secret_like_json_error_does_not_echo_filename(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "mcp-reports"
    workspace.mkdir()
    storage.mkdir()
    report_path = storage / "private-token-report.json"
    report_path.write_text("{not-json", encoding="utf-8")
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=FailingScanService(),
    )

    with pytest.raises(ToolHandlerError) as caught:
        handlers.call_tool("validate_report", {"report_path": report_path.name})

    message = str(caught.value)
    assert message == "Scan report is not valid JSON: report file"
    assert "private-token-report.json" not in message
    assert "private-token" not in message


def test_get_finding_reports_missing_task_without_silent_empty_payload(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    with pytest.raises(ToolHandlerError, match="Finding not found"):
        handlers.call_tool(
            "get_finding",
            {"scan_id": scan.scan_id, "task_id": "task-missing-secret"},
        )


def test_get_finding_missing_task_does_not_echo_task_id(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "payments-api"
    storage = workspace / "mcp-reports"
    repo.mkdir(parents=True)
    handlers = McpToolHandlers(
        workspace_root=workspace,
        storage_dir=storage,
        scan_service=RecordingScanService(scan_report_fixture()),
    )
    scan = handlers.call_tool("scan_repo", {"repo_path": "payments-api", "offline": True})

    with pytest.raises(ToolHandlerError) as caught:
        handlers.call_tool(
            "get_finding",
            {"scan_id": scan.scan_id, "task_id": "task-missing-secret"},
        )

    message = str(caught.value)
    assert message == "Finding not found"
    assert "task-missing-secret" not in message


def scan_report_fixture(
    *,
    evidence_claim: str = "archive-utils@1.4.0 is installed in package-lock.json.",
    summary: str = "Archive parsing vulnerability.",
) -> dict[str, object]:
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_id": "scan-test-001",
        "repo_profile": {"repo_name": "payments-api"},
        "packages": [],
        "vulnerabilities": [],
        "summary": {
            "complete": True,
            "scan_status": "complete",
            "packages": 2,
            "raw_alerts": 2,
            "deduped_remediation_tasks": 2,
            "release_blockers": 0,
            "recommended_sprint_fixes": 2,
            "safe_to_defer": 0,
            "needs_human_review": 0,
            "error_count": 0,
            "priority_counts": {"P1_FIX_THIS_SPRINT": 2},
        },
        "remediation_tasks": [
            remediation_task_fixture(
                "task-archive-utils",
                "archive-utils",
                evidence_claim=evidence_claim,
                summary=summary,
            ),
            remediation_task_fixture("task-image-tool", "image-tool"),
        ],
        "errors": [],
    }


def remediation_task_fixture(
    task_id: str,
    package_name: str,
    *,
    evidence_claim: str | None = None,
    summary: str | None = None,
) -> dict[str, object]:
    claim = (
        "%s@1.4.0 is installed in package-lock.json." % package_name
        if evidence_claim is None
        else evidence_claim
    )
    vulnerability_summary = (
        "%s unsafe deserialization can affect archive parsing." % package_name
        if summary is None
        else summary
    )
    return {
        "task_id": task_id,
        "repo": "payments-api",
        "package": {
            "name": package_name,
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "dependencies",
            "is_direct": True,
            "parent_package": None,
        },
        "vulnerability": {
            "canonical_id": "CVE-2026-0001",
            "source_id": "GHSA-archive",
            "aliases": ["GHSA-archive"],
            "severity": "HIGH",
            "summary": vulnerability_summary,
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 78,
            "known_exploited": None,
            "epss_score": None,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "factors": {},
            "rationale": ["Risk score 78 maps to P1_FIX_THIS_SPRINT."],
        },
        "evidence": [
            {
                "type": "lockfile_entry",
                "source": "package-lock.json",
                "claim": claim,
            },
            {
                "type": "reachability",
                "source": "src/upload.ts",
                "claim": "%s is imported by the production upload route." % package_name,
            },
        ],
        "patch_plan": {
            "recommended_action": "upgrade",
            "target_version": "2.2.0",
            "patch_complexity": "low",
            "breaking_change_risk": "low",
            "steps": ["Upgrade %s to 2.2.0." % package_name],
            "test_plan": ["Run npm test."],
            "rollback_plan": ["Revert package lockfile changes."],
            "pr_description": "Upgrade %s for CVE-2026-0001." % package_name,
        },
        "test_plan": ["Run npm test."],
        "rollback_plan": ["Revert package lockfile changes."],
        "owner": None,
        "human_approval_required": True,
    }
