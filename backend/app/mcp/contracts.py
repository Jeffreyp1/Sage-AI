"""Safe MCP tool contract shared by future Claude, Cursor, and Codex adapters."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from app.schemas.report import RemediationTaskSchema, ScanSummarySchema


MCP_TOOL_NAMES = (
    "scan_repo",
    "list_findings",
    "get_finding",
    "get_finding_evidence",
    "get_remediation_context",
    "get_ai_context_bundle",
    "validate_ai_output",
    "validate_report",
)
UNSAFE_TOOL_NAME_FRAGMENTS = (
    "shell",
    "exec",
    "command",
    "write_file",
    "delete",
    "merge",
    "accept_risk",
    "mark_fixed",
    "auto_fix",
)
MAX_FINDINGS_LIMIT = 50
MAX_INPUT_STRING_LENGTH = 512


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanRepoInput(ContractModel):
    repo_path: str = Field(
        default=".",
        description="Repo-relative path to scan.",
        validation_alias=AliasChoices("repo_path", "path"),
        max_length=MAX_INPUT_STRING_LENGTH,
    )
    offline: bool = Field(default=False, description="Disable external vulnerability lookups.")
    max_findings: int = Field(default=10, ge=1, le=MAX_FINDINGS_LIMIT)


class CompactFinding(ContractModel):
    task_id: str
    package_name: str
    vulnerability_id: str
    priority: str
    risk_score: int = Field(ge=0, le=100)
    severity: str | None = None
    target_version: str | None = None


class ScanRepoOutput(ContractModel):
    schema_version: str
    scan_id: str
    complete: bool
    scan_status: str
    error_count: int = Field(ge=0)
    summary: ScanSummarySchema
    top_findings: list[CompactFinding] = Field(default_factory=list)
    report_path: str | None = None


class ListFindingsInput(ContractModel):
    scan_id: str = Field(max_length=MAX_INPUT_STRING_LENGTH)
    limit: int = Field(default=10, ge=1, le=MAX_FINDINGS_LIMIT)

    @field_validator("limit")
    @classmethod
    def clamp_limit(cls, value: int) -> int:
        if value > MAX_FINDINGS_LIMIT:
            return MAX_FINDINGS_LIMIT
        return value


class ListFindingsOutput(ContractModel):
    scan_id: str
    findings: list[CompactFinding]


class FindingInput(ContractModel):
    scan_id: str = Field(max_length=MAX_INPUT_STRING_LENGTH)
    task_id: str = Field(max_length=MAX_INPUT_STRING_LENGTH)


class AIContextBundleInput(FindingInput):
    include_rag: bool = Field(
        default=False,
        description="Include retrieved report evidence chunks in the AI context bundle.",
    )
    top_k: int = Field(default=5, ge=1, le=10)


class FindingOutput(ContractModel):
    scan_id: str
    finding: RemediationTaskSchema


class FindingEvidenceOutput(ContractModel):
    scan_id: str
    task_id: str
    evidence: list[dict[str, str]]


class RemediationContextOutput(ContractModel):
    scan_id: str
    task_id: str
    context_markdown: str
    finding: CompactFinding
    evidence_count: int = Field(ge=0)


class AIContextBundleOutput(ContractModel):
    scan_id: str
    task_id: str
    bundle: dict[str, object]


class ValidateAIOutputInput(ContractModel):
    scan_id: str = Field(max_length=MAX_INPUT_STRING_LENGTH)
    task_id: str = Field(max_length=MAX_INPUT_STRING_LENGTH)
    ai_output: dict[str, object]
    include_rag: bool = Field(
        default=False,
        description="Validate against retrieved report evidence chunks too.",
    )
    top_k: int = Field(default=5, ge=1, le=10)


class ValidateAIOutputOutput(ContractModel):
    scan_id: str
    task_id: str
    passed: bool
    blocked: bool
    summary: str
    validation: dict[str, object]


class ValidateReportInput(ContractModel):
    report_path: str = Field(max_length=MAX_INPUT_STRING_LENGTH)


class ValidateReportOutput(ContractModel):
    passed: bool
    finding_count: int = Field(ge=0)
    summary: str
    findings: list[dict[str, object]] = Field(default_factory=list)


@dataclass(frozen=True)
class ToolContract:
    name: str
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]


def tool_contracts() -> tuple[ToolContract, ...]:
    return (
        ToolContract(
            name="scan_repo",
            description="Scan a repo path and return a compact vulnerability triage summary.",
            input_model=ScanRepoInput,
            output_model=ScanRepoOutput,
        ),
        ToolContract(
            name="list_findings",
            description="List compact findings for an existing scan.",
            input_model=ListFindingsInput,
            output_model=ListFindingsOutput,
        ),
        ToolContract(
            name="get_finding",
            description="Return one full remediation finding from an existing scan.",
            input_model=FindingInput,
            output_model=FindingOutput,
        ),
        ToolContract(
            name="get_finding_evidence",
            description="Return evidence items for one remediation finding.",
            input_model=FindingInput,
            output_model=FindingEvidenceOutput,
        ),
        ToolContract(
            name="get_remediation_context",
            description="Return compact AI-safe context for explaining one finding.",
            input_model=FindingInput,
            output_model=RemediationContextOutput,
        ),
        ToolContract(
            name="get_ai_context_bundle",
            description="Return a client-AI case file with evidence IDs, rules, prompt, and schema.",
            input_model=AIContextBundleInput,
            output_model=AIContextBundleOutput,
        ),
        ToolContract(
            name="validate_ai_output",
            description="Validate a client AI answer against one finding's evidence bundle.",
            input_model=ValidateAIOutputInput,
            output_model=ValidateAIOutputOutput,
        ),
        ToolContract(
            name="validate_report",
            description="Validate a public report for unsafe or unsupported output.",
            input_model=ValidateReportInput,
            output_model=ValidateReportOutput,
        ),
    )
