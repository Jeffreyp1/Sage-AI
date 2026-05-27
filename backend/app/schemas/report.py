"""Stable public scan report schemas shared by CLI, API, and MCP adapters."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


REPORT_SCHEMA_VERSION = "v1"
ScanStatus = Literal["complete", "incomplete"]


class ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepoProfileSchema(ReportModel):
    repo_name: str
    root_path: str | None = None
    provider: str | None = None
    full_name: str | None = None
    remote_url: str | None = None
    languages: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    lockfiles: list[str] = Field(default_factory=list)
    service_type: str | None = None
    test_commands: list[str] = Field(default_factory=list)
    codeowners: dict[str, str] = Field(default_factory=dict)


class ScanSummarySchema(ReportModel):
    complete: bool
    scan_status: ScanStatus
    packages: int = Field(ge=0)
    raw_alerts: int = Field(ge=0)
    deduped_remediation_tasks: int = Field(ge=0)
    release_blockers: int = Field(ge=0)
    recommended_sprint_fixes: int = Field(default=0, ge=0)
    safe_to_defer: int = Field(default=0, ge=0)
    needs_human_review: int = Field(default=0, ge=0)
    error_count: int = Field(default=0, ge=0)
    priority_counts: dict[str, int] = Field(default_factory=dict)


class DependencyRecordSchema(ReportModel):
    name: str
    current_version: str | None = None
    ecosystem: str
    dependency_type: str
    is_direct: bool
    parent_package: str | None = None
    manifest_path: str | None = None
    lockfile_path: str | None = None
    version_spec: str | None = None
    lockfile_entry_path: str | None = None
    evidence: list["EvidenceItemSchema"] = Field(default_factory=list)


class VulnerabilityRecordSchema(ReportModel):
    canonical_id: str
    source_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    package: str | None = None
    ecosystem: str | None = None
    current_version: str | None = None
    summary: str | None = None
    severity: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)
    published_at: str | None = None
    modified_at: str | None = None
    details_redacted: bool | None = None


class PackageInfoSchema(ReportModel):
    name: str
    ecosystem: str
    current_version: str | None = None
    dependency_type: str
    is_direct: bool
    parent_package: str | None = None


class TaskVulnerabilitySchema(ReportModel):
    canonical_id: str
    source_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    severity: str | None = None
    summary: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)


class RiskSchema(ReportModel):
    priority: str
    risk_score: int = Field(ge=0, le=100)
    known_exploited: bool | None = None
    epss_score: float | None = None
    runtime_scope: str | None = None
    reachability: str | None = None
    confidence: float | str | None = None
    factors: dict[str, float] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)


class EvidenceItemSchema(ReportModel):
    type: str
    source: str
    claim: str
    quote: str | None = None


class PatchPlanSchema(ReportModel):
    recommended_action: str | None = None
    target_version: str | None = None
    patch_complexity: str | None = None
    breaking_change_risk: str | None = None
    steps: list[str] = Field(default_factory=list)
    test_plan: list[str] = Field(default_factory=list)
    rollback_plan: list[str] = Field(default_factory=list)
    pr_description: str | None = None


class RemediationTaskSchema(ReportModel):
    task_id: str
    repo: str
    package: PackageInfoSchema
    vulnerability: TaskVulnerabilitySchema
    risk: RiskSchema
    evidence: list[EvidenceItemSchema] = Field(default_factory=list)
    patch_plan: PatchPlanSchema
    test_plan: list[str] = Field(default_factory=list)
    rollback_plan: list[str] = Field(default_factory=list)
    owner: str | None = None
    human_approval_required: bool = True


class ScanReport(ReportModel):
    schema_version: Literal["v1"]
    scan_id: str
    repo_profile: RepoProfileSchema
    packages: list[DependencyRecordSchema] = Field(default_factory=list)
    vulnerabilities: list[VulnerabilityRecordSchema] = Field(default_factory=list)
    remediation_tasks: list[RemediationTaskSchema] = Field(default_factory=list)
    summary: ScanSummarySchema
    errors: list[str] = Field(default_factory=list)
