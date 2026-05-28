"""Request and response schemas for scans."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.report import (
    REPORT_SCHEMA_VERSION,
    RemediationTaskSchema,
    RepoProfileSchema,
    ScanSummarySchema,
)


class ScanLocalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Local repository path to scan.")
    persist: bool = Field(True, description="Persist scan results to the database.")


class ScanGitHubRequest(BaseModel):
    url: str = Field(..., description="GitHub repository URL to clone and scan.")
    persist: bool = Field(True, description="Persist scan results to the database.")


class ScanLocalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = REPORT_SCHEMA_VERSION
    scan_id: str
    persisted_scan_id: Optional[str] = None
    repo_profile: RepoProfileSchema
    summary: ScanSummarySchema
    remediation_tasks: list[RemediationTaskSchema]
    errors: list[str] = []
