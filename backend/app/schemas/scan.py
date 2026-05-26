"""Request and response schemas for scans."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanLocalRequest(BaseModel):
    path: str = Field(..., description="Local repository path to scan.")
    persist: bool = Field(True, description="Persist scan results to the database.")


class ScanGitHubRequest(BaseModel):
    url: str = Field(..., description="GitHub repository URL to clone and scan.")
    persist: bool = Field(True, description="Persist scan results to the database.")


class ScanLocalResponse(BaseModel):
    scan_id: str
    persisted_scan_id: Optional[str] = None
    repo_profile: Dict[str, Any]
    summary: Dict[str, Any]
    remediation_tasks: List[Dict[str, Any]]
    errors: List[str] = []
