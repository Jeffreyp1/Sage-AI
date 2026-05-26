"""Repository and scan API routes."""

import tempfile

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Package, RemediationTask, Repo, Scan
from app.schemas.scan import ScanGitHubRequest, ScanLocalRequest, ScanLocalResponse
from app.services.github_ingestion import (
    GitHubCloneError,
    GitHubRepository,
    InvalidGitHubUrlError,
    clone_github_repo,
    parse_github_repo_url,
)
from app.services.persistence import RepoPersistenceIdentity, persist_scan_result
from app.services.scan_service import ScanService

router = APIRouter(prefix="/repos", tags=["repos"])


@router.post("/scan-local", response_model=ScanLocalResponse)
def scan_local(request: ScanLocalRequest, db: Session = Depends(get_db)) -> ScanLocalResponse:
    result = ScanService().scan_local(request.path)
    persisted_scan_id = None
    if request.persist:
        scan = persist_scan_result(db, result)
        persisted_scan_id = scan.id
    data = result.to_dict()
    return ScanLocalResponse(
        scan_id=result.scan_id,
        persisted_scan_id=persisted_scan_id,
        repo_profile=data["repo_profile"],
        summary=data["summary"],
        remediation_tasks=data["remediation_tasks"],
        errors=data["errors"],
    )


@router.post("/scan-github", response_model=ScanLocalResponse)
def scan_github(request: ScanGitHubRequest, db: Session = Depends(get_db)) -> ScanLocalResponse:
    try:
        repository = parse_github_repo_url(request.url)
    except InvalidGitHubUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    with tempfile.TemporaryDirectory(prefix="vulnsage-github-") as temp_dir:
        try:
            repo_path = clone_github_repo(request.url, temp_dir)
        except InvalidGitHubUrlError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except GitHubCloneError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

        result = ScanService().scan_local(str(repo_path))

    persisted_scan_id = None
    if request.persist:
        scan = persist_scan_result(db, result, repo_identity=github_repo_identity(repository))
        persisted_scan_id = scan.id
    data = result.to_dict()
    return ScanLocalResponse(
        scan_id=result.scan_id,
        persisted_scan_id=persisted_scan_id,
        repo_profile=github_repo_profile(data["repo_profile"], repository),
        summary=data["summary"],
        remediation_tasks=data["remediation_tasks"],
        errors=data["errors"],
    )


def github_repo_identity(repository: GitHubRepository) -> RepoPersistenceIdentity:
    return RepoPersistenceIdentity(
        provider="github",
        name=repository.repo,
        full_name=repository.full_name,
        remote_url=repository.clone_url,
        organization_name=repository.owner,
    )


def github_repo_profile(
    repo_profile: dict,
    repository: GitHubRepository,
) -> dict:
    github_profile = dict(repo_profile)
    github_profile["provider"] = "github"
    github_profile["repo_name"] = repository.repo
    github_profile["full_name"] = repository.full_name
    github_profile["remote_url"] = repository.clone_url
    github_profile["root_path"] = repository.clone_url
    return github_profile


@router.get("")
def list_repos(db: Session = Depends(get_db)) -> list:
    repos = db.query(Repo).order_by(Repo.created_at.desc()).all()
    return [
        {
            "id": repo.id,
            "name": repo.name,
            "full_name": repo.full_name,
            "provider": repo.provider,
            "language": repo.language,
            "service_type": repo.service_type,
            "created_at": repo.created_at.isoformat(),
            "updated_at": repo.updated_at.isoformat(),
        }
        for repo in repos
    ]


@router.get("/{repo_id}")
def get_repo(repo_id: str, db: Session = Depends(get_db)) -> dict:
    repo = db.query(Repo).filter(Repo.id == repo_id).one()
    return {
        "id": repo.id,
        "name": repo.name,
        "full_name": repo.full_name,
        "provider": repo.provider,
        "remote_url": repo.remote_url,
        "language": repo.language,
        "service_type": repo.service_type,
    }


@router.get("/{repo_id}/scans")
def list_scans(repo_id: str, db: Session = Depends(get_db)) -> list:
    scans = db.query(Scan).filter(Scan.repo_id == repo_id).order_by(Scan.started_at.desc()).all()
    return [
        {
            "id": scan.id,
            "status": scan.status,
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "summary": scan.summary_json,
        }
        for scan in scans
    ]


@router.get("/{repo_id}/packages")
def list_packages(repo_id: str, db: Session = Depends(get_db)) -> list:
    packages = db.query(Package).filter(Package.repo_id == repo_id).order_by(Package.name.asc()).all()
    return [
        {
            "id": package.id,
            "name": package.name,
            "ecosystem": package.ecosystem,
            "current_version": package.current_version,
            "dependency_type": package.dependency_type,
            "is_direct": package.is_direct,
            "parent_package": package.parent_package,
        }
        for package in packages
    ]


@router.get("/{repo_id}/remediation-tasks")
def list_remediation_tasks(repo_id: str, db: Session = Depends(get_db)) -> list:
    tasks = (
        db.query(RemediationTask)
        .filter(RemediationTask.repo_id == repo_id)
        .order_by(RemediationTask.risk_score.desc())
        .all()
    )
    return [
        {
            "id": task.id,
            "priority": task.priority,
            "risk_score": task.risk_score,
            "status": task.status,
            "owner": task.owner,
            "recommended_action": task.recommended_action,
            "patch_plan": task.patch_plan_json,
            "test_plan": task.test_plan_json,
            "rollback_plan": task.rollback_plan_json,
            "citations": task.citations_json,
        }
        for task in tasks
    ]
