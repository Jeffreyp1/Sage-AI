"""Repository and scan API routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Package, RemediationTask, Repo, Scan
from app.schemas.scan import ScanLocalRequest, ScanLocalResponse
from app.services.persistence import persist_scan_result
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

