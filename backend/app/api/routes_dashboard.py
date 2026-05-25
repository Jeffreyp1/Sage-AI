"""Minimal dashboard summary route for the backend MVP."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import RemediationTask, Repo, Scan

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def dashboard_summary(db: Session = Depends(get_db)) -> dict:
    repo_count = db.query(Repo).count()
    scan_count = db.query(Scan).count()
    task_count = db.query(RemediationTask).count()
    release_blockers = (
        db.query(RemediationTask)
        .filter(RemediationTask.priority == "P0_RELEASE_BLOCKER")
        .count()
    )
    return {
        "repos_scanned": repo_count,
        "scans": scan_count,
        "deduped_remediation_tasks": task_count,
        "release_blockers": release_blockers,
    }

