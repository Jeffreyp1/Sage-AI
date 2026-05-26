"""Remediation task lifecycle API routes."""

from collections.abc import Callable

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.services.remediation_workflow import (
    InvalidWorkflowActionError,
    RemediationWorkflowService,
    TaskNotFoundError,
    WorkflowPersistenceError,
    WorkflowValidationError,
)

router = APIRouter(prefix="/remediation-tasks", tags=["remediation-tasks"])


class ApprovalActionRequest(BaseModel):
    approver: str = Field(..., description="Human approver making the decision.")
    reason: str | None = Field(None, description="Optional human decision reason.")
    requested_by: str | None = Field(None, description="Optional requester identifier.")


class AcceptRiskRequest(BaseModel):
    approver: str = Field(..., description="Human approver accepting the risk.")
    reason: str = Field(..., description="Required human reason for accepting risk.")
    requested_by: str | None = Field(None, description="Optional requester identifier.")


@router.get("/{task_id}")
def get_remediation_task(task_id: str, db: Session = Depends(get_db)) -> dict:
    return handle_workflow(lambda: RemediationWorkflowService().get_task(db, task_id))


@router.post("/{task_id}/approve")
def approve_remediation_task(
    task_id: str,
    request: ApprovalActionRequest,
    db: Session = Depends(get_db),
) -> dict:
    return handle_workflow(
        lambda: RemediationWorkflowService().approve_task(
            db,
            task_id,
            approver=request.approver,
            reason=request.reason,
            requested_by=request.requested_by,
        )
    )


@router.post("/{task_id}/reject")
def reject_remediation_task(
    task_id: str,
    request: ApprovalActionRequest,
    db: Session = Depends(get_db),
) -> dict:
    return handle_workflow(
        lambda: RemediationWorkflowService().reject_task(
            db,
            task_id,
            approver=request.approver,
            reason=request.reason,
            requested_by=request.requested_by,
        )
    )


@router.post("/{task_id}/accept-risk")
def accept_remediation_risk(
    task_id: str,
    request: AcceptRiskRequest,
    db: Session = Depends(get_db),
) -> dict:
    return handle_workflow(
        lambda: RemediationWorkflowService().accept_risk(
            db,
            task_id,
            approver=request.approver,
            reason=request.reason,
            requested_by=request.requested_by,
        )
    )


@router.post("/{task_id}/draft")
def draft_remediation_text(
    task_id: str,
    db: Session = Depends(get_db),
) -> dict:
    return handle_workflow(lambda: RemediationWorkflowService().generate_draft(db, task_id))


def handle_workflow(operation: Callable[[], dict]) -> dict:
    try:
        return operation()
    except TaskNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except WorkflowValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except InvalidWorkflowActionError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except WorkflowPersistenceError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
