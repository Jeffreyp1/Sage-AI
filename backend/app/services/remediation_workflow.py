"""Deterministic remediation task workflow service."""

import logging
from dataclasses import dataclass

from sqlalchemy import update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models import (
    HumanApproval,
    PackageVulnerability,
    RemediationTask,
)
from app.services.public_safety import sanitize_public_value, sanitize_text


APPROVED_STATUS = "approved"
OPEN_STATUS = "open"
REJECTED_STATUS = "rejected"
RISK_ACCEPTED_STATUS = "risk_accepted"


logger = logging.getLogger(__name__)


class RemediationWorkflowError(Exception):
    """Base error for remediation workflow operations."""


class TaskNotFoundError(RemediationWorkflowError):
    """Raised when a remediation task does not exist."""


class WorkflowValidationError(RemediationWorkflowError):
    """Raised when a workflow request is missing required human input."""


class InvalidWorkflowActionError(RemediationWorkflowError):
    """Raised when a task cannot move to the requested lifecycle state."""


class WorkflowPersistenceError(RemediationWorkflowError):
    """Raised when a workflow decision cannot be persisted."""


@dataclass(frozen=True)
class WorkflowDecision:
    action_type: str
    status: str
    approver: str
    reason: str | None
    requested_by: str | None


class RemediationWorkflowService:
    """Applies human-controlled remediation task lifecycle transitions."""

    def get_task(self, db: Session, task_id: str) -> dict:
        task = self._get_task_model(db, task_id)
        try:
            return serialize_task(db, task)
        except SQLAlchemyError as exc:
            raise_persistence_error(task_id, "serialize_task", exc)

    def approve_task(
        self,
        db: Session,
        task_id: str,
        approver: str,
        reason: str | None = None,
        requested_by: str | None = None,
    ) -> dict:
        decision = WorkflowDecision(
            action_type="approve",
            status=APPROVED_STATUS,
            approver=require_text(approver, "approver"),
            reason=optional_text(reason),
            requested_by=optional_text(requested_by),
        )
        return self._apply_decision(db, task_id, decision)

    def reject_task(
        self,
        db: Session,
        task_id: str,
        approver: str,
        reason: str | None = None,
        requested_by: str | None = None,
    ) -> dict:
        decision = WorkflowDecision(
            action_type="reject",
            status=REJECTED_STATUS,
            approver=require_text(approver, "approver"),
            reason=optional_text(reason),
            requested_by=optional_text(requested_by),
        )
        return self._apply_decision(db, task_id, decision)

    def accept_risk(
        self,
        db: Session,
        task_id: str,
        approver: str,
        reason: str,
        requested_by: str | None = None,
    ) -> dict:
        decision = WorkflowDecision(
            action_type="accept_risk",
            status=RISK_ACCEPTED_STATUS,
            approver=require_text(approver, "approver"),
            reason=require_text(reason, "reason"),
            requested_by=optional_text(requested_by),
        )
        return self._apply_decision(db, task_id, decision)

    def generate_draft(self, db: Session, task_id: str) -> dict:
        task = self._get_task_model(db, task_id)
        try:
            return {
                "task_id": public_text(task.id),
                "status": public_text(task.status),
                "title": draft_title(task),
                "body": draft_body(task),
                "side_effects": [],
            }
        except SQLAlchemyError as exc:
            raise_persistence_error(task_id, "generate_draft", exc)

    def _apply_decision(
        self,
        db: Session,
        task_id: str,
        decision: WorkflowDecision,
    ) -> dict:
        task = self._get_task_model(db, task_id)
        ensure_open_task(task)
        approval = HumanApproval(
            remediation_task_id=task.id,
            action_type=decision.action_type,
            status=decision.status,
            requested_by=approval_text(decision.requested_by),
            approved_by=approval_text(decision.approver),
            decision_reason=approval_text(decision.reason),
        )
        try:
            update_result = db.execute(
                update(RemediationTask)
                .where(RemediationTask.id == task.id)
                .where(RemediationTask.status == OPEN_STATUS)
                .values(status=decision.status)
                .execution_options(synchronize_session="fetch")
            )
            if update_result.rowcount != 1:
                db.rollback()
                raise InvalidWorkflowActionError(
                    "Remediation task is not open and cannot be changed by this action."
                )
            db.add(approval)
            db.flush()
            response = serialize_task(db, task)
            db.commit()
        except SQLAlchemyError as exc:
            db.rollback()
            raise_persistence_error(task_id, decision.action_type, exc)
        return response

    def _get_task_model(self, db: Session, task_id: str) -> RemediationTask:
        try:
            task = (
                db.query(RemediationTask)
                .filter(RemediationTask.id == task_id)
                .one_or_none()
            )
        except SQLAlchemyError as exc:
            raise_persistence_error(task_id, "task_lookup", exc)
        if task is None:
            raise TaskNotFoundError("Remediation task not found.")
        return task


def ensure_open_task(task: RemediationTask) -> None:
    if task.status == OPEN_STATUS:
        return
    raise InvalidWorkflowActionError(
        "Remediation task is not open and cannot be changed by this action."
    )


def raise_persistence_error(task_id: str, operation: str, exc: SQLAlchemyError) -> None:
    logger.error(
        "Remediation workflow persistence failed.",
        extra={
            "task_id": public_text(task_id),
            "operation": sanitize_text(operation),
            "exception_class": sanitize_text(exc.__class__.__name__),
        },
    )
    raise WorkflowPersistenceError("Remediation workflow persistence failed.") from exc


def require_text(value: str | None, field_name: str) -> str:
    if value is None:
        raise WorkflowValidationError("%s is required." % field_name)
    stripped = value.strip()
    if stripped == "":
        raise WorkflowValidationError("%s is required." % field_name)
    return stripped


def optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    if stripped == "":
        return None
    return stripped


def serialize_task(db: Session, task: RemediationTask) -> dict:
    package = task.package_vulnerability.package
    vulnerability = task.package_vulnerability.vulnerability
    approvals = (
        db.query(HumanApproval)
        .filter(HumanApproval.remediation_task_id == task.id)
        .order_by(HumanApproval.created_at.asc(), HumanApproval.id.asc())
        .all()
    )
    return {
        "id": public_text(task.id),
        "repo_id": public_text(task.repo_id),
        "repo": public_text(task.repo.full_name),
        "package": {
            "name": public_text(package.name),
            "ecosystem": public_text(package.ecosystem),
            "current_version": public_text(package.current_version),
            "dependency_type": public_text(package.dependency_type),
            "is_direct": package.is_direct,
        },
        "vulnerability": {
            "canonical_id": public_text(vulnerability.canonical_id),
            "severity": public_text(vulnerability.severity),
            "summary": public_text(vulnerability.summary),
            "fixed_versions": sanitize_public_value(task.package_vulnerability.fixed_versions_json),
        },
        "priority": public_text(task.priority),
        "risk_score": task.risk_score,
        "status": public_text(task.status),
        "owner": public_text(task.owner),
        "recommended_action": public_text(task.recommended_action),
        "patch_plan": sanitize_public_value(task.patch_plan_json),
        "test_plan": sanitize_public_value(task.test_plan_json),
        "rollback_plan": sanitize_public_value(task.rollback_plan_json),
        "citations": sanitize_public_value(task.citations_json),
        "approvals": [
            {
                "id": public_text(approval.id),
                "action_type": public_text(approval.action_type),
                "status": public_text(approval.status),
                "requested_by": approval_text(approval.requested_by),
                "approved_by": approval_text(approval.approved_by),
                "decision_reason": approval_text(approval.decision_reason),
                "created_at": public_text(approval.created_at.isoformat()),
            }
            for approval in approvals
        ],
    }


def approval_text(value: str | None) -> str | None:
    if value is None:
        return None
    return sanitize_text(value)


def public_text(value: str | None) -> str | None:
    if value is None:
        return None
    return sanitize_text(value)


def draft_title(task: RemediationTask) -> str:
    package = task.package_vulnerability.package
    vulnerability = task.package_vulnerability.vulnerability
    return sanitize_text(
        "Remediate %s in %s" % (vulnerability.canonical_id, package.name)
    )


def draft_body(task: RemediationTask) -> str:
    package = task.package_vulnerability.package
    vulnerability = task.package_vulnerability.vulnerability
    fixed_versions = safe_fixed_versions(task.package_vulnerability)
    lines = [
        "Summary",
        "- Repository: %s" % safe_text(task.repo.full_name),
        "- Package: %s (%s), current version %s"
        % (
            safe_text(package.name),
            safe_text(package.ecosystem),
            safe_text(package.current_version or "unknown"),
        ),
        "- Vulnerability: %s, severity %s"
        % (safe_text(vulnerability.canonical_id), safe_text(vulnerability.severity)),
        "- Recommended action: %s" % safe_text(task.recommended_action),
        "- Fixed versions: %s" % fixed_versions,
        "",
        "Evidence",
    ]
    lines.extend(evidence_lines(task.citations_json))
    lines.extend(section_lines("Plan", step_values(task.patch_plan_json, "steps")))
    lines.extend(section_lines("Validation", string_list(task.test_plan_json)))
    lines.extend(section_lines("Rollback", string_list(task.rollback_plan_json)))
    lines.extend(
        [
            "",
            "Human control",
            "- Draft text only; review is required before PR creation, ticket creation, merge, close, or fixed-state update.",
        ]
    )
    return sanitize_text("\n".join(lines))


def evidence_lines(citations: object) -> list[str]:
    if not isinstance(citations, list) or len(citations) == 0:
        return ["- No persisted evidence citations are available."]
    lines = []
    for citation in citations:
        if not isinstance(citation, dict):
            continue
        source = safe_text(str(citation.get("source") or "unknown source"))
        claim = safe_text(str(citation.get("claim") or "Evidence citation recorded."))
        lines.append("- %s: %s" % (source, claim))
    if len(lines) == 0:
        return ["- No persisted evidence citations are available."]
    return lines


def section_lines(title: str, values: list[str]) -> list[str]:
    if len(values) == 0:
        return []
    lines = ["", title]
    for value in values:
        lines.append("- %s" % safe_text(value))
    return lines


def step_values(value: object, key: str) -> list[str]:
    if not isinstance(value, dict):
        return []
    return string_list(value.get(key))


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
    return result


def safe_fixed_versions(package_vulnerability: PackageVulnerability) -> str:
    versions = string_list(package_vulnerability.fixed_versions_json)
    if len(versions) == 0:
        return "none listed"
    return ", ".join(safe_text(version) for version in versions)


def safe_text(value: str) -> str:
    return sanitize_text(value)
