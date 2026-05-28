import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import (
    HumanApproval,
    Package,
    PackageVulnerability,
    RemediationTask,
    Repo,
    Vulnerability,
)
from app.services import remediation_workflow
from app.services.public_safety import contains_unsafe_public_text
from app.services.remediation_workflow import (
    InvalidWorkflowActionError,
    RemediationWorkflowService,
    WorkflowPersistenceError,
    WorkflowValidationError,
)


def test_approve_transitions_task_and_creates_human_approval():
    db = make_session()
    task_id = create_remediation_task(db)

    result = RemediationWorkflowService().approve_task(
        db,
        task_id,
        approver="security@example.test",
        reason="Patch plan reviewed.",
        requested_by="developer@example.test",
    )

    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    approval = db.query(HumanApproval).one()
    assert task.status == "approved"
    assert result["status"] == "approved"
    assert approval.remediation_task_id == task_id
    assert approval.action_type == "approve"
    assert approval.status == "approved"
    assert approval.approved_by == "security@example.test"
    assert approval.requested_by == "developer@example.test"
    assert approval.decision_reason == "Patch plan reviewed."


def test_reject_transitions_task_and_creates_human_approval():
    db = make_session()
    task_id = create_remediation_task(db)

    result = RemediationWorkflowService().reject_task(
        db,
        task_id,
        approver="security@example.test",
        reason="Upgrade target is not compatible.",
    )

    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    approval = db.query(HumanApproval).one()
    assert task.status == "rejected"
    assert result["status"] == "rejected"
    assert approval.action_type == "reject"
    assert approval.status == "rejected"
    assert approval.approved_by == "security@example.test"
    assert approval.decision_reason == "Upgrade target is not compatible."


def test_accept_risk_requires_human_reason_and_approver():
    db = make_session()
    task_id = create_remediation_task(db)
    service = RemediationWorkflowService()

    with pytest.raises(WorkflowValidationError, match="reason is required"):
        service.accept_risk(db, task_id, approver="security@example.test", reason=" ")

    with pytest.raises(WorkflowValidationError, match="approver is required"):
        service.accept_risk(db, task_id, approver="", reason="Business exception.")

    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"
    assert db.query(HumanApproval).count() == 0


def test_accept_risk_transitions_task_and_records_reason():
    db = make_session()
    task_id = create_remediation_task(db)

    result = RemediationWorkflowService().accept_risk(
        db,
        task_id,
        approver="security@example.test",
        reason="Temporary exception until vendor patch is certified.",
    )

    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    approval = db.query(HumanApproval).one()
    assert task.status == "risk_accepted"
    assert result["status"] == "risk_accepted"
    assert approval.action_type == "accept_risk"
    assert approval.status == "risk_accepted"
    assert approval.approved_by == "security@example.test"
    assert approval.decision_reason == "Temporary exception until vendor patch is certified."


def test_approval_fields_are_sanitized_before_persistence_and_service_output():
    db = make_session()
    task_id = create_remediation_task(db)

    result = RemediationWorkflowService().accept_risk(
        db,
        task_id,
        approver="security proof-of-concept reviewer",
        reason="Temporary exception while malicious payload details stay private.",
        requested_by="developer with exploit payload context",
    )

    approval = db.query(HumanApproval).one()
    assert "proof-of-concept" not in approval.approved_by
    assert "malicious payload" not in approval.decision_reason
    assert "exploit payload" not in approval.requested_by
    assert contains_unsafe_public_text(
        {
            "approved_by": approval.approved_by,
            "decision_reason": approval.decision_reason,
            "requested_by": approval.requested_by,
        }
    ) is False
    assert "proof-of-concept" not in str(result)
    assert "malicious payload" not in str(result)
    assert "exploit payload" not in str(result)
    assert contains_unsafe_public_text(result) is False


def test_serialized_task_sanitizes_existing_raw_approval_fields():
    db = make_session()
    task_id = create_remediation_task(db)
    db.add(
        HumanApproval(
            remediation_task_id=task_id,
            action_type="approve",
            status="approved",
            approved_by="security proof-of-concept reviewer",
            decision_reason="Reviewed malicious payload details.",
            requested_by="developer with exploit payload context",
        )
    )
    db.commit()

    result = RemediationWorkflowService().get_task(db, task_id)

    assert "proof-of-concept" not in str(result)
    assert "malicious payload" not in str(result)
    assert "exploit payload" not in str(result)
    assert contains_unsafe_public_text(result) is False


@pytest.mark.parametrize("failure_method", ["add", "commit"])
def test_decision_persistence_failure_rolls_back_and_raises_controlled_error(
    monkeypatch,
    failure_method,
):
    db = make_session()
    task_id = create_remediation_task(db)
    rollback_calls = []
    original_rollback = db.rollback

    def fail_persistence(*_args):
        raise SQLAlchemyError("database error with malicious payload details")

    def rollback_spy():
        rollback_calls.append(True)
        original_rollback()

    monkeypatch.setattr(db, failure_method, fail_persistence)
    monkeypatch.setattr(db, "rollback", rollback_spy)

    with pytest.raises(WorkflowPersistenceError) as caught:
        RemediationWorkflowService().approve_task(
            db,
            task_id,
            approver="security@example.test",
        )

    assert rollback_calls == [True]
    assert "malicious payload" not in str(caught.value)
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"
    assert db.query(HumanApproval).count() == 0


def test_decision_response_does_not_depend_on_post_commit_refresh(monkeypatch):
    db = make_session()
    task_id = create_remediation_task(db)

    def fail_refresh(*_args):
        raise SQLAlchemyError("post-commit refresh should not be called")

    monkeypatch.setattr(db, "refresh", fail_refresh)

    result = RemediationWorkflowService().approve_task(
        db,
        task_id,
        approver="security@example.test",
    )

    assert result["status"] == "approved"
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "approved"
    assert db.query(HumanApproval).count() == 1


def test_get_task_lookup_failure_raises_controlled_persistence_error(monkeypatch):
    db = make_session()

    def fail_query(*_args, **_kwargs):
        raise SQLAlchemyError("lookup failure with malicious payload details")

    monkeypatch.setattr(db, "query", fail_query)

    with pytest.raises(WorkflowPersistenceError) as caught:
        RemediationWorkflowService().get_task(db, "task-workflow")

    assert str(caught.value) == "Remediation workflow persistence failed."
    assert "malicious payload" not in str(caught.value)


def test_get_task_serialization_failure_raises_controlled_persistence_error(monkeypatch):
    db = make_session()
    task_id = create_remediation_task(db)
    original_query = db.query

    def query_spy(*entities, **kwargs):
        if entities == (HumanApproval,):
            raise SQLAlchemyError("serialization failure with malicious payload details")
        return original_query(*entities, **kwargs)

    monkeypatch.setattr(db, "query", query_spy)

    with pytest.raises(WorkflowPersistenceError) as caught:
        RemediationWorkflowService().get_task(db, task_id)

    assert str(caught.value) == "Remediation workflow persistence failed."
    assert "malicious payload" not in str(caught.value)


def test_serialized_task_sanitizes_public_string_scalars():
    db = make_session()
    task_id = create_remediation_task(db)
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    package = task.package_vulnerability.package
    vulnerability = task.package_vulnerability.vulnerability
    task.repo.full_name = "local/proof-of-concept-payments"
    package.name = "archive-utils payload"
    package.ecosystem = "npm proof-of-concept"
    package.current_version = "2.1.4 payload"
    package.dependency_type = "dependencies proof-of-concept"
    package.manifest_path = "package-payload.json"
    package.lockfile_path = "package-lock-poc.json"
    vulnerability.canonical_id = "CVE-proof-of-concept"
    vulnerability.severity = "HIGH payload"
    task.package_vulnerability.fixed_versions_json = ["2.2.0 payload"]
    task.priority = "P1 proof-of-concept"
    task.status = "open payload"
    task.owner = "@payments payload"
    task.recommended_action = "upgrade proof-of-concept"
    db.commit()

    result = RemediationWorkflowService().get_task(db, task_id)

    assert contains_unsafe_public_text(result) is False
    assert "[redacted]" in result["repo"]
    assert "[redacted]" in result["package"]["name"]
    assert "[redacted]" in result["package"]["ecosystem"]
    assert "[redacted]" in result["package"]["current_version"]
    assert "[redacted]" in result["package"]["dependency_type"]
    assert "manifest_path" not in result["package"]
    assert "lockfile_path" not in result["package"]
    assert "[redacted]" in result["vulnerability"]["canonical_id"]
    assert "[redacted]" in result["vulnerability"]["severity"]
    assert "[redacted]" in result["vulnerability"]["fixed_versions"][0]
    assert "[redacted]" in result["priority"]
    assert "[redacted]" in result["status"]
    assert "[redacted]" in result["owner"]
    assert "[redacted]" in result["recommended_action"]


def test_serialized_task_sanitizes_secret_like_public_scalars():
    db = make_session()
    task_id = create_remediation_task(db)
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    package = task.package_vulnerability.package
    vulnerability = task.package_vulnerability.vulnerability
    package.name = "private-token-package"
    vulnerability.canonical_id = "GHSA-secret-token"
    task.owner = "private-token-owner"
    task.recommended_action = "private-token-action"
    db.commit()

    result = RemediationWorkflowService().get_task(db, task_id)
    result_text = repr(result)

    assert "private-token-package" not in result_text
    assert "GHSA-secret-token" not in result_text
    assert "private-token-owner" not in result_text
    assert "private-token-action" not in result_text
    assert result["package"]["name"] == "[redacted-secret]"
    assert result["vulnerability"]["canonical_id"] == "[redacted-secret]"
    assert result["owner"] == "[redacted-secret]"
    assert result["recommended_action"] == "[redacted-secret]"


def test_persistence_log_extras_sanitize_secret_like_task_id(monkeypatch):
    db = make_session()
    logged = {}

    def fail_query(*_args, **_kwargs):
        raise SQLAlchemyError("lookup failure with malicious payload details")

    def record_error(message, *, extra):
        logged["message"] = message
        logged["extra"] = extra

    monkeypatch.setattr(db, "query", fail_query)
    monkeypatch.setattr(remediation_workflow.logger, "error", record_error)

    with pytest.raises(WorkflowPersistenceError):
        RemediationWorkflowService().get_task(db, "GHSA-secret-token")

    assert logged["extra"]["task_id"] == "[redacted-secret]"
    assert "GHSA-secret-token" not in repr(logged)


def test_non_open_task_error_sanitizes_persisted_status():
    db = make_session()
    task_id = create_remediation_task(db)
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    task.status = "proof-of-concept"
    db.commit()

    with pytest.raises(InvalidWorkflowActionError) as caught:
        RemediationWorkflowService().approve_task(
            db,
            task_id,
            approver="security@example.test",
        )

    assert "proof-of-concept" not in str(caught.value)
    assert "Remediation task is not open" in str(caught.value)


def test_serialized_task_sanitizes_public_json_field_keys():
    db = make_session()
    task_id = create_remediation_task(db)
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    task.patch_plan_json = {
        "payload plan key": ["Upgrade archive-utils to 2.2.0."],
        "steps": [{"proof-of-concept nested key": "safe nested value"}],
    }
    task.test_plan_json = [{"exploit steps test key": "npm test"}]
    task.rollback_plan_json = [{"payload rollback key": "Revert dependency bump."}]
    task.citations_json = [{"proof-of-concept citation key": "safe citation"}]
    task.package_vulnerability.fixed_versions_json = [
        {"malicious payload version key": "2.2.0"}
    ]
    db.commit()

    result = RemediationWorkflowService().get_task(db, task_id)
    result_text = repr(result)

    assert "payload plan key" not in result_text
    assert "proof-of-concept nested key" not in result_text
    assert "exploit steps test key" not in result_text
    assert "payload rollback key" not in result_text
    assert "proof-of-concept citation key" not in result_text
    assert "malicious payload version key" not in result_text
    assert contains_unsafe_public_text(result) is False


def test_terminal_task_cannot_be_changed_by_second_action():
    db = make_session()
    task_id = create_remediation_task(db)
    service = RemediationWorkflowService()
    service.approve_task(db, task_id, approver="security@example.test")

    with pytest.raises(InvalidWorkflowActionError, match="cannot be changed"):
        service.reject_task(db, task_id, approver="security@example.test")

    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "approved"
    assert db.query(HumanApproval).count() == 1


@pytest.mark.parametrize(
    ("first_action", "first_status", "second_action"),
    [
        ("approve", "approved", "reject"),
        ("reject", "rejected", "accept_risk"),
        ("accept_risk", "risk_accepted", "approve"),
    ],
)
def test_stale_session_cannot_record_second_decision(
    monkeypatch,
    tmp_path,
    first_action,
    first_status,
    second_action,
):
    db_url = "sqlite:///%s" % (tmp_path / "workflow.db")
    engine = create_engine(db_url)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    first_db = session_factory()
    stale_db = session_factory()
    observer_db = session_factory()
    try:
        task_id = create_remediation_task(first_db)
        service = RemediationWorkflowService()
        original_ensure_open_task = remediation_workflow.ensure_open_task
        concurrent_decisions = []

        def interleave_concurrent_decision(task):
            original_ensure_open_task(task)
            if len(concurrent_decisions) > 0:
                return
            concurrent_decisions.append(True)
            apply_workflow_action(service, first_db, first_action, task_id)

        monkeypatch.setattr(
            remediation_workflow,
            "ensure_open_task",
            interleave_concurrent_decision,
        )
        with pytest.raises(InvalidWorkflowActionError, match="cannot be changed"):
            apply_workflow_action(service, stale_db, second_action, task_id)
        stale_db.rollback()

        task = observer_db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
        approvals = observer_db.query(HumanApproval).order_by(HumanApproval.created_at.asc()).all()
        assert task.status == first_status
        assert len(approvals) == 1
        assert approvals[0].action_type == first_action
        assert approvals[0].status == first_status
    finally:
        first_db.close()
        stale_db.close()
        observer_db.close()


def test_draft_is_safe_evidence_backed_and_has_no_side_effects():
    db = make_session()
    task_id = create_remediation_task(db)

    draft = RemediationWorkflowService().generate_draft(db, task_id)

    assert draft["task_id"] == task_id
    assert draft["side_effects"] == []
    assert "CVE-2026-1234" in draft["title"]
    assert "src/upload.py" in draft["body"]
    assert "archive-utils is imported by upload handling code" in draft["body"]
    assert "2.2.0" in draft["body"]
    assert "PR creation" in draft["body"]
    assert "ticket creation" in draft["body"]
    assert contains_unsafe_public_text(draft) is False
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    assert task.status == "open"


def make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def create_remediation_task(db, task_id: str = "task-workflow") -> str:
    repo = Repo(
        id="repo-workflow",
        name="payments-api",
        full_name="local/payments-api",
        provider="local",
    )
    package = Package(
        id="package-workflow",
        repo_id=repo.id,
        name="archive-utils",
        ecosystem="npm",
        current_version="2.1.4",
        dependency_type="dependencies",
        is_direct=True,
        manifest_path="package.json",
        lockfile_path="package-lock.json",
    )
    vulnerability = Vulnerability(
        id="vulnerability-workflow",
        canonical_id="CVE-2026-1234",
        summary="Proof-of-concept payload details should be redacted.",
        severity="HIGH",
        raw_json={},
    )
    package_vulnerability = PackageVulnerability(
        id="package-vulnerability-workflow",
        package_id=package.id,
        vulnerability_id=vulnerability.id,
        affected_version="2.1.4",
        fixed_versions_json=["2.2.0"],
        is_affected=True,
    )
    task = RemediationTask(
        id=task_id,
        repo_id=repo.id,
        package_vulnerability_id=package_vulnerability.id,
        priority="P1_FIX_THIS_SPRINT",
        risk_score=86,
        status="open",
        owner="@payments",
        recommended_action="upgrade",
        patch_plan_json={
            "steps": [
                "Upgrade archive-utils to 2.2.0.",
                "Review advisory text; proof-of-concept content must stay out of the ticket.",
            ]
        },
        test_plan_json=["npm test"],
        rollback_plan_json=["Revert package.json and package-lock.json."],
        citations_json=[
            {
                "type": "code_usage",
                "source": "src/upload.py",
                "claim": "archive-utils is imported by upload handling code.",
            },
            {
                "type": "advisory",
                "source": "advisory",
                "claim": "Proof-of-concept payload details are not needed for remediation.",
            },
        ],
    )
    db.add_all([repo, package, vulnerability, package_vulnerability, task])
    db.commit()
    return task_id


def apply_workflow_action(
    service: RemediationWorkflowService,
    db,
    action: str,
    task_id: str,
) -> dict:
    if action == "approve":
        return service.approve_task(db, task_id, approver="security@example.test")
    if action == "reject":
        return service.reject_task(db, task_id, approver="security@example.test")
    if action == "accept_risk":
        return service.accept_risk(
            db,
            task_id,
            approver="security@example.test",
            reason="Temporary exception.",
        )
    raise AssertionError("Unknown workflow action: %s" % action)
