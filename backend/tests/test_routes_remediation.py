import pytest
from fastapi import FastAPI
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.api.routes_remediation import (
    AcceptRiskRequest,
    ApprovalActionRequest,
    approve_remediation_task,
    accept_remediation_risk,
    draft_remediation_text,
    get_remediation_task,
    reject_remediation_task,
    router,
)
from app.models import (
    HumanApproval,
    Package,
    PackageVulnerability,
    RemediationTask,
    Repo,
    Vulnerability,
)
from app.services.public_safety import contains_unsafe_public_text


def test_get_task_route_returns_persisted_task_details():
    db = make_session()
    task_id = create_remediation_task(db)

    data = get_remediation_task(task_id, db=db)

    assert data["id"] == task_id
    assert data["status"] == "open"
    assert data["package"]["name"] == "archive-utils"
    assert data["vulnerability"]["canonical_id"] == "CVE-2026-1234"


def test_get_task_route_omits_absolute_package_paths():
    db = make_session()
    task_id = create_remediation_task(db)
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id).one()
    package = task.package_vulnerability.package
    package.manifest_path = "/repos/private/payments-api/package.json"
    package.lockfile_path = "/repos/private/payments-api/package-lock.json"
    db.commit()

    data = get_remediation_task(task_id, db=db)

    assert "manifest_path" not in data["package"]
    assert "lockfile_path" not in data["package"]
    assert "/repos/private" not in repr(data)


def test_approve_route_transitions_task_and_creates_approval():
    db = make_session()
    task_id = create_remediation_task(db)

    data = approve_remediation_task(
        task_id,
        ApprovalActionRequest(
            approver="security@example.test",
            reason="Reviewed.",
            requested_by="developer@example.test",
        ),
        db=db,
    )

    assert data["status"] == "approved"
    approval = db.query(HumanApproval).one()
    assert approval.action_type == "approve"
    assert approval.approved_by == "security@example.test"
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "approved"


def test_reject_route_transitions_task_and_creates_approval():
    db = make_session()
    task_id = create_remediation_task(db)

    data = reject_remediation_task(
        task_id,
        ApprovalActionRequest(
            approver="security@example.test",
            reason="Needs another target.",
        ),
        db=db,
    )

    assert data["status"] == "rejected"
    approval = db.query(HumanApproval).one()
    assert approval.action_type == "reject"
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "rejected"


def test_accept_risk_route_requires_reason_and_approver():
    db = make_session()
    task_id = create_remediation_task(db)

    with pytest.raises(HTTPException) as missing_reason:
        accept_remediation_risk(
            task_id,
            AcceptRiskRequest(approver="security@example.test", reason=" "),
            db=db,
        )
    with pytest.raises(HTTPException) as missing_approver:
        accept_remediation_risk(
            task_id,
            AcceptRiskRequest(approver="", reason="Temporary exception."),
            db=db,
        )

    assert missing_reason.value.status_code == 422
    assert missing_approver.value.status_code == 422
    assert db.query(HumanApproval).count() == 0
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"


def test_accept_risk_route_transitions_task_and_creates_approval():
    db = make_session()
    task_id = create_remediation_task(db)

    data = accept_remediation_risk(
        task_id,
        AcceptRiskRequest(
            approver="security@example.test",
            reason="Temporary exception until maintenance window.",
        ),
        db=db,
    )

    assert data["status"] == "risk_accepted"
    approval = db.query(HumanApproval).one()
    assert approval.action_type == "accept_risk"
    assert approval.decision_reason == "Temporary exception until maintenance window."


def test_approval_route_sanitizes_unsafe_human_fields_from_public_output():
    db = make_session()
    task_id = create_remediation_task(db)

    data = approve_remediation_task(
        task_id,
        ApprovalActionRequest(
            approver="security proof-of-concept reviewer",
            reason="Reviewed malicious payload details.",
            requested_by="developer with exploit payload context",
        ),
        db=db,
    )

    assert "proof-of-concept" not in str(data)
    assert "malicious payload" not in str(data)
    assert "exploit payload" not in str(data)
    assert contains_unsafe_public_text(data) is False


@pytest.mark.parametrize("failure_method", ["add", "commit"])
def test_approve_route_maps_persistence_failure_to_500_and_rolls_back(monkeypatch, failure_method):
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

    with pytest.raises(HTTPException) as caught:
        approve_remediation_task(
            task_id,
            ApprovalActionRequest(approver="security@example.test"),
            db=db,
        )

    assert caught.value.status_code == 500
    assert caught.value.detail == "Remediation workflow persistence failed."
    assert "malicious payload" not in caught.value.detail
    assert rollback_calls == [True]
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"
    assert db.query(HumanApproval).count() == 0


def test_get_route_maps_serialization_failure_to_controlled_500(monkeypatch):
    db = make_session()
    task_id = create_remediation_task(db)
    original_query = db.query

    def query_spy(*entities, **kwargs):
        if entities == (HumanApproval,):
            raise SQLAlchemyError("serialization failure with malicious payload details")
        return original_query(*entities, **kwargs)

    monkeypatch.setattr(db, "query", query_spy)

    with pytest.raises(HTTPException) as caught:
        get_remediation_task(task_id, db=db)

    assert caught.value.status_code == 500
    assert caught.value.detail == "Remediation workflow persistence failed."
    assert "malicious payload" not in caught.value.detail


def test_draft_route_returns_safe_text_without_changing_status():
    db = make_session()
    task_id = create_remediation_task(db)

    data = draft_remediation_text(task_id, db=db)

    assert data["side_effects"] == []
    assert "src/upload.py" in data["body"]
    assert "archive-utils is imported by upload handling code" in data["body"]
    assert contains_unsafe_public_text(data) is False
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"
    assert db.query(HumanApproval).count() == 0


def test_draft_route_can_be_called_without_request_body():
    db = make_session()
    task_id = create_remediation_task(db)

    data = draft_remediation_text(task_id, db=db)

    assert data["task_id"] == task_id
    assert data["side_effects"] == []
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"


def test_draft_route_openapi_has_no_request_body():
    db = make_session()
    task_id = create_remediation_task(db)
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = lambda: db

    schema = app.openapi()
    draft_operation = schema["paths"]["/remediation-tasks/{task_id}/draft"]["post"]
    data = draft_remediation_text(task_id, db=db)

    assert "requestBody" not in draft_operation
    assert data["task_id"] == task_id
    assert db.query(RemediationTask).filter(RemediationTask.id == task_id).one().status == "open"
    assert db.query(HumanApproval).count() == 0


def test_unknown_task_route_returns_404():
    db = make_session()

    with pytest.raises(HTTPException) as caught:
        get_remediation_task("missing", db=db)

    assert caught.value.status_code == 404


def test_router_exposes_required_remediation_task_paths():
    paths = {(route.path, ",".join(sorted(route.methods))) for route in router.routes}

    assert ("/remediation-tasks/{task_id}", "GET") in paths
    assert ("/remediation-tasks/{task_id}/approve", "POST") in paths
    assert ("/remediation-tasks/{task_id}/reject", "POST") in paths
    assert ("/remediation-tasks/{task_id}/accept-risk", "POST") in paths
    assert ("/remediation-tasks/{task_id}/draft", "POST") in paths


def make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def create_remediation_task(db, task_id: str = "task-route") -> str:
    repo = Repo(
        id="repo-route",
        name="payments-api",
        full_name="local/payments-api",
        provider="local",
    )
    package = Package(
        id="package-route",
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
        id="vulnerability-route",
        canonical_id="CVE-2026-1234",
        summary="Proof-of-concept payload details should be redacted.",
        severity="HIGH",
        raw_json={},
    )
    package_vulnerability = PackageVulnerability(
        id="package-vulnerability-route",
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
                "Keep proof-of-concept payload details out of draft text.",
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
