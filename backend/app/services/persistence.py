"""Persistence adapter for scan results."""

from datetime import datetime
from typing import Dict, Optional

from sqlalchemy.orm import Session

from app.models import (
    AdvisoryReference,
    Organization,
    Package as PackageModel,
    PackageVulnerability,
    ReachabilityAssessment,
    RemediationTask,
    Repo,
    Scan,
    Vulnerability,
    VulnerabilityAlias,
)
from app.services.scan_service import RemediationTaskOutput, ScanResult
from app.services.vulnerability_normalizer import NormalizedVulnerability


def persist_scan_result(db: Session, result: ScanResult) -> Scan:
    organization = get_or_create_organization(db, "local")
    repo = get_or_create_repo(db, organization, result)
    scan = Scan(
        repo_id=repo.id,
        status="completed",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        summary_json=result.summary,
    )
    db.add(scan)
    db.flush()

    package_models = {}
    for package in result.packages:
        model = PackageModel(
            repo_id=repo.id,
            name=package.name,
            ecosystem=package.ecosystem,
            current_version=package.current_version,
            dependency_type=package.dependency_type,
            is_direct=package.is_direct,
            parent_package=package.parent_package,
            manifest_path=package.manifest_path,
            lockfile_path=package.lockfile_path,
        )
        db.add(model)
        db.flush()
        package_models[package_key(package.name, package.current_version, package.parent_package)] = model

    vulnerability_models = {
        vulnerability.canonical_id: get_or_create_vulnerability(db, vulnerability)
        for vulnerability in result.vulnerabilities
    }

    for task in result.remediation_tasks:
        package_model = package_models.get(
            package_key(
                str(task.package.get("name")),
                optional_str(task.package.get("current_version")),
                optional_str(task.package.get("parent_package")),
            )
        )
        vulnerability_model = vulnerability_models.get(
            str(task.vulnerability.get("canonical_id"))
        )
        if package_model is None or vulnerability_model is None:
            continue
        package_vulnerability = PackageVulnerability(
            package_id=package_model.id,
            vulnerability_id=vulnerability_model.id,
            affected_version=optional_str(task.package.get("current_version")),
            fixed_versions_json=task.vulnerability.get("fixed_versions", []),
            is_affected=True,
        )
        db.add(package_vulnerability)
        db.flush()

        reachability = ReachabilityAssessment(
            package_vulnerability_id=package_vulnerability.id,
            reachability=str(task.risk.get("reachability")),
            runtime_scope=str(task.risk.get("runtime_scope")),
            confidence=float(task.risk.get("confidence") or 0.0),
            evidence_json=task.evidence,
        )
        db.add(reachability)

        remediation_task = RemediationTask(
            repo_id=repo.id,
            package_vulnerability_id=package_vulnerability.id,
            priority=str(task.risk.get("priority")),
            risk_score=int(task.risk.get("risk_score") or 0),
            status="open",
            owner=task.owner,
            recommended_action=str(task.patch_plan.get("recommended_action")),
            patch_plan_json=task.patch_plan,
            test_plan_json=task.test_plan,
            rollback_plan_json=task.rollback_plan,
            citations_json=task.evidence,
        )
        db.add(remediation_task)
        db.flush()
        task.task_id = remediation_task.id

    db.commit()
    db.refresh(scan)
    return scan


def get_or_create_organization(db: Session, name: str) -> Organization:
    organization = db.query(Organization).filter(Organization.name == name).one_or_none()
    if organization is not None:
        return organization
    organization = Organization(name=name)
    db.add(organization)
    db.flush()
    return organization


def get_or_create_repo(db: Session, organization: Organization, result: ScanResult) -> Repo:
    full_name = "local/%s" % result.repo_profile.repo_name
    repo = db.query(Repo).filter(Repo.full_name == full_name).one_or_none()
    if repo is not None:
        repo.language = ", ".join(result.repo_profile.languages)
        repo.service_type = result.repo_profile.service_type
        return repo
    repo = Repo(
        org_id=organization.id,
        name=result.repo_profile.repo_name,
        full_name=full_name,
        provider="local",
        remote_url=result.repo_profile.root_path,
        language=", ".join(result.repo_profile.languages),
        service_type=result.repo_profile.service_type,
    )
    db.add(repo)
    db.flush()
    return repo


def get_or_create_vulnerability(
    db: Session,
    vulnerability: NormalizedVulnerability,
) -> Vulnerability:
    model = (
        db.query(Vulnerability)
        .filter(Vulnerability.canonical_id == vulnerability.canonical_id)
        .one_or_none()
    )
    if model is None:
        model = Vulnerability(
            canonical_id=vulnerability.canonical_id,
            summary=vulnerability.summary,
            details=vulnerability.details,
            severity=vulnerability.severity,
            published_at=parse_datetime(vulnerability.published_at),
            modified_at=parse_datetime(vulnerability.modified_at),
            source="OSV",
            raw_json=vulnerability.raw,
        )
        db.add(model)
        db.flush()
    else:
        model.summary = vulnerability.summary or model.summary
        model.details = vulnerability.details or model.details
        model.severity = vulnerability.severity
        model.modified_at = parse_datetime(vulnerability.modified_at) or model.modified_at
        model.raw_json = vulnerability.raw

    ensure_aliases(db, model, vulnerability)
    ensure_references(db, model, vulnerability)
    return model


def ensure_aliases(
    db: Session,
    model: Vulnerability,
    vulnerability: NormalizedVulnerability,
) -> None:
    existing = {
        alias.alias
        for alias in db.query(VulnerabilityAlias)
        .filter(VulnerabilityAlias.vulnerability_id == model.id)
        .all()
    }
    for alias in [vulnerability.source_id] + vulnerability.aliases:
        if alias in existing:
            continue
        db.add(
            VulnerabilityAlias(
                vulnerability_id=model.id,
                alias=alias,
                alias_type=alias_type(alias),
            )
        )


def ensure_references(
    db: Session,
    model: Vulnerability,
    vulnerability: NormalizedVulnerability,
) -> None:
    existing = {
        reference.url
        for reference in db.query(AdvisoryReference)
        .filter(AdvisoryReference.vulnerability_id == model.id)
        .all()
    }
    for reference in vulnerability.references:
        url = reference.get("url")
        if not url or url in existing:
            continue
        db.add(
            AdvisoryReference(
                vulnerability_id=model.id,
                url=url,
                reference_type=reference.get("type"),
            )
        )


def parse_datetime(value: Optional[str]):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def alias_type(alias: str) -> str:
    if alias.startswith("CVE-"):
        return "CVE"
    if alias.startswith("GHSA-"):
        return "GHSA"
    if alias.startswith("OSV-"):
        return "OSV"
    return "OTHER"


def package_key(name: str, version: Optional[str], parent: Optional[str]) -> str:
    return "%s|%s|%s" % (name, version or "", parent or "")


def optional_str(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None

