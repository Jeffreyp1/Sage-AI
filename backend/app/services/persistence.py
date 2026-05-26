"""Persistence adapter for scan results."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional

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
from app.services.dependency_parser import ParsedDependency
from app.services.scan_service import RemediationTaskOutput, ScanResult
from app.services.vulnerability_normalizer import NormalizedVulnerability


@dataclass(frozen=True)
class RepoPersistenceIdentity:
    provider: str
    name: str
    full_name: str
    remote_url: Optional[str]
    organization_name: str


def persist_scan_result(
    db: Session,
    result: ScanResult,
    repo_identity: Optional[RepoPersistenceIdentity] = None,
) -> Scan:
    identity = repo_identity or local_repo_identity(result)
    organization = get_or_create_organization(db, identity.organization_name)
    repo = get_or_create_repo(db, organization, result, identity)
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
        model = get_or_create_package(db, repo, package)
        package_models[
            package_key(
                package.name,
                package.ecosystem,
                package.current_version,
                package.parent_package,
            )
        ] = model

    vulnerability_models = {
        vulnerability.canonical_id: get_or_create_vulnerability(db, vulnerability)
        for vulnerability in result.vulnerabilities
    }

    for task in result.remediation_tasks:
        package_model = package_models.get(task_package_key(task))
        vulnerability_model = vulnerability_models.get(
            str(task.vulnerability.get("canonical_id"))
        )
        if package_model is None or vulnerability_model is None:
            continue
        package_vulnerability = get_or_create_package_vulnerability(
            db,
            package_model,
            vulnerability_model,
            task,
        )
        upsert_reachability_assessment(
            db,
            package_vulnerability,
            task,
        )

        remediation_task = get_or_create_current_remediation_task(
            db,
            repo,
            package_vulnerability,
            task,
        )
        task.task_id = remediation_task.id

    db.commit()
    db.refresh(scan)
    return scan


def local_repo_identity(result: ScanResult) -> RepoPersistenceIdentity:
    return RepoPersistenceIdentity(
        provider="local",
        name=result.repo_profile.repo_name,
        full_name="local/%s" % result.repo_profile.repo_name,
        remote_url=result.repo_profile.root_path,
        organization_name="local",
    )


def get_or_create_organization(db: Session, name: str) -> Organization:
    organization = db.query(Organization).filter(Organization.name == name).one_or_none()
    if organization is not None:
        return organization
    organization = Organization(name=name)
    db.add(organization)
    db.flush()
    return organization


def get_or_create_repo(
    db: Session,
    organization: Organization,
    result: ScanResult,
    identity: RepoPersistenceIdentity,
) -> Repo:
    repo = (
        db.query(Repo)
        .filter(Repo.provider == identity.provider, Repo.full_name == identity.full_name)
        .order_by(Repo.id)
        .first()
    )
    if repo is not None:
        repo.org_id = organization.id
        repo.name = identity.name
        repo.remote_url = identity.remote_url
        repo.language = ", ".join(result.repo_profile.languages)
        repo.service_type = result.repo_profile.service_type
        return repo
    repo = Repo(
        org_id=organization.id,
        name=identity.name,
        full_name=identity.full_name,
        provider=identity.provider,
        remote_url=identity.remote_url,
        language=", ".join(result.repo_profile.languages),
        service_type=result.repo_profile.service_type,
    )
    db.add(repo)
    db.flush()
    return repo


def get_or_create_package(
    db: Session,
    repo: Repo,
    package: ParsedDependency,
) -> PackageModel:
    model = (
        db.query(PackageModel)
        .filter(
            PackageModel.repo_id == repo.id,
            PackageModel.name == package.name,
            PackageModel.ecosystem == package.ecosystem,
            PackageModel.current_version == package.current_version,
            PackageModel.parent_package == package.parent_package,
        )
        .order_by(PackageModel.id)
        .first()
    )
    if model is None:
        model = PackageModel(
            repo_id=repo.id,
            name=package.name,
            ecosystem=package.ecosystem,
            current_version=package.current_version,
            parent_package=package.parent_package,
            dependency_type=package.dependency_type,
            is_direct=package.is_direct,
            manifest_path=package.manifest_path,
            lockfile_path=package.lockfile_path,
        )
        db.add(model)
        db.flush()

    model.dependency_type = package.dependency_type
    model.is_direct = package.is_direct
    model.manifest_path = package.manifest_path
    model.lockfile_path = package.lockfile_path
    return model


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
        if not alias or alias in existing:
            continue
        db.add(
            VulnerabilityAlias(
                vulnerability_id=model.id,
                alias=alias,
                alias_type=alias_type(alias),
            )
        )
        existing.add(alias)


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
        existing.add(url)


def get_or_create_package_vulnerability(
    db: Session,
    package: PackageModel,
    vulnerability: Vulnerability,
    task: RemediationTaskOutput,
) -> PackageVulnerability:
    affected_version = optional_str(task.package.get("current_version"))
    model = (
        db.query(PackageVulnerability)
        .filter(
            PackageVulnerability.package_id == package.id,
            PackageVulnerability.vulnerability_id == vulnerability.id,
            PackageVulnerability.affected_version == affected_version,
        )
        .order_by(PackageVulnerability.id)
        .first()
    )
    if model is None:
        model = PackageVulnerability(
            package_id=package.id,
            vulnerability_id=vulnerability.id,
            affected_version=affected_version,
            fixed_versions_json=list_values(task.vulnerability.get("fixed_versions")),
            is_affected=True,
        )
        db.add(model)
        db.flush()

    model.fixed_versions_json = list_values(task.vulnerability.get("fixed_versions"))
    model.is_affected = True
    return model


def upsert_reachability_assessment(
    db: Session,
    package_vulnerability: PackageVulnerability,
    task: RemediationTaskOutput,
) -> ReachabilityAssessment:
    model = (
        db.query(ReachabilityAssessment)
        .filter(ReachabilityAssessment.package_vulnerability_id == package_vulnerability.id)
        .order_by(ReachabilityAssessment.id)
        .first()
    )
    if model is None:
        model = ReachabilityAssessment(
            package_vulnerability_id=package_vulnerability.id,
            reachability="unknown",
            runtime_scope="unknown",
            confidence=0.0,
            evidence_json=[],
        )
        db.add(model)
        db.flush()

    model.reachability = str(task.risk.get("reachability") or "unknown")
    model.runtime_scope = str(task.risk.get("runtime_scope") or "unknown")
    model.confidence = float(task.risk.get("confidence") or 0.0)
    model.evidence_json = task.evidence
    return model


def get_or_create_current_remediation_task(
    db: Session,
    repo: Repo,
    package_vulnerability: PackageVulnerability,
    task: RemediationTaskOutput,
) -> RemediationTask:
    model = (
        db.query(RemediationTask)
        .filter(
            RemediationTask.repo_id == repo.id,
            RemediationTask.package_vulnerability_id == package_vulnerability.id,
            RemediationTask.status == "open",
        )
        .order_by(RemediationTask.id)
        .first()
    )
    if model is None:
        model = RemediationTask(
            repo_id=repo.id,
            package_vulnerability_id=package_vulnerability.id,
            status="open",
            priority="NEEDS_HUMAN_REVIEW",
            risk_score=0,
            recommended_action="review",
            patch_plan_json={},
            test_plan_json=[],
            rollback_plan_json=[],
            citations_json=[],
        )
        db.add(model)
        db.flush()

    model.priority = str(task.risk.get("priority") or "NEEDS_HUMAN_REVIEW")
    model.risk_score = int(task.risk.get("risk_score") or 0)
    model.owner = task.owner
    model.recommended_action = str(task.patch_plan.get("recommended_action") or "review")
    model.patch_plan_json = task.patch_plan
    model.test_plan_json = task.test_plan
    model.rollback_plan_json = task.rollback_plan
    model.citations_json = task.evidence
    return model


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


def task_package_key(task: RemediationTaskOutput) -> str:
    return package_key(
        str(task.package.get("name")),
        str(task.package.get("ecosystem")),
        optional_str(task.package.get("current_version")),
        optional_str(task.package.get("parent_package")),
    )


def package_key(name: str, ecosystem: str, version: Optional[str], parent: Optional[str]) -> str:
    return "%s|%s|%s|%s" % (name, ecosystem, version or "", parent or "")


def optional_str(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


def list_values(value: object) -> list:
    return value if isinstance(value, list) else []
