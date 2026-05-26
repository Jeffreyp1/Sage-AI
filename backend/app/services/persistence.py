"""Persistence adapter for scan results."""

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional, TypeVar

from sqlalchemy.exc import IntegrityError
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

ModelT = TypeVar("ModelT")


@dataclass(frozen=True)
class RepoPersistenceIdentity:
    provider: str
    name: str
    full_name: str
    remote_url: Optional[str]
    organization_name: str


class PersistenceError(Exception):
    """Raised when a scan result cannot be persisted without losing data."""


def persist_scan_result(
    db: Session,
    result: ScanResult,
    repo_identity: Optional[RepoPersistenceIdentity] = None,
) -> Scan:
    try:
        return _persist_scan_result(db, result, repo_identity)
    except PersistenceError:
        db.rollback()
        raise
    except IntegrityError as exc:
        db.rollback()
        raise PersistenceError(
            "Failed to persist scan result because a natural uniqueness constraint was violated."
        ) from exc


def _persist_scan_result(
    db: Session,
    result: ScanResult,
    repo_identity: Optional[RepoPersistenceIdentity],
) -> Scan:
    identity = repo_identity or local_repo_identity(result)
    organization = get_or_create_organization(db, identity.organization_name)
    repo = get_or_create_repo(db, organization, result, identity)
    repo_root = remote_safe_repo_root(result, identity)
    scan = Scan(
        repo_id=repo.id,
        status="completed",
        started_at=utc_now(),
        completed_at=utc_now(),
        summary_json=result.summary,
    )
    db.add(scan)
    db.flush()

    package_models = {}
    for package in result.packages:
        storage_package = remote_safe_package(package, repo_root)
        model = get_or_create_package(db, repo, storage_package)
        package_models[
            package_key(
                storage_package.name,
                storage_package.ecosystem,
                storage_package.current_version,
                storage_package.parent_package,
            )
        ] = model

    vulnerability_models = {
        vulnerability.canonical_id: get_or_create_vulnerability(db, vulnerability)
        for vulnerability in result.vulnerabilities
    }

    for task in result.remediation_tasks:
        storage_task = remote_safe_task(task, repo_root, identity.full_name)
        package_model = package_models.get(task_package_key(storage_task))
        vulnerability_model = vulnerability_models.get(
            str(storage_task.vulnerability.get("canonical_id"))
        )
        if package_model is None or vulnerability_model is None:
            raise task_link_error(storage_task, package_model, vulnerability_model)
        package_vulnerability = get_or_create_package_vulnerability(
            db,
            package_model,
            vulnerability_model,
            storage_task,
        )
        upsert_reachability_assessment(
            db,
            package_vulnerability,
            storage_task,
        )

        remediation_task = get_or_create_current_remediation_task(
            db,
            repo,
            package_vulnerability,
            storage_task,
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
    def query_organization() -> Organization | None:
        return db.query(Organization).filter(Organization.name == name).one_or_none()

    organization = query_organization()
    if organization is not None:
        return organization
    organization = Organization(name=name)
    organization, _ = add_or_get_existing(
        db,
        organization,
        query_organization,
        "Failed to create organization '%s'." % name,
    )
    return organization


def get_or_create_repo(
    db: Session,
    organization: Organization,
    result: ScanResult,
    identity: RepoPersistenceIdentity,
) -> Repo:
    def query_repo() -> Repo | None:
        return (
            db.query(Repo)
            .filter(
                Repo.provider == identity.provider,
                Repo.full_name == identity.full_name,
            )
            .order_by(Repo.id)
            .first()
        )

    repo = query_repo()
    if repo is None:
        repo = Repo(
            org_id=organization.id,
            name=identity.name,
            full_name=identity.full_name,
            provider=identity.provider,
            remote_url=identity.remote_url,
            language=", ".join(result.repo_profile.languages),
            service_type=result.repo_profile.service_type,
        )
        repo, _ = add_or_get_existing(
            db,
            repo,
            query_repo,
            "Failed to create repo '%s'." % identity.full_name,
        )

    repo.org_id = organization.id
    repo.name = identity.name
    repo.remote_url = identity.remote_url
    repo.language = ", ".join(result.repo_profile.languages)
    repo.service_type = result.repo_profile.service_type
    return repo


def utc_now() -> datetime:
    return datetime.now(UTC)


def remote_safe_repo_root(
    result: ScanResult,
    identity: RepoPersistenceIdentity,
) -> Path | None:
    if identity.provider != "github":
        return None
    if not result.repo_profile.root_path:
        return None
    return Path(result.repo_profile.root_path).resolve()


def remote_safe_package(
    package: ParsedDependency,
    repo_root: Path | None,
) -> ParsedDependency:
    if repo_root is None:
        return package
    return replace(
        package,
        manifest_path=remote_safe_optional_text(package.manifest_path, repo_root),
        lockfile_path=remote_safe_optional_text(package.lockfile_path, repo_root),
        evidence=remote_safe_value(package.evidence, repo_root),
    )


def remote_safe_task(
    task: RemediationTaskOutput,
    repo_root: Path | None,
    repo_full_name: str,
) -> RemediationTaskOutput:
    if repo_root is None:
        return task
    return replace(
        task,
        repo=repo_full_name,
        package=remote_safe_value(task.package, repo_root),
        evidence=remote_safe_value(task.evidence, repo_root),
        patch_plan=remote_safe_value(task.patch_plan, repo_root),
        test_plan=remote_safe_value(task.test_plan, repo_root),
        rollback_plan=remote_safe_value(task.rollback_plan, repo_root),
    )


def remote_safe_optional_text(value: Optional[str], repo_root: Path) -> Optional[str]:
    if value is None:
        return None
    return remote_safe_text(value, repo_root)


def remote_safe_value(value, repo_root: Path | str):
    root = Path(repo_root).resolve()
    return _remote_safe_value(value, root)


def _remote_safe_value(value, repo_root: Path):
    if isinstance(value, dict):
        return {
            key: _remote_safe_value(item, repo_root)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_remote_safe_value(item, repo_root) for item in value]
    if isinstance(value, tuple):
        return tuple(_remote_safe_value(item, repo_root) for item in value)
    if isinstance(value, str):
        return remote_safe_text(value, repo_root)
    return value


def remote_safe_text(value: str, repo_root: Path) -> str:
    try:
        path = Path(value)
        if path.is_absolute():
            return path.resolve().relative_to(repo_root).as_posix()
    except ValueError:
        pass
    root_text = str(repo_root)
    if value == root_text:
        return "."
    if root_text in value:
        return value.replace(root_text + "/", "").replace(root_text, ".")
    return value


def get_or_create_package(
    db: Session,
    repo: Repo,
    package: ParsedDependency,
) -> PackageModel:
    def query_package() -> PackageModel | None:
        return (
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

    model = query_package()
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
        model, _ = add_or_get_existing(
            db,
            model,
            query_package,
            "Failed to create package '%s'." % package.name,
        )

    model.dependency_type = package.dependency_type
    model.is_direct = package.is_direct
    model.manifest_path = package.manifest_path
    model.lockfile_path = package.lockfile_path
    return model


def get_or_create_vulnerability(
    db: Session,
    vulnerability: NormalizedVulnerability,
) -> Vulnerability:
    def query_vulnerability() -> Vulnerability | None:
        return (
            db.query(Vulnerability)
            .filter(Vulnerability.canonical_id == vulnerability.canonical_id)
            .one_or_none()
        )

    model = query_vulnerability()
    created = False
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
        model, created = add_or_get_existing(
            db,
            model,
            query_vulnerability,
            "Failed to create vulnerability '%s'." % vulnerability.canonical_id,
        )
    if not created:
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

        def query_alias() -> VulnerabilityAlias | None:
            return (
                db.query(VulnerabilityAlias)
                .filter(
                    VulnerabilityAlias.vulnerability_id == model.id,
                    VulnerabilityAlias.alias == alias,
                )
                .order_by(VulnerabilityAlias.id)
                .first()
            )

        alias_model = VulnerabilityAlias(
            vulnerability_id=model.id,
            alias=alias,
            alias_type=alias_type(alias),
        )
        add_or_get_existing(
            db,
            alias_model,
            query_alias,
            "Failed to create vulnerability alias '%s'." % alias,
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

        def query_reference() -> AdvisoryReference | None:
            return (
                db.query(AdvisoryReference)
                .filter(
                    AdvisoryReference.vulnerability_id == model.id,
                    AdvisoryReference.url == url,
                )
                .order_by(AdvisoryReference.id)
                .first()
            )

        reference_model = AdvisoryReference(
            vulnerability_id=model.id,
            url=url,
            reference_type=reference.get("type"),
        )
        add_or_get_existing(
            db,
            reference_model,
            query_reference,
            "Failed to create advisory reference '%s'." % url,
        )
        existing.add(url)


def get_or_create_package_vulnerability(
    db: Session,
    package: PackageModel,
    vulnerability: Vulnerability,
    task: RemediationTaskOutput,
) -> PackageVulnerability:
    affected_version = optional_str(task.package.get("current_version"))

    def query_package_vulnerability() -> PackageVulnerability | None:
        return (
            db.query(PackageVulnerability)
            .filter(
                PackageVulnerability.package_id == package.id,
                PackageVulnerability.vulnerability_id == vulnerability.id,
                PackageVulnerability.affected_version == affected_version,
            )
            .order_by(PackageVulnerability.id)
            .first()
        )

    model = query_package_vulnerability()
    if model is None:
        model = PackageVulnerability(
            package_id=package.id,
            vulnerability_id=vulnerability.id,
            affected_version=affected_version,
            fixed_versions_json=list_values(task.vulnerability.get("fixed_versions")),
            is_affected=True,
        )
        model, _ = add_or_get_existing(
            db,
            model,
            query_package_vulnerability,
            "Failed to create package vulnerability link.",
        )

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
    def query_remediation_task() -> RemediationTask | None:
        return (
            db.query(RemediationTask)
            .filter(
                RemediationTask.repo_id == repo.id,
                RemediationTask.package_vulnerability_id == package_vulnerability.id,
                RemediationTask.status == "open",
            )
            .order_by(RemediationTask.id)
            .first()
        )

    model = query_remediation_task()
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
        model, _ = add_or_get_existing(
            db,
            model,
            query_remediation_task,
            "Failed to create open remediation task.",
        )

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


def task_link_error(
    task: RemediationTaskOutput,
    package_model: PackageModel | None,
    vulnerability_model: Vulnerability | None,
) -> PersistenceError:
    missing = []
    package_name = str(task.package.get("name"))
    canonical_id = str(task.vulnerability.get("canonical_id"))
    if package_model is None:
        missing.append("package '%s'" % package_name)
    if vulnerability_model is None:
        missing.append("vulnerability '%s'" % canonical_id)
    return PersistenceError(
        "Cannot persist remediation task '%s': missing %s link."
        % (task.task_id, " and ".join(missing))
    )


def add_or_get_existing(
    db: Session,
    model: ModelT,
    query_existing: Callable[[], ModelT | None],
    error_message: str,
) -> tuple[ModelT, bool]:
    try:
        with db.begin_nested():
            db.add(model)
            db.flush()
    except IntegrityError as exc:
        existing = query_existing()
        if existing is None:
            raise PersistenceError(error_message) from exc
        return existing, False
    return model, True


def optional_str(value: object) -> Optional[str]:
    return value if isinstance(value, str) else None


def list_values(value: object) -> list:
    return value if isinstance(value, list) else []
