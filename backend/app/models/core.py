"""SQLAlchemy models for the backend MVP."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import relationship

from app.db import Base


def uuid_pk() -> str:
    return str(uuid4())


class TimestampMixin:
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255), nullable=True)


class Organization(Base, TimestampMixin):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    name = Column(String(255), unique=True, nullable=False)

    repos = relationship("Repo", back_populates="organization")


class Repo(Base, TimestampMixin):
    __tablename__ = "repos"
    __table_args__ = (
        UniqueConstraint("provider", "full_name", name="uq_repos_provider_full_name"),
    )

    id = Column(String(36), primary_key=True, default=uuid_pk)
    org_id = Column(String(36), ForeignKey("organizations.id"), nullable=True)
    name = Column(String(255), nullable=False)
    full_name = Column(String(512), nullable=False)
    provider = Column(String(50), default="local", nullable=False)
    remote_url = Column(Text, nullable=True)
    default_branch = Column(String(255), nullable=True)
    language = Column(String(255), nullable=True)
    service_type = Column(String(255), nullable=True)

    organization = relationship("Organization", back_populates="repos")
    scans = relationship("Scan", back_populates="repo")
    packages = relationship("Package", back_populates="repo")
    remediation_tasks = relationship("RemediationTask", back_populates="repo")


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    repo_id = Column(String(36), ForeignKey("repos.id"), nullable=False)
    status = Column(String(50), nullable=False)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    commit_sha = Column(String(64), nullable=True)
    summary_json = Column(JSON, nullable=False, default=dict)

    repo = relationship("Repo", back_populates="scans")


class Package(Base, TimestampMixin):
    __tablename__ = "packages"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    repo_id = Column(String(36), ForeignKey("repos.id"), nullable=False)
    name = Column(String(255), nullable=False)
    ecosystem = Column(String(50), nullable=False)
    current_version = Column(String(255), nullable=True)
    dependency_type = Column(String(50), nullable=False)
    is_direct = Column(Boolean, nullable=False, default=False)
    parent_package = Column(String(255), nullable=True)
    manifest_path = Column(Text, nullable=True)
    lockfile_path = Column(Text, nullable=True)

    repo = relationship("Repo", back_populates="packages")
    package_vulnerabilities = relationship("PackageVulnerability", back_populates="package")


class Vulnerability(Base, TimestampMixin):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    canonical_id = Column(String(255), unique=True, nullable=False)
    summary = Column(Text, nullable=True)
    details = Column(Text, nullable=True)
    severity = Column(String(50), nullable=False, default="UNKNOWN")
    published_at = Column(DateTime, nullable=True)
    modified_at = Column(DateTime, nullable=True)
    source = Column(String(50), nullable=False, default="OSV")
    raw_json = Column(JSON, nullable=False, default=dict)

    aliases = relationship("VulnerabilityAlias", back_populates="vulnerability")
    references = relationship("AdvisoryReference", back_populates="vulnerability")
    package_vulnerabilities = relationship(
        "PackageVulnerability", back_populates="vulnerability"
    )


class VulnerabilityAlias(Base, TimestampMixin):
    __tablename__ = "vulnerability_aliases"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "alias", name="uq_vulnerability_aliases_identity"),
    )

    id = Column(String(36), primary_key=True, default=uuid_pk)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id"), nullable=False)
    alias = Column(String(255), nullable=False)
    alias_type = Column(String(50), nullable=False)

    vulnerability = relationship("Vulnerability", back_populates="aliases")


class PackageVulnerability(Base, TimestampMixin):
    __tablename__ = "package_vulnerabilities"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    package_id = Column(String(36), ForeignKey("packages.id"), nullable=False)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id"), nullable=False)
    affected_version = Column(String(255), nullable=True)
    fixed_versions_json = Column(JSON, nullable=False, default=list)
    is_affected = Column(Boolean, nullable=False, default=True)

    package = relationship("Package", back_populates="package_vulnerabilities")
    vulnerability = relationship("Vulnerability", back_populates="package_vulnerabilities")
    reachability_assessments = relationship(
        "ReachabilityAssessment", back_populates="package_vulnerability"
    )
    remediation_tasks = relationship("RemediationTask", back_populates="package_vulnerability")


class AdvisoryReference(Base, TimestampMixin):
    __tablename__ = "advisory_references"
    __table_args__ = (
        UniqueConstraint("vulnerability_id", "url", name="uq_advisory_references_identity"),
    )

    id = Column(String(36), primary_key=True, default=uuid_pk)
    vulnerability_id = Column(String(36), ForeignKey("vulnerabilities.id"), nullable=False)
    url = Column(Text, nullable=False)
    reference_type = Column(String(100), nullable=True)

    vulnerability = relationship("Vulnerability", back_populates="references")


class RepoFile(Base, TimestampMixin):
    __tablename__ = "repo_files"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    repo_id = Column(String(36), ForeignKey("repos.id"), nullable=False)
    path = Column(Text, nullable=False)
    file_type = Column(String(100), nullable=False)
    content_hash = Column(String(128), nullable=False)
    content_text = Column(Text, nullable=True)


class Embedding(Base, TimestampMixin):
    __tablename__ = "embeddings"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    repo_id = Column(String(36), ForeignKey("repos.id"), nullable=True)
    source_type = Column(String(100), nullable=False)
    source_id = Column(String(36), nullable=True)
    content = Column(Text, nullable=False)
    metadata_json = Column(JSON, nullable=False, default=dict)
    embedding = Column(Text, nullable=True)


class ReachabilityAssessment(Base, TimestampMixin):
    __tablename__ = "reachability_assessments"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    package_vulnerability_id = Column(
        String(36), ForeignKey("package_vulnerabilities.id"), nullable=False
    )
    reachability = Column(String(50), nullable=False)
    runtime_scope = Column(String(50), nullable=False)
    confidence = Column(Float, nullable=False)
    evidence_json = Column(JSON, nullable=False, default=list)

    package_vulnerability = relationship(
        "PackageVulnerability", back_populates="reachability_assessments"
    )


class RemediationTask(Base, TimestampMixin):
    __tablename__ = "remediation_tasks"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    repo_id = Column(String(36), ForeignKey("repos.id"), nullable=False)
    package_vulnerability_id = Column(
        String(36), ForeignKey("package_vulnerabilities.id"), nullable=False
    )
    priority = Column(String(50), nullable=False)
    risk_score = Column(Integer, nullable=False)
    status = Column(String(50), nullable=False, default="open")
    owner = Column(String(255), nullable=True)
    recommended_action = Column(String(100), nullable=False)
    patch_plan_json = Column(JSON, nullable=False, default=dict)
    test_plan_json = Column(JSON, nullable=False, default=list)
    rollback_plan_json = Column(JSON, nullable=False, default=list)
    citations_json = Column(JSON, nullable=False, default=list)

    repo = relationship("Repo", back_populates="remediation_tasks")
    package_vulnerability = relationship(
        "PackageVulnerability", back_populates="remediation_tasks"
    )


class HumanApproval(Base, TimestampMixin):
    __tablename__ = "human_approvals"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    remediation_task_id = Column(String(36), ForeignKey("remediation_tasks.id"), nullable=False)
    action_type = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    requested_by = Column(String(255), nullable=True)
    approved_by = Column(String(255), nullable=True)
    decision_reason = Column(Text, nullable=True)


class EvalCase(Base, TimestampMixin):
    __tablename__ = "eval_cases"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    name = Column(String(255), nullable=False)
    case_type = Column(String(100), nullable=False)
    input_json = Column(JSON, nullable=False, default=dict)
    expected_json = Column(JSON, nullable=False, default=dict)


class EvalRun(Base, TimestampMixin):
    __tablename__ = "eval_runs"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    case_id = Column(String(36), ForeignKey("eval_cases.id"), nullable=False)
    status = Column(String(50), nullable=False)
    actual_json = Column(JSON, nullable=False, default=dict)
    score_json = Column(JSON, nullable=False, default=dict)


class LlmTrace(Base, TimestampMixin):
    __tablename__ = "llm_traces"

    id = Column(String(36), primary_key=True, default=uuid_pk)
    trace_id = Column(String(255), nullable=False)
    agent_name = Column(String(255), nullable=False)
    input_json = Column(JSON, nullable=False, default=dict)
    retrieved_context_json = Column(JSON, nullable=False, default=list)
    output_json = Column(JSON, nullable=False, default=dict)
    model = Column(String(255), nullable=True)
    latency_ms = Column(Integer, nullable=True)
    token_count = Column(Integer, nullable=True)
    cost_usd = Column(Float, nullable=True)


Index(
    "uq_packages_identity",
    Package.repo_id,
    Package.name,
    Package.ecosystem,
    func.coalesce(Package.current_version, ""),
    func.coalesce(Package.parent_package, ""),
    unique=True,
)
Index(
    "uq_package_vulnerabilities_identity",
    PackageVulnerability.package_id,
    PackageVulnerability.vulnerability_id,
    func.coalesce(PackageVulnerability.affected_version, ""),
    unique=True,
)
Index(
    "uq_remediation_tasks_open",
    RemediationTask.repo_id,
    RemediationTask.package_vulnerability_id,
    unique=True,
    sqlite_where=RemediationTask.status == "open",
    postgresql_where=RemediationTask.status == "open",
)
