import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import (
    AdvisoryReference,
    Package,
    PackageVulnerability,
    ReachabilityAssessment,
    RemediationTask,
    Repo,
    Scan,
    Vulnerability,
    VulnerabilityAlias,
)
from app.services.dependency_parser import ParsedDependency
from app.services.persistence import (
    PersistenceError,
    RepoPersistenceIdentity,
    persist_scan_result,
)
from app.services.repo_ingestion import RepoProfile
from app.services.scan_service import RemediationTaskOutput, ScanResult
from app.services.vulnerability_normalizer import NormalizedVulnerability


def test_persist_scan_result_stores_scan_graph():
    db = make_session()
    result = deterministic_scan_result()

    scan = persist_scan_result(db, result)

    assert scan.id
    assert db.query(Repo).count() == 1
    assert db.query(Scan).count() == 1
    assert db.query(Package).count() == 2
    assert db.query(Vulnerability).count() == 1
    assert db.query(VulnerabilityAlias).count() == 2
    assert db.query(AdvisoryReference).count() == 1
    assert db.query(PackageVulnerability).count() == 1
    assert db.query(ReachabilityAssessment).count() == 1
    assert db.query(RemediationTask).count() == 1

    repo = db.query(Repo).one()
    assert repo.full_name == "local/payments-api"
    assert repo.language == "Python, TypeScript"
    assert repo.service_type == "api"

    package = db.query(Package).filter(Package.name == "archive-utils").one()
    assert package.current_version == "2.1.4"
    assert package.dependency_type == "dependencies"
    assert package.is_direct is True

    vulnerability = db.query(Vulnerability).one()
    assert vulnerability.canonical_id == "CVE-2026-1234"
    assert vulnerability.severity == "HIGH"
    assert sorted(alias.alias for alias in vulnerability.aliases) == [
        "CVE-2026-1234",
        "GHSA-aaaa-bbbb-cccc",
    ]

    package_vulnerability = db.query(PackageVulnerability).one()
    assert package_vulnerability.package_id == package.id
    assert package_vulnerability.vulnerability_id == vulnerability.id
    assert package_vulnerability.fixed_versions_json == ["2.2.0"]

    reachability = db.query(ReachabilityAssessment).one()
    assert reachability.package_vulnerability_id == package_vulnerability.id
    assert reachability.reachability == "reachable"
    assert reachability.runtime_scope == "runtime"
    assert reachability.confidence == 0.9
    assert reachability.evidence_json == result.remediation_tasks[0].evidence

    task = db.query(RemediationTask).one()
    assert task.repo_id == repo.id
    assert task.package_vulnerability_id == package_vulnerability.id
    assert task.status == "open"
    assert task.priority == "P1_FIX_THIS_SPRINT"
    assert task.risk_score == 86
    assert task.owner == "@payments"
    assert task.recommended_action == "upgrade"
    assert result.remediation_tasks[0].task_id == task.id


def test_persisting_same_result_twice_is_idempotent_for_current_records():
    db = make_session()
    first_result = deterministic_scan_result()
    second_result = deterministic_scan_result()
    second_result.remediation_tasks[0].risk["risk_score"] = 91
    second_result.remediation_tasks[0].risk["priority"] = "P0_RELEASE_BLOCKER"
    second_result.remediation_tasks[0].owner = "@security"
    second_result.remediation_tasks[0].patch_plan["steps"] = [
        "Upgrade archive-utils to 2.2.0.",
        "Run focused regression tests.",
    ]

    first_scan = persist_scan_result(db, first_result)
    first_task_id = first_result.remediation_tasks[0].task_id
    second_scan = persist_scan_result(db, second_result)

    assert first_scan.id != second_scan.id
    assert db.query(Repo).count() == 1
    assert db.query(Scan).count() == 2
    assert db.query(Package).count() == 2
    assert db.query(Vulnerability).count() == 1
    assert db.query(VulnerabilityAlias).count() == 2
    assert db.query(AdvisoryReference).count() == 1
    assert db.query(PackageVulnerability).count() == 1
    assert db.query(ReachabilityAssessment).count() == 1
    assert db.query(RemediationTask).count() == 1

    task = db.query(RemediationTask).one()
    assert task.id == first_task_id
    assert second_result.remediation_tasks[0].task_id == first_task_id
    assert task.status == "open"
    assert task.priority == "P0_RELEASE_BLOCKER"
    assert task.risk_score == 91
    assert task.owner == "@security"
    assert task.patch_plan_json["steps"] == [
        "Upgrade archive-utils to 2.2.0.",
        "Run focused regression tests.",
    ]


def test_persist_scan_result_raises_when_task_package_link_is_missing():
    db = make_session()
    result = deterministic_scan_result()
    result.remediation_tasks[0].package["name"] = "missing-package"

    with pytest.raises(PersistenceError, match="missing-package"):
        persist_scan_result(db, result)

    assert db.query(Scan).count() == 0
    assert db.query(RemediationTask).count() == 0


def test_persist_scan_result_prevents_duplicate_natural_records():
    db = make_session()
    first_result = deterministic_scan_result()
    duplicate_package = first_result.packages[0]
    first_result.packages.append(duplicate_package)
    first_result.vulnerabilities[0].aliases.append("CVE-2026-1234")
    first_result.vulnerabilities[0].references.append(
        {
            "type": "ADVISORY",
            "url": "https://example.test/advisories/GHSA-aaaa-bbbb-cccc",
        }
    )
    first_result.remediation_tasks.append(first_result.remediation_tasks[0])
    second_result = deterministic_scan_result()

    persist_scan_result(db, first_result)
    persist_scan_result(db, second_result)

    assert db.query(Repo).count() == 1
    assert db.query(Package).count() == 2
    assert db.query(Vulnerability).count() == 1
    assert db.query(VulnerabilityAlias).count() == 2
    assert db.query(AdvisoryReference).count() == 1
    assert db.query(PackageVulnerability).count() == 1
    assert db.query(ReachabilityAssessment).count() == 1
    assert db.query(RemediationTask).count() == 1


def test_persist_scan_result_keeps_local_and_github_repo_identities_separate():
    db = make_session()
    local_result = deterministic_scan_result()
    local_result.repo_profile.repo_name = "foo"
    local_result.repo_profile.root_path = "/repos/foo"
    github_result = deterministic_scan_result()
    github_result.repo_profile.repo_name = "foo"
    github_result.repo_profile.root_path = "/tmp/vulnsage-github/local-foo"

    local_scan = persist_scan_result(db, local_result)
    github_scan = persist_scan_result(
        db,
        github_result,
        repo_identity=RepoPersistenceIdentity(
            provider="github",
            name="foo",
            full_name="local/foo",
            remote_url="https://github.com/local/foo.git",
            organization_name="local",
        ),
    )

    assert local_scan.repo_id != github_scan.repo_id
    repos = db.query(Repo).order_by(Repo.provider.asc()).all()
    assert [(repo.provider, repo.name, repo.full_name) for repo in repos] == [
        ("github", "foo", "local/foo"),
        ("local", "foo", "local/foo"),
    ]


def test_persist_scan_result_keeps_github_casing_variants_separate():
    db = make_session()
    lower_result = deterministic_scan_result()
    mixed_result = deterministic_scan_result()

    lower_scan = persist_scan_result(
        db,
        lower_result,
        repo_identity=RepoPersistenceIdentity(
            provider="github",
            name="foo",
            full_name="local/foo",
            remote_url="https://github.com/local/foo.git",
            organization_name="local",
        ),
    )
    mixed_scan = persist_scan_result(
        db,
        mixed_result,
        repo_identity=RepoPersistenceIdentity(
            provider="github",
            name="Foo",
            full_name="Local/Foo",
            remote_url="https://github.com/Local/Foo.git",
            organization_name="Local",
        ),
    )

    assert lower_scan.repo_id != mixed_scan.repo_id
    repos = db.query(Repo).order_by(Repo.full_name.asc()).all()
    assert [(repo.provider, repo.name, repo.full_name) for repo in repos] == [
        ("github", "Foo", "Local/Foo"),
        ("github", "foo", "local/foo"),
    ]


def make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def deterministic_scan_result() -> ScanResult:
    profile = RepoProfile(
        repo_name="payments-api",
        root_path="/repos/payments-api",
        languages=["Python", "TypeScript"],
        package_managers=["npm"],
        dependency_files=["package.json"],
        lockfiles=["package-lock.json"],
        service_type="api",
        test_commands=["npm test"],
        codeowners={"src/payments": "@payments"},
    )
    packages = [
        ParsedDependency(
            name="archive-utils",
            current_version="2.1.4",
            ecosystem="npm",
            dependency_type="dependencies",
            is_direct=True,
            manifest_path="/repos/payments-api/package.json",
            lockfile_path="/repos/payments-api/package-lock.json",
            version_spec="^2.1.4",
            lockfile_entry_path="node_modules/archive-utils",
            evidence=[
                {
                    "type": "manifest",
                    "source": "package.json",
                    "claim": "archive-utils is a direct dependencies",
                }
            ],
        ),
        ParsedDependency(
            name="safe-helper",
            current_version="1.0.0",
            ecosystem="npm",
            dependency_type="transitive",
            is_direct=False,
            parent_package="archive-utils",
            lockfile_path="/repos/payments-api/package-lock.json",
            lockfile_entry_path="node_modules/archive-utils/node_modules/safe-helper",
            evidence=[
                {
                    "type": "lockfile",
                    "source": "package-lock.json",
                    "claim": "safe-helper@1.0.0 is installed",
                }
            ],
        ),
    ]
    vulnerability = NormalizedVulnerability(
        canonical_id="CVE-2026-1234",
        source_id="GHSA-aaaa-bbbb-cccc",
        aliases=["CVE-2026-1234"],
        package="archive-utils",
        ecosystem="npm",
        current_version="2.1.4",
        summary="Archive extraction can bypass validation.",
        details="Detailed advisory text",
        severity="HIGH",
        affected_versions=[">=0"],
        fixed_versions=["2.2.0"],
        references=[
            {
                "type": "ADVISORY",
                "url": "https://example.test/advisories/GHSA-aaaa-bbbb-cccc",
            }
        ],
        published_at="2026-01-02T00:00:00Z",
        modified_at="2026-01-03T00:00:00Z",
        raw={"id": "GHSA-aaaa-bbbb-cccc"},
    )
    task = RemediationTaskOutput(
        task_id="task_deterministic",
        repo="payments-api",
        package={
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "2.1.4",
            "dependency_type": "dependencies",
            "is_direct": True,
            "parent_package": None,
        },
        vulnerability={
            "canonical_id": "CVE-2026-1234",
            "source_id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2026-1234"],
            "severity": "HIGH",
            "summary": "Archive extraction can bypass validation.",
            "fixed_versions": ["2.2.0"],
        },
        risk={
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 86,
            "known_exploited": None,
            "epss_score": None,
            "runtime_scope": "runtime",
            "reachability": "reachable",
            "confidence": 0.9,
            "factors": ["direct dependency"],
            "rationale": ["High severity reachable runtime dependency."],
        },
        evidence=[
            {
                "type": "code_usage",
                "source": "src/payments/archive.py",
                "claim": "archive-utils is imported by payment processing code.",
            }
        ],
        patch_plan={
            "recommended_action": "upgrade",
            "target_version": "2.2.0",
            "steps": ["Upgrade archive-utils to 2.2.0."],
            "test_plan": ["npm test"],
            "rollback_plan": ["Revert package-lock.json."],
        },
        test_plan=["npm test"],
        rollback_plan=["Revert package-lock.json."],
        owner="@payments",
    )
    return ScanResult(
        scan_id="scan_deterministic",
        repo_profile=profile,
        packages=packages,
        vulnerabilities=[vulnerability],
        remediation_tasks=[task],
        summary={
            "packages": 2,
            "raw_alerts": 1,
            "deduped_remediation_tasks": 1,
            "scan_status": "complete",
        },
        errors=[],
    )
