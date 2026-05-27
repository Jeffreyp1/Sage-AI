import asyncio
import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import create_app
from app.db import Base
from app.api.routes_repos import get_repo, list_remediation_tasks, scan_github, scan_local
from app.models import Package, PackageVulnerability, RemediationTask, Repo, Scan, Vulnerability
from app.schemas.scan import ScanGitHubRequest, ScanLocalRequest
from app.schemas.report import REPORT_SCHEMA_VERSION
from app.services.dependency_parser import ParsedDependency
from app.services.github_ingestion import GitHubCloneError
from app.services.repo_ingestion import RepoProfile
from app.services.scan_service import RemediationTaskOutput, ScanResult
from app.services.vulnerability_normalizer import NormalizedVulnerability


class FakeScanResult:
    scan_id = "scan-test"

    def __init__(self, repo_path: str = "/tmp/widget") -> None:
        self.repo_profile = RepoProfile(
            repo_name=Path(repo_path).name,
            root_path=repo_path,
            languages=["TypeScript"],
            package_managers=["npm"],
            dependency_files=["package.json"],
            lockfiles=[],
            service_type="api",
            test_commands=["npm test"],
            codeowners={},
        )
        self.packages = []
        self.vulnerabilities = []
        self.remediation_tasks = []
        self.summary = {"deduped_remediation_tasks": 0}
        self.errors = []

    def to_dict(self):
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "repo_profile": self.repo_profile.to_dict(),
            "summary": {
                "complete": True,
                "scan_status": "complete",
                "packages": 0,
                "raw_alerts": 0,
                "deduped_remediation_tasks": 0,
                "release_blockers": 0,
                "recommended_sprint_fixes": 0,
                "safe_to_defer": 0,
                "needs_human_review": 0,
                "error_count": 0,
                "priority_counts": {},
            },
            "remediation_tasks": [],
            "errors": self.errors,
        }


class FakeScanService:
    scanned_path = None

    def scan_local(self, repo_path: str, *, workspace_root=None):
        FakeScanService.scanned_path = repo_path
        return FakeScanResult(repo_path)


class FailingScanService:
    scanned_path = None

    def scan_local(self, repo_path: str, *, workspace_root=None):
        FailingScanService.scanned_path = repo_path
        raise OSError("cannot read %s" % repo_path)


class VulnerableFakeScanService:
    scanned_path = None

    def scan_local(self, repo_path: str, *, workspace_root=None):
        VulnerableFakeScanService.scanned_path = repo_path
        return vulnerable_scan_result(repo_path)


class ResolvedLocalFakeScanService:
    scanned_path = None

    def scan_local(self, repo_path: str, *, workspace_root=None):
        ResolvedLocalFakeScanService.scanned_path = repo_path
        root = Path(workspace_root) / repo_path if workspace_root is not None else Path(repo_path)
        return FakeScanResult(str(root.resolve()))


class RawErrorFakeScanService:
    scanned_path = None

    def scan_local(self, repo_path: str, *, workspace_root=None):
        RawErrorFakeScanService.scanned_path = repo_path
        result = vulnerable_scan_result(repo_path)
        result.errors = [
            "OSV query failed for archive-utils@2.1.4: GET https://api.osv.dev?token=ghp_secret123 failed while reading /Users/auditor/private/repo/package-lock.json"
        ]
        result.summary["complete"] = False
        result.summary["scan_status"] = "incomplete"
        result.summary["error_count"] = 1
        return result


class ApiSettings:
    def __init__(self, local_scan_workspace_root: str) -> None:
        self.local_scan_workspace_root = local_scan_workspace_root


class RepoRoutesTest(unittest.TestCase):
    def setUp(self):
        FakeScanService.scanned_path = None
        FailingScanService.scanned_path = None
        VulnerableFakeScanService.scanned_path = None
        ResolvedLocalFakeScanService.scanned_path = None
        RawErrorFakeScanService.scanned_path = None

    def test_request_validation_error_does_not_echo_raw_input(self):
        handler = create_app().exception_handlers[RequestValidationError]
        response = asyncio.run(
            handler(
                None,
                RequestValidationError(
                    [
                        {
                            "type": "string_type",
                            "loc": ("body", "path"),
                            "msg": "Input should be a valid string",
                            "input": {
                                "root": "/Users/auditor/private/repo",
                                "token": "ghp_secret1234567890abcdef",
                            },
                        },
                        {
                            "type": "bool_parsing",
                            "loc": ("body", "persist"),
                            "msg": "Input should be a valid boolean",
                            "input": "definitely",
                        },
                        {
                            "type": "extra_forbidden",
                            "loc": ("body", "unexpected"),
                            "msg": "Extra inputs are not permitted",
                            "input": "sk_live_51SecretTokenLikeValue",
                        },
                    ]
                ),
            )
        )

        self.assertEqual(response.status_code, 422)
        body = json.loads(response.body)
        serialized = json.dumps(body, sort_keys=True)
        self.assertIn("detail", body)
        self.assertNotIn("input", serialized)
        self.assertNotIn("/Users/auditor/private/repo", serialized)
        self.assertNotIn("ghp_secret1234567890abcdef", serialized)
        self.assertNotIn("sk_live_51SecretTokenLikeValue", serialized)

    def test_scan_github_rejects_invalid_url(self):
        request = ScanGitHubRequest(url="git@github.com:acme/widget.git", persist=False)

        with self.assertRaises(HTTPException) as caught:
            scan_github(request, db=None)

        self.assertEqual(caught.exception.status_code, 400)
        self.assertIn("https", caught.exception.detail)

    def test_scan_github_clones_then_scans_without_persisting(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"
            repo_path.mkdir()
            with (
                patch("app.api.routes_repos.clone_github_repo", return_value=repo_path) as clone,
                patch("app.api.routes_repos.ScanService", return_value=FakeScanService()),
            ):
                response = scan_github(
                    ScanGitHubRequest(url="https://github.com/acme/widget", persist=False),
                    db=None,
                )

        clone.assert_called_once()
        clone_url, clone_base_dir = clone.call_args.args
        self.assertEqual(clone_url, "https://github.com/acme/widget")
        self.assertTrue(Path(clone_base_dir).name.startswith("vulnsage-github-"))
        self.assertEqual(FakeScanService.scanned_path, str(repo_path))
        self.assertEqual(response.scan_id, "scan-test")
        self.assertIsNone(response.persisted_scan_id)

    def test_scan_github_response_uses_github_identity_without_temp_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "acme-widget"
            repo_path.mkdir()
            with (
                patch("app.api.routes_repos.clone_github_repo", return_value=repo_path),
                patch("app.api.routes_repos.ScanService", return_value=FakeScanService()),
            ):
                response = scan_github(
                    ScanGitHubRequest(url="https://github.com/acme/widget", persist=False),
                    db=None,
                )

            profile = response.repo_profile
            self.assertEqual(profile.provider, "github")
            self.assertEqual(profile.repo_name, "widget")
            self.assertEqual(profile.full_name, "acme/widget")
            self.assertEqual(profile.remote_url, "https://github.com/acme/widget.git")
            self.assertEqual(profile.root_path, "https://github.com/acme/widget.git")
            self.assertNotIn(str(Path(temp_dir).resolve()), str(profile))

    def test_scan_github_persists_owner_scoped_identity_for_same_repo_name(self):
        db = make_session()

        with tempfile.TemporaryDirectory() as temp_dir:
            paths = {
                "https://github.com/acme/widget": Path(temp_dir) / "acme-widget",
                "https://github.com/other/widget": Path(temp_dir) / "other-widget",
            }
            for path in paths.values():
                path.mkdir()

            def clone_side_effect(url: str, base_directory: str) -> Path:
                return paths[url]

            with (
                patch("app.api.routes_repos.clone_github_repo", side_effect=clone_side_effect),
                patch("app.api.routes_repos.ScanService", return_value=FakeScanService()),
            ):
                first = scan_github(
                    ScanGitHubRequest(url="https://github.com/acme/widget", persist=True),
                    db=db,
                )
                second = scan_github(
                    ScanGitHubRequest(url="https://github.com/other/widget", persist=True),
                    db=db,
                )

        self.assertIsNotNone(first.persisted_scan_id)
        self.assertIsNotNone(second.persisted_scan_id)
        repos = db.query(Repo).order_by(Repo.full_name.asc()).all()
        self.assertEqual(
            [(repo.provider, repo.name, repo.full_name, repo.remote_url) for repo in repos],
            [
                ("github", "widget", "acme/widget", "https://github.com/acme/widget.git"),
                ("github", "widget", "other/widget", "https://github.com/other/widget.git"),
            ],
        )

    def test_scan_github_persists_remote_safe_paths_and_normalizes_task_repo(self):
        db = make_session()

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = str(Path(temp_dir).resolve())
            repo_path = Path(temp_dir) / "local-foo-clone"
            repo_path.mkdir()
            with (
                patch("app.api.routes_repos.clone_github_repo", return_value=repo_path),
                patch("app.api.routes_repos.ScanService", return_value=VulnerableFakeScanService()),
            ):
                response = scan_github(
                    ScanGitHubRequest(url="https://github.com/local/foo", persist=True),
                    db=db,
                )

        self.assertEqual(response.remediation_tasks[0].repo, "local/foo")
        response_tasks = [
            task.model_dump(mode="json") for task in response.remediation_tasks
        ]
        self.assertNotIn(temp_root, json.dumps(response_tasks, sort_keys=True))

        repo = db.query(Repo).one()
        package = db.query(Package).one()
        task = db.query(RemediationTask).one()
        persisted_payload = {
            "repo": {
                "name": repo.name,
                "full_name": repo.full_name,
                "provider": repo.provider,
                "remote_url": repo.remote_url,
            },
            "package": {
                "manifest_path": package.manifest_path,
                "lockfile_path": package.lockfile_path,
            },
            "task": {
                "patch_plan": task.patch_plan_json,
                "citations": task.citations_json,
            },
        }
        self.assertEqual(package.manifest_path, "package.json")
        self.assertEqual(package.lockfile_path, "package-lock.json")
        self.assertNotIn(temp_root, json.dumps(persisted_payload, sort_keys=True))

    def test_scan_github_reports_clone_failure(self):
        with patch(
            "app.api.routes_repos.clone_github_repo",
            side_effect=GitHubCloneError("Unable to clone GitHub repository: nope"),
        ):
            request = ScanGitHubRequest(url="https://github.com/acme/widget", persist=False)
            with self.assertRaises(HTTPException) as caught:
                scan_github(request, db=None)

        self.assertEqual(caught.exception.status_code, 502)
        self.assertIn("Unable to clone", caught.exception.detail)

    def test_scan_github_reports_scan_failure_without_temp_path_leak(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            repo_path = Path(temp_dir) / "repo"
            repo_path.mkdir()
            with (
                patch("app.api.routes_repos.clone_github_repo", return_value=repo_path),
                patch("app.api.routes_repos.ScanService", return_value=FailingScanService()),
                patch("app.api.routes_repos.logger") as logger,
            ):
                request = ScanGitHubRequest(url="https://github.com/acme/widget", persist=False)
                with self.assertRaises(HTTPException) as caught:
                    scan_github(request, db=None)

            log_call = logger.warning.call_args

        self.assertEqual(caught.exception.status_code, 422)
        self.assertEqual(caught.exception.detail, "Unable to scan GitHub repository.")
        self.assertNotIn(str(Path(temp_dir).resolve()), caught.exception.detail)
        self.assertEqual(FailingScanService.scanned_path, str(repo_path))
        logger.warning.assert_called_once()
        self.assertEqual(log_call.args[0], "github_scan_failure")
        self.assertEqual(log_call.kwargs["extra"]["github_owner"], "acme")
        self.assertEqual(log_call.kwargs["extra"]["github_repo"], "widget")
        self.assertEqual(log_call.kwargs["extra"]["error_type"], "OSError")
        self.assertNotIn(str(Path(temp_dir).resolve()), str(log_call))

    def test_scan_local_malformed_manifest_error_does_not_leak_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo_path = root / "repo"
            repo_path.mkdir()
            (repo_path / "package.json").write_text("{not-json", encoding="utf-8")

            with (
                patch(
                    "app.api.routes_repos.get_settings",
                    return_value=ApiSettings(str(root)),
                ),
                self.assertRaises(HTTPException) as caught,
            ):
                scan_local(ScanLocalRequest(path="repo", persist=False), db=None)

        self.assertEqual(caught.exception.status_code, 400)
        detail = str(caught.exception.detail)
        self.assertIn("Invalid JSON", detail)
        self.assertNotIn(str(root), detail)
        self.assertNotIn("package.json", detail)

    def test_scan_local_persist_then_get_repo_does_not_return_local_root_as_remote_url(self):
        db = make_session()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            repo_path = root / "secret-repo"
            repo_path.mkdir()

            with (
                patch(
                    "app.api.routes_repos.get_settings",
                    return_value=ApiSettings(str(root)),
                ),
                patch(
                    "app.api.routes_repos.ScanService",
                    return_value=ResolvedLocalFakeScanService(),
                ),
            ):
                response = scan_local(
                    ScanLocalRequest(path="secret-repo", persist=True),
                    db=db,
                )

        self.assertIsNotNone(response.persisted_scan_id)
        scan = db.query(Scan).one()
        repo = get_repo(scan.repo_id, db=db)
        serialized = json.dumps(repo, sort_keys=True)
        self.assertIsNone(repo["remote_url"])
        self.assertNotIn(str(root), serialized)

    def test_list_remediation_tasks_sanitizes_public_db_fields(self):
        db = make_session()
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
        )
        vulnerability = Vulnerability(
            id="vulnerability-route",
            canonical_id="CVE-2026-1234",
            summary="Archive issue.",
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
            id="task-route",
            repo_id=repo.id,
            package_vulnerability_id=package_vulnerability.id,
            priority="P1_FIX_THIS_SPRINT",
            risk_score=99,
            status="open",
            owner="private-token-package",
            recommended_action="upgrade token=secret-value",
            patch_plan_json={
                "steps": ["Edit /Users/auditor/private/repo/package.json"],
                "GHSA-secret-token": "private-token-package",
            },
            test_plan_json=["run /Users/auditor/private/repo/test.sh"],
            rollback_plan_json=["restore password=hunter2"],
            citations_json=[
                {
                    "source": "/Users/auditor/private/repo/src/archive.py",
                    "claim": "GHSA-secret-token",
                }
            ],
        )
        db.add_all([repo, package, vulnerability, package_vulnerability, task])
        db.commit()

        result = list_remediation_tasks(repo.id, db)

        serialized = json.dumps(result, sort_keys=True)
        self.assertIn("[redacted", serialized)
        self.assertNotIn("private-token-package", serialized)
        self.assertNotIn("GHSA-secret-token", serialized)
        self.assertNotIn("/Users/auditor/private/repo", serialized)
        self.assertNotIn("token=secret-value", serialized)
        self.assertNotIn("password=hunter2", serialized)

    def test_scan_local_response_does_not_return_raw_osv_error_text(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            repo_path = root / "repo"
            repo_path.mkdir()

            with (
                patch(
                    "app.api.routes_repos.get_settings",
                    return_value=ApiSettings(str(root)),
                ),
                patch(
                    "app.api.routes_repos.ScanService",
                    return_value=RawErrorFakeScanService(),
                ),
            ):
                response = scan_local(
                    ScanLocalRequest(path="repo", persist=False),
                    db=None,
                )

        serialized = json.dumps(response.model_dump(mode="json"), sort_keys=True)
        self.assertEqual(
            response.errors,
            [
                "OSV query failed for archive-utils@2.1.4; vulnerability data may be incomplete."
            ],
        )
        self.assertNotIn("ghp_secret123", serialized)
        self.assertNotIn("/Users/auditor/private/repo", serialized)


def make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return session_factory()


def vulnerable_scan_result(repo_path: str) -> ScanResult:
    root = Path(repo_path).resolve()
    package = ParsedDependency(
        name="archive-utils",
        current_version="2.1.4",
        ecosystem="npm",
        dependency_type="dependencies",
        is_direct=True,
        manifest_path=str(root / "package.json"),
        lockfile_path=str(root / "package-lock.json"),
        version_spec="^2.1.4",
        lockfile_entry_path="node_modules/archive-utils",
        evidence=[
            {
                "type": "manifest",
                "source": str(root / "package.json"),
                "claim": "archive-utils is a direct dependency",
            }
        ],
    )
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
        repo=root.name,
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
            "factors": {"direct_dependency_score": 1.0},
            "rationale": ["High severity reachable runtime dependency."],
        },
        evidence=[
            {
                "type": "code_usage",
                "source": str(root / "src/payments/archive.py"),
                "claim": "archive-utils is imported by payment processing code.",
            }
        ],
        patch_plan={
            "recommended_action": "upgrade",
            "target_version": "2.2.0",
            "steps": ["Upgrade %s." % (root / "package.json")],
            "test_plan": ["npm test"],
            "rollback_plan": ["Revert %s." % (root / "package-lock.json")],
        },
        test_plan=["npm test"],
        rollback_plan=["Revert %s." % (root / "package-lock.json")],
        owner="@payments",
    )
    return ScanResult(
        scan_id="scan-deterministic",
        repo_profile=RepoProfile(
            repo_name=root.name,
            root_path=str(root),
            languages=["TypeScript"],
            package_managers=["npm"],
            dependency_files=[str(root / "package.json")],
            lockfiles=[str(root / "package-lock.json")],
            service_type="api",
            test_commands=["npm test"],
            codeowners={},
        ),
        packages=[package],
        vulnerabilities=[vulnerability],
        remediation_tasks=[task],
        summary={
            "complete": True,
            "packages": 1,
            "raw_alerts": 1,
            "deduped_remediation_tasks": 1,
            "release_blockers": 0,
            "recommended_sprint_fixes": 1,
            "safe_to_defer": 0,
            "needs_human_review": 0,
            "error_count": 0,
            "priority_counts": {"P1_FIX_THIS_SPRINT": 1},
            "scan_status": "complete",
        },
        errors=[],
    )


if __name__ == "__main__":
    unittest.main()
