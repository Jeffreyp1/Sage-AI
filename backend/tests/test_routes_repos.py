import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from app.api.routes_repos import scan_github
from app.schemas.scan import ScanGitHubRequest
from app.services.github_ingestion import GitHubCloneError


class FakeScanResult:
    scan_id = "scan-test"

    def to_dict(self):
        return {
            "repo_profile": {"repo_name": "widget", "root_path": "/tmp/widget"},
            "summary": {"deduped_remediation_tasks": 0},
            "remediation_tasks": [],
            "errors": [],
        }


class FakeScanService:
    scanned_path = None

    def scan_local(self, repo_path: str):
        FakeScanService.scanned_path = repo_path
        return FakeScanResult()


class RepoRoutesTest(unittest.TestCase):
    def setUp(self):
        FakeScanService.scanned_path = None

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


if __name__ == "__main__":
    unittest.main()
