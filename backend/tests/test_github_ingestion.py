import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.github_ingestion import (
    GitHubCloneError,
    InvalidGitHubUrlError,
    clone_github_repo,
    parse_github_repo_url,
)


class GitHubIngestionTest(unittest.TestCase):
    def test_parse_accepts_https_github_repo_urls(self):
        accepted = [
            "https://github.com/acme/widget",
            "https://github.com/acme/widget.git",
            "https://github.com/acme/widget/",
            "https://github.com/acme/widget.git/",
            "https://github.com/Acme-Co/widget.service_2",
        ]

        for url in accepted:
            with self.subTest(url=url):
                repository = parse_github_repo_url(url)
                self.assertEqual(repository.clone_url, "https://github.com/%s/%s.git" % (
                    repository.owner,
                    repository.repo,
                ))

    def test_parse_rejects_unsafe_or_malformed_urls(self):
        rejected = [
            "http://github.com/acme/widget",
            "https://gitlab.com/acme/widget",
            "https://www.github.com/acme/widget",
            "git@github.com:acme/widget.git",
            "ssh://git@github.com/acme/widget.git",
            "/tmp/acme/widget",
            "../widget",
            "https://github.com/acme",
            "https://github.com//acme/widget",
            "https://github.com/acme/widget//",
            "https://github.com/acme/widget/issues",
            "https://github.com/acme/widget?tab=readme",
            "https://github.com/acme/widget#readme",
            "https://github.com/user:pass@github.com/acme/widget",
            "https://github.com:bad/acme/widget",
            "https://github.com/acme/.git",
            "https://github.com/-acme/widget",
            "https://github.com/acme-/widget",
            "https://github.com/acme/bad repo",
            "https://github.com/acme/../widget",
        ]

        for url in rejected:
            with self.subTest(url=url):
                with self.assertRaises(InvalidGitHubUrlError):
                    parse_github_repo_url(url)

    def test_clone_builds_safe_argument_list_without_shell(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.github_ingestion.subprocess.run") as run:
                destination = clone_github_repo("https://github.com/acme/widget.git", temp_dir)

        run.assert_called_once()
        args, kwargs = run.call_args
        command = args[0]
        self.assertEqual(
            command[:5],
            ["git", "clone", "--depth", "1", "https://github.com/acme/widget.git"],
        )
        self.assertEqual(Path(command[5]), destination)
        self.assertFalse(kwargs.get("shell", False))
        self.assertTrue(kwargs["check"])
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertEqual(kwargs["timeout"], 120)
        self.assertTrue(destination.name.startswith("acme-widget-"))
        self.assertEqual(destination.parent, Path(temp_dir).resolve())

    def test_clone_logs_start_and_success_with_sanitized_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("app.services.github_ingestion.subprocess.run"),
                patch("app.services.github_ingestion.logger") as logger,
            ):
                destination = clone_github_repo("https://github.com/acme/widget.git", temp_dir)

        expected_extra = {
            "github_owner": "acme",
            "github_repo": "widget",
            "destination_name": destination.name,
        }
        logger.info.assert_any_call("github_clone_start", extra=expected_extra)
        logger.info.assert_any_call("github_clone_success", extra=expected_extra)
        for call in logger.info.call_args_list:
            self.assertNotIn(str(destination.parent), str(call))
            self.assertNotIn("https://github.com/acme/widget.git", str(call))

    def test_clone_failure_raises_domain_error(self):
        error = subprocess.CalledProcessError(
            returncode=128,
            cmd=["git", "clone"],
            stderr="fatal: repository not found",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch("app.services.github_ingestion.subprocess.run", side_effect=error):
                with self.assertRaises(GitHubCloneError) as caught:
                    clone_github_repo("https://github.com/acme/missing", temp_dir)

        self.assertIn("repository not found", str(caught.exception))

    def test_clone_failure_logs_failure_with_sanitized_identity(self):
        error = subprocess.CalledProcessError(
            returncode=128,
            cmd=["git", "clone"],
            stderr="fatal: repository not found",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                patch("app.services.github_ingestion.subprocess.run", side_effect=error),
                patch("app.services.github_ingestion.logger") as logger,
            ):
                with self.assertRaises(GitHubCloneError):
                    clone_github_repo("https://github.com/acme/missing", temp_dir)

        logger.warning.assert_called_once()
        message = logger.warning.call_args.args[0]
        extra = logger.warning.call_args.kwargs["extra"]
        self.assertEqual(message, "github_clone_failure")
        self.assertEqual(extra["github_owner"], "acme")
        self.assertEqual(extra["github_repo"], "missing")
        self.assertTrue(extra["destination_name"].startswith("acme-missing-"))
        self.assertEqual(extra["returncode"], 128)
        self.assertNotIn(str(Path(temp_dir).resolve()), str(logger.warning.call_args))
        self.assertNotIn("https://github.com/acme/missing.git", str(logger.warning.call_args))


if __name__ == "__main__":
    unittest.main()
