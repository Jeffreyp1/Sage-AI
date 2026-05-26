import tempfile
import unittest
from pathlib import Path

from app.eval.run_eval import FixtureOsvClient, verify_query_inputs, write_fixture_repo


class EvalRunnerFixtureRepoTest(unittest.TestCase):
    def test_write_fixture_repo_writes_relative_fixture_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            write_fixture_repo(
                root,
                {
                    "package_json": {"name": "fixture-repo"},
                    "files": {"src/index.js": "console.log('ok')\n"},
                },
            )

            self.assertEqual((root / "src" / "index.js").read_text(encoding="utf-8"), "console.log('ok')\n")

    def test_write_fixture_repo_rejects_absolute_fixture_file_paths(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside_tmp:
            root = Path(tmp)
            outside_path = Path(outside_tmp) / "escape.txt"

            with self.assertRaisesRegex(ValueError, "fixture file path must be relative"):
                write_fixture_repo(
                    root,
                    {
                        "package_json": {"name": "fixture-repo"},
                        "files": {str(outside_path): "outside"},
                    },
                )

            self.assertFalse(outside_path.exists())

    def test_write_fixture_repo_rejects_parent_traversal_fixture_file_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            root.mkdir()
            outside_path = root.parent / "escape.txt"

            with self.assertRaisesRegex(ValueError, "fixture file path must stay under repo root"):
                write_fixture_repo(
                    root,
                    {
                        "package_json": {"name": "fixture-repo"},
                        "files": {"../escape.txt": "outside"},
                    },
                )

            self.assertFalse(outside_path.exists())


class FixtureOsvClientTest(unittest.TestCase):
    def test_query_uses_version_specific_key_and_preserves_package_fallback(self):
        advisory = {"id": "GHSA-version-specific"}
        fallback_advisory = {"id": "GHSA-package-only"}
        client = FixtureOsvClient(
            responses={
                "minimist@1.2.8#npm": [advisory],
                "lodash": [fallback_advisory],
            }
        )

        self.assertEqual(client.query("minimist", "1.2.8", "npm"), [advisory])
        self.assertEqual(client.query("minimist", "1.2.7", "npm"), [])
        self.assertEqual(client.query("lodash", "4.17.21", "npm"), [fallback_advisory])


class EvalRunnerQueryVerificationTest(unittest.TestCase):
    def test_explicit_expected_osv_queries_detect_mismatch(self):
        case = {
            "repo_fixture": {
                "package_json": {"name": "fixture-repo"},
                "lock_packages": {"node_modules/minimist": {"version": "1.2.8"}},
            },
            "expected_osv_queries": [
                {
                    "package": "minimist",
                    "version": "1.2.7",
                    "ecosystem": "npm",
                }
            ],
        }

        findings = verify_query_inputs(
            case=case,
            actual_queries=[
                {
                    "package": "minimist",
                    "version": "1.2.8",
                    "ecosystem": "npm",
                }
            ],
        )

        self.assertEqual([finding["code"] for finding in findings], ["osv_query_mismatch"])


if __name__ == "__main__":
    unittest.main()
