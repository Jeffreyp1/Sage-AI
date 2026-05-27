import json
import shutil
import tempfile
import unittest
from pathlib import Path

from app.eval.generate_demo_report import DEFAULT_REPO_PATH, PROJECT_ROOT, generate_report, main
from app.eval.report_validator import validate_report


class DemoReportTest(unittest.TestCase):
    def test_generate_report_uses_fixture_osv_and_passes_validator(self):
        report = generate_report(DEFAULT_REPO_PATH)

        validation = validate_report(report)
        self.assertTrue(validation["passed"], validation)
        self.assertEqual(report["scan_id"], "scan_wave1_demo_payments_api")
        self.assertEqual(report["repo_profile"]["root_path"], "demo-repos/payments-api")

        tasks_by_package = {
            task["package"]["name"]: task for task in report["remediation_tasks"]
        }
        archive_task = tasks_by_package["archive-utils"]
        self.assertEqual(archive_task["vulnerability"]["severity"], "HIGH")
        self.assertEqual(archive_task["risk"]["runtime_scope"], "production")
        self.assertEqual(archive_task["risk"]["priority"], "P0_RELEASE_BLOCKER")

        dev_task = tasks_by_package["test-bundle-tool"]
        self.assertEqual(dev_task["vulnerability"]["severity"], "CRITICAL")
        self.assertEqual(dev_task["risk"]["runtime_scope"], "development")
        self.assertEqual(dev_task["risk"]["priority"], "P3_MONITOR_DEFER")

    def test_main_writes_deterministic_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            first_path = Path(temp_dir) / "first.json"
            second_path = Path(temp_dir) / "second.json"

            self.assertEqual(main(["--output", str(first_path)]), 0)
            self.assertEqual(main(["--output", str(second_path)]), 0)

            first = first_path.read_text(encoding="utf-8")
            second = second_path.read_text(encoding="utf-8")
            self.assertEqual(first, second)

            report = json.loads(first)
            self.assertTrue(validate_report(report)["passed"])

    def test_generated_report_json_does_not_leak_absolute_paths(self):
        default_report = generate_report(DEFAULT_REPO_PATH)
        self.assertTrue(validate_report(default_report)["passed"])
        default_json = json.dumps(default_report, sort_keys=True)

        for forbidden in ("/Users/", "/private/", str(PROJECT_ROOT)):
            self.assertNotIn(forbidden, default_json)

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_root = Path(temp_dir)
            temp_repo_path = temp_root / "payments-api"
            shutil.copytree(DEFAULT_REPO_PATH, temp_repo_path)

            temp_report = generate_report(temp_repo_path)
            self.assertTrue(validate_report(temp_report)["passed"])
            temp_json = json.dumps(temp_report, sort_keys=True)

            for forbidden in (
                "/Users/",
                "/private/",
                str(temp_root),
                str(temp_root.resolve()),
            ):
                self.assertNotIn(forbidden, temp_json)


if __name__ == "__main__":
    unittest.main()
