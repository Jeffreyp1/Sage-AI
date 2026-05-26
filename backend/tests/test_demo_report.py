import json
import tempfile
import unittest
from pathlib import Path

from app.eval.generate_demo_report import generate_report, main
from app.eval.report_validator import validate_report


class DemoReportTest(unittest.TestCase):
    def test_generate_report_uses_fixture_osv_and_passes_validator(self):
        report = generate_report(Path("../demo-repos/payments-api"))

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


if __name__ == "__main__":
    unittest.main()
