import json
import tempfile
import unittest
from pathlib import Path

from app.services.scan_service import ScanService


class FakeOsvClient:
    def query(self, package_name, version, ecosystem):
        if package_name == "archive-utils":
            return [
                {
                    "id": "GHSA-runtime",
                    "aliases": ["CVE-2025-12345"],
                    "summary": "Archive parsing vulnerability",
                    "database_specific": {"severity": "HIGH"},
                    "affected": [
                        {
                            "package": {"name": "archive-utils", "ecosystem": "npm"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "2.2.0"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        if package_name == "test-bundle-tool":
            return [
                {
                    "id": "GHSA-dev",
                    "aliases": ["CVE-2025-99999"],
                    "summary": "Dev tooling vulnerability",
                    "database_specific": {"severity": "CRITICAL"},
                    "affected": [
                        {
                            "package": {"name": "test-bundle-tool", "ecosystem": "npm"},
                            "ranges": [
                                {
                                    "type": "SEMVER",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                }
            ]
        return []


class UnsafeDetailsOsvClient:
    def query(self, package_name, version, ecosystem):
        if package_name != "archive-utils":
            return []
        return [
            {
                "id": "GHSA-unsafe",
                "aliases": ["CVE-2025-77777"],
                "summary": "Archive parsing vulnerability",
                "details": "PoC: run malicious payload against the vulnerable service",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "archive-utils", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "2.2.0"}],
                            }
                        ],
                    }
                ],
                "references": [
                    {"type": "ADVISORY", "url": "https://example.test/advisory"},
                    {"type": "WEB", "url": "https://example.test/PoC.zip"},
                ],
            }
        ]


class ScanServiceTest(unittest.TestCase):
    def test_scan_builds_prioritized_remediation_tasks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "upload").mkdir(parents=True)
            (root / "src" / "routes").mkdir(parents=True)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "scripts": {"test": "vitest run", "lint": "eslint src"},
                        "dependencies": {"archive-utils": "2.1.4"},
                        "devDependencies": {"test-bundle-tool": "1.0.0"},
                    }
                ),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/archive-utils": {"version": "2.1.4"},
                            "node_modules/test-bundle-tool": {
                                "version": "1.0.0",
                                "dev": True,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "CODEOWNERS").write_text("src/upload/ @payments-platform\n", encoding="utf-8")
            (root / "src" / "upload" / "receiptParser.ts").write_text(
                'import archiveUtils from "archive-utils";\n'
                "export function parseReceiptArchive(buffer: Buffer) { return archiveUtils.read(buffer); }\n",
                encoding="utf-8",
            )
            (root / "src" / "routes" / "receipts.ts").write_text(
                'import { parseReceiptArchive } from "../upload/receiptParser";\n'
                'router.post("/api/receipts/upload", (request, response) => parseReceiptArchive(request.body));\n',
                encoding="utf-8",
            )

            result = ScanService(osv_client=FakeOsvClient()).scan_local(str(root))

        self.assertEqual(result.summary["deduped_remediation_tasks"], 2)
        top_task = result.remediation_tasks[0]
        self.assertEqual(top_task.package["name"], "archive-utils")
        self.assertEqual(top_task.risk["priority"], "P0_RELEASE_BLOCKER")
        self.assertEqual(top_task.owner, "@payments-platform")
        self.assertTrue(
            any(evidence["type"] == "route" for evidence in top_task.evidence),
            "expected route evidence for upload endpoint",
        )
        dev_task = [
            task for task in result.remediation_tasks if task.package["name"] == "test-bundle-tool"
        ][0]
        self.assertEqual(dev_task.risk["priority"], "P3_MONITOR_DEFER")

    def test_public_scan_output_redacts_raw_advisory_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"archive-utils": "2.1.4"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/archive-utils": {"version": "2.1.4"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = ScanService(osv_client=UnsafeDetailsOsvClient()).scan_local(str(root))

        output = result.to_dict()
        vulnerability = output["vulnerabilities"][0]
        serialized = json.dumps(output)
        forbidden_keys = []

        def collect_forbidden_keys(value, path=""):
            if isinstance(value, dict):
                for key, child in value.items():
                    if key in {"raw", "details"}:
                        forbidden_keys.append(path + "." + key if path else key)
                    collect_forbidden_keys(child, path + "." + key if path else key)
            if isinstance(value, list):
                for index, child in enumerate(value):
                    collect_forbidden_keys(child, "%s[%s]" % (path, index))

        collect_forbidden_keys(output)
        self.assertNotIn("raw", vulnerability)
        self.assertNotIn("details", vulnerability)
        self.assertEqual(forbidden_keys, [])
        self.assertNotIn("PoC", serialized)
        self.assertNotIn("malicious payload", serialized)
        self.assertTrue(vulnerability["details_redacted"])


if __name__ == "__main__":
    unittest.main()
