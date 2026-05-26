import json
import tempfile
import unittest
from pathlib import Path

from app.services.scan_service import ScanService
from app.services.osv_client import OsvClientError


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


class FailingOsvClient:
    def query(self, package_name, version, ecosystem):
        raise OsvClientError("provider unavailable")


class MismatchedOsvClient:
    def query(self, package_name, version, ecosystem):
        return [
            {
                "id": "GHSA-wrong-package",
                "aliases": ["CVE-2025-42424"],
                "summary": "Wrong package vulnerability",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "other-package", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                            }
                        ],
                    }
                ],
            }
        ]


class UnsafeSummaryOsvClient:
    def query(self, package_name, version, ecosystem):
        return [
            {
                "id": "GHSA-unsafe-summary",
                "aliases": ["CVE-2025-51515"],
                "summary": "PoC advisory mentions malicious payload handling",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": package_name, "ecosystem": ecosystem},
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


class DuplicateLockPathOsvClient:
    def query(self, package_name, version, ecosystem):
        if package_name != "shared-parser":
            return []
        return [
            {
                "id": "GHSA-shared-parser",
                "aliases": ["CVE-2026-10101"],
                "summary": "Shared parser vulnerability",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "shared-parser", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "1.2.4"}],
                            }
                        ],
                    }
                ],
            }
        ]


class DirectAndTransitiveOsvClient:
    def query(self, package_name, version, ecosystem):
        if package_name != "shared-parser":
            return []
        return [
            {
                "id": "GHSA-direct-transitive",
                "aliases": ["CVE-2026-30303"],
                "summary": "Shared parser duplicate path vulnerability",
                "database_specific": {"severity": "HIGH"},
                "affected": [
                    {
                        "package": {"name": "shared-parser", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}, {"fixed": "1.2.4"}],
                            }
                        ],
                    }
                ],
            }
        ]


class DevNoFixedVersionOsvClient:
    def query(self, package_name, version, ecosystem):
        if package_name != "test-bundle-tool":
            return []
        return [
            {
                "id": "GHSA-dev-no-fix",
                "aliases": ["CVE-2026-20202"],
                "summary": "Dev tooling vulnerability without a fix",
                "database_specific": {"severity": "CRITICAL"},
                "affected": [
                    {
                        "package": {"name": "test-bundle-tool", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [{"introduced": "0"}],
                            }
                        ],
                    }
                ],
            }
        ]


class DowngradeOnlyFixedVersionOsvClient:
    def query(self, package_name, version, ecosystem):
        if package_name != "archive-utils":
            return []
        return [
            {
                "id": "GHSA-downgrade-only",
                "aliases": ["CVE-2026-40404"],
                "summary": "Archive parsing vulnerability with only a lower fixed version",
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
        self.assertIsNone(top_task.risk["known_exploited"])
        self.assertEqual(top_task.owner, "@payments-platform")
        self.assertTrue(
            any(evidence["type"] == "route" for evidence in top_task.evidence),
            "expected route evidence for upload endpoint",
        )
        dev_task = [
            task for task in result.remediation_tasks if task.package["name"] == "test-bundle-tool"
        ][0]
        self.assertEqual(dev_task.risk["priority"], "P3_MONITOR_DEFER")

    def test_duplicate_tasks_from_multiple_lockfile_paths_are_collapsed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"parent-a": "1.0.0", "parent-b": "1.0.0"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/parent-a": {"version": "1.0.0"},
                            "node_modules/parent-a/node_modules/shared-parser": {
                                "version": "1.2.3",
                            },
                            "node_modules/parent-b": {"version": "1.0.0"},
                            "node_modules/parent-b/node_modules/shared-parser": {
                                "version": "1.2.3",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = ScanService(osv_client=DuplicateLockPathOsvClient()).scan_local(str(root))

        self.assertEqual(result.summary["raw_alerts"], 2)
        self.assertEqual(result.summary["deduped_remediation_tasks"], 1)
        self.assertEqual(result.summary["priority_counts"], {"P2_SCHEDULE_SOON": 1})
        task = result.remediation_tasks[0]
        self.assertEqual(task.package["name"], "shared-parser")
        self.assertEqual(task.package["current_version"], "1.2.3")
        self.assertEqual(task.vulnerability["canonical_id"], "CVE-2026-10101")
        self.assertEqual(task.risk["priority"], "P2_SCHEDULE_SOON")

        claims = [evidence["claim"] for evidence in task.evidence]
        self.assertTrue(
            any(
                "node_modules/parent-a/node_modules/shared-parser" in claim
                for claim in claims
            ),
            "expected parent-a lockfile path evidence",
        )
        self.assertTrue(
            any(
                "node_modules/parent-b/node_modules/shared-parser" in claim
                for claim in claims
            ),
            "expected parent-b lockfile path evidence",
        )
        self.assertTrue(
            any("parent package parent-a" in claim for claim in claims),
            "expected parent-a dependency path evidence",
        )
        self.assertTrue(
            any("parent package parent-b" in claim for claim in claims),
            "expected parent-b dependency path evidence",
        )

    def test_direct_and_transitive_duplicate_has_coherent_package_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {"parent-a": "1.0.0"},
                        "devDependencies": {"shared-parser": "1.2.3"},
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
                            "node_modules/parent-a": {"version": "1.0.0"},
                            "node_modules/shared-parser": {
                                "version": "1.2.3",
                                "dev": True,
                            },
                            "node_modules/parent-a/node_modules/shared-parser": {
                                "version": "1.2.3",
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = ScanService(osv_client=DirectAndTransitiveOsvClient()).scan_local(str(root))

        self.assertEqual(result.summary["raw_alerts"], 2)
        self.assertEqual(result.summary["deduped_remediation_tasks"], 1)
        self.assertEqual(result.summary["priority_counts"], {"P2_SCHEDULE_SOON": 1})
        task = result.remediation_tasks[0]
        self.assertEqual(task.package["name"], "shared-parser")
        self.assertEqual(task.package["current_version"], "1.2.3")
        self.assertTrue(task.package["is_direct"])
        self.assertIsNone(task.package["parent_package"])
        self.assertEqual(task.package["dependency_type"], "devDependency")
        self.assertEqual(task.vulnerability["canonical_id"], "CVE-2026-30303")
        self.assertEqual(task.risk["priority"], "P2_SCHEDULE_SOON")
        self.assertEqual(task.risk["risk_score"], 41)

        claims = [evidence["claim"] for evidence in task.evidence]
        self.assertTrue(
            any("node_modules/shared-parser" in claim for claim in claims),
            "expected direct lockfile path evidence",
        )
        self.assertTrue(
            any(
                "node_modules/parent-a/node_modules/shared-parser" in claim
                for claim in claims
            ),
            "expected transitive lockfile path evidence",
        )
        self.assertTrue(
            any("parent package parent-a" in claim for claim in claims),
            "expected transitive dependency path evidence",
        )

    def test_no_fixed_version_p3_task_becomes_human_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"devDependencies": {"test-bundle-tool": "1.0.0"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/test-bundle-tool": {
                                "version": "1.0.0",
                                "dev": True,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            result = ScanService(osv_client=DevNoFixedVersionOsvClient()).scan_local(str(root))

        self.assertEqual(result.summary["deduped_remediation_tasks"], 1)
        self.assertEqual(result.summary["safe_to_defer"], 0)
        self.assertEqual(result.summary["needs_human_review"], 1)
        task = result.remediation_tasks[0]
        self.assertEqual(task.risk["priority"], "NEEDS_HUMAN_REVIEW")
        self.assertIsNone(task.patch_plan["target_version"])
        self.assertEqual(task.patch_plan["recommended_action"], "needs_human_review")
        self.assertNotIn("P3_MONITOR_DEFER", " ".join(task.risk["rationale"]))

    def test_downgrade_only_fixed_version_becomes_human_review_without_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src" / "upload").mkdir(parents=True)
            (root / "src" / "routes").mkdir(parents=True)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"archive-utils": "2.3.0"}}),
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/archive-utils": {"version": "2.3.0"},
                        },
                    }
                ),
                encoding="utf-8",
            )
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

            result = ScanService(
                osv_client=DowngradeOnlyFixedVersionOsvClient()
            ).scan_local(str(root))

        self.assertEqual(result.summary["deduped_remediation_tasks"], 1)
        self.assertEqual(result.summary["release_blockers"], 0)
        self.assertEqual(result.summary["needs_human_review"], 1)
        task = result.remediation_tasks[0]
        self.assertEqual(task.risk["priority"], "NEEDS_HUMAN_REVIEW")
        self.assertIsNone(task.patch_plan["target_version"])
        self.assertEqual(task.patch_plan["recommended_action"], "needs_human_review")

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

    def test_osv_failure_marks_scan_incomplete(self):
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

            result = ScanService(osv_client=FailingOsvClient()).scan_local(str(root)).to_dict()

        self.assertEqual(result["summary"]["scan_status"], "incomplete")
        self.assertFalse(result["summary"]["complete"])
        self.assertEqual(result["summary"]["deduped_remediation_tasks"], 0)
        self.assertEqual(result["summary"]["error_count"], 1)

    def test_mismatched_osv_package_does_not_create_task(self):
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

            result = ScanService(osv_client=MismatchedOsvClient()).scan_local(str(root)).to_dict()

        self.assertEqual(result["summary"]["deduped_remediation_tasks"], 0)
        self.assertEqual(result["summary"]["scan_status"], "incomplete")

    def test_public_output_sanitizes_unsafe_summary_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
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
            (root / "src" / "index.ts").write_text(
                'import archiveUtils from "archive-utils";\n',
                encoding="utf-8",
            )

            output = ScanService(osv_client=UnsafeSummaryOsvClient()).scan_local(str(root)).to_dict()

        serialized = json.dumps(output)
        self.assertNotIn("PoC", serialized)
        self.assertNotIn("malicious payload", serialized)
        self.assertIn("[redacted]", serialized)


if __name__ == "__main__":
    unittest.main()
