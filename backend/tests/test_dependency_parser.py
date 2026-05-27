import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.dependency_parser import DependencyParserError, NodeDependencyParser


class NodeDependencyParserTest(unittest.TestCase):
    def test_parses_direct_and_transitive_dependencies_from_package_lock_v3(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps(
                    {
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
                            "node_modules/parent/node_modules/child": {
                                "version": "0.5.0"
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )

            dependencies = NodeDependencyParser().parse(str(root))

        by_name = {dependency.name: dependency for dependency in dependencies}
        self.assertEqual(by_name["archive-utils"].current_version, "2.1.4")
        self.assertTrue(by_name["archive-utils"].is_direct)
        self.assertEqual(by_name["archive-utils"].dependency_type, "dependencies")
        self.assertEqual(by_name["test-bundle-tool"].dependency_type, "devDependency")
        self.assertFalse(by_name["child"].is_direct)
        self.assertEqual(by_name["child"].parent_package, "parent")

    def test_falls_back_to_manifest_when_lockfile_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"lodash": "^4.17.20"}}),
                encoding="utf-8",
            )

            dependencies = NodeDependencyParser().parse(str(root))

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].name, "lodash")
        self.assertIsNone(dependencies[0].current_version)
        self.assertEqual(dependencies[0].version_spec, "^4.17.20")
        self.assertTrue(dependencies[0].is_direct)

    def test_malformed_manifest_error_does_not_leak_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{not-json", encoding="utf-8")

            with self.assertRaises(DependencyParserError) as caught:
                NodeDependencyParser().parse(str(root))

        message = str(caught.exception)
        self.assertIn("Invalid JSON", message)
        self.assertNotIn(str(root), message)
        self.assertNotIn("package.json", message)

    def test_rejects_manifest_symlink_escape_without_leaking_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            outside_manifest = outside / "package.json"
            outside_manifest.write_text(
                json.dumps({"dependencies": {"outside-lib": "1.0.0"}}),
                encoding="utf-8",
            )
            (root / "package.json").symlink_to(outside_manifest)

            with self.assertRaises(DependencyParserError) as caught:
                NodeDependencyParser().parse(str(root))

        message = str(caught.exception)
        self.assertIn("outside the repository", message)
        self.assertNotIn(str(root), message)
        self.assertNotIn(str(outside), message)
        self.assertNotIn("outside-lib", message)

    def test_rejects_lockfile_symlink_escape_without_leaking_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            outside = Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"inside-lib": "1.0.0"}}),
                encoding="utf-8",
            )
            outside_lockfile = outside / "package-lock.json"
            outside_lockfile.write_text(
                json.dumps(
                    {
                        "lockfileVersion": 3,
                        "packages": {
                            "": {},
                            "node_modules/outside-lib": {"version": "9.9.9"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            (root / "package-lock.json").symlink_to(outside_lockfile)

            with self.assertRaises(DependencyParserError) as caught:
                NodeDependencyParser().parse(str(root))

        message = str(caught.exception)
        self.assertIn("outside the repository", message)
        self.assertNotIn(str(root), message)
        self.assertNotIn(str(outside), message)
        self.assertNotIn("outside-lib", message)

    def test_non_utf8_manifest_error_does_not_leak_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_bytes(b"\xff\xfe\x00")

            with self.assertRaises(DependencyParserError) as caught:
                NodeDependencyParser().parse(str(root))

        message = str(caught.exception)
        self.assertIn("Unable to read dependency file", message)
        self.assertNotIn(str(root), message)
        self.assertNotIn("package.json", message)

    def test_manifest_oserror_does_not_leak_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{}", encoding="utf-8")

            with (
                patch.object(
                    Path,
                    "open",
                    side_effect=OSError("disk failure under %s" % root),
                ),
                self.assertRaises(DependencyParserError) as caught,
            ):
                NodeDependencyParser().parse(str(root))

        message = str(caught.exception)
        self.assertIn("Unable to read dependency file", message)
        self.assertNotIn(str(root), message)
        self.assertNotIn("package.json", message)


if __name__ == "__main__":
    unittest.main()
