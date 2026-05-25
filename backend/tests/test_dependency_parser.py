import json
import tempfile
import unittest
from pathlib import Path

from app.services.dependency_parser import NodeDependencyParser


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
        self.assertEqual(dependencies[0].current_version, "^4.17.20")
        self.assertTrue(dependencies[0].is_direct)


if __name__ == "__main__":
    unittest.main()

