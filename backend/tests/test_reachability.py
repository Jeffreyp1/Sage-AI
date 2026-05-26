import tempfile
import unittest
from pathlib import Path

from app.services.dependency_parser import ParsedDependency
from app.services.reachability import analyze_reachability, is_production_source


def make_dependency(
    name: str,
    dependency_type: str = "dependencies",
    is_direct: bool = True,
) -> ParsedDependency:
    return ParsedDependency(
        name=name,
        current_version="1.0.0",
        ecosystem="npm",
        dependency_type=dependency_type,
        is_direct=is_direct,
    )


class ReachabilityTest(unittest.TestCase):
    def test_root_index_and_app_imports_are_production_reachable(self):
        cases = {
            "index.js": 'const runtimeLib = require("runtime-lib");\n',
            "app.js": 'import runtimeLib from "runtime-lib";\n',
        }

        for source_path, contents in cases.items():
            with self.subTest(source_path=source_path):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / source_path
                    target.write_text(contents, encoding="utf-8")

                    result = analyze_reachability(str(root), make_dependency("runtime-lib"))

                self.assertEqual(result.reachability, "possibly_reachable")
                self.assertEqual(result.runtime_scope, "production")
                self.assertTrue(
                    any(evidence["source"] == source_path for evidence in result.evidence),
                    "expected source evidence for %s" % source_path,
                )

    def test_node_app_layout_imports_are_production_reachable(self):
        cases = {
            "server.js": 'const runtimeLib = require("runtime-lib");\n',
            "app.ts": 'import runtimeLib from "runtime-lib";\n',
            "index.ts": 'import runtimeLib from "runtime-lib";\n',
            "main.js": 'const runtimeLib = require("runtime-lib");\n',
            "backend/server.js": 'const runtimeLib = require("runtime-lib");\n',
            "backend/server.ts": 'import runtimeLib from "runtime-lib";\n',
            "packages/api/server.mjs": 'import runtimeLib from "runtime-lib";\n',
            "packages/api/server.cjs": 'const runtimeLib = require("runtime-lib");\n',
            "packages/api/app.cjs": 'const runtimeLib = require("runtime-lib");\n',
            "packages/api/index.mjs": 'import runtimeLib from "runtime-lib";\n',
            "packages/api/main.ts": 'import runtimeLib from "runtime-lib";\n',
            "app/routes/foo.js": 'import runtimeLib from "runtime-lib";\n',
            "packages/api/app/routes/foo.js": 'import runtimeLib from "runtime-lib";\n',
        }

        for source_path, contents in cases.items():
            with self.subTest(source_path=source_path):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / source_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(contents, encoding="utf-8")

                    result = analyze_reachability(str(root), make_dependency("runtime-lib"))

                self.assertEqual(result.reachability, "possibly_reachable")
                self.assertEqual(result.runtime_scope, "production")
                self.assertTrue(
                    any(evidence["source"] == source_path for evidence in result.evidence),
                    "expected source evidence for %s" % source_path,
                )

    def test_test_and_e2e_imports_are_development_unlikely(self):
        cases = {
            "tests/foo.test.js": 'const testTool = require("test-tool");\n',
            "e2e/login.js": 'import testTool from "test-tool";\n',
            "src/login.e2e.ts": 'import testTool from "test-tool";\n',
            "src/components/Button.cy.tsx": 'import testTool from "test-tool";\n',
            "app/routes/foo.spec.js": 'import testTool from "test-tool";\n',
            "app/routes/foo.test.js": 'import testTool from "test-tool";\n',
        }

        for source_path, contents in cases.items():
            with self.subTest(source_path=source_path):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    target = root / source_path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(contents, encoding="utf-8")

                    result = analyze_reachability(
                        str(root),
                        make_dependency("test-tool", dependency_type="devDependency"),
                    )

                self.assertEqual(result.reachability, "unlikely_reachable")
                self.assertEqual(result.runtime_scope, "development")
                self.assertTrue(
                    any(evidence["source"] == source_path for evidence in result.evidence),
                    "expected source evidence for %s" % source_path,
                )

    def test_production_source_classifier_keeps_test_and_generated_paths_out(self):
        production_paths = [
            "server.js",
            "app.js",
            "app.ts",
            "app.mjs",
            "app.cjs",
            "index.js",
            "index.ts",
            "index.mjs",
            "index.cjs",
            "main.js",
            "main.ts",
            "main.mjs",
            "main.cjs",
            "backend/server.js",
            "backend/server.ts",
            "packages/api/server.mjs",
            "packages/api/server.cjs",
            "packages/api/app.cjs",
            "packages/api/index.mjs",
            "packages/api/main.ts",
            "app/routes/foo.js",
            "packages/api/app/routes/foo.js",
            "routes/foo.js",
            "controllers/foo.js",
            "services/foo.js",
            "lib/foo.js",
            "src/foo.js",
        ]
        non_production_paths = [
            "tests/foo.js",
            "specs/foo.js",
            "e2e/foo.js",
            "cypress/e2e/foo.js",
            "node_modules/pkg/index.js",
            "build/server.js",
            "build/app.js",
            "coverage/index.ts",
            ".next/server/main.mjs",
            "dist/routes/foo.js",
            "dist/index.cjs",
            "src/login.e2e.ts",
            "src/components/Button.cy.tsx",
            "app/routes/foo.spec.js",
            "app/routes/foo.test.js",
            "routes/foo.test.js",
        ]

        for path in production_paths:
            with self.subTest(path=path):
                self.assertTrue(is_production_source(path))

        for path in non_production_paths:
            with self.subTest(path=path):
                self.assertFalse(is_production_source(path))
