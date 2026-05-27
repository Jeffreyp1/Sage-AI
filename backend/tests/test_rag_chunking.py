import tempfile
import unittest
from unittest import mock
from pathlib import Path

from app.services.public_safety import contains_unsafe_public_text
from app.services.rag_chunking import chunk_advisory, chunk_repository
from app.services.vulnerability_normalizer import NormalizedVulnerability


class RagChunkingTest(unittest.TestCase):
    def test_source_metadata_is_correct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")

            chunks = chunk_repository(root, repo_id="repo-1")

        self.assertEqual(len(chunks), 1)
        chunk = chunks[0]
        self.assertEqual(chunk.source_type, "source_file")
        self.assertEqual(
            chunk.metadata,
            {
                "source_type": "source_file",
                "repo_id": "repo-1",
                "file_path": "src/app.py",
                "line_start": 1,
                "line_end": 1,
                "content_hash": chunk.metadata["content_hash"],
            },
        )
        self.assertEqual(len(chunk.chunk_id), 32)
        self.assertEqual(len(str(chunk.metadata["content_hash"])), 64)

    def test_supported_file_types_are_included(self):
        files = {
            "package.json": "{}\n",
            "package-lock.json": "{}\n",
            "Dockerfile": "FROM python:3.12\n",
            "README.md": "# Service\n",
            "README.security": "# Security\n",
            "CODEOWNERS": "* @team/security\n",
            ".github/CODEOWNERS": "* @team/platform\n",
            ".github/workflows/ci.yml": "name: ci\n",
            "src/index.ts": "export const value = 1\n",
        }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for file_path, content in files.items():
                target = root / file_path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")

            chunks = chunk_repository(root)

        by_path = {str(chunk.metadata["file_path"]): chunk for chunk in chunks}
        self.assertEqual(set(by_path), set(files))
        self.assertEqual(by_path["package.json"].source_type, "package_json")
        self.assertEqual(by_path["package-lock.json"].source_type, "package_lock")
        self.assertEqual(by_path["Dockerfile"].source_type, "dockerfile")
        self.assertEqual(by_path["README.md"].source_type, "readme")
        self.assertEqual(by_path["README.security"].source_type, "readme")
        self.assertEqual(by_path["CODEOWNERS"].source_type, "codeowners")
        self.assertEqual(by_path[".github/CODEOWNERS"].source_type, "codeowners")
        self.assertEqual(by_path[".github/workflows/ci.yml"].source_type, "ci_workflow")
        self.assertEqual(by_path["src/index.ts"].source_type, "source_file")

    def test_skipped_dirs_are_excluded(self):
        skipped_dirs = [
            ".git",
            "node_modules",
            "dist",
            "build",
            "coverage",
            ".next",
            "__pycache__",
        ]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "app.js").write_text("console.log('ok')\n", encoding="utf-8")
            for dirname in skipped_dirs:
                target = root / dirname / "hidden.js"
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("console.log('skip')\n", encoding="utf-8")

            chunks = chunk_repository(root)

        paths = {chunk.metadata["file_path"] for chunk in chunks}
        self.assertEqual(paths, {"src/app.js"})

    def test_skipped_dirs_are_pruned_before_descending(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
            skipped_file = root / "node_modules" / "pkg" / "deep" / "hidden.py"
            skipped_file.parent.mkdir(parents=True)
            skipped_file.write_text("print('skip')\n", encoding="utf-8")
            for index in range(50):
                noisy_file = root / "node_modules" / f"pkg-{index}" / "index.ts"
                noisy_file.parent.mkdir(parents=True)
                noisy_file.write_text("export const skip = true\n", encoding="utf-8")

            original_is_file = Path.is_file

            def fail_if_descended_into_skipped_dir(path):
                relative_parts = path.relative_to(root).parts if path.is_relative_to(root) else ()
                if "node_modules" in relative_parts[:-1]:
                    raise AssertionError(f"descended into skipped directory: {path}")
                return original_is_file(path)

            with mock.patch.object(Path, "is_file", fail_if_descended_into_skipped_dir):
                chunks = chunk_repository(root)

        paths = {chunk.metadata["file_path"] for chunk in chunks}
        self.assertEqual(paths, {"src/app.py"})

    def test_unreadable_supported_file_is_skipped_without_crashing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            readable_file = root / "src" / "app.py"
            unreadable_file = root / "src" / "vanished.py"
            readable_file.write_text("print('ok')\n", encoding="utf-8")
            unreadable_file.write_text("print('gone')\n", encoding="utf-8")
            unreadable_resolved = unreadable_file.resolve()
            original_read_text = Path.read_text

            def raise_for_unreadable_file(path, *args, **kwargs):
                if path == unreadable_resolved:
                    raise OSError("deleted mid-scan")
                return original_read_text(path, *args, **kwargs)

            with (
                mock.patch.object(Path, "read_text", raise_for_unreadable_file),
                self.assertLogs("app.services.rag_chunking", level="WARNING") as logged,
            ):
                chunks = chunk_repository(root)

        paths = {chunk.metadata["file_path"] for chunk in chunks}
        self.assertEqual(paths, {"src/app.py"})
        self.assertEqual(len(logged.records), 1)
        self.assertEqual(logged.records[0].file_path, "src/vanished.py")
        self.assertEqual(logged.records[0].error_type, "OSError")

    def test_unreadable_supported_file_warning_includes_repo_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            unreadable_file = root / "src" / "vanished.py"
            unreadable_file.write_text("print('gone')\n", encoding="utf-8")
            unreadable_resolved = unreadable_file.resolve()

            def raise_for_unreadable_file(path, *args, **kwargs):
                if path == unreadable_resolved:
                    raise PermissionError("permission denied")
                return ""

            with (
                mock.patch.object(Path, "read_text", raise_for_unreadable_file),
                self.assertLogs("app.services.rag_chunking", level="WARNING") as logged,
            ):
                chunks = chunk_repository(root, repo_id="repo-read")

        self.assertEqual(chunks, [])
        self.assertEqual(len(logged.records), 1)
        self.assertEqual(logged.records[0].file_path, "src/vanished.py")
        self.assertEqual(logged.records[0].repo_id, "repo-read")
        self.assertEqual(logged.records[0].error_type, "PermissionError")

    def test_directory_listing_warning_includes_relative_path_and_repo_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
            blocked_dir = root / "blocked"
            blocked_dir.mkdir()
            original_iterdir = Path.iterdir

            def raise_for_blocked_dir(path):
                if path == blocked_dir:
                    raise PermissionError("permission denied")
                return original_iterdir(path)

            with (
                mock.patch.object(Path, "iterdir", raise_for_blocked_dir),
                self.assertLogs("app.services.rag_chunking", level="WARNING") as logged,
            ):
                chunks = chunk_repository(root, repo_id="repo-dir")

        paths = {chunk.metadata["file_path"] for chunk in chunks}
        self.assertEqual(paths, {"src/app.py"})
        self.assertEqual(len(logged.records), 1)
        self.assertEqual(logged.records[0].directory_path, "blocked")
        self.assertEqual(logged.records[0].repo_id, "repo-dir")
        self.assertEqual(logged.records[0].error_type, "PermissionError")

    def test_oversized_supported_file_is_skipped_with_warning_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            oversized_file = root / "src" / "large.py"
            oversized_file.write_text("x" * 20, encoding="utf-8")
            oversized_resolved = oversized_file.resolve()
            original_read_text = Path.read_text

            def fail_if_oversized_file_is_read(path, *args, **kwargs):
                if path == oversized_resolved:
                    raise AssertionError("oversized file should not be read")
                return original_read_text(path, *args, **kwargs)

            with (
                mock.patch.object(Path, "read_text", fail_if_oversized_file_is_read),
                self.assertLogs("app.services.rag_chunking", level="WARNING") as logged,
            ):
                chunks = chunk_repository(root, repo_id="repo-large", max_file_bytes=10)

        self.assertEqual(chunks, [])
        self.assertEqual(len(logged.records), 1)
        self.assertEqual(logged.records[0].file_path, "src/large.py")
        self.assertEqual(logged.records[0].repo_id, "repo-large")
        self.assertEqual(logged.records[0].error_type, "FileTooLarge")
        self.assertEqual(logged.records[0].file_size, 20)
        self.assertEqual(logged.records[0].max_file_bytes, 10)

    def test_large_files_split_with_stable_line_ranges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "large.py").write_text(
                "alpha\nbravo\ncharlie\ndelta\n",
                encoding="utf-8",
            )

            first_run = chunk_repository(root, max_chars=12)
            second_run = chunk_repository(root, max_chars=12)

        self.assertEqual(
            [(chunk.metadata["line_start"], chunk.metadata["line_end"]) for chunk in first_run],
            [(1, 2), (3, 3), (4, 4)],
        )
        self.assertEqual([chunk.chunk_id for chunk in first_run], [chunk.chunk_id for chunk in second_run])
        self.assertEqual([chunk.content for chunk in first_run], ["alpha\nbravo", "charlie", "delta"])

    def test_single_line_longer_than_max_chars_is_split_into_bounded_chunks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "long.py").write_text("abcdefghijABCDEFGHIJxyz\nshort\n", encoding="utf-8")

            first_run = chunk_repository(root, max_chars=10)
            second_run = chunk_repository(root, max_chars=10)

        self.assertEqual([len(chunk.content) for chunk in first_run], [10, 10, 3, 5])
        self.assertTrue(all(len(chunk.content) <= 10 for chunk in first_run))
        self.assertEqual(
            [(chunk.metadata["line_start"], chunk.metadata["line_end"]) for chunk in first_run],
            [(1, 1), (1, 1), (1, 1), (2, 2)],
        )
        self.assertEqual(
            [chunk.content for chunk in first_run],
            ["abcdefghij", "ABCDEFGHIJ", "xyz", "short"],
        )
        self.assertEqual([chunk.chunk_id for chunk in first_run], [chunk.chunk_id for chunk in second_run])

    def test_repeated_long_line_segments_have_unique_schema_safe_chunk_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "repeated.py").write_text("aaaaaaaaaaaaaaaaaaaa\n", encoding="utf-8")

            chunks = chunk_repository(root, max_chars=5)

        chunk_ids = [chunk.chunk_id for chunk in chunks]

        self.assertEqual(len(chunks), 4)
        self.assertEqual(len(set(chunk_ids)), 4)
        self.assertTrue(all(len(chunk_id) == 32 for chunk_id in chunk_ids))
        self.assertTrue(all(chunk.content == "aaaaa" for chunk in chunks))

    def test_advisory_unsafe_text_is_sanitized(self):
        vulnerability = NormalizedVulnerability(
            canonical_id="CVE-2026-12345",
            source_id="GHSA-test",
            aliases=["GHSA-test"],
            package="archive-utils",
            ecosystem="npm",
            current_version="2.1.4",
            summary="Proof of concept exploit code is public",
            details="A malicious payload is described in PoC notes.",
            severity="HIGH",
            affected_versions=[],
            fixed_versions=["2.2.0"],
            references=[{"type": "ADVISORY", "url": "https://example.test/advisory"}],
            published_at=None,
            modified_at=None,
        )

        chunks = chunk_advisory(vulnerability, max_chars=120)

        self.assertGreaterEqual(len(chunks), 1)
        self.assertFalse(contains_unsafe_public_text([chunk.content for chunk in chunks]))
        self.assertIn("[redacted]", "\n".join(chunk.content for chunk in chunks))
        self.assertEqual(chunks[0].source_type, "advisory")
        self.assertEqual(chunks[0].metadata["source_type"], "advisory")
        self.assertEqual(chunks[0].metadata["vulnerability_id"], "CVE-2026-12345")
        self.assertEqual(chunks[0].metadata["package"], "archive-utils")
        self.assertEqual(chunks[0].metadata["ecosystem"], "npm")
        self.assertEqual(chunks[0].metadata["current_version"], "2.1.4")
        self.assertEqual(chunks[0].metadata["fixed_versions"], ["2.2.0"])

    def test_chunk_ids_are_deterministic_for_structured_advisory_fields(self):
        first_run = chunk_advisory(
            vulnerability_id="GHSA-aaaa-bbbb",
            package="pkg",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_versions=["1.0.1"],
            summary="Upgrade to the fixed release.",
            max_chars=80,
        )
        second_run = chunk_advisory(
            vulnerability_id="GHSA-aaaa-bbbb",
            package="pkg",
            ecosystem="npm",
            current_version="1.0.0",
            fixed_versions=["1.0.1"],
            summary="Upgrade to the fixed release.",
            max_chars=80,
        )

        self.assertEqual([chunk.chunk_id for chunk in first_run], [chunk.chunk_id for chunk in second_run])
        self.assertEqual(
            [chunk.metadata["content_hash"] for chunk in first_run],
            [chunk.metadata["content_hash"] for chunk in second_run],
        )

    def test_advisory_string_references_are_not_split_into_characters(self):
        chunks = chunk_advisory(
            vulnerability_id="GHSA-string-ref",
            package="pkg",
            ecosystem="npm",
            references="https://example.test/advisory",
        )

        content = "\n".join(chunk.content for chunk in chunks)

        self.assertIn("Reference: https://example.test/advisory", content)


if __name__ == "__main__":
    unittest.main()
