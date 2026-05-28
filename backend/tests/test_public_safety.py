import unittest

from app.services.public_safety import (
    contains_unsafe_public_text,
    replace_case_insensitive,
    sanitize_public_identifier,
    sanitize_public_value,
    sanitize_text,
)


class PublicSafetyTest(unittest.TestCase):
    def test_sanitize_text_leaves_safe_text_unchanged(self):
        value = "Upgrade archive-utils to 2.2.0 and review release notes."

        self.assertEqual(sanitize_text(value), value)

    def test_sanitize_text_redacts_existing_markers_case_insensitively(self):
        value = "PoC mentions malicious payload and EXPLOIT STEPS."

        self.assertEqual(
            sanitize_text(value),
            "[redacted] mentions [redacted] and [redacted].",
        )

    def test_sanitize_text_redacts_poc_variants_and_exploit_code_phrases(self):
        cases = {
            "P o C details are available": "[redacted] details are available",
            "P-o-C details are available": "[redacted] details are available",
            "Proof of concept exploit code is available": "[redacted] [redacted] is available",
            "proof-of-concept exploit-code is available": "[redacted] [redacted] is available",
        }

        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(sanitize_text(value), expected)

    def test_sanitize_text_redacts_local_paths_and_secret_like_tokens(self):
        value = (
            "Read /Users/example/private-token/report.json with "
            "github_pat_11SECRET and token=secret-invalid-citation."
        )

        result = sanitize_text(value)

        self.assertNotIn("/Users/example", result)
        self.assertNotIn("private-token", result)
        self.assertNotIn("github_pat_11SECRET", result)
        self.assertNotIn("token=secret-invalid-citation", result)
        self.assertIn("[redacted-path]", result)
        self.assertIn("[redacted-secret]", result)

    def test_sanitize_text_redacts_local_path_variants_in_references(self):
        cases = [
            "Reference file:///Users/alice/private/repo/package-lock.json",
            "Reference https://scanner.local/report?path=/repos/private/payments/package.json",
            "Reference C:/Users/alice/private/repo/package-lock.json",
        ]

        for value in cases:
            with self.subTest(value=value):
                result = sanitize_text(value)

                self.assertNotIn("/Users/alice", result)
                self.assertNotIn("/repos/private", result)
                self.assertNotIn("C:/Users/alice", result)
                self.assertIn("[redacted-path]", result)
                self.assertFalse(contains_unsafe_public_text(result))
                self.assertTrue(contains_unsafe_public_text(value))

    def test_sanitize_text_redacts_colon_style_secret_fragments(self):
        value = (
            "Authorization: Bearer abcdefghijklmnop password: hunter2 "
            "api_key: plain token: abc123"
        )

        result = sanitize_text(value)

        self.assertNotIn("abcdefghijklmnop", result)
        self.assertNotIn("hunter2", result)
        self.assertNotIn("plain", result)
        self.assertNotIn("abc123", result)
        self.assertEqual(result.count("[redacted-secret]"), 4)

    def test_sanitize_text_preserves_already_redacted_colon_and_bearer_fragments(self):
        cases = [
            "Authorization: Bearer [redacted]",
            "Authorization: Bearer [redacted-secret]",
            "token: [redacted-secret]",
            "api_key: [redacted]",
        ]

        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(sanitize_text(value), value)
                self.assertFalse(contains_unsafe_public_text(value))

    def test_sanitize_public_value_redacts_secret_like_names(self):
        value = {
            "token": "secret-value",
            "package": {"name": "private-token-package"},
        }

        result = sanitize_public_value(value)
        text = repr(result)

        self.assertNotIn("token", text)
        self.assertNotIn("secret-value", text)
        self.assertNotIn("private-token-package", text)
        self.assertIn("[redacted-secret]", text)

    def test_sanitize_public_value_preserves_legitimate_token_named_packages(self):
        value = {"package": {"name": "jsonwebtoken", "alias": "csrf-token"}}

        self.assertEqual(sanitize_public_value(value), value)

    def test_sanitize_public_value_preserves_legitimate_package_identifiers(self):
        value = {
            "packages": [
                {"name": "cookie"},
                {"name": "payload-parser"},
                {"name": "safe-payload-utils"},
            ],
            "top_findings": [{"package_name": "payload-parser"}],
        }

        self.assertEqual(sanitize_public_value(value), value)

    def test_sanitize_public_identifier_still_redacts_unsafe_identifier_values(self):
        cases = [
            "private-token-package",
            "proof-of-concept-payload-lib",
            "/Users/auditor/private/repo",
            "/etc/passwd",
            "@private/token",
            "token-secret-version",
        ]

        for value in cases:
            with self.subTest(value=value):
                result = sanitize_public_identifier(value)

                self.assertNotIn("private-token-package", result)
                self.assertNotIn("proof-of-concept-payload-lib", result)
                self.assertNotIn("token-secret-version", result)
                self.assertNotIn("@private/token", result)
                self.assertNotIn("/Users/auditor", result)
                self.assertNotIn("/etc/passwd", result)
                self.assertIn("[redacted", result)

    def test_contains_unsafe_public_text_allows_safe_metric_names(self):
        self.assertFalse(contains_unsafe_public_text({"token_count": 101}))

    def test_sanitize_text_redacts_scoped_private_package_in_freeform_text(self):
        value = "Upgrade @private/token and review @safe/payload-parser."

        result = sanitize_text(value)

        self.assertNotIn("@private/token", result)
        self.assertIn("[redacted-secret]", result)
        self.assertIn("@safe/payload-parser", result)

    def test_contains_public_leak_text_flags_scoped_private_package_in_freeform_text(self):
        self.assertTrue(contains_unsafe_public_text("Upgrade @private/token."))
        self.assertFalse(contains_unsafe_public_text("Review @safe/payload-parser."))

    def test_sanitize_text_preserves_existing_redacted_secret_assignments(self):
        value = "password=[redacted] api_key=[redacted] token=[redacted]"

        self.assertEqual(sanitize_text(value), value)

    def test_sanitize_text_handles_repeated_markers_without_recursion(self):
        value = " ".join(["PoC"] * 1500)

        self.assertEqual(sanitize_text(value).count("[redacted]"), 1500)

    def test_sanitize_text_preserves_bad_input_error_type(self):
        with self.assertRaises(AttributeError):
            sanitize_text(None)  # type: ignore[arg-type]

    def test_sanitize_public_value_walks_nested_lists_and_mappings(self):
        value = {
            1: ["safe", "PoC"],
            "nested": {"details": "malicious payload", "count": 3},
            "empty": None,
        }

        self.assertEqual(
            sanitize_public_value(value),
            {
                "1": ["safe", "[redacted]"],
                "nested": {"details": "[redacted]", "count": 3},
                "empty": None,
            },
        )

    def test_sanitize_public_value_sanitizes_mapping_keys_recursively(self):
        value = {
            "payload key": {
                "proof-of-concept nested key": "safe value",
                "items": [{"exploit steps item key": "malicious payload"}],
            }
        }

        result = sanitize_public_value(value)
        result_text = repr(result)

        self.assertNotIn("payload key", result_text)
        self.assertNotIn("proof-of-concept nested key", result_text)
        self.assertNotIn("exploit steps item key", result_text)
        self.assertFalse(contains_unsafe_public_text(result))

    def test_contains_unsafe_public_text_checks_mapping_keys(self):
        self.assertTrue(contains_unsafe_public_text({"payload key": "safe value"}))

    def test_contains_unsafe_public_text_uses_public_safety_patterns(self):
        self.assertTrue(
            contains_unsafe_public_text(
                {"details": ["Proof of concept exploit code is available"]}
            )
        )
        self.assertFalse(contains_unsafe_public_text({"details": ["Upgrade to 2.2.0"]}))

    def test_replace_case_insensitive_handles_repeated_markers_iteratively(self):
        value = " ".join(["PoC"] * 1500)

        self.assertEqual(
            replace_case_insensitive(value, "poc", "[redacted]").count("[redacted]"),
            1500,
        )


if __name__ == "__main__":
    unittest.main()
