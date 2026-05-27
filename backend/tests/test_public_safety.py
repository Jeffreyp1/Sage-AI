import unittest

from app.services.public_safety import (
    contains_unsafe_public_text,
    replace_case_insensitive,
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
