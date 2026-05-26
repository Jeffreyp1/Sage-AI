import unittest

from app.eval.metrics import exact_match_accuracy, precision_at_k, summarize_scores


class EvalMetricsTest(unittest.TestCase):
    def test_exact_match_accuracy_supports_nested_paths(self):
        rows = [
            {"expected": {"risk": {"priority": "P0"}}, "actual": {"risk": {"priority": "P0"}}},
            {"expected": {"risk": {"priority": "P1"}}, "actual": {"risk": {"priority": "P2"}}},
        ]

        self.assertEqual(exact_match_accuracy(rows, "risk.priority"), 0.5)

    def test_summarize_scores_averages_rates_and_sums_counts(self):
        summary = summarize_scores(
            [
                {
                    "passed": True,
                    "vulnerability_match_accuracy": 1.0,
                    "fixed_version_accuracy": 1.0,
                    "finding_count": 0,
                },
                {
                    "passed": False,
                    "vulnerability_match_accuracy": 0.5,
                    "fixed_version_accuracy": 0.0,
                    "finding_count": 2,
                },
            ]
        )

        self.assertFalse(summary["passed"])
        self.assertEqual(summary["case_count"], 2)
        self.assertEqual(summary["vulnerability_match_accuracy"], 0.75)
        self.assertEqual(summary["fixed_version_accuracy"], 0.5)
        self.assertEqual(summary["finding_count"], 2)

    def test_precision_at_k_scores_ranked_retrieval_ids(self):
        results = [
            {"chunk_id": "source-upload"},
            {"chunk": {"chunk_id": "route-receipts"}},
            "advisory-archive-utils",
        ]

        self.assertEqual(
            precision_at_k(
                results,
                expected_ids=["route-receipts", "advisory-archive-utils"],
                k=2,
            ),
            0.5,
        )
        self.assertEqual(
            precision_at_k(
                results,
                expected_ids=["route-receipts", "advisory-archive-utils"],
                k=3,
            ),
            2 / 3,
        )

    def test_precision_at_k_handles_empty_and_invalid_inputs(self):
        self.assertEqual(precision_at_k([], expected_ids=["missing"], k=5), 0.0)
        self.assertEqual(precision_at_k(["anything"], expected_ids=[], k=5), 0.0)
        self.assertEqual(precision_at_k(["anything"], expected_ids=["anything"], k=0), 0.0)


if __name__ == "__main__":
    unittest.main()
