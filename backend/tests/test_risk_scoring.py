import unittest

from app.services.risk_scoring import RiskInput, score_risk


class RiskScoringTest(unittest.TestCase):
    def test_high_runtime_reachable_vulnerability_outranks_critical_dev_only(self):
        production = score_risk(
            RiskInput(
                severity="HIGH",
                known_exploited=False,
                epss_score=None,
                runtime_scope="production",
                reachability="possibly_reachable",
                dependency_type="dependencies",
                is_direct=True,
                fix_available=True,
            )
        )
        dev_only = score_risk(
            RiskInput(
                severity="CRITICAL",
                known_exploited=False,
                epss_score=None,
                runtime_scope="development",
                reachability="unlikely_reachable",
                dependency_type="devDependency",
                is_direct=True,
                fix_available=True,
            )
        )

        self.assertGreater(production.risk_score, dev_only.risk_score)
        self.assertEqual(production.priority, "P0_RELEASE_BLOCKER")
        self.assertEqual(dev_only.priority, "P3_MONITOR_DEFER")

    def test_critical_production_unknown_reachability_needs_review(self):
        result = score_risk(
            RiskInput(
                severity="CRITICAL",
                known_exploited=False,
                epss_score=None,
                runtime_scope="production",
                reachability="unknown",
                dependency_type="dependencies",
                is_direct=True,
                fix_available=True,
            )
        )

        self.assertEqual(result.priority, "NEEDS_HUMAN_REVIEW")

    def test_high_production_without_fix_needs_review(self):
        result = score_risk(
            RiskInput(
                severity="HIGH",
                known_exploited=False,
                epss_score=None,
                runtime_scope="production",
                reachability="possibly_reachable",
                dependency_type="dependencies",
                is_direct=True,
                fix_available=False,
            )
        )

        self.assertEqual(result.priority, "NEEDS_HUMAN_REVIEW")


if __name__ == "__main__":
    unittest.main()
