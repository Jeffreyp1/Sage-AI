import unittest
from typing import List, Optional

from app.services.dependency_parser import ParsedDependency
from app.services.patch_planner import build_patch_plan
from app.services.vulnerability_normalizer import NormalizedVulnerability


class PatchPlannerTest(unittest.TestCase):
    def test_chooses_nearest_fixed_version_at_or_above_installed(self):
        plan = build_patch_plan(
            dependency=dependency(current_version="6.5.2"),
            vulnerability=vulnerability(fixed_versions=["6.2.4", "6.5.3"]),
            test_commands=[],
        )

        self.assertEqual(plan.recommended_action, "upgrade")
        self.assertEqual(plan.target_version, "6.5.3")
        self.assertEqual(plan.patch_complexity, "low")
        self.assertEqual(plan.steps[0], "Update vulnerable-lib from 6.5.2 to 6.5.3")

    def test_requires_review_when_only_fixed_versions_are_below_installed(self):
        plan = build_patch_plan(
            dependency=dependency(current_version="6.5.2"),
            vulnerability=vulnerability(fixed_versions=["6.2.4"]),
            test_commands=[],
        )

        self.assertEqual(plan.recommended_action, "needs_human_review")
        self.assertIsNone(plan.target_version)
        self.assertEqual(plan.patch_complexity, "unknown")
        self.assertEqual(plan.breaking_change_risk, "unknown")
        self.assertIn("Review advisory", plan.steps[0])

    def test_requires_review_when_fixed_version_is_lower_prerelease(self):
        plan = build_patch_plan(
            dependency=dependency(current_version="1.2.4"),
            vulnerability=vulnerability(fixed_versions=["1.2.4-beta.1"]),
            test_commands=[],
        )

        self.assertEqual(plan.recommended_action, "needs_human_review")
        self.assertIsNone(plan.target_version)

    def test_accepts_fixed_version_equal_to_installed_version(self):
        plan = build_patch_plan(
            dependency=dependency(current_version="1.2.4"),
            vulnerability=vulnerability(fixed_versions=["1.2.4"]),
            test_commands=[],
        )

        self.assertEqual(plan.recommended_action, "upgrade")
        self.assertEqual(plan.target_version, "1.2.4")
        self.assertEqual(plan.patch_complexity, "low")

    def test_does_not_mutate_provided_test_commands(self):
        test_commands = ["npm test"]

        plan = build_patch_plan(
            dependency=dependency(current_version="1.2.4"),
            vulnerability=vulnerability(fixed_versions=["1.2.5"]),
            test_commands=test_commands,
        )

        self.assertEqual(test_commands, ["npm test"])
        self.assertEqual(plan.test_plan, ["npm test", "npm run lint"])

    def test_direct_dependency_upgrade_uses_safe_target(self):
        plan = build_patch_plan(
            dependency=dependency(current_version="2.1.4"),
            vulnerability=vulnerability(fixed_versions=["2.2.0"]),
            test_commands=["npm test"],
        )

        self.assertEqual(plan.recommended_action, "upgrade")
        self.assertEqual(plan.target_version, "2.2.0")
        self.assertEqual(
            plan.steps[:2],
            ["Update vulnerable-lib from 2.1.4 to 2.2.0", "Regenerate package-lock.json"],
        )
        self.assertEqual(plan.test_plan, ["npm test", "npm run lint"])

    def test_transitive_dependency_with_parent_recommends_parent_upgrade(self):
        plan = build_patch_plan(
            dependency=dependency(
                name="child-lib",
                current_version="1.0.0",
                is_direct=False,
                parent_package="parent-lib",
            ),
            vulnerability=vulnerability(package="child-lib", fixed_versions=["1.0.1"]),
            test_commands=[],
        )
        steps = " ".join(plan.steps)

        self.assertEqual(plan.recommended_action, "upgrade_parent_package")
        self.assertEqual(plan.target_version, "1.0.1")
        self.assertIn("Upgrade parent package parent-lib", steps)
        self.assertIn("child-lib", steps)
        self.assertNotIn("Update child-lib", steps)
        self.assertNotIn("Update vulnerable package", steps)

    def test_transitive_dependency_without_parent_recommends_override_or_resolution(self):
        plan = build_patch_plan(
            dependency=dependency(name="child-lib", current_version="1.0.0", is_direct=False),
            vulnerability=vulnerability(package="child-lib", fixed_versions=["1.0.1"]),
            test_commands=[],
        )
        steps = " ".join(plan.steps)

        self.assertEqual(plan.recommended_action, "override_or_resolution")
        self.assertEqual(plan.target_version, "1.0.1")
        self.assertIn("npm override/resolution", steps)
        self.assertNotIn("Update child-lib", steps)
        self.assertNotIn("Update vulnerable package", steps)


def dependency(
    name: str = "vulnerable-lib",
    current_version: str = "1.0.0",
    is_direct: bool = True,
    parent_package: Optional[str] = None,
) -> ParsedDependency:
    return ParsedDependency(
        name=name,
        current_version=current_version,
        ecosystem="npm",
        dependency_type="dependencies" if is_direct else "transitive",
        is_direct=is_direct,
        parent_package=parent_package,
    )


def vulnerability(
    package: str = "vulnerable-lib",
    fixed_versions: Optional[List[str]] = None,
) -> NormalizedVulnerability:
    return NormalizedVulnerability(
        canonical_id="CVE-2026-12345",
        source_id="GHSA-patch-plan",
        aliases=[],
        package=package,
        ecosystem="npm",
        current_version="1.0.0",
        summary="Test vulnerability",
        details=None,
        severity="HIGH",
        affected_versions=[],
        fixed_versions=fixed_versions or [],
        references=[],
        published_at=None,
        modified_at=None,
    )


if __name__ == "__main__":
    unittest.main()
