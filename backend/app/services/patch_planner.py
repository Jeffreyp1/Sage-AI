"""Deterministic patch-plan scaffolding for the MVP."""

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional

from app.services.dependency_parser import ParsedDependency
from app.services.vulnerability_normalizer import NormalizedVulnerability


@dataclass
class PatchPlan:
    recommended_action: str
    target_version: Optional[str]
    patch_complexity: str
    breaking_change_risk: str
    steps: List[str]
    test_plan: List[str]
    rollback_plan: List[str]
    pr_description: str

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def build_patch_plan(
    dependency: ParsedDependency,
    vulnerability: NormalizedVulnerability,
    test_commands: List[str],
) -> PatchPlan:
    target_version = vulnerability.fixed_versions[0] if vulnerability.fixed_versions else None
    recommended_action = "upgrade" if target_version else "needs_human_review"
    patch_complexity = infer_patch_complexity(dependency.current_version, target_version)
    breaking_change_risk = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "unknown": "unknown",
    }[patch_complexity]

    steps = []
    if target_version:
        steps.extend(
            [
                "Update %s from %s to %s"
                % (dependency.name, dependency.current_version or "unknown", target_version),
                "Regenerate package-lock.json",
            ]
        )
    else:
        steps.append("Review advisory and package release notes to identify a safe remediation")
    steps.extend(["Run targeted tests", "Deploy to staging and verify affected flows"])

    tests = test_commands or ["npm test"]
    if dependency.name and any("upload" in ev.get("source", "") for ev in dependency.evidence):
        tests.append("npm run test:integration -- upload")
    if "npm run lint" not in tests:
        tests.append("npm run lint")

    rollback = [
        "Revert dependency bump PR",
        "Restore previous package-lock.json",
        "Redeploy previous service version",
    ]

    pr_description = (
        "Upgrade %s to remediate %s. This plan is evidence-grounded and requires human review "
        "before merge."
        % (dependency.name, vulnerability.canonical_id)
    )

    return PatchPlan(
        recommended_action=recommended_action,
        target_version=target_version,
        patch_complexity=patch_complexity,
        breaking_change_risk=breaking_change_risk,
        steps=steps,
        test_plan=dedupe_keep_order(tests),
        rollback_plan=rollback,
        pr_description=pr_description,
    )


def infer_patch_complexity(current_version: Optional[str], target_version: Optional[str]) -> str:
    if not current_version or not target_version:
        return "unknown"
    current_parts = semver_parts(current_version)
    target_parts = semver_parts(target_version)
    if not current_parts or not target_parts:
        return "unknown"
    if target_parts[0] > current_parts[0]:
        return "high"
    if target_parts[1] > current_parts[1]:
        return "low"
    if target_parts[2] >= current_parts[2]:
        return "low"
    return "medium"


def semver_parts(version: str) -> Optional[tuple]:
    clean = version.strip().lstrip("v").split("-", 1)[0]
    parts = clean.split(".")
    if len(parts) < 3:
        return None
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return None


def dedupe_keep_order(values: List[str]) -> List[str]:
    seen = set()
    output = []
    for value in values:
        if value not in seen:
            seen.add(value)
            output.append(value)
    return output

