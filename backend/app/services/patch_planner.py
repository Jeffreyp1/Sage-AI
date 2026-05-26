"""Deterministic patch-plan scaffolding for the MVP."""

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

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
    target_version = choose_target_version(
        current_version=dependency.current_version,
        fixed_versions=vulnerability.fixed_versions,
    )
    recommended_action = recommended_action_for(dependency, target_version)
    patch_complexity = infer_patch_complexity(dependency.current_version, target_version)
    breaking_change_risk = {
        "low": "low",
        "medium": "medium",
        "high": "high",
        "unknown": "unknown",
    }[patch_complexity]

    steps = remediation_steps(dependency, target_version)
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

    pr_description = pr_description_for(dependency, vulnerability, target_version)

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


def choose_target_version(
    current_version: Optional[str],
    fixed_versions: List[str],
) -> Optional[str]:
    current_parts = semver_parts(current_version)
    if current_parts is None:
        return None

    candidates: List[Tuple[Tuple[int, int, int], str]] = []
    for version in fixed_versions:
        target_parts = semver_parts(version)
        if target_parts is None:
            continue
        if target_parts >= current_parts:
            candidates.append((target_parts, version.strip()))

    if len(candidates) == 0:
        return None

    candidates.sort(key=lambda candidate: candidate[0])
    return candidates[0][1]


def recommended_action_for(
    dependency: ParsedDependency,
    target_version: Optional[str],
) -> str:
    if target_version is None:
        return "needs_human_review"
    if not dependency.is_direct and dependency.parent_package:
        return "upgrade_parent_package"
    if not dependency.is_direct:
        return "override_or_resolution"
    return "upgrade"


def remediation_steps(
    dependency: ParsedDependency,
    target_version: Optional[str],
) -> List[str]:
    if target_version is None:
        if not dependency.is_direct and dependency.parent_package:
            return [
                "Review advisory and %s release notes to identify a safe parent package upgrade"
                % dependency.parent_package
            ]
        if not dependency.is_direct:
            return [
                "Review advisory, dependency tree, and npm override/resolution options to identify "
                "a safe remediation"
            ]
        return ["Review advisory and package release notes to identify a safe remediation"]

    current_version = dependency.current_version or "unknown"
    if dependency.is_direct:
        return [
            "Update %s from %s to %s" % (dependency.name, current_version, target_version),
            "Regenerate package-lock.json",
        ]

    if dependency.parent_package:
        return [
            "Upgrade parent package %s so %s resolves from %s to %s"
            % (dependency.parent_package, dependency.name, current_version, target_version),
            "Regenerate package-lock.json and verify %s is no longer locked at %s"
            % (dependency.name, current_version),
        ]

    return [
        "Add an npm override/resolution for %s to %s, or escalate for human review"
        % (dependency.name, target_version),
        "Regenerate package-lock.json and verify %s is no longer locked at %s"
        % (dependency.name, current_version),
    ]


def pr_description_for(
    dependency: ParsedDependency,
    vulnerability: NormalizedVulnerability,
    target_version: Optional[str],
) -> str:
    if target_version is None:
        action = "Review remediation options for %s" % dependency.name
    elif not dependency.is_direct and dependency.parent_package:
        action = "Upgrade parent package %s to remediate %s" % (
            dependency.parent_package,
            dependency.name,
        )
    elif not dependency.is_direct:
        action = "Add an npm override/resolution to remediate %s" % dependency.name
    else:
        action = "Upgrade %s to remediate %s" % (dependency.name, vulnerability.canonical_id)

    return (
        "%s. This plan is evidence-grounded and requires human review before merge."
        % action
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
    if target_parts >= current_parts:
        return "low"
    return "unknown"


def semver_parts(version: Optional[str]) -> Optional[Tuple[int, int, int]]:
    if not version:
        return None
    clean = version.strip()
    if clean.startswith("v"):
        clean = clean[1:]
    clean = clean.split("-", 1)[0]
    clean = clean.split("+", 1)[0]
    parts = clean.split(".")
    if len(parts) != 3:
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
