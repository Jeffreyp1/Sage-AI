"""End-to-end local repository scan orchestration."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from uuid import uuid4

from app.config import get_settings
from app.services.dependency_parser import ParsedDependency, parse_dependencies
from app.services.osv_client import OsvClient, OsvClientError
from app.services.patch_planner import PatchPlan, build_patch_plan
from app.services.public_safety import sanitize_public_value, sanitize_text
from app.services.reachability import ReachabilityResult, analyze_reachability
from app.services.repo_ingestion import RepoProfile, profile_repo
from app.services.risk_scoring import RiskInput, RiskResult, score_risk
from app.services.vulnerability_normalizer import (
    NormalizedVulnerability,
    deduplicate_vulnerabilities,
    normalize_osv_vulnerability,
    osv_advisory_matches_package,
)

PRIORITY_ORDER = {
    "P0_RELEASE_BLOCKER": 0,
    "P1_FIX_THIS_SPRINT": 1,
    "NEEDS_HUMAN_REVIEW": 2,
    "P2_SCHEDULE_SOON": 3,
    "P3_MONITOR_DEFER": 4,
}

MISSING_FIX_ESCALATION_PRIORITIES = {"P2_SCHEDULE_SOON", "P3_MONITOR_DEFER"}


@dataclass
class RemediationTaskOutput:
    task_id: str
    repo: str
    package: Dict[str, object]
    vulnerability: Dict[str, object]
    risk: Dict[str, object]
    evidence: List[Dict[str, str]]
    patch_plan: Dict[str, object]
    test_plan: List[str]
    rollback_plan: List[str]
    owner: Optional[str]
    human_approval_required: bool = True

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    repo_profile: RepoProfile
    packages: List[ParsedDependency]
    vulnerabilities: List[NormalizedVulnerability]
    remediation_tasks: List[RemediationTaskOutput]
    summary: Dict[str, object]
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return sanitize_public_value(
            {
                "scan_id": self.scan_id,
                "repo_profile": self.repo_profile.to_dict(),
                "packages": [package.to_dict() for package in self.packages],
                "vulnerabilities": [
                    vulnerability.to_public_dict() for vulnerability in self.vulnerabilities
                ],
                "remediation_tasks": [task.to_dict() for task in self.remediation_tasks],
                "summary": self.summary,
                "errors": self.errors,
            }
        )


class ScanService:
    def __init__(self, osv_client: Optional[OsvClient] = None) -> None:
        settings = get_settings()
        self.osv_client = osv_client or OsvClient(
            api_url=settings.osv_api_url,
            timeout_seconds=settings.osv_timeout_seconds,
        )

    def scan_local(self, repo_path: str) -> ScanResult:
        root = Path(repo_path).resolve()
        if not root.exists() or not root.is_dir():
            raise ValueError("Repository path does not exist or is not a directory: %s" % repo_path)

        profile = profile_repo(str(root))
        packages = parse_dependencies(str(root))
        all_vulnerabilities: List[NormalizedVulnerability] = []
        tasks: List[RemediationTaskOutput] = []
        errors = []
        raw_alert_count = 0

        for dependency in packages:
            query_version = dependency.current_version
            if not query_version:
                errors.append(
                    "Skipped OSV query for %s because exact installed version was unavailable."
                    % dependency.name
                )
                continue
            try:
                raw_vulnerabilities = self.osv_client.query(
                    package_name=dependency.name,
                    version=query_version,
                    ecosystem=dependency.ecosystem,
                )
            except OsvClientError as exc:
                errors.append("OSV query failed for %s@%s: %s" % (dependency.name, query_version, exc))
                raw_vulnerabilities = []
            raw_alert_count += len(raw_vulnerabilities)

            normalized = []
            for raw in raw_vulnerabilities:
                if not osv_advisory_matches_package(raw, dependency.name, dependency.ecosystem):
                    errors.append(
                        "Skipped OSV advisory for %s because affected package did not match."
                        % dependency.name
                    )
                    continue
                normalized.append(
                    normalize_osv_vulnerability(
                        raw=raw,
                        package_name=dependency.name,
                        ecosystem=dependency.ecosystem,
                        current_version=query_version,
                    )
                )
            deduped = deduplicate_vulnerabilities(normalized)
            all_vulnerabilities.extend(deduped)

            if not deduped:
                continue

            reachability = analyze_reachability(
                repo_path=str(root),
                dependency=dependency,
                codeowners=profile.codeowners,
            )

            for vulnerability in deduped:
                risk = score_risk(
                    RiskInput(
                        severity=vulnerability.severity,
                        known_exploited=False,
                        epss_score=None,
                        runtime_scope=reachability.runtime_scope,
                        reachability=reachability.reachability,
                        dependency_type=dependency.dependency_type,
                        is_direct=dependency.is_direct,
                        fix_available=bool(vulnerability.fixed_versions),
                    )
                )
                patch_plan = build_patch_plan(
                    dependency=dependency,
                    vulnerability=vulnerability,
                    test_commands=profile.test_commands,
                )
                risk = escalate_missing_fix_to_review(risk, patch_plan)
                tasks.append(
                    build_task_output(
                        profile=profile,
                        dependency=dependency,
                        vulnerability=vulnerability,
                        reachability=reachability,
                        risk=risk,
                        patch_plan=patch_plan,
                    )
                )

        deduped_all = deduplicate_vulnerabilities(all_vulnerabilities)
        tasks = sort_tasks(deduplicate_remediation_tasks(tasks))
        summary = build_summary(
            packages=packages,
            vulnerabilities=deduped_all,
            tasks=tasks,
            errors=errors,
            raw_alert_count=raw_alert_count,
        )

        return ScanResult(
            scan_id=str(uuid4()),
            repo_profile=profile,
            packages=packages,
            vulnerabilities=deduped_all,
            remediation_tasks=tasks,
            summary=summary,
            errors=errors,
        )


def build_task_output(
    profile: RepoProfile,
    dependency: ParsedDependency,
    vulnerability: NormalizedVulnerability,
    reachability: ReachabilityResult,
    risk: RiskResult,
    patch_plan: PatchPlan,
) -> RemediationTaskOutput:
    evidence = (
        dependency.evidence
        + dependency_location_evidence(dependency)
        + reachability.evidence
    )
    return RemediationTaskOutput(
        task_id="task_%s" % uuid4().hex[:12],
        repo=profile.repo_name,
        package={
            "name": dependency.name,
            "ecosystem": dependency.ecosystem,
            "current_version": dependency.current_version,
            "dependency_type": dependency.dependency_type,
            "is_direct": dependency.is_direct,
            "parent_package": dependency.parent_package,
        },
        vulnerability={
            "canonical_id": vulnerability.canonical_id,
            "source_id": vulnerability.source_id,
            "aliases": vulnerability.aliases,
            "severity": vulnerability.severity,
            "summary": sanitize_text(vulnerability.summary) if vulnerability.summary else None,
            "fixed_versions": vulnerability.fixed_versions,
        },
        risk={
            "priority": risk.priority,
            "risk_score": risk.risk_score,
            "known_exploited": None,
            "epss_score": None,
            "runtime_scope": reachability.runtime_scope,
            "reachability": reachability.reachability,
            "confidence": reachability.confidence,
            "factors": risk.factors,
            "rationale": risk.rationale,
        },
        evidence=dedupe_evidence(evidence),
        patch_plan=patch_plan.to_dict(),
        test_plan=patch_plan.test_plan,
        rollback_plan=patch_plan.rollback_plan,
        owner=reachability.owner,
    )


def escalate_missing_fix_to_review(risk: RiskResult, patch_plan: PatchPlan) -> RiskResult:
    if patch_plan.target_version is not None:
        return risk
    if risk.priority not in MISSING_FIX_ESCALATION_PRIORITIES:
        return risk

    rationale = [
        item
        for item in risk.rationale
        if not item.startswith("Risk score ") and item != "No fixed version was identified."
    ]
    rationale.append("No fixed version was identified; human review is required.")
    rationale.append(
        "Risk score %s maps to NEEDS_HUMAN_REVIEW because no target version is available."
        % risk.risk_score
    )
    return RiskResult(
        risk_score=risk.risk_score,
        priority="NEEDS_HUMAN_REVIEW",
        factors=risk.factors,
        rationale=rationale,
    )


def dependency_location_evidence(dependency: ParsedDependency) -> List[Dict[str, str]]:
    evidence = []
    source = (
        Path(dependency.lockfile_path).name
        if dependency.lockfile_path
        else "package-lock.json"
    )
    if dependency.lockfile_entry_path:
        evidence.append(
            {
                "type": "lockfile_entry",
                "source": source,
                "claim": "%s@%s is installed at %s"
                % (
                    dependency.name,
                    dependency.current_version or "unknown",
                    dependency.lockfile_entry_path,
                ),
            }
        )
    if dependency.parent_package:
        evidence.append(
            {
                "type": "dependency_path",
                "source": source,
                "claim": "%s is required through parent package %s"
                % (dependency.name, dependency.parent_package),
            }
        )
    return evidence


def deduplicate_remediation_tasks(
    tasks: List[RemediationTaskOutput],
) -> List[RemediationTaskOutput]:
    deduped: List[RemediationTaskOutput] = []
    for task in tasks:
        merged = False
        for index, existing in enumerate(deduped):
            if should_merge_tasks(existing, task):
                deduped[index] = merge_remediation_tasks(existing, task)
                merged = True
                break
        if not merged:
            deduped.append(task)
    return deduped


def should_merge_tasks(first: RemediationTaskOutput, second: RemediationTaskOutput) -> bool:
    if first.package.get("name") != second.package.get("name"):
        return False
    if first.package.get("ecosystem") != second.package.get("ecosystem"):
        return False
    if first.package.get("current_version") != second.package.get("current_version"):
        return False
    return bool(task_identity_set(first).intersection(task_identity_set(second)))


def merge_remediation_tasks(
    first: RemediationTaskOutput,
    second: RemediationTaskOutput,
) -> RemediationTaskOutput:
    winner = higher_priority_task(first, second)
    return RemediationTaskOutput(
        task_id=winner.task_id,
        repo=winner.repo,
        package=merge_package(first.package, second.package, winner.package),
        vulnerability=merge_vulnerability(
            first.vulnerability,
            second.vulnerability,
            winner.vulnerability,
        ),
        risk=merge_risk(first.risk, second.risk, winner.risk),
        evidence=dedupe_evidence(first.evidence + second.evidence),
        patch_plan=merge_patch_plan(first.patch_plan, second.patch_plan, winner.patch_plan),
        test_plan=dedupe_strings(first.test_plan + second.test_plan),
        rollback_plan=dedupe_strings(first.rollback_plan + second.rollback_plan),
        owner=winner.owner or first.owner or second.owner,
        human_approval_required=(
            first.human_approval_required or second.human_approval_required
        ),
    )


def higher_priority_task(
    first: RemediationTaskOutput,
    second: RemediationTaskOutput,
) -> RemediationTaskOutput:
    first_key = (
        priority_rank(first.risk.get("priority")),
        -risk_score(first.risk),
    )
    second_key = (
        priority_rank(second.risk.get("priority")),
        -risk_score(second.risk),
    )
    return first if first_key <= second_key else second


def merge_package(
    first: Dict[str, object],
    second: Dict[str, object],
    winner: Dict[str, object],
) -> Dict[str, object]:
    package = dict(winner)
    is_direct = bool(first.get("is_direct")) or bool(second.get("is_direct"))
    package["is_direct"] = is_direct
    if is_direct:
        package["parent_package"] = None

    dependency_types = [first.get("dependency_type"), second.get("dependency_type")]
    if "dependencies" in dependency_types:
        package["dependency_type"] = "dependencies"
    elif is_direct and package.get("dependency_type") == "transitive":
        direct_package = first if first.get("is_direct") else second
        package["dependency_type"] = direct_package.get("dependency_type")
    return package


def merge_vulnerability(
    first: Dict[str, object],
    second: Dict[str, object],
    winner: Dict[str, object],
) -> Dict[str, object]:
    vulnerability = dict(winner)
    vulnerability["aliases"] = sorted(vulnerability_aliases(first) | vulnerability_aliases(second))
    vulnerability["fixed_versions"] = sorted(
        vulnerability_versions(first, "fixed_versions")
        | vulnerability_versions(second, "fixed_versions")
    )
    return vulnerability


def merge_risk(
    first: Dict[str, object],
    second: Dict[str, object],
    winner: Dict[str, object],
) -> Dict[str, object]:
    risk = dict(winner)
    priority = str(winner.get("priority"))
    score = max(risk_score(first), risk_score(second))
    risk["priority"] = priority
    risk["risk_score"] = score
    risk["rationale"] = merged_rationale(winner, score, priority)
    return risk


def merge_patch_plan(
    first: Dict[str, object],
    second: Dict[str, object],
    winner: Dict[str, object],
) -> Dict[str, object]:
    patch_plan = dict(winner)
    first_target = first.get("target_version")
    second_target = second.get("target_version")
    if patch_plan.get("target_version") is None:
        patch_plan["target_version"] = first_target or second_target
    patch_plan["steps"] = dedupe_strings(
        strings_from_mapping(first, "steps") + strings_from_mapping(second, "steps")
    )
    patch_plan["test_plan"] = dedupe_strings(
        strings_from_mapping(first, "test_plan") + strings_from_mapping(second, "test_plan")
    )
    patch_plan["rollback_plan"] = dedupe_strings(
        strings_from_mapping(first, "rollback_plan")
        + strings_from_mapping(second, "rollback_plan")
    )
    return patch_plan


def task_identity_set(task: RemediationTaskOutput) -> Set[str]:
    vulnerability = task.vulnerability
    identities = {
        value
        for value in [
            vulnerability.get("canonical_id"),
            vulnerability.get("source_id"),
        ]
        if isinstance(value, str) and value and value != "UNKNOWN"
    }
    aliases = vulnerability.get("aliases", [])
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str) and alias and alias != "UNKNOWN":
                identities.add(alias)
    return identities


def vulnerability_aliases(vulnerability: Dict[str, object]) -> Set[str]:
    aliases = vulnerability.get("aliases", [])
    if not isinstance(aliases, list):
        return set()
    return {alias for alias in aliases if isinstance(alias, str) and alias}


def vulnerability_versions(vulnerability: Dict[str, object], key: str) -> Set[str]:
    versions = vulnerability.get(key, [])
    if not isinstance(versions, list):
        return set()
    return {version for version in versions if isinstance(version, str) and version}


def merged_rationale(risk: Dict[str, object], score: int, priority: str) -> List[str]:
    rationale = [
        item
        for item in strings_from_mapping(risk, "rationale")
        if not item.startswith("Risk score ")
    ]
    rationale.append(
        "Merged duplicate findings; highest risk score %s maps to %s." % (score, priority)
    )
    return rationale


def strings_from_mapping(mapping: Dict[str, object], key: str) -> List[str]:
    values = mapping.get(key, [])
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, str)]


def dedupe_strings(values: List[str]) -> List[str]:
    seen = set()
    output = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def priority_rank(priority: object) -> int:
    return PRIORITY_ORDER.get(str(priority), 99)


def risk_score(risk: Dict[str, object]) -> int:
    value = risk.get("risk_score", 0)
    if isinstance(value, int):
        return value
    return 0


def build_summary(
    packages: List[ParsedDependency],
    vulnerabilities: List[NormalizedVulnerability],
    tasks: List[RemediationTaskOutput],
    errors: List[str],
    raw_alert_count: int,
) -> Dict[str, object]:
    priority_counts: Dict[str, int] = {}
    for task in tasks:
        priority = str(task.risk.get("priority"))
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
    return {
        "packages": len(packages),
        "raw_alerts": raw_alert_count,
        "deduped_remediation_tasks": len(tasks),
        "release_blockers": priority_counts.get("P0_RELEASE_BLOCKER", 0),
        "recommended_sprint_fixes": priority_counts.get("P1_FIX_THIS_SPRINT", 0),
        "safe_to_defer": priority_counts.get("P3_MONITOR_DEFER", 0),
        "needs_human_review": priority_counts.get("NEEDS_HUMAN_REVIEW", 0),
        "priority_counts": priority_counts,
        "complete": len(errors) == 0,
        "scan_status": "complete" if len(errors) == 0 else "incomplete",
        "error_count": len(errors),
    }


def sort_tasks(tasks: List[RemediationTaskOutput]) -> List[RemediationTaskOutput]:
    return sorted(
        tasks,
        key=lambda task: (
            priority_rank(task.risk.get("priority")),
            -risk_score(task.risk),
            str(task.package.get("name")),
        ),
    )


def dedupe_evidence(evidence: List[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    output = []
    for item in evidence:
        key = (item.get("type"), item.get("source"), item.get("claim"))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output
