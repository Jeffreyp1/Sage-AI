"""End-to-end local repository scan orchestration."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
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
        tasks = sort_tasks(tasks)
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
    evidence = dependency.evidence + reachability.evidence
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
    priority_order = {
        "P0_RELEASE_BLOCKER": 0,
        "P1_FIX_THIS_SPRINT": 1,
        "NEEDS_HUMAN_REVIEW": 2,
        "P2_SCHEDULE_SOON": 3,
        "P3_MONITOR_DEFER": 4,
    }
    return sorted(
        tasks,
        key=lambda task: (
            priority_order.get(str(task.risk.get("priority")), 99),
            -int(task.risk.get("risk_score", 0)),
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
