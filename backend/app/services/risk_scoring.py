"""Deterministic risk scoring for remediation prioritization."""

from dataclasses import asdict, dataclass
from typing import Dict, List, Optional


@dataclass
class RiskInput:
    severity: str
    known_exploited: bool
    epss_score: Optional[float]
    runtime_scope: str
    reachability: str
    dependency_type: str
    is_direct: bool
    fix_available: bool
    service_criticality: str = "medium"


@dataclass
class RiskResult:
    risk_score: int
    priority: str
    factors: Dict[str, float]
    rationale: List[str]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def score_risk(risk_input: RiskInput) -> RiskResult:
    factors = {
        "severity_score": severity_score(risk_input.severity),
        "exploit_likelihood_score": exploit_likelihood_score(risk_input.epss_score),
        "known_exploited_score": 1.0 if risk_input.known_exploited else 0.0,
        "runtime_exposure_score": runtime_scope_score(risk_input.runtime_scope),
        "reachability_score": reachability_score(risk_input.reachability),
        "direct_dependency_score": 1.0 if risk_input.is_direct else 0.45,
        "fix_availability_score": 1.0 if risk_input.fix_available else 0.15,
        "service_criticality_score": service_criticality_score(risk_input.service_criticality),
    }

    weighted = (
        0.20 * factors["severity_score"]
        + 0.15 * factors["exploit_likelihood_score"]
        + 0.15 * factors["known_exploited_score"]
        + 0.15 * factors["runtime_exposure_score"]
        + 0.15 * factors["reachability_score"]
        + 0.10 * factors["direct_dependency_score"]
        + 0.05 * factors["fix_availability_score"]
        + 0.05 * factors["service_criticality_score"]
    )
    score = int(round(weighted * 100))
    priority = assign_priority(score, risk_input)

    return RiskResult(
        risk_score=score,
        priority=priority,
        factors=factors,
        rationale=risk_rationale(risk_input, score, priority),
    )


def assign_priority(score: int, risk_input: RiskInput) -> str:
    if (
        risk_input.dependency_type == "devDependency"
        and not risk_input.known_exploited
        and risk_input.runtime_scope == "development"
        and risk_input.reachability == "unlikely_reachable"
    ):
        return "P3_MONITOR_DEFER"
    if risk_input.known_exploited and risk_input.runtime_scope == "production":
        return "P0_RELEASE_BLOCKER"
    if (
        not risk_input.fix_available
        and risk_input.severity.upper() in {"CRITICAL", "HIGH"}
        and risk_input.runtime_scope == "production"
    ):
        return "NEEDS_HUMAN_REVIEW"
    if (
        risk_input.reachability == "unknown"
        and risk_input.severity.upper() == "CRITICAL"
        and risk_input.runtime_scope in {"production", "unknown"}
    ):
        return "NEEDS_HUMAN_REVIEW"
    if (
        risk_input.severity.upper() in {"CRITICAL", "HIGH"}
        and risk_input.runtime_scope == "production"
        and risk_input.reachability in {"likely_reachable", "possibly_reachable"}
        and risk_input.fix_available
        and score >= 60
    ):
        return "P0_RELEASE_BLOCKER"
    if score >= 65:
        return "P1_FIX_THIS_SPRINT"
    if score >= 40:
        return "P2_SCHEDULE_SOON"
    return "P3_MONITOR_DEFER"


def severity_score(severity: str) -> float:
    normalized = severity.upper()
    return {
        "CRITICAL": 1.0,
        "HIGH": 0.78,
        "MEDIUM": 0.48,
        "MODERATE": 0.48,
        "LOW": 0.22,
        "UNKNOWN": 0.12,
    }.get(normalized, 0.12)


def exploit_likelihood_score(epss_score: Optional[float]) -> float:
    if epss_score is None:
        return 0.20
    return max(0.0, min(1.0, epss_score))


def runtime_scope_score(runtime_scope: str) -> float:
    return {
        "production": 1.0,
        "runtime": 0.90,
        "development": 0.12,
        "ci": 0.25,
        "unknown": 0.35,
    }.get(runtime_scope, 0.35)


def reachability_score(reachability: str) -> float:
    return {
        "likely_reachable": 0.90,
        "possibly_reachable": 0.68,
        "unlikely_reachable": 0.10,
        "unknown": 0.35,
    }.get(reachability, 0.35)


def service_criticality_score(service_criticality: str) -> float:
    return {
        "critical": 1.0,
        "high": 0.80,
        "medium": 0.55,
        "low": 0.25,
    }.get(service_criticality, 0.55)


def risk_rationale(risk_input: RiskInput, score: int, priority: str) -> List[str]:
    rationale = [
        "Severity is %s." % risk_input.severity.upper(),
        "Runtime scope is %s." % risk_input.runtime_scope,
        "Reachability is %s." % risk_input.reachability,
    ]
    if risk_input.known_exploited:
        rationale.append("Known exploited status is confirmed by an upstream source.")
    else:
        rationale.append("Known exploited status was not evaluated in this scan.")
    if risk_input.fix_available:
        rationale.append("A fixed version is available.")
    else:
        rationale.append("No fixed version was identified.")
    rationale.append("Risk score %s maps to %s." % (score, priority))
    return rationale
