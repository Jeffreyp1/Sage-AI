"""State objects for deterministic remediation triage workflows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping, cast

from app.services.public_safety import sanitize_public_value
from app.services.rag_types import EvidenceChunk


JsonMapping = Mapping[str, object]


@dataclass(frozen=True)
class RepoContext:
    repo: str | None
    package_name: str | None
    ecosystem: str | None
    current_version: str | None
    owner: str | None
    evidence_chunk_ids: list[str]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class VulnerabilityTriageExplanation:
    vulnerability_id: str | None
    severity: str | None
    priority: str | None
    risk_score: int | None
    factors: list[str]
    rationale: list[str]
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ReachabilityExplanation:
    reachability: str | None
    runtime_scope: str | None
    confidence: str | None
    evidence: list[dict[str, str]]
    explanation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PatchExplanation:
    recommended_action: str | None
    target_version: str | None
    patch_complexity: str | None
    breaking_change_risk: str | None
    steps: list[str]
    test_plan: list[str]
    rollback_plan: list[str]
    explanation: str
    safe_to_auto_apply: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CitationVerification:
    blocked: bool
    retrieved_chunk_ids: list[str]
    validation: dict[str, object]
    summary: dict[str, object] | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HumanApprovalDecision:
    status: str
    approved_by: str | None = None
    decision_reason: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class HumanApprovalGate:
    required: bool
    approved: bool
    status: str
    requested_actions: list[str]
    prohibited_actions: list[str]
    blocked_reasons: list[str]
    decision: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TriageNodeResult:
    node_name: str
    validation_status: str
    output: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass
class TriageWorkflowState:
    remediation_task: JsonMapping
    evidence_chunks: list[EvidenceChunk]
    status: str = "pending"
    approved: bool = False
    repo_context: RepoContext | None = None
    vulnerability_triage: VulnerabilityTriageExplanation | None = None
    reachability: ReachabilityExplanation | None = None
    patch: PatchExplanation | None = None
    citation_verification: CitationVerification | None = None
    human_approval: HumanApprovalGate | None = None
    blocked_reasons: list[str] = field(default_factory=list)
    node_results: list[TriageNodeResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "status": self.status,
            "approved": self.approved,
            "remediation_task": dict(self.remediation_task),
            "evidence_chunks": [chunk.to_dict() for chunk in self.evidence_chunks],
            "repo_context": (
                self.repo_context.to_dict() if self.repo_context is not None else None
            ),
            "vulnerability_triage": (
                self.vulnerability_triage.to_dict()
                if self.vulnerability_triage is not None
                else None
            ),
            "reachability": (
                self.reachability.to_dict() if self.reachability is not None else None
            ),
            "patch": self.patch.to_dict() if self.patch is not None else None,
            "citation_verification": (
                self.citation_verification.to_dict()
                if self.citation_verification is not None
                else None
            ),
            "human_approval": (
                self.human_approval.to_dict()
                if self.human_approval is not None
                else None
            ),
            "blocked_reasons": list(self.blocked_reasons),
            "node_results": [result.to_dict() for result in self.node_results],
        }
        return cast(dict[str, object], sanitize_public_value(data))
