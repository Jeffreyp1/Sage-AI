"""Deterministic LangGraph-style shell for remediation triage."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping

from app.ai.contracts import AIProvider, MockAIProvider
from app.agents.state import (
    CitationVerification,
    HumanApprovalDecision,
    HumanApprovalGate,
    PatchExplanation,
    ReachabilityExplanation,
    RepoContext,
    TriageNodeResult,
    TriageWorkflowState,
    VulnerabilityTriageExplanation,
)
from app.services.ai_summary_service import AISummaryService
from app.services.public_safety import sanitize_text
from app.services.rag_types import EvidenceChunk
from app.services.trace_service import TraceService


PASSED = "passed"
BLOCKED = "blocked"
PROHIBITED_ACTIONS = [
    "auto_merge",
    "close_vulnerability",
    "accept_risk",
    "mark_fixed",
]
RISKY_REMEDIATION_ACTIONS = {
    "upgrade",
    "upgrade_parent_package",
    "override_or_resolution",
    "needs_human_review",
}
MAX_TRIAGE_EVIDENCE_CHUNKS = 50
AI_SUMMARY_BLOCKED_REASON = "AI summary validation blocked citation verification."
EVIDENCE_LIMIT_BLOCKED_REASON = "Evidence chunk limit exceeded."


logger = logging.getLogger(__name__)


class TriageGraph:
    """Run deterministic triage explanation nodes for one remediation task."""

    def __init__(
        self,
        *,
        ai_provider: AIProvider | None = None,
        trace_service: TraceService | None = None,
    ) -> None:
        self.ai_provider = ai_provider or MockAIProvider()
        self.trace_service = trace_service or TraceService()

    def run(
        self,
        remediation_task: Mapping[str, object],
        evidence_chunks: Iterable[EvidenceChunk],
        human_decision: HumanApprovalDecision | None = None,
    ) -> TriageWorkflowState:
        bounded_chunks, evidence_limit_exceeded = bounded_evidence_chunks(evidence_chunks)
        state = TriageWorkflowState(
            remediation_task=dict(remediation_task),
            evidence_chunks=[] if evidence_limit_exceeded else bounded_chunks,
        )

        if evidence_limit_exceeded:
            self.evidence_limit_node(state)
            return state

        self.repo_context_node(state)
        self.vulnerability_triage_node(state)
        self.reachability_node(state)
        self.patch_node(state)
        self.citation_verification_node(state)
        self.human_approval_node(state, human_decision)
        return state

    def repo_context_node(self, state: TriageWorkflowState) -> None:
        package = mapping_value(state.remediation_task.get("package"))
        output = RepoContext(
            repo=string_value(state.remediation_task.get("repo")),
            package_name=string_value(package.get("name")),
            ecosystem=string_value(package.get("ecosystem")),
            current_version=string_value(package.get("current_version")),
            owner=string_value(state.remediation_task.get("owner")),
            evidence_chunk_ids=[chunk.chunk_id for chunk in state.evidence_chunks],
        )
        state.repo_context = output
        self.record_node(state, "repo_context", PASSED, output.to_dict())

    def vulnerability_triage_node(self, state: TriageWorkflowState) -> None:
        vulnerability = mapping_value(state.remediation_task.get("vulnerability"))
        risk = mapping_value(state.remediation_task.get("risk"))
        vulnerability_id = string_value(
            vulnerability.get("canonical_id") or vulnerability.get("source_id")
        )
        priority = string_value(risk.get("priority"))
        risk_score = integer_value(risk.get("risk_score"))
        severity = string_value(vulnerability.get("severity"))
        output = VulnerabilityTriageExplanation(
            vulnerability_id=vulnerability_id,
            severity=severity,
            priority=priority,
            risk_score=risk_score,
            factors=string_list_value(risk.get("factors")),
            rationale=string_list_value(risk.get("rationale")),
            explanation=triage_explanation(vulnerability_id, severity, priority, risk_score),
        )
        state.vulnerability_triage = output
        self.record_node(state, "vulnerability_triage", PASSED, output.to_dict())

    def reachability_node(self, state: TriageWorkflowState) -> None:
        risk = mapping_value(state.remediation_task.get("risk"))
        evidence = reachability_evidence(state.remediation_task)
        reachability = string_value(risk.get("reachability"))
        runtime_scope = string_value(risk.get("runtime_scope"))
        confidence = string_value(risk.get("confidence"))
        output = ReachabilityExplanation(
            reachability=reachability,
            runtime_scope=runtime_scope,
            confidence=confidence,
            evidence=evidence,
            explanation=reachability_explanation(
                reachability,
                runtime_scope,
                confidence,
                len(evidence),
            ),
        )
        state.reachability = output
        self.record_node(state, "reachability", PASSED, output.to_dict())

    def patch_node(self, state: TriageWorkflowState) -> None:
        patch_plan = mapping_value(state.remediation_task.get("patch_plan"))
        recommended_action = string_value(patch_plan.get("recommended_action"))
        target_version = string_value(patch_plan.get("target_version"))
        output = PatchExplanation(
            recommended_action=recommended_action,
            target_version=target_version,
            patch_complexity=string_value(patch_plan.get("patch_complexity")),
            breaking_change_risk=string_value(patch_plan.get("breaking_change_risk")),
            steps=string_list_value(patch_plan.get("steps")),
            test_plan=string_list_value(state.remediation_task.get("test_plan")),
            rollback_plan=string_list_value(state.remediation_task.get("rollback_plan")),
            explanation=patch_explanation(recommended_action, target_version),
        )
        state.patch = output
        self.record_node(state, "patch", PASSED, output.to_dict())

    def evidence_limit_node(self, state: TriageWorkflowState) -> None:
        state.status = BLOCKED
        state.approved = False
        state.blocked_reasons.append(EVIDENCE_LIMIT_BLOCKED_REASON)
        output = {
            "blocked": True,
            "reason": EVIDENCE_LIMIT_BLOCKED_REASON,
            "max_evidence_chunks": MAX_TRIAGE_EVIDENCE_CHUNKS,
            "observed_evidence_chunks": MAX_TRIAGE_EVIDENCE_CHUNKS + 1,
        }
        self.record_node(state, "evidence_limit", BLOCKED, output)

    def citation_verification_node(self, state: TriageWorkflowState) -> None:
        try:
            summary_service = AISummaryService(
                provider=self.ai_provider,
                trace_service=self.trace_service,
            )
            result = summary_service.summarize_remediation_task(
                state.remediation_task,
                state.evidence_chunks,
            )
        except Exception as exc:
            task_id = state.remediation_task.get("task_id")
            logger.error(
                "AI summary setup failed.",
                extra={
                    "task_id": sanitize_text(str(task_id)) if task_id is not None else None,
                    "exception_class": sanitize_text(exc.__class__.__name__),
                },
            )
            output = CitationVerification(
                blocked=True,
                retrieved_chunk_ids=[],
                validation=blocked_summary_setup_validation(),
                summary=None,
            )
            state.citation_verification = output
            state.status = BLOCKED
            state.approved = False
            state.blocked_reasons.append(AI_SUMMARY_BLOCKED_REASON)
            self.record_node(state, "citation_verification", BLOCKED, output.to_dict())
            return

        public_result = result.to_dict()
        output = CitationVerification(
            blocked=result.blocked,
            retrieved_chunk_ids=list(result.retrieved_chunk_ids),
            validation=mapping_to_dict(public_result.get("validation")),
            summary=mapping_to_dict_or_none(public_result.get("response")),
        )
        state.citation_verification = output
        validation_status = BLOCKED if output.blocked else PASSED
        if output.blocked:
            state.status = BLOCKED
            state.approved = False
            state.blocked_reasons.append(AI_SUMMARY_BLOCKED_REASON)
        self.record_node(state, "citation_verification", validation_status, output.to_dict())

    def human_approval_node(
        self,
        state: TriageWorkflowState,
        human_decision: HumanApprovalDecision | None,
    ) -> None:
        required = human_approval_required(state.remediation_task, state.patch)
        requested_actions = requested_human_actions(required, state.patch)
        blocked_reasons = list(state.blocked_reasons)
        decision_dict = public_human_decision_dict(human_decision)
        approved_by_decision = (
            human_decision is not None and human_decision.status == "approved"
        )

        if len(blocked_reasons) > 0:
            status = BLOCKED
            approved = False
            validation_status = BLOCKED
        elif human_decision is not None and human_decision.status == "rejected":
            status = BLOCKED
            approved = False
            blocked_reasons.append("Human approval was rejected.")
            state.blocked_reasons = blocked_reasons
            validation_status = BLOCKED
        elif required and not approved_by_decision:
            status = "awaiting_human_approval"
            approved = False
            validation_status = PASSED
        else:
            status = "approved"
            approved = approved_by_decision
            validation_status = PASSED

        gate = HumanApprovalGate(
            required=required,
            approved=approved,
            status=status,
            requested_actions=requested_actions,
            prohibited_actions=list(PROHIBITED_ACTIONS),
            blocked_reasons=blocked_reasons,
            decision=decision_dict,
        )
        state.human_approval = gate
        state.status = status
        state.approved = approved
        self.record_node(state, "human_approval", validation_status, gate.to_dict())

    def record_node(
        self,
        state: TriageWorkflowState,
        node_name: str,
        validation_status: str,
        output: dict[str, object],
    ) -> None:
        result = TriageNodeResult(
            node_name=node_name,
            validation_status=validation_status,
            output=output,
        )
        state.node_results.append(result)
        self.trace_service.record_event(
            agent_name="triage-graph",
            event_type="agent.node.%s" % node_name,
            input_json={
                "task_id": state.remediation_task.get("task_id"),
                "status_before_output": state.status,
            },
            retrieved_context_json=[chunk.to_dict() for chunk in state.evidence_chunks],
            output_json=output,
            model=None,
            validation_status=validation_status,
        )


def run_triage_workflow(
    remediation_task: Mapping[str, object],
    evidence_chunks: Iterable[EvidenceChunk],
    *,
    ai_provider: AIProvider | None = None,
    trace_service: TraceService | None = None,
    human_decision: HumanApprovalDecision | None = None,
) -> TriageWorkflowState:
    graph = TriageGraph(ai_provider=ai_provider, trace_service=trace_service)
    return graph.run(remediation_task, evidence_chunks, human_decision)


def mapping_value(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    return {}


def mapping_to_dict(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def mapping_to_dict_or_none(value: object) -> dict[str, object] | None:
    if isinstance(value, Mapping):
        return dict(value)
    return None


def public_human_decision_dict(
    human_decision: HumanApprovalDecision | None,
) -> dict[str, object] | None:
    if human_decision is None:
        return None
    return {
        "status": sanitize_text(human_decision.status),
        "approved_by": sanitize_optional_text(human_decision.approved_by),
        "decision_reason": sanitize_optional_text(human_decision.decision_reason),
    }


def sanitize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    return sanitize_text(value)


def bounded_evidence_chunks(
    chunks: Iterable[EvidenceChunk],
) -> tuple[list[EvidenceChunk], bool]:
    bounded_chunks: list[EvidenceChunk] = []
    for index, chunk in enumerate(chunks):
        if index >= MAX_TRIAGE_EVIDENCE_CHUNKS:
            return bounded_chunks, True
        bounded_chunks.append(chunk)
    return bounded_chunks, False


def blocked_summary_setup_validation() -> dict[str, object]:
    return {
        "valid": False,
        "blocked": True,
        "errors": ["AI summary request could not be built."],
        "warnings": [],
        "invalid_citation_ids": [],
        "unsupported_claim_ids": [],
        "mutated_fields": [],
    }


def string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip() != "":
        return value
    return None


def integer_value(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def string_list_value(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []

    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        items.append(item)
    return items


def reachability_evidence(task: Mapping[str, object]) -> list[dict[str, str]]:
    evidence_items: list[dict[str, str]] = []
    evidence_value = task.get("evidence")
    if not isinstance(evidence_value, list | tuple):
        return evidence_items

    for item in evidence_value:
        item_mapping = mapping_value(item)
        if string_value(item_mapping.get("type")) != "reachability":
            continue
        evidence_items.append(
            {
                "type": string_value(item_mapping.get("type")) or "reachability",
                "source": string_value(item_mapping.get("source")) or "remediation_task",
                "claim": string_value(item_mapping.get("claim")) or "",
            }
        )
    return evidence_items


def triage_explanation(
    vulnerability_id: str | None,
    severity: str | None,
    priority: str | None,
    risk_score: int | None,
) -> str:
    return (
        "Scanner triage is preserved for %s: severity %s, priority %s, risk score %s."
        % (
            vulnerability_id or "unknown vulnerability",
            severity or "UNKNOWN",
            priority or "unknown",
            risk_score if risk_score is not None else "unknown",
        )
    )


def reachability_explanation(
    reachability: str | None,
    runtime_scope: str | None,
    confidence: str | None,
    evidence_count: int,
) -> str:
    return (
        "Reachability remains %s in %s scope with %s confidence, based on %s evidence item(s)."
        % (
            reachability or "unknown",
            runtime_scope or "unknown",
            confidence or "unknown",
            evidence_count,
        )
    )


def patch_explanation(
    recommended_action: str | None,
    target_version: str | None,
) -> str:
    if target_version is None:
        return (
            "Patch planning recommends %s and requires human review before any repository action."
            % (recommended_action or "review")
        )
    return (
        "Patch planning recommends %s toward %s and requires human review before any repository action."
        % (recommended_action or "review", target_version)
    )


def human_approval_required(
    task: Mapping[str, object],
    patch: PatchExplanation | None,
) -> bool:
    if task.get("human_approval_required") is True:
        return True
    if patch is None:
        return True
    if patch.recommended_action in RISKY_REMEDIATION_ACTIONS:
        return True
    if patch.target_version is not None:
        return True
    return False


def requested_human_actions(
    required: bool,
    patch: PatchExplanation | None,
) -> list[str]:
    if not required:
        return []

    actions = ["review_triage_explanation", "review_citations"]
    if patch is not None:
        actions.append("approve_patch_plan_before_repository_change")
    return actions
