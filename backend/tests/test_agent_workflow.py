import logging
from copy import deepcopy

from pytest import MonkeyPatch

from app.agents import (
    CitationVerification,
    HumanApprovalDecision,
    HumanApprovalGate,
    PatchExplanation,
    ReachabilityExplanation,
    RepoContext,
    TriageGraph,
    TriageNodeResult,
    TriageWorkflowState,
    VulnerabilityTriageExplanation,
    run_triage_workflow,
)
from app.agents import triage_graph
from app.ai.contracts import MockAIProvider
from app.services.public_safety import contains_unsafe_public_text
from app.services.rag_types import EvidenceChunk
from app.services.trace_service import TraceService


def remediation_task() -> dict[str, object]:
    return {
        "task_id": "task_agent_123",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "runtime",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "GHSA-1234-5678",
            "source_id": "CVE-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "severity": "HIGH",
            "summary": "archive-utils has unsafe deserialization.",
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 78,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "factors": ["High severity", "Production reachable"],
            "rationale": ["Risk score 78 maps to P1_FIX_THIS_SPRINT."],
        },
        "evidence": [
            {
                "type": "lockfile_entry",
                "source": "package-lock.json",
                "claim": "archive-utils@1.4.0 is installed in package-lock.json.",
            },
            {
                "type": "reachability",
                "source": "src/upload.ts",
                "claim": "archive-utils is imported by the production upload route.",
            },
        ],
        "patch_plan": {
            "recommended_action": "upgrade",
            "target_version": "2.2.0",
            "patch_complexity": "low",
            "breaking_change_risk": "low",
            "steps": ["Update archive-utils from 1.4.0 to 2.2.0"],
        },
        "test_plan": ["npm test", "npm run lint"],
        "rollback_plan": ["Revert dependency bump PR"],
        "owner": "@security",
        "human_approval_required": True,
    }


def evidence_chunks() -> list[EvidenceChunk]:
    return [
        EvidenceChunk(
            chunk_id="chunk-advisory",
            source_type="advisory",
            content=(
                "GHSA-1234-5678 advisory for archive-utils: unsafe deserialization "
                "remote code execution. Fixed in 2.2.0."
            ),
            metadata={
                "repo_id": "payments-api",
                "package": "archive-utils",
                "path": "advisories/GHSA-1234-5678.md",
            },
        ),
        EvidenceChunk(
            chunk_id="chunk-reachable",
            source_type="reachability",
            content="archive-utils is imported by src/upload.ts in a production request path.",
            metadata={
                "repo_id": "payments-api",
                "package": "archive-utils",
                "path": "src/upload.ts",
            },
        ),
    ]


def cited_client_ai_output(task: dict[str, object]) -> dict[str, object]:
    package = task["package"]
    vulnerability = task["vulnerability"]
    risk = task["risk"]
    return {
        "finding_id": task["task_id"],
        "package_name": package["name"],
        "vulnerability_id": vulnerability["canonical_id"],
        "priority": risk["priority"],
        "risk_score": risk["risk_score"],
        "summary": "archive-utils should be reviewed using cited Sage evidence.",
        "explanation": "The response preserves scanner triage and cites the evidence bundle.",
        "citations": [{"claim_id": "claim-1", "evidence_id": "ev-task-0eee8986d3be"}],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils is imported by the production upload route.",
                "disposition": "fact",
                "evidence_ids": ["ev-task-0eee8986d3be"],
            }
        ],
        "provider_name": "client-ai",
    }


def many_evidence_chunks(count: int) -> list[EvidenceChunk]:
    chunks: list[EvidenceChunk] = []
    for index in range(count):
        chunks.append(
            EvidenceChunk(
                chunk_id="chunk-%03d" % index,
                source_type="advisory",
                content="archive-utils GHSA-1234-5678 evidence chunk %s." % index,
                metadata={
                    "repo_id": "payments-api",
                    "package": "archive-utils",
                    "path": "advisories/%03d.md" % index,
                },
            )
        )
    return chunks


def test_triage_workflow_happy_path_records_human_approval() -> None:
    trace_service = TraceService()
    task = remediation_task()
    original_task = deepcopy(task)

    state = run_triage_workflow(
        task,
        evidence_chunks(),
        trace_service=trace_service,
        human_decision=HumanApprovalDecision(
            status="approved",
            approved_by="security-reviewer",
            decision_reason="Patch plan and citations reviewed.",
        ),
    )

    assert state.status == "approved"
    assert state.approved is True
    assert state.citation_verification is not None
    assert state.citation_verification.blocked is False
    assert state.human_approval is not None
    assert state.human_approval.required is True
    assert state.human_approval.approved is True
    assert state.patch is not None
    assert state.patch.safe_to_auto_apply is False
    assert "auto_merge" in state.human_approval.prohibited_actions
    assert task == original_task


def test_human_approval_decision_public_output_sanitizes_unsafe_text() -> None:
    trace_service = TraceService()
    unsafe_approver = "security reviewer supplied PoC payload"
    unsafe_reason = (
        "Approved after proof-of-concept exploit steps with malicious payload."
    )

    state = run_triage_workflow(
        remediation_task(),
        evidence_chunks(),
        trace_service=trace_service,
        human_decision=HumanApprovalDecision(
            status="approved",
            approved_by=unsafe_approver,
            decision_reason=unsafe_reason,
        ),
    )

    public_state = state.to_dict()
    trace_records = trace_service.list_records()
    public_text = repr({"state": public_state, "traces": trace_records})

    assert state.status == "approved"
    assert state.approved is True
    assert state.human_approval is not None
    assert state.human_approval.decision is not None
    assert state.human_approval.decision["status"] == "approved"
    assert unsafe_approver not in public_text
    assert unsafe_reason not in public_text
    assert contains_unsafe_public_text(public_state) is False
    assert contains_unsafe_public_text(trace_records) is False


def test_workflow_state_to_dict_sanitizes_public_fields_values_and_keys() -> None:
    state = TriageWorkflowState(
        remediation_task={
            "task_id": "task-state-safety",
            "payload key": "proof-of-concept task value",
            "package": {
                "name": "archive-utils malicious payload",
                "exploit steps key": "safe value",
            },
        },
        evidence_chunks=[
            EvidenceChunk(
                chunk_id="chunk-payload",
                source_type="advisory proof-of-concept",
                content="Evidence contains exploit code and malicious payload.",
                metadata={"payload metadata key": "proof-of-concept metadata value"},
            )
        ],
        status="blocked by malicious payload",
        blocked_reasons=["proof-of-concept blocked reason"],
    )
    state.repo_context = RepoContext(
        repo="repo with payload",
        package_name="package proof-of-concept",
        ecosystem="npm",
        current_version="1.0.0",
        owner="owner with exploit payload",
        evidence_chunk_ids=["chunk-payload"],
    )
    state.vulnerability_triage = VulnerabilityTriageExplanation(
        vulnerability_id="CVE-proof-of-concept",
        severity="HIGH payload",
        priority="P1 payload",
        risk_score=90,
        factors=["malicious payload factor"],
        rationale=["proof-of-concept rationale"],
        explanation="exploit steps explanation",
    )
    state.reachability = ReachabilityExplanation(
        reachability="reachable payload",
        runtime_scope="production proof-of-concept",
        confidence="high",
        evidence=[{"payload evidence key": "malicious payload evidence"}],
        explanation="proof-of-concept reachability",
    )
    state.patch = PatchExplanation(
        recommended_action="upgrade payload",
        target_version="2.0.0 payload",
        patch_complexity="low",
        breaking_change_risk="proof-of-concept risk",
        steps=["exploit steps should not leak"],
        test_plan=["test malicious payload"],
        rollback_plan=["rollback proof-of-concept"],
        explanation="patch explanation with payload",
    )
    state.citation_verification = CitationVerification(
        blocked=True,
        retrieved_chunk_ids=["chunk-payload"],
        validation={"payload validation key": "proof-of-concept validation"},
        summary={"exploit steps summary key": "malicious payload summary"},
    )
    state.human_approval = HumanApprovalGate(
        required=True,
        approved=False,
        status="blocked proof-of-concept",
        requested_actions=["review payload"],
        prohibited_actions=["auto_merge"],
        blocked_reasons=["malicious payload approval reason"],
        decision={"payload decision key": "proof-of-concept decision"},
    )
    state.node_results.append(
        TriageNodeResult(
            node_name="node payload",
            validation_status="blocked proof-of-concept",
            output={"exploit steps output key": "malicious payload output"},
        )
    )

    public_state = state.to_dict()
    public_text = repr(public_state)

    assert "payload key" not in public_text
    assert "payload metadata key" not in public_text
    assert "exploit steps output key" not in public_text
    assert "proof-of-concept" not in public_text
    assert "malicious payload" not in public_text
    assert "exploit code" not in public_text
    assert contains_unsafe_public_text(public_state) is False


def test_ai_validation_block_keeps_workflow_blocked_and_unapproved() -> None:
    provider = MockAIProvider(
        unsupported_claims=["The package is confirmed exploited in production."]
    )

    state = run_triage_workflow(
        remediation_task(),
        evidence_chunks(),
        ai_provider=provider,
        human_decision=HumanApprovalDecision(
            status="approved",
            approved_by="security-reviewer",
            decision_reason="This must not override AI validation.",
        ),
    )

    assert state.status == "blocked"
    assert state.approved is False
    assert state.citation_verification is not None
    assert state.citation_verification.blocked is True
    assert state.citation_verification.summary is None
    assert state.human_approval is not None
    assert state.human_approval.status == "blocked"
    assert state.human_approval.approved is False
    assert state.human_approval.blocked_reasons == [
        "AI summary validation blocked citation verification."
    ]


def test_ai_summary_service_constructor_failure_blocks_workflow_without_raw_exception(
    monkeypatch: MonkeyPatch,
) -> None:
    trace_service = TraceService()

    def fail_to_construct_summary_service(
        *,
        provider: object,
        trace_service: object,
    ) -> object:
        raise RuntimeError(
            "raw constructor failure: package.name is required; malicious payload"
        )

    monkeypatch.setattr(
        triage_graph,
        "AISummaryService",
        fail_to_construct_summary_service,
    )

    state = run_triage_workflow(
        remediation_task(),
        evidence_chunks(),
        trace_service=trace_service,
        human_decision=HumanApprovalDecision(
            status="approved",
            approved_by="security-reviewer",
            decision_reason="This must not override a setup failure.",
        ),
    )

    records = trace_service.list_records()
    node_statuses = {
        record["event_type"]: record["validation_status"]
        for record in records
        if str(record["event_type"]).startswith("agent.node.")
    }
    public_text = repr({"state": state.to_dict(), "traces": records})

    assert state.status == "blocked"
    assert state.approved is False
    assert state.citation_verification is not None
    assert state.citation_verification.blocked is True
    assert state.citation_verification.summary is None
    assert state.human_approval is not None
    assert state.human_approval.status == "blocked"
    assert state.human_approval.approved is False
    assert state.human_approval.blocked_reasons == [
        "AI summary validation blocked citation verification."
    ]
    assert node_statuses["agent.node.citation_verification"] == "blocked"
    assert node_statuses["agent.node.human_approval"] == "blocked"
    assert "raw constructor failure" not in public_text
    assert "package.name" not in public_text
    assert "malicious payload" not in public_text
    assert "RuntimeError" not in public_text


def test_ai_summary_setup_failure_logs_sanitized_context_and_generic_public_output(
    monkeypatch: MonkeyPatch,
    caplog,
) -> None:
    trace_service = TraceService()

    def fail_to_construct_summary_service(
        *,
        provider: object,
        trace_service: object,
    ) -> object:
        raise RuntimeError(
            "raw constructor failure: package.name is required; malicious payload"
        )

    monkeypatch.setattr(
        triage_graph,
        "AISummaryService",
        fail_to_construct_summary_service,
    )

    with caplog.at_level(logging.ERROR, logger=triage_graph.logger.name):
        state = run_triage_workflow(
            remediation_task(),
            evidence_chunks(),
            trace_service=trace_service,
        )

    public_text = repr(state.to_dict())
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    matching_records = [
        record
        for record in caplog.records
        if record.getMessage() == "AI summary setup failed."
    ]

    assert matching_records != []
    assert matching_records[0].task_id == "task_agent_123"
    assert matching_records[0].exception_class == "RuntimeError"
    assert "raw constructor failure" not in log_text
    assert "package.name" not in log_text
    assert "malicious payload" not in log_text
    assert "raw constructor failure" not in public_text
    assert "package.name" not in public_text
    assert "RuntimeError" not in public_text
    assert "AI summary request could not be built." in public_text


def test_human_approval_is_required_for_risky_actions() -> None:
    state = run_triage_workflow(remediation_task(), evidence_chunks())

    assert state.status == "awaiting_human_approval"
    assert state.approved is False
    assert state.human_approval is not None
    assert state.human_approval.required is True
    assert state.human_approval.approved is False
    assert state.human_approval.requested_actions == [
        "review_triage_explanation",
        "review_citations",
        "approve_patch_plan_before_repository_change",
    ]
    assert state.human_approval.prohibited_actions == [
        "auto_merge",
        "close_vulnerability",
        "accept_risk",
        "mark_fixed",
    ]


def test_triage_graph_records_rag_bundle_validation_and_human_gate() -> None:
    graph = TriageGraph()
    task = remediation_task()
    output = cited_client_ai_output(task)
    output["citations"] = [{"claim_id": "claim-1", "evidence_id": "ev-chunk-23ac3397cf6d"}]
    output["claim_checks"][0]["claim"] = (
        "archive-utils is imported by src/upload.ts in a production request path."
    )
    output["claim_checks"][0]["evidence_ids"] = ["ev-chunk-23ac3397cf6d"]
    bundle = graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=evidence_chunks(),
        ai_output=output,
    )

    node_names = [node.node_name for node in bundle.node_results]

    assert "ai_context_bundle" in node_names
    assert "client_ai_validation" in node_names
    assert bundle.status == "awaiting_human_approval"
    assert bundle.human_approval is not None
    assert bundle.human_approval.required is True


def test_triage_graph_client_ai_validation_failure_blocks_human_gate() -> None:
    graph = TriageGraph()
    task = remediation_task()
    invalid_output = cited_client_ai_output(task)
    invalid_output["citations"] = []

    state = graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=evidence_chunks(),
        ai_output=invalid_output,
    )

    node_statuses = {
        result.node_name: result.validation_status for result in state.node_results
    }

    assert state.status == "blocked"
    assert state.approved is False
    assert node_statuses["client_ai_validation"] == "blocked"
    assert state.human_approval is not None
    assert state.human_approval.status == "blocked"
    assert "Client AI output validation blocked human approval." in state.blocked_reasons


def test_node_traces_exist_and_show_ai_validation_failure() -> None:
    trace_service = TraceService()
    provider = MockAIProvider(
        unsupported_claims=["The package is confirmed exploited in production."]
    )
    graph = TriageGraph(ai_provider=provider, trace_service=trace_service)

    state = graph.run(remediation_task(), evidence_chunks())

    records = trace_service.list_records()
    node_records = [
        record
        for record in records
        if str(record["event_type"]).startswith("agent.node.")
    ]
    node_statuses = {
        record["event_type"]: record["validation_status"] for record in node_records
    }

    assert state.status == "blocked"
    assert [result.node_name for result in state.node_results] == [
        "repo_context",
        "vulnerability_triage",
        "reachability",
        "patch",
        "citation_verification",
        "human_approval",
    ]
    assert node_statuses == {
        "agent.node.repo_context": "passed",
        "agent.node.vulnerability_triage": "passed",
        "agent.node.reachability": "passed",
        "agent.node.patch": "passed",
        "agent.node.citation_verification": "blocked",
        "agent.node.human_approval": "blocked",
    }
    ai_records = [
        record for record in records if record["event_type"] == "ai.finding_summary"
    ]
    assert len(ai_records) == 1
    assert ai_records[0]["validation_status"] == "blocked"


def test_malformed_task_missing_package_name_blocks_workflow_without_raw_exception() -> None:
    trace_service = TraceService()
    task = remediation_task()
    task["package"] = {
        "ecosystem": "npm",
        "current_version": "1.4.0",
    }

    state = run_triage_workflow(
        task,
        evidence_chunks(),
        trace_service=trace_service,
        human_decision=HumanApprovalDecision(
            status="approved",
            approved_by="security-reviewer",
            decision_reason="This must not override a blocked workflow.",
        ),
    )

    records = trace_service.list_records()
    node_statuses = {
        record["event_type"]: record["validation_status"]
        for record in records
        if str(record["event_type"]).startswith("agent.node.")
    }
    public_text = repr(state.to_dict())

    assert state.status == "blocked"
    assert state.approved is False
    assert state.citation_verification is not None
    assert state.citation_verification.blocked is True
    assert state.citation_verification.summary is None
    assert state.human_approval is not None
    assert state.human_approval.status == "blocked"
    assert state.human_approval.blocked_reasons == [
        "AI summary validation blocked citation verification."
    ]
    assert node_statuses["agent.node.citation_verification"] == "blocked"
    assert node_statuses["agent.node.human_approval"] == "blocked"
    assert "package.name" not in public_text
    assert "is required" not in public_text
    assert "ValueError" not in public_text


def test_malformed_task_risk_score_blocks_workflow_without_raw_exception() -> None:
    trace_service = TraceService()
    task = remediation_task()
    risk = dict(task["risk"])
    risk["risk_score"] = "seventy-eight"
    task["risk"] = risk

    state = run_triage_workflow(
        task,
        evidence_chunks(),
        trace_service=trace_service,
    )

    records = trace_service.list_records()
    node_statuses = {
        record["event_type"]: record["validation_status"]
        for record in records
        if str(record["event_type"]).startswith("agent.node.")
    }
    public_text = repr(state.to_dict())

    assert state.status == "blocked"
    assert state.approved is False
    assert state.citation_verification is not None
    assert state.citation_verification.blocked is True
    assert state.citation_verification.summary is None
    assert node_statuses["agent.node.citation_verification"] == "blocked"
    assert node_statuses["agent.node.human_approval"] == "blocked"
    assert "invalid literal" not in public_text
    assert "base 10" not in public_text
    assert "ValueError" not in public_text


def test_too_many_evidence_chunks_blocks_without_tracing_every_chunk() -> None:
    trace_service = TraceService()

    state = run_triage_workflow(
        remediation_task(),
        many_evidence_chunks(51),
        trace_service=trace_service,
    )

    records = trace_service.list_records()
    retrieved_context_lengths = [
        len(record["retrieved_context_json"])
        for record in records
        if isinstance(record["retrieved_context_json"], list)
    ]

    assert state.status == "blocked"
    assert state.approved is False
    assert state.blocked_reasons == ["Evidence chunk limit exceeded."]
    assert [result.node_name for result in state.node_results] == ["evidence_limit"]
    assert state.node_results[0].validation_status == "blocked"
    assert len(records) == 1
    assert records[0]["event_type"] == "agent.node.evidence_limit"
    assert records[0]["validation_status"] == "blocked"
    assert max(retrieved_context_lengths) < 51
