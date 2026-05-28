from app.agents import TriageGraph
from app.services.ai_context_bundle import build_ai_context_bundle
from app.services.rag_types import EvidenceChunk


def test_triage_graph_blocks_unaudited_generated_action_claims() -> None:
    graph = TriageGraph()
    task = remediation_task()

    state = graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=evidence_chunks(),
        ai_output=unaudited_action_output(task),
    )

    validation_node = [
        result for result in state.node_results if result.node_name == "client_ai_validation"
    ][0]

    assert state.status == "blocked"
    assert state.approved is False
    assert validation_node.validation_status == "blocked"
    assert validation_node.output["blocked"] is True
    assert validation_node.output["validation"]["errors"] == [
        "AI output claim audit failed."
    ]
    assert "Client AI output validation blocked human approval." in state.blocked_reasons


def test_triage_graph_allows_conservative_unknown_without_action_claims() -> None:
    graph = TriageGraph()
    task = remediation_task()
    output = unaudited_action_output(task)
    output["summary"] = "Exploitability is unknown and needs human review."
    output["explanation"] = "Manual review is required because exploitability is unknown."

    state = graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=evidence_chunks(),
        ai_output=output,
    )

    validation_node = [
        result for result in state.node_results if result.node_name == "client_ai_validation"
    ][0]

    assert state.status == "awaiting_human_approval"
    assert validation_node.validation_status == "passed"
    assert validation_node.output["passed"] is True
    assert validation_node.output["validation"]["warnings"] == [
        "AI output did not include auditable claims."
    ]


def unaudited_action_output(task: dict[str, object]) -> dict[str, object]:
    bundle = build_ai_context_bundle(task, retrieved_chunks=evidence_chunks())
    request = bundle["ai_request"]
    return {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "Upgrade archive-utils before release; exploitability is unknown.",
        "explanation": "Exploitability is unknown and needs human review.",
        "citations": [],
        "claim_checks": [],
        "provider_name": "client-ai",
    }


def remediation_task() -> dict[str, object]:
    return {
        "task_id": "task-agent-archive-utils",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "runtime",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "CVE-2026-0001",
            "source_id": "GHSA-archive",
            "aliases": ["GHSA-archive"],
            "severity": "HIGH",
            "summary": "archive-utils unsafe archive parsing.",
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
                "CVE-2026-0001 advisory for archive-utils: unsafe archive parsing. "
                "Fixed in 2.2.0."
            ),
            metadata={
                "repo_id": "payments-api",
                "package": "archive-utils",
                "path": "advisories/CVE-2026-0001.md",
            },
        )
    ]
