from app.services.ai_context_bundle import build_ai_context_bundle, validate_client_ai_output
from app.services.rag_types import EvidenceChunk


def test_ai_context_bundle_contains_stable_evidence_ids_prompt_and_schema():
    task = remediation_task_fixture()

    first = build_ai_context_bundle(task)
    second = build_ai_context_bundle(task)

    assert first == second
    assert first["schema_version"] == "vulnsage.ai_context_bundle.v1"
    assert first["finding_id"] == "task-archive-utils"
    assert first["ai_request"]["package_name"] == "archive-utils"
    assert first["ai_request"]["priority"] == "P1_FIX_THIS_SPRINT"
    evidence = first["ai_request"]["evidence"]
    assert len(evidence) >= 2
    assert evidence[0]["id"].startswith("ev-task-")
    assert "Use only the evidence in this bundle" in first["prompt"]
    assert "citations" in first["expected_output_schema"]["required"]
    assert "Every fact or inference claim must cite matching evidence IDs." in first["citation_rules"]


def test_ai_context_bundle_includes_retrieved_chunks_after_task_evidence():
    task = remediation_task_fixture()
    chunks = [
        EvidenceChunk(
            chunk_id="source-upload-route",
            source_type="source_file",
            content="archive-utils is used by POST /receipts/upload.",
            metadata={"source": "src/routes/receipts.ts", "package": "archive-utils"},
        )
    ]

    bundle = build_ai_context_bundle(task, retrieved_chunks=chunks)

    evidence = bundle["ai_request"]["evidence"]
    assert evidence[-1]["metadata"]["chunk_id"] == "source-upload-route"
    assert evidence[-1]["metadata"]["source_type"] == "source_file"
    assert evidence[-1]["kind"] == "source_file"


def test_validate_client_ai_output_accepts_cited_claims():
    task = remediation_task_fixture()
    bundle = build_ai_context_bundle(task)
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded based on the cited finding evidence.",
        "explanation": "The package and remediation priority are described by the cited evidence.",
        "citations": [
            {
                "claim_id": "claim-1",
                "evidence_id": evidence_id,
                "note": "Supports the remediation summary.",
            }
        ],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "client-ai",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is True
    assert result["blocked"] is False
    assert result["validation"]["valid"] is True


def test_validate_client_ai_output_accepts_retrieved_chunk_citations():
    task = remediation_task_fixture()
    chunks = [
        EvidenceChunk(
            chunk_id="source-upload-route",
            source_type="source_file",
            content="archive-utils is used by POST /receipts/upload.",
            metadata={"source": "src/routes/receipts.ts", "package": "archive-utils"},
        )
    ]
    bundle = build_ai_context_bundle(task, retrieved_chunks=chunks)
    request = bundle["ai_request"]
    retrieved_evidence = [
        item
        for item in request["evidence"]
        if item["metadata"].get("origin") == "retrieved_context"
    ][0]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils is used by the cited receipt upload route evidence.",
        "explanation": "The cited retrieved evidence describes usage in POST /receipts/upload.",
        "citations": [
            {
                "claim_id": "claim-1",
                "evidence_id": retrieved_evidence["id"],
                "note": "Supports retrieved route usage.",
            }
        ],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils is used by POST /receipts/upload.",
                "disposition": "fact",
                "evidence_ids": [retrieved_evidence["id"]],
            }
        ],
        "provider_name": "client-ai",
    }

    result = validate_client_ai_output(task, output, retrieved_chunks=chunks)

    assert result["passed"] is True
    assert result["blocked"] is False


def test_validate_client_ai_output_blocks_uncited_claims():
    task = remediation_task_fixture()
    bundle = build_ai_context_bundle(task)
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded based on evidence.",
        "explanation": "This explanation omits the required citation object.",
        "citations": [],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "client-ai",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is False
    assert result["blocked"] is True
    assert result["validation"]["unsupported_claim_ids"] == ["claim-1"]
    assert "matching citation" in result["summary"]


def test_validate_client_ai_output_blocks_unsafe_generated_text():
    task = remediation_task_fixture()
    bundle = build_ai_context_bundle(task)
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded.",
        "explanation": "This includes exploit steps and a malicious payload.",
        "citations": [
            {
                "claim_id": "claim-1",
                "evidence_id": evidence_id,
                "note": "proof of concept details",
            }
        ],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "client-ai",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is False
    assert result["blocked"] is True
    assert result["validation"]["errors"] == ["AI response contained unsafe text."]


def test_validate_client_ai_output_blocks_unsafe_text_before_parse_errors():
    task = remediation_task_fixture()
    output = {
        "summary": "This includes exploit steps and a malicious payload.",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is False
    assert result["blocked"] is True
    assert result["validation"]["errors"] == ["AI response contained unsafe text."]
    assert "finding_id" not in result["summary"]


def test_validate_client_ai_output_blocks_unknown_fields_before_ignored_text():
    task = remediation_task_fixture()
    bundle = build_ai_context_bundle(task)
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded.",
        "explanation": "The response uses only the provided evidence.",
        "citations": [{"claim_id": "claim-1", "evidence_id": evidence_id}],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "client-ai",
        "ignored_notes": "This includes exploit steps and a malicious payload.",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is False
    assert result["blocked"] is True
    assert result["validation"]["errors"] == ["AI output contained unsupported fields."]
    assert "exploit steps" not in repr(result)


def test_validate_client_ai_output_blocks_unknown_nested_citation_fields():
    task = remediation_task_fixture()
    bundle = build_ai_context_bundle(task)
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded.",
        "explanation": "The response uses only the provided evidence.",
        "citations": [
            {
                "claim_id": "claim-1",
                "evidence_id": evidence_id,
                "ignored_notes": "This includes exploit steps and a malicious payload.",
            }
        ],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
            }
        ],
        "provider_name": "client-ai",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is False
    assert result["blocked"] is True
    assert result["validation"]["errors"] == ["AI output contained unsupported fields."]
    assert "exploit steps" not in repr(result)


def test_validate_client_ai_output_blocks_unknown_nested_claim_check_fields():
    task = remediation_task_fixture()
    bundle = build_ai_context_bundle(task)
    request = bundle["ai_request"]
    evidence_id = request["evidence"][0]["id"]
    output = {
        "finding_id": request["finding_id"],
        "package_name": request["package_name"],
        "vulnerability_id": request["vulnerability_id"],
        "priority": request["priority"],
        "risk_score": request["risk_score"],
        "summary": "archive-utils should be upgraded.",
        "explanation": "The response uses only the provided evidence.",
        "citations": [{"claim_id": "claim-1", "evidence_id": evidence_id}],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils should be upgraded.",
                "disposition": "fact",
                "evidence_ids": [evidence_id],
                "ignored_notes": "This includes exploit steps and a malicious payload.",
            }
        ],
        "provider_name": "client-ai",
    }

    result = validate_client_ai_output(task, output)

    assert result["passed"] is False
    assert result["blocked"] is True
    assert result["validation"]["errors"] == ["AI output contained unsupported fields."]
    assert "malicious payload" not in repr(result)


def remediation_task_fixture() -> dict[str, object]:
    return {
        "task_id": "task-archive-utils",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "dependencies",
            "is_direct": True,
            "parent_package": None,
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
            "known_exploited": None,
            "epss_score": None,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "factors": {},
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
            "steps": ["Upgrade archive-utils to 2.2.0."],
            "test_plan": ["Run npm test."],
            "rollback_plan": ["Revert dependency bump."],
            "pr_description": "Upgrade archive-utils.",
        },
        "test_plan": ["Run npm test."],
        "rollback_plan": ["Revert dependency bump."],
        "owner": None,
        "human_approval_required": True,
    }
