from app.services.ai_context_bundle import build_ai_context_bundle, validate_client_ai_output


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
