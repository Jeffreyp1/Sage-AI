from app.eval.claim_auditor import audit_ai_claims


def cited_output():
    return {
        "summary": "archive-utils may be reachable based on the cited import evidence.",
        "recommendation": (
            "The fixed version appears to be 2.2.0. This needs human review before release."
        ),
        "citations": [
            {"claim_id": "claim-1", "evidence_id": "ev-lockfile"},
            {"claim_id": "claim-2", "evidence_id": "ev-import"},
        ],
        "claims": [
            {
                "claim_id": "claim-1",
                "text": "archive-utils 2.1.4 appears in the lockfile.",
                "type": "fact",
                "evidence_ids": ["ev-lockfile"],
            },
            {
                "claim_id": "claim-2",
                "text": "The package may be reachable from the upload route.",
                "type": "inference",
                "evidence_ids": ["ev-import"],
            },
            {
                "claim_id": "claim-3",
                "text": "Exploitability is unknown without human review.",
                "type": "unknown",
                "evidence_ids": [],
            },
        ],
    }


def finding_codes(result):
    return {finding["code"] for finding in result["findings"]}


def blocked_claim_ids(result):
    return {claim["claim_id"] for claim in result["blocked_claims"]}


def test_auditor_passes_conservative_cited_claims():
    result = audit_ai_claims(cited_output())

    assert result["passed"] is True
    assert result["score"] == 100
    assert result["findings"] == []
    assert result["blocked_claims"] == []
    assert result["warnings"] == []


def test_auditor_blocks_fact_claim_without_evidence_id():
    output = cited_output()
    output["claims"][0]["evidence_ids"] = []

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert result["score"] < 100
    assert "missing_claim_evidence" in finding_codes(result)
    assert "claim-1" in blocked_claim_ids(result)


def test_auditor_blocks_claim_with_evidence_id_but_no_matching_citation():
    output = cited_output()
    output["citations"] = [{"claim_id": "claim-1", "evidence_id": "ev-other"}]

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "missing_matching_citation" in finding_codes(result)
    assert "claim-1" in blocked_claim_ids(result)


def test_auditor_blocks_overconfident_fix_language_in_recommendation():
    output = cited_output()
    output["recommendation"] = "Install archive-utils 2.2.0 and it fixes everything."

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "overconfident_fix_language" in finding_codes(result)


def test_auditor_blocks_safe_to_ignore_and_no_risk_language_in_summary():
    output = cited_output()
    output["summary"] = "This is safe to ignore because there is no risk."

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "overconfident_fix_language" in finding_codes(result)


def test_auditor_blocks_unsafe_offensive_wording_using_existing_markers():
    output = cited_output()
    output["claims"][1]["text"] = "The explanation includes exploit steps."

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "unsafe_offensive_wording" in finding_codes(result)


def test_auditor_accepts_existing_claim_checks_shape():
    output = cited_output()
    output["claim_checks"] = [
        {
            "claim_id": claim["claim_id"],
            "claim": claim["text"],
            "disposition": claim["type"],
            "evidence_ids": claim["evidence_ids"],
        }
        for claim in output.pop("claims")
    ]
    output["explanation"] = output.pop("recommendation")

    result = audit_ai_claims(output)

    assert result["passed"] is True
    assert result["score"] == 100
