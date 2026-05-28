from app.eval.claim_auditor import audit_ai_claims


def cited_output():
    return {
        "summary": "archive-utils may be reachable based on the cited import evidence.",
        "recommendation": "Exploitability is unknown and needs human review.",
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


def test_auditor_disposition_matrix():
    cases = [
        ("fact", ["ev-lockfile"], True, set(), set()),
        ("inference", ["ev-lockfile"], True, set(), set()),
        ("unknown", [], True, set(), set()),
        ("unsupported", [], False, {"unsupported_claim"}, {"claim-1"}),
    ]

    for disposition, evidence_ids, expected_passed, expected_codes, expected_blocked in cases:
        output = {
            "citations": [{"claim_id": "claim-1", "evidence_id": "ev-lockfile"}],
            "claims": [
                {
                    "claim_id": "claim-1",
                    "text": "archive-utils status needs review.",
                    "type": disposition,
                    "evidence_ids": evidence_ids,
                }
            ],
        }

        result = audit_ai_claims(output)

        assert result["passed"] is expected_passed
        assert expected_codes.issubset(finding_codes(result))
        assert expected_blocked.issubset(blocked_claim_ids(result))


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


def test_auditor_blocks_unsupported_disposition():
    output = cited_output()
    output["claims"][1]["type"] = "unsupported"
    output["claims"][1]["evidence_ids"] = []

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "unsupported_claim" in finding_codes(result)
    assert "claim-2" in blocked_claim_ids(result)


def test_auditor_blocks_factual_generated_summary_with_no_claims():
    output = {
        "summary": "archive-utils 2.1.4 is installed in production.",
        "citations": [],
    }

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "missing_auditable_claims" in finding_codes(result)


def test_auditor_blocks_mixed_factual_and_unknown_summary_with_no_claims():
    output = {
        "summary": "archive-utils 2.1.4 is installed, but exploitability is unknown.",
        "citations": [],
    }

    result = audit_ai_claims(output)

    assert result["passed"] is False
    assert "missing_auditable_claims" in finding_codes(result)


def test_auditor_no_claims_prose_matrix():
    cases = [
        ("factual", "archive-utils is installed in production.", False),
        ("advisory", "Upgrade archive-utils before release.", False),
        ("versioned", "archive-utils 2.1.4 needs review.", False),
        ("unknown-only", "Exploitability is unknown and needs human review.", True),
        (
            "mixed unknown plus advisory",
            "Upgrade archive-utils before release; exploitability is unknown.",
            False,
        ),
    ]

    for _, summary, expected_passed in cases:
        output = {"summary": summary, "citations": []}

        result = audit_ai_claims(output)

        assert result["passed"] is expected_passed
        if expected_passed:
            assert result["warnings"] == ["AI output did not include auditable claims."]
            assert result["findings"] == []
        else:
            assert "missing_auditable_claims" in finding_codes(result)


def test_auditor_blocks_unknown_plus_advisory_prose_in_all_generated_fields():
    text = "Upgrade archive-utils before release; exploitability is unknown."

    for field in ("summary", "explanation", "recommendation"):
        result = audit_ai_claims({field: text, "citations": []})

        assert result["passed"] is False
        assert "missing_auditable_claims" in finding_codes(result)
        assert any(finding["path"] == field for finding in result["findings"])


def test_auditor_blocks_unsupported_advisory_prose_alongside_supported_claims():
    text = "Upgrade archive-utils before release; exploitability is unknown."

    cases = [
        ("summary", lambda output: output.update({"summary": text}), "summary"),
        ("explanation", lambda output: output.update({"explanation": text}), "explanation"),
        (
            "recommendation",
            lambda output: output.update({"recommendation": text}),
            "recommendation",
        ),
        (
            "rationale",
            lambda output: output["claims"][0].update({"rationale": text}),
            "claims[0].rationale",
        ),
    ]

    for _, mutate, expected_path in cases:
        output = cited_output()
        mutate(output)

        result = audit_ai_claims(output)

        assert result["passed"] is False
        assert "missing_auditable_claims" in finding_codes(result)
        assert any(finding["path"] == expected_path for finding in result["findings"])


def test_auditor_allows_conservative_unknown_prose_with_no_claims():
    output = {
        "summary": "Exploitability is unknown and needs human review.",
        "citations": [],
    }

    result = audit_ai_claims(output)

    assert result["passed"] is True
    assert result["warnings"] == ["AI output did not include auditable claims."]


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


def test_auditor_reports_overconfident_language_from_claim_field_paths():
    cases = [
        ("claims", "text", "claims[0].text"),
        ("claims", "claim", "claims[0].claim"),
        ("claims", "rationale", "claims[0].rationale"),
        ("claim_checks", "claim", "claim_checks[0].claim"),
        ("claim_checks", "rationale", "claim_checks[0].rationale"),
    ]

    for claim_key, field, expected_path in cases:
        output = cited_output()
        claim = output["claims"][0]
        if claim_key == "claim_checks":
            output["claim_checks"] = [
                {
                    "claim_id": claim["claim_id"],
                    "claim": claim["text"],
                    "disposition": claim["type"],
                    "evidence_ids": claim["evidence_ids"],
                }
            ]
            output.pop("claims")
            claim = output["claim_checks"][0]
        claim[field] = "Install archive-utils 2.2.0 and it fixes everything."

        result = audit_ai_claims(output)

        assert result["passed"] is False
        assert any(
            finding["code"] == "overconfident_fix_language"
            and finding["path"] == expected_path
            for finding in result["findings"]
        )


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
