from app.services.report_evidence_index import chunks_from_report
from app.services.rag_retrieval import InMemoryEvidenceIndex


def test_report_chunks_include_advisory_risk_and_source_evidence():
    report = scan_report_fixture()

    chunks = chunks_from_report(report)

    source_types = [chunk.source_type for chunk in chunks]
    assert "advisory" in source_types
    assert "risk" in source_types
    assert "finding_evidence" in source_types
    assert all(chunk.chunk_id.startswith("report-") for chunk in chunks)


def test_report_chunks_include_filterable_task_metadata():
    report = scan_report_fixture()

    chunks = chunks_from_report(report)

    archive_chunks = [
        chunk for chunk in chunks if chunk.metadata.get("task_id") == "task-archive-utils"
    ]
    assert len(archive_chunks) == 4
    assert {chunk.metadata["package"] for chunk in archive_chunks} == {"archive-utils"}
    assert {chunk.metadata["vulnerability_id"] for chunk in archive_chunks} == {
        "CVE-2026-0001"
    }
    assert any(chunk.metadata["source"] == "src/upload.ts" for chunk in archive_chunks)


def test_report_chunks_are_public_safe_and_deterministic():
    report = scan_report_fixture()
    report["remediation_tasks"][0]["evidence"][0]["source"] = (
        "/Users/auditor/private/repo/package-lock.json"
    )
    report["remediation_tasks"][0]["evidence"][0]["claim"] = (
        "Proof-of-concept payload appears in token=ghp_secret123."
    )

    first = [chunk.to_dict() for chunk in chunks_from_report(report)]
    second = [chunk.to_dict() for chunk in chunks_from_report(report)]

    assert first == second
    encoded = str(first)
    assert "/Users/" not in encoded
    assert "ghp_secret123" not in encoded
    assert "payload" not in encoded.lower()


def test_report_chunks_can_be_indexed_and_filtered_for_retrieval():
    report = scan_report_fixture()
    chunks = chunks_from_report(report)
    index = InMemoryEvidenceIndex()
    index.add_chunks(chunks)

    results = index.search(
        "production upload route archive-utils",
        top_k=5,
        filters={
            "repo_id": "scan-test-report-index",
            "package": "archive-utils",
            "vulnerability_id": "CVE-2026-0001",
        },
    )

    assert len(results) > 0
    assert any(result.chunk.source_type == "finding_evidence" for result in results)
    assert all(result.chunk.metadata["package"] == "archive-utils" for result in results)


def test_report_chunks_sanitize_identifier_metadata():
    report = scan_report_fixture()
    report["scan_id"] = "/Users/auditor/private/repo"
    report["remediation_tasks"][0]["task_id"] = "secret.task-archive-utils"
    report["remediation_tasks"][0]["evidence"][0]["source"] = (
        "/Users/auditor/private/repo/package-lock.json"
    )
    report["remediation_tasks"][0]["evidence"][0]["claim"] = (
        "Proof-of-concept payload uses token=ghp_secret123."
    )

    encoded = str([chunk.to_dict() for chunk in chunks_from_report(report)])

    assert "/Users/" not in encoded
    assert "private/repo" not in encoded
    assert "secret.task" not in encoded
    assert "ghp_secret123" not in encoded
    assert "payload" not in encoded.lower()


def scan_report_fixture() -> dict[str, object]:
    return {
        "schema_version": "v1",
        "scan_id": "scan-test-report-index",
        "repo_profile": {"repo_name": "payments-api"},
        "packages": [],
        "vulnerabilities": [],
        "summary": {
            "complete": True,
            "scan_status": "complete",
            "packages": 1,
            "raw_alerts": 1,
            "deduped_remediation_tasks": 1,
            "release_blockers": 0,
            "recommended_sprint_fixes": 1,
            "safe_to_defer": 0,
            "needs_human_review": 0,
            "error_count": 0,
            "priority_counts": {"P1_FIX_THIS_SPRINT": 1},
        },
        "remediation_tasks": [remediation_task_fixture()],
        "errors": [],
    }


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
            "summary": "archive-utils unsafe deserialization can affect archive parsing.",
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
