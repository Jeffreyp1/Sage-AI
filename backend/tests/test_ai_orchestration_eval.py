import json
import subprocess
import sys
from pathlib import Path

from app.eval.run_ai_orchestration_eval import (
    DEFAULT_CASE_PATH,
    load_cases,
    main,
    run_case,
    summarize_results,
)


def test_ai_orchestration_eval_blocks_uncited_claim_case():
    result = run_case(uncited_fact_claim_case())

    assert result["passed"] is True
    assert result["blocked"] is True
    assert result["reason"] == "uncited_claim_blocked"


def test_default_ai_orchestration_eval_cases_pass():
    cases = load_cases(DEFAULT_CASE_PATH)
    results = [run_case(case) for case in cases]
    summary = summarize_results(results)

    assert len(cases) >= 5
    assert summary["passed"] is True
    assert summary["case_count"] == len(cases)
    assert summary["blocked_when_expected_rate"] == 1.0
    assert summary["citation_precision"] >= 0.8


def test_ai_orchestration_eval_module_exits_nonzero_for_failing_case(
    tmp_path: Path,
) -> None:
    path = tmp_path / "failing.jsonl"
    case = uncited_fact_claim_case()
    case["expected_blocked"] = False
    path.write_text(json.dumps(case, sort_keys=True) + "\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "-m", "app.eval.run_ai_orchestration_eval", "--cases", str(path)],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "\"failed_count\": 1" in completed.stdout
    assert completed.stderr == ""


def test_ai_orchestration_eval_main_outputs_summary(tmp_path: Path, capsys) -> None:
    path = tmp_path / "passing.jsonl"
    path.write_text(json.dumps(uncited_fact_claim_case(), sort_keys=True) + "\n", encoding="utf-8")

    exit_code = main(["--cases", str(path)])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["summary"]["passed"] is True
    assert output["summary"]["case_count"] == 1


def uncited_fact_claim_case() -> dict[str, object]:
    case = valid_cited_case()
    case["case_id"] = "uncited_fact_claim"
    case["expected_blocked"] = True
    case["expected_reason"] = "uncited_claim_blocked"
    case["ai_output"]["citations"] = []
    return case


def valid_cited_case() -> dict[str, object]:
    return {
        "case_id": "valid_cited_answer",
        "expected_blocked": False,
        "expected_reason": "passed",
        "remediation_task": remediation_task_fixture(),
        "evidence_chunks": evidence_chunks_fixture(),
        "ai_output": cited_ai_output_fixture(),
    }


def remediation_task_fixture() -> dict[str, object]:
    return {
        "task_id": "task-ai-orchestration",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "dependencies",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "CVE-2026-0001",
            "source_id": "GHSA-archive",
            "severity": "HIGH",
            "summary": "archive-utils unsafe deserialization can affect archive parsing.",
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 78,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
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
        },
        "test_plan": ["Run npm test."],
        "rollback_plan": ["Revert dependency bump."],
        "human_approval_required": True,
    }


def evidence_chunks_fixture() -> list[dict[str, object]]:
    return [
        {
            "chunk_id": "chunk-upload",
            "source_type": "source_file",
            "content": "archive-utils is imported by src/upload.ts in production.",
            "metadata": {"source": "src/upload.ts", "package": "archive-utils"},
        }
    ]


def cited_ai_output_fixture() -> dict[str, object]:
    return {
        "finding_id": "task-ai-orchestration",
        "package_name": "archive-utils",
        "vulnerability_id": "CVE-2026-0001",
        "priority": "P1_FIX_THIS_SPRINT",
        "risk_score": 78,
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
