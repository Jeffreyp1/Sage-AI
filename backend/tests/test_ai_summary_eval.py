import json
import subprocess
import sys
from pathlib import Path

from app.eval.run_ai_summary_eval import (
    DEFAULT_CASE_PATH,
    load_cases,
    main,
    run_case,
    summarize_results,
)


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def valid_case() -> dict[str, object]:
    return {
        "case_id": "valid-cited-summary",
        "provider_mode": "valid",
        "expected_blocked": False,
        "task": task_fixture(),
        "chunks": chunks_fixture(),
    }


def unsupported_claim_case() -> dict[str, object]:
    case = valid_case()
    case["case_id"] = "unsupported-claim-blocks"
    case["provider_mode"] = "unsupported_claim"
    case["expected_blocked"] = True
    case["unsupported_claims"] = ["The package is confirmed exploited in production."]
    case["expected_unsupported_claim_ids"] = ["claim-unsupported-1"]
    return case


def mutating_priority_case() -> dict[str, object]:
    case = valid_case()
    case["case_id"] = "priority-risk-mutation-blocks"
    case["provider_mode"] = "mutating_priority"
    case["expected_blocked"] = True
    case["expected_mutated_fields"] = ["priority", "risk_score"]
    return case


def failing_case() -> dict[str, object]:
    case = unsupported_claim_case()
    case["case_id"] = "unsupported-claim-not-expected"
    case["expected_blocked"] = False
    case["expected_unsupported_claim_ids"] = []
    return case


def task_fixture() -> dict[str, object]:
    return {
        "task_id": "task-ai-summary",
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
            }
        ],
    }


def chunks_fixture() -> list[dict[str, object]]:
    return [
        {
            "chunk_id": "chunk-advisory",
            "source_type": "advisory",
            "content": (
                "CVE-2026-0001 advisory for archive-utils unsafe deserialization. "
                "Fixed in version 2.2.0."
            ),
            "metadata": {
                "repo_id": "payments-api",
                "package": "archive-utils",
                "source": "advisory",
            },
        }
    ]


def test_default_eval_cases_pass() -> None:
    cases = load_cases(DEFAULT_CASE_PATH)
    results = [run_case(case) for case in cases]
    summary = summarize_results(results)

    assert len(cases) >= 3
    assert summary["passed"] is True
    assert summary["case_count"] == len(cases)
    assert summary["passed_count"] == len(cases)
    assert summary["citation_precision"] == 1.0
    assert summary["mutation_block_rate"] == 1.0


def test_run_case_accepts_valid_cited_summary() -> None:
    result = run_case(valid_case())

    assert result["passed"] is True
    assert result["blocked"] is False
    assert result["valid"] is True
    assert result["citation_precision"] == 1.0


def test_run_case_requires_unsupported_claim_block() -> None:
    result = run_case(unsupported_claim_case())

    assert result["passed"] is True
    assert result["blocked"] is True
    assert result["unsupported_claim_ids"] == ["claim-unsupported-1"]


def test_run_case_requires_priority_and_risk_mutation_block() -> None:
    result = run_case(mutating_priority_case())

    assert result["passed"] is True
    assert result["blocked"] is True
    assert result["mutated_fields"] == ["priority", "risk_score"]


def test_main_returns_nonzero_when_case_fails(tmp_path: Path, capsys) -> None:
    path = tmp_path / "failing.jsonl"
    write_jsonl(path, [failing_case()])

    exit_code = main(["--cases", str(path)])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["summary"]["passed"] is False
    assert output["summary"]["failed_count"] == 1


def test_eval_module_exits_nonzero_for_failing_case(tmp_path: Path) -> None:
    path = tmp_path / "failing.jsonl"
    write_jsonl(path, [failing_case()])

    completed = subprocess.run(
        [sys.executable, "-m", "app.eval.run_ai_summary_eval", "--cases", str(path)],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "\"failed_count\": 1" in completed.stdout
    assert completed.stderr == ""
