import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.eval.run_retrieval_eval import load_cases, main, run_case


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def passing_case() -> dict[str, object]:
    return {
        "case_id": "advisory-hit",
        "chunks": [
            {
                "chunk_id": "src-archive-import",
                "source_type": "source_file",
                "content": "archive-utils upload handler unpacks invoice bundles before validation",
                "metadata": {
                    "repo_id": "payments-api",
                    "ecosystem": "npm",
                    "package": "archive-utils",
                },
            },
            {
                "chunk_id": "adv-archive-utils",
                "source_type": "advisory",
                "content": "archive-utils critical CVE remote code execution fixed in 2.2.0",
                "metadata": {
                    "repo_id": "payments-api",
                    "ecosystem": "npm",
                    "package": "archive-utils",
                },
            },
        ],
        "query": "archive-utils rce remote code execution CVE",
        "top_k": 1,
        "filters": {},
        "expected_chunk_ids": ["adv-archive-utils"],
        "min_precision": 1.0,
    }


def failing_case() -> dict[str, object]:
    case = passing_case()
    case["case_id"] = "missing-hit"
    case["expected_chunk_ids"] = ["not-in-index"]
    case["min_precision"] = 1.0
    return case


def test_load_cases_skips_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "retrieval.jsonl"
    rows = [passing_case()]
    path.write_text("\n" + json.dumps(rows[0]) + "\n\n", encoding="utf-8")

    cases = load_cases(path)

    assert cases == rows


def test_run_case_builds_index_searches_and_scores_precision() -> None:
    case = passing_case()
    assert case["chunks"][0]["chunk_id"] != case["expected_chunk_ids"][0]

    result = run_case(case)

    assert result["passed"] is True
    assert result["precision_at_k"] == 1.0
    assert result["retrieved_chunk_ids"] == ["adv-archive-utils"]


def test_run_case_applies_metadata_filters() -> None:
    case = passing_case()
    case["chunks"] = [
        {
            "chunk_id": "payments-advisory",
            "source_type": "advisory",
            "content": "auth-gateway authorization bypass in payments-api checkout",
            "metadata": {"repo_id": "payments-api", "package": "auth-gateway"},
        },
        {
            "chunk_id": "admin-advisory",
            "source_type": "advisory",
            "content": "auth-gateway authorization bypass in admin-portal dashboard",
            "metadata": {"repo_id": "admin-portal", "package": "auth-gateway"},
        },
    ]
    case["query"] = "auth-gateway authorization bypass advisory"
    case["top_k"] = 1
    case["filters"] = {"repo_id": "admin-portal"}
    case["expected_chunk_ids"] = ["admin-advisory"]

    result = run_case(case)

    assert result["passed"] is True
    assert result["retrieved_chunk_ids"] == ["admin-advisory"]


def test_run_case_rejects_empty_expected_chunk_ids() -> None:
    case = passing_case()
    case["expected_chunk_ids"] = []

    with pytest.raises(ValueError, match="expected_chunk_ids must not be empty"):
        run_case(case)


def test_main_returns_nonzero_for_failing_cases(tmp_path: Path, capsys) -> None:
    path = tmp_path / "failing.jsonl"
    write_jsonl(path, [failing_case()])

    exit_code = main(["--cases", str(path)])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["summary"]["passed"] is False
    assert output["summary"]["failed_count"] == 1


def test_cli_exits_nonzero_for_empty_expected_chunk_ids(tmp_path: Path) -> None:
    case = passing_case()
    case["expected_chunk_ids"] = []
    path = tmp_path / "malformed.jsonl"
    write_jsonl(path, [case])

    completed = subprocess.run(
        [sys.executable, "-m", "app.eval.run_retrieval_eval", "--cases", str(path)],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "expected_chunk_ids must not be empty" in completed.stderr
