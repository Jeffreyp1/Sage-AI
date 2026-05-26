"""Run deterministic retrieval Precision@K evaluation cases."""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from app.eval.metrics import precision_at_k
from app.services.rag_retrieval import InMemoryEvidenceIndex
from app.services.rag_types import EvidenceChunk


DEFAULT_CASE_PATH = Path(__file__).parent / "cases" / "retrieval.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.eval.run_retrieval_eval")
    parser.add_argument("--cases", default=str(DEFAULT_CASE_PATH), help="Path to JSONL eval cases.")
    parser.add_argument("--verbose", action="store_true", help="Print full per-case results.")
    args = parser.parse_args(argv)

    try:
        cases = load_cases(Path(args.cases))
        results = [run_case(case) for case in cases]
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    output = {
        "summary": summarize_results(results),
        "results": results if args.verbose else compact_results(results),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["summary"].get("passed") is True else 1


def load_cases(path: Path) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if stripped == "":
            continue
        data = json.loads(stripped)
        if not isinstance(data, dict):
            raise ValueError(f"case line {line_number} must be a JSON object")
        cases.append(data)
    return cases


def run_case(case: Mapping[str, object]) -> dict[str, object]:
    chunks = parse_chunks(case.get("chunks"), case_id=case.get("case_id"))
    query = required_string(case, "query")
    top_k = required_positive_int(case, "top_k")
    filters = optional_filters(case.get("filters"))
    expected_chunk_ids = required_string_list(case, "expected_chunk_ids")
    if len(expected_chunk_ids) == 0:
        raise ValueError("expected_chunk_ids must not be empty")
    min_precision = required_float(case, "min_precision")

    index = InMemoryEvidenceIndex()
    index.add_chunks(chunks)
    search_results = index.search(query=query, top_k=top_k, filters=filters)
    result_rows = [result.to_dict() for result in search_results]
    precision = precision_at_k(result_rows, expected_ids=expected_chunk_ids, k=top_k)
    passed = precision >= min_precision

    return {
        "case_id": case.get("case_id"),
        "passed": passed,
        "query": query,
        "top_k": top_k,
        "filters": dict(filters) if filters is not None else {},
        "expected_chunk_ids": expected_chunk_ids,
        "retrieved_chunk_ids": [result.chunk.chunk_id for result in search_results],
        "precision_at_k": precision,
        "min_precision": min_precision,
        "results": result_rows,
    }


def parse_chunks(value: object, case_id: object) -> list[EvidenceChunk]:
    if not isinstance(value, list):
        raise ValueError(f"case {case_id} requires chunks")

    chunks: list[EvidenceChunk] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"case {case_id} chunk {index} must be an object")
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError(f"case {case_id} chunk {index} metadata must be an object")
        chunks.append(
            EvidenceChunk(
                chunk_id=required_string(item, "chunk_id"),
                source_type=required_string(item, "source_type"),
                content=required_string(item, "content"),
                metadata=dict(metadata),
            )
        )
    return chunks


def optional_filters(value: object) -> Mapping[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("filters must be an object")
    return value


def required_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def required_positive_int(data: Mapping[str, object], key: str) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{key} must be a positive integer")
    return value


def required_float(data: Mapping[str, object], key: str) -> float:
    value = data.get(key)
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{key} must be a number")
    return float(value)


def required_string_list(data: Mapping[str, object], key: str) -> list[str]:
    value = data.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")

    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{key}[{index}] must be a string")
        items.append(item)
    return items


def summarize_results(results: Sequence[Mapping[str, object]]) -> dict[str, object]:
    case_count = len(results)
    passed_count = sum(1 for result in results if result.get("passed") is True)
    precisions = [
        result.get("precision_at_k")
        for result in results
        if isinstance(result.get("precision_at_k"), (int, float))
        and not isinstance(result.get("precision_at_k"), bool)
    ]
    if precisions:
        average_precision = sum(float(precision) for precision in precisions) / len(precisions)
    else:
        average_precision = 0.0
    return {
        "case_count": case_count,
        "passed_count": passed_count,
        "failed_count": case_count - passed_count,
        "average_precision_at_k": average_precision,
        "passed": case_count > 0 and passed_count == case_count,
    }


def compact_results(results: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    compact: list[dict[str, object]] = []
    for result in results:
        compact.append(
            {
                "case_id": result.get("case_id"),
                "passed": result.get("passed"),
                "precision_at_k": result.get("precision_at_k"),
                "min_precision": result.get("min_precision"),
                "retrieved_chunk_ids": result.get("retrieved_chunk_ids"),
            }
        )
    return compact


if __name__ == "__main__":
    raise SystemExit(main())
