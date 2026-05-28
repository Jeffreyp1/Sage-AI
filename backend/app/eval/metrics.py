"""Deterministic evaluation metrics for scanner report quality."""

from collections.abc import Mapping, Sequence


def exact_match_accuracy(rows: Sequence[Mapping[str, object]], key: str) -> float:
    if len(rows) == 0:
        return 1.0

    matches = 0
    for row in rows:
        expected = row.get("expected")
        actual = row.get("actual")
        if not isinstance(expected, Mapping) or not isinstance(actual, Mapping):
            continue
        if value_at_path(expected, key) == value_at_path(actual, key):
            matches += 1
    return matches / len(rows)


def precision_at_k(
    results: Sequence[object],
    expected_ids: Sequence[str],
    k: int,
) -> float:
    if len(expected_ids) == 0:
        return 0.0
    if k <= 0:
        return 0.0

    expected = set(expected_ids)
    limit = min(k, len(results))
    if limit == 0:
        return 0.0

    hits = 0
    for result in results[:limit]:
        result_id = retrieval_result_id(result)
        if result_id in expected:
            hits += 1
    return hits / k


def retrieval_result_id(result: object) -> str | None:
    if isinstance(result, str):
        return result
    if not isinstance(result, Mapping):
        return None
    chunk_id = result.get("chunk_id")
    if isinstance(chunk_id, str):
        return chunk_id
    chunk = result.get("chunk")
    if isinstance(chunk, Mapping):
        nested_id = chunk.get("chunk_id")
        if isinstance(nested_id, str):
            return nested_id
    return None


def score_case(case: Mapping[str, object], report: Mapping[str, object]) -> dict[str, object]:
    from app.eval.verifier import verify_report

    result = verify_report(case=case, report=report)
    scores = result.get("scores", {})
    if not isinstance(scores, Mapping):
        return {}
    return dict(scores)


def summarize_scores(scores: Sequence[Mapping[str, object]]) -> dict[str, object]:
    summary: dict[str, object] = {"case_count": len(scores)}
    if len(scores) == 0:
        summary["passed"] = False
        return summary

    keys: set[str] = set()
    for score in scores:
        keys.update(str(key) for key in score)

    for key in sorted(keys):
        values = [score.get(key) for score in scores]
        numeric_values = [
            value
            for value in values
            if isinstance(value, (int, float)) and not isinstance(value, bool)
        ]
        if len(numeric_values) == 0:
            continue
        if key.endswith("_count") or key.endswith("_findings"):
            summary[key] = sum(numeric_values)
        else:
            summary[key] = sum(numeric_values) / len(numeric_values)

    summary["passed"] = all(score.get("passed") is True for score in scores)
    return summary


def value_at_path(data: Mapping[str, object], path: str) -> object:
    current: object = data
    for part in path.split("."):
        if not isinstance(current, Mapping):
            return None
        current = current.get(part)
    return current
