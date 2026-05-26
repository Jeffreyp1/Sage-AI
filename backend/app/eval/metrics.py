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
