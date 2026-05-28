"""Run deterministic client-AI orchestration evaluation cases."""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from app.agents.triage_graph import TriageGraph
from app.services.rag_types import EvidenceChunk


DEFAULT_CASE_PATH = Path(__file__).parent / "cases" / "ai_orchestration.jsonl"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.eval.run_ai_orchestration_eval")
    parser.add_argument("--cases", default=str(DEFAULT_CASE_PATH), help="Path to JSONL eval cases.")
    parser.add_argument("--verbose", action="store_true", help="Print full per-case results.")
    args = parser.parse_args(argv)

    try:
        cases = load_cases(Path(args.cases))
        results = [run_case(case) for case in cases]
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
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
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as error:
            raise ValueError(
                "case line %s is not valid JSON: %s" % (line_number, error.msg)
            ) from error
        if not isinstance(data, dict):
            raise ValueError("case line %s must be a JSON object" % line_number)
        cases.append(data)
    return cases


def run_case(case: Mapping[str, object]) -> dict[str, object]:
    case_id = required_string(case, "case_id")
    task = required_mapping(case, "remediation_task")
    chunks = parse_chunks(case.get("evidence_chunks"), case_id=case_id)
    ai_output = required_mapping(case, "ai_output")
    expected_blocked = required_bool(case, "expected_blocked")
    expected_reason = string_value(case.get("expected_reason")) or "passed"

    state = TriageGraph().run_with_client_ai(
        remediation_task=task,
        evidence_chunks=chunks,
        ai_output=ai_output,
    )
    blocked = state.status == "blocked"
    reason = reason_for_state(state)
    citation_precision = citation_precision_for_output(ai_output, state)
    passed = blocked is expected_blocked and reason == expected_reason

    return {
        "case_id": case_id,
        "passed": passed,
        "blocked": blocked,
        "expected_blocked": expected_blocked,
        "reason": reason,
        "expected_reason": expected_reason,
        "citation_precision": citation_precision,
        "status": state.status,
        "node_results": [node.to_dict() for node in state.node_results],
    }


def reason_for_state(state: object) -> str:
    blocked_reasons = getattr(state, "blocked_reasons", [])
    if not isinstance(blocked_reasons, list) or len(blocked_reasons) == 0:
        return "passed"

    node_results = getattr(state, "node_results", [])
    validation_node = None
    for node in node_results:
        if getattr(node, "node_name", None) == "client_ai_validation":
            validation_node = node
            break
    validation = {}
    if validation_node is not None:
        output = getattr(validation_node, "output", {})
        if isinstance(output, Mapping):
            validation = mapping_value(output.get("validation"))

    invalid_ids = list_value(validation.get("invalid_citation_ids"))
    unsupported_ids = list_value(validation.get("unsupported_claim_ids"))
    mutated_fields = list_value(validation.get("mutated_fields"))
    errors = " ".join(str(error) for error in list_value(validation.get("errors"))).lower()

    if len(mutated_fields) > 0 or "changed protected triage fields" in errors:
        return "priority_mutation_blocked"
    if len(invalid_ids) > 0 or "referenced unknown evidence" in errors:
        return "unknown_evidence_id_blocked"
    if len(unsupported_ids) > 0 or "unsupported claims" in errors:
        return "uncited_claim_blocked"
    if "offensive" in errors or "unsafe" in errors or "exploit" in errors:
        return "unsafe_wording_blocked"
    return "validation_blocked"


def citation_precision_for_output(
    ai_output: Mapping[str, object],
    state: object,
) -> float:
    citations = ai_output.get("citations")
    if not isinstance(citations, list):
        return 0.0
    if len(citations) == 0:
        return 1.0 if getattr(state, "status", "") != "blocked" else 0.0
    validation_reason = reason_for_state(state)
    if validation_reason == "unknown_evidence_id_blocked":
        return 0.0
    return 1.0


def summarize_results(results: Sequence[Mapping[str, object]]) -> dict[str, object]:
    case_count = len(results)
    passed_count = sum(1 for result in results if result.get("passed") is True)
    expected_blocked_count = sum(
        1 for result in results if result.get("expected_blocked") is True
    )
    correctly_blocked_count = sum(
        1
        for result in results
        if result.get("expected_blocked") is True and result.get("blocked") is True
    )
    citation_scores = [
        float(result["citation_precision"])
        for result in results
        if result.get("blocked") is False
        and isinstance(result.get("citation_precision"), int | float)
        and not isinstance(result.get("citation_precision"), bool)
    ]
    if expected_blocked_count == 0:
        blocked_when_expected_rate = 1.0
    else:
        blocked_when_expected_rate = correctly_blocked_count / expected_blocked_count
    if len(citation_scores) == 0:
        citation_precision = 0.0
    else:
        citation_precision = sum(citation_scores) / len(citation_scores)

    return {
        "case_count": case_count,
        "passed_count": passed_count,
        "failed_count": case_count - passed_count,
        "passed": passed_count == case_count,
        "blocked_when_expected_rate": blocked_when_expected_rate,
        "citation_precision": citation_precision,
    }


def compact_results(results: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    return [
        {
            "case_id": str(result.get("case_id", "")),
            "passed": result.get("passed") is True,
            "blocked": result.get("blocked") is True,
            "reason": str(result.get("reason", "")),
        }
        for result in results
    ]


def parse_chunks(value: object, case_id: str) -> list[EvidenceChunk]:
    if not isinstance(value, list):
        raise ValueError("case %s requires evidence_chunks" % case_id)

    chunks: list[EvidenceChunk] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError("case %s chunk %s must be an object" % (case_id, index))
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict):
            raise ValueError("case %s chunk %s metadata must be an object" % (case_id, index))
        chunks.append(
            EvidenceChunk(
                chunk_id=required_string(item, "chunk_id"),
                source_type=required_string(item, "source_type"),
                content=required_string(item, "content"),
                metadata=dict(metadata),
            )
        )
    return chunks


def required_mapping(value: Mapping[str, object], key: str) -> dict[str, object]:
    raw = value.get(key)
    if isinstance(raw, Mapping):
        return dict(raw)
    raise ValueError("case requires object field %s" % key)


def required_string(value: Mapping[str, object], key: str) -> str:
    raw = value.get(key)
    if isinstance(raw, str) and raw.strip() != "":
        return raw
    raise ValueError("case requires string field %s" % key)


def required_bool(value: Mapping[str, object], key: str) -> bool:
    raw = value.get(key)
    if isinstance(raw, bool):
        return raw
    raise ValueError("case requires boolean field %s" % key)


def mapping_value(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def list_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip() != "":
        return value
    return None


if __name__ == "__main__":
    raise SystemExit(main())
