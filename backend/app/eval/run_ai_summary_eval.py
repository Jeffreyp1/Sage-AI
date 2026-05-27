"""Run deterministic AI summary safety evaluation cases."""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from app.ai.contracts import (
    AIFindingSummaryRequest,
    AIFindingSummaryResponse,
    Citation,
    ClaimCheck,
    MockAIProvider,
)
from app.services.ai_summary_service import AISummaryService
from app.services.rag_types import EvidenceChunk


DEFAULT_CASE_PATH = Path(__file__).parent / "cases" / "ai_summary.jsonl"


class MutatingPriorityProvider:
    name = "eval-mutating-priority-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        response = MockAIProvider().summarize_finding(request)
        return replace(
            response,
            priority="P3_MONITOR_DEFER",
            risk_score=12,
            provider_name=self.name,
        )


class FalseCitedFactProvider:
    name = "eval-false-cited-fact-provider"

    def summarize_finding(
        self,
        request: AIFindingSummaryRequest,
    ) -> AIFindingSummaryResponse:
        evidence_id = request.evidence[0].id
        claim_id = "claim-false-fact-1"
        return AIFindingSummaryResponse(
            finding_id=request.finding_id,
            package_name=request.package_name,
            vulnerability_id=request.vulnerability_id,
            priority=request.priority,
            risk_score=request.risk_score,
            summary="safe-looking summary",
            explanation="safe-looking explanation",
            citations=[Citation(evidence_id=evidence_id, claim_id=claim_id)],
            claim_checks=[
                ClaimCheck(
                    claim_id=claim_id,
                    claim="archive-utils is confirmed exploited in production",
                    disposition="fact",
                    evidence_ids=[evidence_id],
                    rationale="The claim cites a real evidence item.",
                )
            ],
            provider_name=self.name,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.eval.run_ai_summary_eval")
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
    task = required_mapping(case, "task")
    chunks = parse_chunks(case.get("chunks"), case_id=case_id)
    provider = provider_for_case(case)
    expected_blocked = required_bool(case, "expected_blocked")
    expected_mutated_fields = optional_string_list(case, "expected_mutated_fields")
    expected_unsupported_claim_ids = optional_string_list(
        case,
        "expected_unsupported_claim_ids",
    )

    result = AISummaryService(provider=provider).summarize_remediation_task(task, chunks)
    response = result.response
    validation = result.validation
    citation_precision = citation_precision_for_result(result.to_dict())
    unsupported_claim_count = len(validation.unsupported_claim_ids)
    mutated_field_count = len(validation.mutated_fields)
    passed = result.blocked is expected_blocked
    passed = passed and validation.mutated_fields == expected_mutated_fields
    passed = passed and validation.unsupported_claim_ids == expected_unsupported_claim_ids
    if expected_blocked is False:
        passed = passed and validation.valid is True
        passed = passed and citation_precision == 1.0

    return {
        "case_id": case_id,
        "passed": passed,
        "provider_mode": string_value(case.get("provider_mode")) or "valid",
        "expected_blocked": expected_blocked,
        "blocked": result.blocked,
        "valid": validation.valid,
        "citation_precision": citation_precision,
        "unsupported_claim_count": unsupported_claim_count,
        "mutated_field_count": mutated_field_count,
        "mutated_fields": validation.mutated_fields,
        "unsupported_claim_ids": validation.unsupported_claim_ids,
        "error_count": len(validation.errors),
        "retrieved_chunk_ids": result.retrieved_chunk_ids,
        "summary": response.summary if response is not None else None,
    }


def provider_for_case(case: Mapping[str, object]):
    mode = string_value(case.get("provider_mode")) or "valid"
    if mode == "valid":
        return MockAIProvider()
    if mode == "unsupported_claim":
        claims = optional_string_list(case, "unsupported_claims")
        if len(claims) == 0:
            claims = ["The package is confirmed exploited in production."]
        return MockAIProvider(unsupported_claims=claims)
    if mode == "mutating_priority":
        return MutatingPriorityProvider()
    if mode == "false_cited_fact":
        return FalseCitedFactProvider()
    raise ValueError("unsupported provider_mode: %s" % mode)


def parse_chunks(value: object, case_id: str) -> list[EvidenceChunk]:
    if not isinstance(value, list):
        raise ValueError("case %s requires chunks" % case_id)

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


def citation_precision_for_result(result: Mapping[str, object]) -> float:
    request = required_mapping(result, "request")
    response = result.get("response")
    if response is None:
        return 0.0
    if not isinstance(response, Mapping):
        return 0.0

    evidence = request.get("evidence")
    citations = response.get("citations")
    if not isinstance(evidence, list) or not isinstance(citations, list):
        return 0.0
    if len(citations) == 0:
        return 1.0

    evidence_ids = set()
    for item in evidence:
        if isinstance(item, Mapping):
            evidence_id = item.get("id")
            if isinstance(evidence_id, str):
                evidence_ids.add(evidence_id)

    valid_count = 0
    for citation in citations:
        if not isinstance(citation, Mapping):
            continue
        evidence_id = citation.get("evidence_id")
        if isinstance(evidence_id, str) and evidence_id in evidence_ids:
            valid_count += 1
    return valid_count / len(citations)


def summarize_results(results: Sequence[Mapping[str, object]]) -> dict[str, object]:
    case_count = len(results)
    passed_count = sum(1 for result in results if result.get("passed") is True)
    citation_precisions = [
        float(result["citation_precision"])
        for result in results
        if result.get("blocked") is False
        and isinstance(result.get("citation_precision"), int | float)
        and not isinstance(result.get("citation_precision"), bool)
    ]
    unsupported_claim_counts = numeric_values(results, "unsupported_claim_count")
    mutation_cases = [
        result
        for result in results
        if isinstance(result.get("mutated_field_count"), int)
        and result.get("mutated_field_count") > 0
    ]
    mutation_blocks = [
        result for result in mutation_cases if result.get("blocked") is True
    ]

    if len(citation_precisions) == 0:
        citation_precision = 0.0
    else:
        citation_precision = sum(citation_precisions) / len(citation_precisions)
    if case_count == 0:
        unsupported_claim_rate = 0.0
    else:
        unsupported_claim_rate = sum(unsupported_claim_counts) / case_count
    if len(mutation_cases) == 0:
        mutation_block_rate = 1.0
    else:
        mutation_block_rate = len(mutation_blocks) / len(mutation_cases)

    return {
        "case_count": case_count,
        "passed_count": passed_count,
        "failed_count": case_count - passed_count,
        "citation_precision": citation_precision,
        "unsupported_claim_rate": unsupported_claim_rate,
        "mutation_block_rate": mutation_block_rate,
        "passed": case_count > 0 and passed_count == case_count,
    }


def compact_results(results: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    compact: list[dict[str, object]] = []
    for result in results:
        compact.append(
            {
                "case_id": result.get("case_id"),
                "passed": result.get("passed"),
                "provider_mode": result.get("provider_mode"),
                "expected_blocked": result.get("expected_blocked"),
                "blocked": result.get("blocked"),
                "citation_precision": result.get("citation_precision"),
                "unsupported_claim_ids": result.get("unsupported_claim_ids"),
                "mutated_fields": result.get("mutated_fields"),
            }
        )
    return compact


def numeric_values(
    results: Sequence[Mapping[str, object]],
    key: str,
) -> list[float]:
    values: list[float] = []
    for result in results:
        value = result.get(key)
        if isinstance(value, int | float) and not isinstance(value, bool):
            values.append(float(value))
    return values


def required_mapping(data: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = data.get(key)
    if not isinstance(value, Mapping):
        raise ValueError("%s must be an object" % key)
    return value


def required_string(data: Mapping[str, object], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or value.strip() == "":
        raise ValueError("%s must be a non-empty string" % key)
    return value


def required_bool(data: Mapping[str, object], key: str) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise ValueError("%s must be a boolean" % key)
    return value


def optional_string_list(data: Mapping[str, object], key: str) -> list[str]:
    value = data.get(key)
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("%s must be a list" % key)
    items: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError("%s[%s] must be a string" % (key, index))
        items.append(item)
    return items


def string_value(value: object) -> str | None:
    if isinstance(value, str) and value.strip() != "":
        return value
    return None


if __name__ == "__main__":
    raise SystemExit(main())
