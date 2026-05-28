"""Evidence chunk helpers for CLI report summarization."""

from collections.abc import Mapping

from app.cli_support import mapping_value, string_from_mapping, string_value
from app.services.rag_types import EvidenceChunk


def evidence_chunks_from_task(task: Mapping[str, object]) -> list[EvidenceChunk]:
    chunks: list[EvidenceChunk] = []
    package_name = string_from_mapping(task.get("package"), "name")
    repo_id = string_value(task.get("repo_id")) or string_value(task.get("repo"))
    advisory_text = advisory_content(mapping_value(task.get("vulnerability")))
    if advisory_text is not None:
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-advisory",
                source_type="advisory",
                content=advisory_text,
                metadata=chunk_metadata(repo_id, package_name, "vulnerability"),
            )
        )

    risk_text = risk_content(mapping_value(task.get("risk")))
    if risk_text is not None:
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-risk",
                source_type="risk",
                content=risk_text,
                metadata=chunk_metadata(repo_id, package_name, "risk"),
            )
        )

    evidence = task.get("evidence")
    if isinstance(evidence, list):
        chunks.extend(task_evidence_chunks(evidence, repo_id, package_name))
    return chunks


def task_evidence_chunks(
    evidence: list[object],
    repo_id: str | None,
    package_name: str | None,
) -> list[EvidenceChunk]:
    chunks: list[EvidenceChunk] = []
    for index, item in enumerate(evidence):
        if not isinstance(item, Mapping):
            continue
        claim = string_value(item.get("claim"))
        if claim is None or claim.strip() == "":
            continue
        chunks.append(
            EvidenceChunk(
                chunk_id="cli-evidence-%s" % (index + 1),
                source_type=string_value(item.get("type")) or "task_evidence",
                content=claim,
                metadata=chunk_metadata(
                    repo_id,
                    package_name,
                    string_value(item.get("source")) or "remediation_task",
                ),
            )
        )
    return chunks


def advisory_content(vulnerability: Mapping[str, object]) -> str | None:
    fields = [
        ("Vulnerability", vulnerability.get("canonical_id") or vulnerability.get("source_id")),
        ("Severity", vulnerability.get("severity")),
        ("Summary", vulnerability.get("summary")),
        ("Fixed versions", vulnerability.get("fixed_versions")),
    ]
    return content_from_fields(fields)


def risk_content(risk: Mapping[str, object]) -> str | None:
    fields = [
        ("Priority", risk.get("priority")),
        ("Risk score", risk.get("risk_score")),
        ("Reachability", risk.get("reachability")),
        ("Runtime scope", risk.get("runtime_scope")),
        ("Confidence", risk.get("confidence")),
        ("Rationale", risk.get("rationale")),
    ]
    return content_from_fields(fields)


def content_from_fields(fields: list[tuple[str, object]]) -> str | None:
    lines: list[str] = []
    for label, value in fields:
        text = field_text(value)
        if text is not None:
            lines.append("%s: %s" % (label, text))
    if len(lines) == 0:
        return None
    return "\n".join(lines)


def field_text(value: object) -> str | None:
    if isinstance(value, str):
        stripped = value.strip()
        return stripped if stripped != "" else None
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    if not isinstance(value, list):
        return None

    items: list[str] = []
    for item in value:
        text = field_text(item)
        if text is not None:
            items.append(text)
    if len(items) == 0:
        return None
    return ", ".join(items)


def chunk_metadata(
    repo_id: str | None,
    package_name: str | None,
    source: str,
) -> dict[str, object]:
    metadata: dict[str, object] = {"source": source}
    if repo_id is not None:
        metadata["repo_id"] = repo_id
    if package_name is not None:
        metadata["package"] = package_name
    return metadata
