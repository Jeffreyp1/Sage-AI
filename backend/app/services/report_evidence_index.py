"""Convert public scan reports into deterministic RAG evidence chunks."""

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from app.services.ai_summary_service import remediation_task_query
from app.services.public_safety import sanitize_public_identifier, sanitize_public_text
from app.services.rag_retrieval import InMemoryEvidenceIndex
from app.services.rag_types import EvidenceChunk


def chunks_from_report(report: Mapping[str, object]) -> list[EvidenceChunk]:
    """Build searchable evidence chunks from a public scan report."""

    repo_id = _repo_id(report)
    chunks: list[EvidenceChunk] = []

    for task_index, task_value in enumerate(_list_value(report.get("remediation_tasks"))):
        task = _mapping_value(task_value)
        if len(task) == 0:
            continue

        context = _TaskChunkContext.from_task(repo_id, task_index, task)
        chunks.append(_advisory_chunk(context, task))
        chunks.append(_risk_chunk(context, task))
        chunks.extend(_finding_evidence_chunks(context, task))

    return chunks


def retrieved_chunks_for_task(
    report: Mapping[str, object],
    task: Mapping[str, object],
    *,
    top_k: int = 5,
) -> list[EvidenceChunk]:
    """Retrieve report chunks most relevant to one remediation task."""

    if top_k <= 0:
        return []

    context = _TaskChunkContext.from_task(_repo_id(report), 0, task)
    index = InMemoryEvidenceIndex()
    index.add_chunks(chunks_from_report(report))
    results = index.search(
        remediation_task_query(task),
        top_k=top_k,
        filters={
            "repo_id": context.repo_id,
            "package": context.package,
            "vulnerability_id": context.vulnerability_id,
        },
    )
    return [result.chunk for result in results]


@dataclass(frozen=True)
class _TaskChunkContext:
    repo_id: str
    task_index: int
    task_id: str
    package: str
    vulnerability_id: str

    @classmethod
    def from_task(
        cls,
        repo_id: str,
        task_index: int,
        task: Mapping[str, object],
    ) -> "_TaskChunkContext":
        package = _mapping_value(task.get("package"))
        vulnerability = _mapping_value(task.get("vulnerability"))
        return cls(
            repo_id=repo_id,
            task_index=task_index,
            task_id=_clean_identifier(task.get("task_id")) or "task-%s" % task_index,
            package=_clean_identifier(package.get("name")) or "unknown-package",
            vulnerability_id=(
                _clean_identifier(
                    vulnerability.get("canonical_id") or vulnerability.get("source_id")
                )
                or "unknown-vulnerability"
            ),
        )

    def metadata(self, *, source: str) -> dict[str, object]:
        return {
            "repo_id": self.repo_id,
            "task_id": self.task_id,
            "package": self.package,
            "vulnerability_id": self.vulnerability_id,
            "source": sanitize_public_text(source),
        }

    def chunk_id(self, kind: str, *parts: object) -> str:
        values = [
            self.repo_id,
            str(self.task_index),
            self.task_id,
            self.package,
            self.vulnerability_id,
            kind,
            *(str(part) for part in parts),
        ]
        digest = sha256("\x1f".join(values).encode("utf-8")).hexdigest()[:20]
        return "report-%s-%s" % (_safe_id_part(kind), digest)


def _advisory_chunk(
    context: _TaskChunkContext,
    task: Mapping[str, object],
) -> EvidenceChunk:
    vulnerability = _mapping_value(task.get("vulnerability"))
    package = _mapping_value(task.get("package"))
    content = _join_lines(
        [
            "Advisory %s affects %s." % (context.vulnerability_id, context.package),
            "Severity: %s." % (_clean_text(vulnerability.get("severity")) or "UNKNOWN"),
            "Current version: %s." % (_clean_text(package.get("current_version")) or "unknown"),
            "Fixed versions: %s." % _fixed_versions_text(vulnerability),
            _clean_text(vulnerability.get("summary")),
        ]
    )
    return EvidenceChunk(
        chunk_id=context.chunk_id("advisory"),
        source_type="advisory",
        content=content,
        metadata=context.metadata(source="vulnerability"),
    )


def _risk_chunk(
    context: _TaskChunkContext,
    task: Mapping[str, object],
) -> EvidenceChunk:
    risk = _mapping_value(task.get("risk"))
    rationale = " ".join(_clean_text(value) for value in _list_value(risk.get("rationale")))
    content = _join_lines(
        [
            "Risk priority: %s." % (_clean_text(risk.get("priority")) or "unknown"),
            "Risk score: %s." % (_clean_text(risk.get("risk_score")) or "unknown"),
            "Runtime scope: %s." % (_clean_text(risk.get("runtime_scope")) or "unknown"),
            "Reachability: %s." % (_clean_text(risk.get("reachability")) or "unknown"),
            rationale,
        ]
    )
    return EvidenceChunk(
        chunk_id=context.chunk_id("risk"),
        source_type="risk",
        content=content,
        metadata=context.metadata(source="risk"),
    )


def _finding_evidence_chunks(
    context: _TaskChunkContext,
    task: Mapping[str, object],
) -> list[EvidenceChunk]:
    chunks: list[EvidenceChunk] = []
    for index, evidence_value in enumerate(_list_value(task.get("evidence"))):
        evidence = _mapping_value(evidence_value)
        claim = _clean_text(evidence.get("claim"))
        if claim == "":
            continue
        source = _clean_text(evidence.get("source")) or "remediation_task"
        metadata = context.metadata(source=source)
        metadata["evidence_type"] = _clean_text(evidence.get("type")) or "finding_evidence"
        metadata["evidence_index"] = index
        chunks.append(
            EvidenceChunk(
                chunk_id=context.chunk_id("finding-evidence", index, source, claim),
                source_type="finding_evidence",
                content=claim,
                metadata=metadata,
            )
        )
    return chunks


def _repo_id(report: Mapping[str, object]) -> str:
    scan_id = _clean_identifier(report.get("scan_id"))
    if scan_id != "":
        return scan_id

    repo_profile = _mapping_value(report.get("repo_profile"))
    repo_name = _clean_identifier(repo_profile.get("repo_name"))
    if repo_name != "":
        return repo_name

    return "unknown-repo"


def _fixed_versions_text(vulnerability: Mapping[str, object]) -> str:
    fixed_versions = _clean_text_list(vulnerability.get("fixed_versions"))
    if len(fixed_versions) == 0:
        return "unknown"
    return ", ".join(fixed_versions)


def _join_lines(lines: list[str | None]) -> str:
    return "\n".join(line for line in lines if line is not None and line.strip() != "")


def _mapping_value(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _list_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []


def _clean_text_list(value: object) -> list[str]:
    return [text for text in (_clean_text(item) for item in _list_value(value)) if text != ""]


def _clean_text(value: object) -> str:
    if value is None:
        return ""
    return sanitize_public_text(str(value)).strip()


def _clean_identifier(value: object) -> str:
    if value is None:
        return ""
    return sanitize_public_identifier(str(value)).strip()


def _safe_id_part(value: str) -> str:
    return "".join(character if character.isalnum() else "-" for character in value)
