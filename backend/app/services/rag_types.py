"""Shared evidence retrieval types."""

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class EvidenceChunk:
    chunk_id: str
    source_type: str
    content: str
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceSearchResult:
    chunk: EvidenceChunk
    score: float

    def to_dict(self) -> dict[str, object]:
        data = self.chunk.to_dict()
        data["score"] = round(self.score, 6)
        return data
