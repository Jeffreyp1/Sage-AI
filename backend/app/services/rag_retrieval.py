"""Deterministic evidence embedding and retrieval helpers."""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import blake2b
from math import isfinite, sqrt
import re
from typing import Protocol

from app.services.rag_types import EvidenceChunk, EvidenceSearchResult


Vector = list[float]
MetadataFilters = Mapping[str, object]

_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[-_./:][a-z0-9]+)*")
_MIN_DIMENSION = 16
PGVECTOR_DIMENSION = 1536
_DEFAULT_DIMENSION = PGVECTOR_DIMENSION
_DEFAULT_CANDIDATE_LIMIT = 1000
_MAX_CONTEXT_TEXT_LENGTH = 160

_SECURITY_EXPANSIONS: Mapping[str, tuple[str, ...]] = {
    "auth": ("authentication", "authorization", "access-control"),
    "authentication": ("auth", "access-control"),
    "authorization": ("auth", "access-control"),
    "bypass": ("access-control", "auth"),
    "cve": ("vulnerability", "advisory"),
    "critical": ("severity-critical", "priority"),
    "csrf": ("cross-site-request-forgery", "web-vulnerability"),
    "cwe": ("weakness", "vulnerability"),
    "deserialization": ("rce", "remote-code-execution", "code-execution"),
    "dos": ("denial-of-service", "availability"),
    "exploit": ("poc", "weaponized", "vulnerability"),
    "ghsa": ("vulnerability", "advisory"),
    "high": ("severity-high", "priority"),
    "injection": ("code-execution", "tainted-input"),
    "osv": ("vulnerability", "advisory"),
    "pollution": ("prototype-pollution", "javascript", "object-injection"),
    "rce": ("remote-code-execution", "code-execution"),
    "sqli": ("sql-injection", "injection", "database"),
    "ssrf": ("server-side-request-forgery", "network", "web-vulnerability"),
    "xss": ("cross-site-scripting", "web-vulnerability"),
}

_PHRASE_EXPANSIONS: Mapping[tuple[str, ...], str] = {
    ("access", "control"): "access-control",
    ("code", "execution"): "code-execution",
    ("cross", "site", "scripting"): "cross-site-scripting",
    ("denial", "of", "service"): "denial-of-service",
    ("prototype", "pollution"): "prototype-pollution",
    ("remote", "code", "execution"): "remote-code-execution",
    ("server", "side", "request", "forgery"): "server-side-request-forgery",
    ("sql", "injection"): "sql-injection",
}


class EmbeddingProvider(Protocol):
    """Embeds text into deterministic normalized numeric vectors."""

    @property
    def dimension(self) -> int:
        """Return the number of dimensions produced by this provider."""

    def embed_text(self, text: str) -> Vector:
        """Embed text into a normalized vector."""


class RetrievalError(RuntimeError):
    """Raised when persistent evidence retrieval fails."""

    def __init__(
        self,
        message: str,
        *,
        query: str,
        top_k: int,
        filters: MetadataFilters | None,
    ) -> None:
        self.context = {
            "query": _safe_context_text(query),
            "top_k": top_k,
            "filters": _safe_filters_context(filters),
        }
        super().__init__(f"{message}: {self.context}")


@dataclass(frozen=True)
class DeterministicLocalEmbeddingProvider:
    """Stable lexical embedder for tests and offline retrieval.

    The provider hashes lexical, package-name, and security-domain features into a
    fixed-size signed vector. It is intentionally simple, deterministic, and free
    of network or model dependencies.
    """

    dimension: int = _DEFAULT_DIMENSION

    def __post_init__(self) -> None:
        if self.dimension < _MIN_DIMENSION:
            raise ValueError(f"dimension must be at least {_MIN_DIMENSION}")

    def embed_text(self, text: str) -> Vector:
        features = _extract_features(text)
        vector = [0.0] * self.dimension

        for feature, weight in features.items():
            index, sign = _feature_slot(feature, self.dimension)
            vector[index] += sign * weight

        return normalize_vector(vector)


@dataclass(frozen=True)
class _IndexedChunk:
    chunk: EvidenceChunk
    vector: Vector


class InMemoryEvidenceIndex:
    """Small deterministic evidence index for tests and local RAG workflows."""

    def __init__(self, provider: EmbeddingProvider | None = None) -> None:
        self.provider = provider or DeterministicLocalEmbeddingProvider()
        self._records: list[_IndexedChunk] = []

    def add_chunks(self, chunks: Iterable[EvidenceChunk]) -> None:
        incoming = list(chunks)
        if len(incoming) == 0:
            return

        incoming_ids = {chunk.chunk_id for chunk in incoming}
        self._records = [
            record for record in self._records if record.chunk.chunk_id not in incoming_ids
        ]

        for chunk in incoming:
            self._records.append(
                _IndexedChunk(chunk=chunk, vector=self.provider.embed_text(_chunk_text(chunk)))
            )

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: MetadataFilters | None = None,
    ) -> list[EvidenceSearchResult]:
        if top_k <= 0:
            return []
        if query.strip() == "":
            return []

        query_vector = self.provider.embed_text(query)
        if _is_zero_vector(query_vector):
            return []

        return _rank_records(
            records=self._records,
            query_vector=query_vector,
            top_k=top_k,
            filters=filters,
        )


class SQLAlchemyEmbeddingStore:
    """Adapter for storing deterministic evidence embeddings with app.models.Embedding."""

    def __init__(self, session: object, provider: EmbeddingProvider | None = None) -> None:
        self.session = session
        self.provider = provider or DeterministicLocalEmbeddingProvider()
        self.candidate_limit = _DEFAULT_CANDIDATE_LIMIT

    def add_chunks(self, chunks: Iterable[EvidenceChunk], repo_id: str | None = None) -> None:
        from app.models import Embedding

        rows = []
        for chunk in chunks:
            metadata = dict(chunk.metadata)
            effective_repo_id = repo_id or _string_metadata(metadata, "repo_id")
            if effective_repo_id is not None:
                metadata["repo_id"] = effective_repo_id
            vector = self.provider.embed_text(_chunk_text(chunk))
            rows.append(
                Embedding(
                    repo_id=effective_repo_id,
                    source_type=chunk.source_type,
                    source_id=chunk.chunk_id,
                    content=chunk.content,
                    metadata_json=metadata,
                    embedding=vector_to_pgvector_literal(vector),
                )
            )
        if len(rows) == 0:
            return

        self.session.add_all(rows)

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: MetadataFilters | None = None,
    ) -> list[EvidenceSearchResult]:
        from app.models import Embedding

        if top_k <= 0:
            return []
        if query.strip() == "":
            return []

        query_vector = self.provider.embed_text(query)
        if _is_zero_vector(query_vector):
            return []

        try:
            rows = _search_embedding_rows(
                session=self.session,
                embedding_model=Embedding,
                filters=filters,
                candidate_limit=self.candidate_limit,
            )
        except Exception as exc:
            raise RetrievalError(
                "SQLAlchemy embedding retrieval failed",
                query=query,
                top_k=top_k,
                filters=filters,
            ) from exc

        records: list[_IndexedChunk] = []
        for row in rows:
            metadata = dict(row.metadata_json or {})
            row_repo_id = getattr(row, "repo_id", None)
            if isinstance(row_repo_id, str):
                metadata["repo_id"] = row_repo_id
            chunk = EvidenceChunk(
                chunk_id=row.source_id or row.id,
                source_type=row.source_type,
                content=row.content,
                metadata=metadata,
            )
            vector = self.provider.embed_text(_chunk_text(chunk))
            if row.embedding is not None:
                try:
                    vector = vector_from_pgvector_literal(row.embedding)
                except (AttributeError, TypeError, ValueError):
                    continue
            if len(vector) != len(query_vector):
                continue
            records.append(_IndexedChunk(chunk=chunk, vector=vector))

        return _rank_records(
            records=records,
            query_vector=query_vector,
            top_k=top_k,
            filters=filters,
        )


def _search_embedding_rows(
    session: object,
    embedding_model: object,
    filters: MetadataFilters | None,
    candidate_limit: object,
) -> Sequence[object]:
    limit = _candidate_limit_value(candidate_limit)
    if limit <= 0:
        return []

    query = session.query(embedding_model)
    query = _apply_sqlalchemy_metadata_filters(query, embedding_model, filters)
    return query.limit(limit).all()


def _candidate_limit_value(candidate_limit: object) -> int:
    try:
        limit = int(candidate_limit)
    except (TypeError, ValueError):
        return _DEFAULT_CANDIDATE_LIMIT
    return limit


def _apply_sqlalchemy_metadata_filters(
    query: object,
    embedding_model: object,
    filters: MetadataFilters | None,
) -> object:
    if filters is None:
        return query
    if len(filters) == 0:
        return query

    criteria = []
    for key, expected in filters.items():
        criteria.append(_sqlalchemy_metadata_filter(embedding_model, key, expected))
    return query.filter(*criteria)


def _sqlalchemy_metadata_filter(embedding_model: object, key: str, expected: object) -> object:
    if key == "repo_id":
        return embedding_model.repo_id == expected
    if key == "source_type":
        return embedding_model.source_type == expected
    if key == "chunk_id":
        from sqlalchemy import or_

        return or_(embedding_model.source_id == expected, embedding_model.id == expected)

    metadata_value = embedding_model.metadata_json[key]
    if expected is None:
        return metadata_value.is_(None)
    if isinstance(expected, bool):
        return metadata_value.as_boolean() == expected
    if isinstance(expected, int):
        return metadata_value.as_integer() == expected
    if isinstance(expected, float):
        return metadata_value.as_float() == expected
    return metadata_value.as_string() == str(expected)


def _string_metadata(metadata: Mapping[str, object], key: str) -> str | None:
    value = metadata.get(key)
    if isinstance(value, str):
        return value
    return None


def _safe_filters_context(filters: MetadataFilters | None) -> dict[str, object] | None:
    if filters is None:
        return None
    return {
        str(key): _safe_context_value(value)
        for key, value in filters.items()
    }


def _safe_context_value(value: object) -> object:
    if isinstance(value, str):
        return _safe_context_text(value)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value
    return _safe_context_text(repr(value))


def _safe_context_text(value: str) -> str:
    if len(value) <= _MAX_CONTEXT_TEXT_LENGTH:
        return value
    return value[: _MAX_CONTEXT_TEXT_LENGTH - 3] + "..."


def vector_to_pgvector_literal(vector: Sequence[float]) -> str:
    """Serialize a vector as a pgvector-compatible literal, for example [0.1,0.2]."""

    values: list[str] = []
    for value in vector:
        numeric = float(value)
        if not isfinite(numeric):
            raise ValueError("pgvector literal values must be finite")
        values.append(format(numeric, ".12g"))
    return "[" + ",".join(values) + "]"


def vector_from_pgvector_literal(literal: str) -> Vector:
    """Parse a pgvector-compatible vector literal into floats."""

    stripped = literal.strip()
    if not stripped.startswith("[") or not stripped.endswith("]"):
        raise ValueError("pgvector literal must be wrapped in brackets")

    body = stripped[1:-1].strip()
    if body == "":
        return []

    vector: Vector = []
    for item in body.split(","):
        value_text = item.strip()
        if value_text == "":
            raise ValueError("pgvector literal contains an empty value")
        try:
            value = float(value_text)
        except ValueError as exc:
            raise ValueError(f"invalid pgvector value: {value_text}") from exc
        if not isfinite(value):
            raise ValueError("pgvector literal values must be finite")
        vector.append(value)
    return vector


def normalize_vector(vector: Sequence[float]) -> Vector:
    norm = sqrt(sum(float(value) * float(value) for value in vector))
    if norm == 0.0:
        return [0.0 for _ in vector]
    return [float(value) / norm for value in vector]


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise ValueError("vectors must have the same dimension")
    return sum(float(left_item) * float(right_item) for left_item, right_item in zip(left, right))


def _rank_records(
    records: Sequence[_IndexedChunk],
    query_vector: Sequence[float],
    top_k: int,
    filters: MetadataFilters | None,
) -> list[EvidenceSearchResult]:
    filtered_records = [
        record for record in records if _metadata_matches(record.chunk, filters)
    ]
    scored_results: list[EvidenceSearchResult] = []
    for record in filtered_records:
        score = cosine_similarity(query_vector, record.vector)
        if score <= 0.0:
            continue
        scored_results.append(EvidenceSearchResult(chunk=record.chunk, score=score))

    scored_results.sort(key=lambda result: (-result.score, result.chunk.chunk_id))
    return scored_results[:top_k]


def _chunk_text(chunk: EvidenceChunk) -> str:
    metadata_terms = []
    for key, value in sorted(chunk.metadata.items()):
        metadata_terms.append(str(key))
        metadata_terms.append(str(value))
    return " ".join([chunk.source_type, chunk.content, *metadata_terms])


def _extract_features(text: str) -> dict[str, float]:
    tokens = _tokenize(text)
    features: dict[str, float] = {}

    for token in tokens:
        _add_feature(features, token, 1.0)
        for part in re.split(r"[-_./:]", token):
            if part != "":
                _add_feature(features, part, 0.8)
        for expansion in _SECURITY_EXPANSIONS.get(token, ()):
            _add_feature(features, expansion, 0.9)

    for phrase_tokens, expansion in _PHRASE_EXPANSIONS.items():
        if _contains_phrase(tokens, phrase_tokens):
            _add_feature(features, expansion, 1.5)

    for size in (2, 3):
        for index in range(0, max(len(tokens) - size + 1, 0)):
            phrase = "-".join(tokens[index : index + size])
            _add_feature(features, phrase, 0.6)

    return features


def _tokenize(text: str) -> list[str]:
    return [match.group(0).lower() for match in _TOKEN_RE.finditer(text)]


def _add_feature(features: dict[str, float], feature: str, weight: float) -> None:
    if feature == "":
        return
    features[feature] = features.get(feature, 0.0) + weight


def _contains_phrase(tokens: Sequence[str], phrase: Sequence[str]) -> bool:
    if len(tokens) < len(phrase):
        return False
    for index in range(0, len(tokens) - len(phrase) + 1):
        if list(tokens[index : index + len(phrase)]) == list(phrase):
            return True
    return False


def _feature_slot(feature: str, dimension: int) -> tuple[int, float]:
    digest = blake2b(feature.encode("utf-8"), digest_size=8).digest()
    bucket = int.from_bytes(digest[:4], byteorder="big", signed=False) % dimension
    sign = 1.0 if digest[4] % 2 == 0 else -1.0
    return bucket, sign


def _is_zero_vector(vector: Sequence[float]) -> bool:
    return all(value == 0.0 for value in vector)


def _metadata_matches(chunk: EvidenceChunk, filters: MetadataFilters | None) -> bool:
    if filters is None:
        return True
    for key, expected in filters.items():
        actual = _metadata_value(chunk, key)
        if actual != expected:
            return False
    return True


def _metadata_value(chunk: EvidenceChunk, key: str) -> object:
    if key == "chunk_id":
        return chunk.chunk_id
    if key == "source_type":
        return chunk.source_type
    return chunk.metadata.get(key)
