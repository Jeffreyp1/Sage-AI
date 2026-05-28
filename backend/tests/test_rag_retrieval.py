from dataclasses import dataclass
from math import isclose, sqrt

import pytest

from app.services import rag_retrieval
from app.services.rag_retrieval import (
    DeterministicLocalEmbeddingProvider,
    InMemoryEvidenceIndex,
    PGVECTOR_DIMENSION,
    SQLAlchemyEmbeddingStore,
    vector_from_pgvector_literal,
    vector_to_pgvector_literal,
)
from app.services.rag_types import EvidenceChunk


def sample_chunks() -> list[EvidenceChunk]:
    return [
        EvidenceChunk(
            chunk_id="adv-rce",
            source_type="advisory",
            content=(
                "GHSA advisory for archive-utils: critical CVE remote code execution "
                "through unsafe deserialization. Fixed in 2.2.0."
            ),
            metadata={
                "repo_id": "payments-api",
                "ecosystem": "npm",
                "package": "archive-utils",
                "path": "package-lock.json",
                "line_start": 42,
            },
        ),
        EvidenceChunk(
            chunk_id="adv-xss",
            source_type="advisory",
            content=(
                "Cross site scripting in frontend-widget allows stored XSS in rendered "
                "profile names."
            ),
            metadata={
                "repo_id": "web-app",
                "ecosystem": "npm",
                "package": "frontend-widget",
                "path": "yarn.lock",
            },
        ),
        EvidenceChunk(
            chunk_id="reachability-test",
            source_type="reachability",
            content="The package is only imported by a test helper and is not in production paths.",
            metadata={
                "repo_id": "payments-api",
                "ecosystem": "npm",
                "package": "test-helper",
                "path": "tests/helpers.py",
            },
        ),
        EvidenceChunk(
            chunk_id="license",
            source_type="manifest",
            content="The project declares an MIT license and Python packaging metadata.",
            metadata={
                "repo_id": "docs",
                "ecosystem": "pypi",
                "package": "docs-site",
                "path": "pyproject.toml",
            },
        ),
    ]


def test_deterministic_vectors_are_stable_and_normalized() -> None:
    first_provider = DeterministicLocalEmbeddingProvider()
    second_provider = DeterministicLocalEmbeddingProvider()

    first_vector = first_provider.embed_text("archive-utils remote code execution CVE")
    second_vector = first_provider.embed_text("archive-utils remote code execution CVE")
    third_vector = second_provider.embed_text("archive-utils remote code execution CVE")

    assert first_vector == second_vector
    assert first_vector == third_vector
    assert len(first_vector) == first_provider.dimension
    assert isclose(sqrt(sum(value * value for value in first_vector)), 1.0)


def test_search_returns_top_k_sorted_by_relevance() -> None:
    index = InMemoryEvidenceIndex()
    index.add_chunks(sample_chunks())

    results = index.search("archive-utils rce remote code execution exploit", top_k=2)

    assert results[0].chunk.chunk_id == "adv-rce"
    assert len(results) <= 2
    assert results == sorted(results, key=lambda result: (-result.score, result.chunk.chunk_id))


def test_search_supports_metadata_filters() -> None:
    index = InMemoryEvidenceIndex()
    index.add_chunks(sample_chunks())

    results = index.search("remote code execution", filters={"repo_id": "payments-api"})
    filtered_out = index.search("remote code execution", filters={"ecosystem": "maven"})
    source_filtered = index.search("remote code execution", filters={"source_type": "advisory"})

    assert results[0].chunk.chunk_id == "adv-rce"
    assert {result.chunk.metadata["repo_id"] for result in results} == {"payments-api"}
    assert filtered_out == []
    assert source_filtered[0].chunk.chunk_id == "adv-rce"


def test_empty_query_returns_no_results() -> None:
    index = InMemoryEvidenceIndex()
    index.add_chunks(sample_chunks())

    assert index.search("") == []
    assert index.search("   ") == []
    assert index.search("remote code execution", top_k=0) == []


def test_pgvector_literal_roundtrip() -> None:
    vector = [0.1, -0.25, 1.0 / 3.0, 2.5]

    literal = vector_to_pgvector_literal(vector)
    parsed = vector_from_pgvector_literal(literal)

    assert literal == "[0.1,-0.25,0.333333333333,2.5]"
    assert parsed == pytest.approx(vector)


@pytest.mark.parametrize("literal", ["0.1,0.2", "[0.1,,0.2]", "[nan]", "[inf]"])
def test_pgvector_literal_rejects_invalid_values(literal: str) -> None:
    with pytest.raises(ValueError):
        vector_from_pgvector_literal(literal)


def test_source_metadata_is_preserved_in_search_results() -> None:
    source_chunk = sample_chunks()[0]
    index = InMemoryEvidenceIndex()
    index.add_chunks([source_chunk])

    result = index.search("archive-utils critical CVE")[0]

    assert result.chunk == source_chunk
    assert result.chunk.metadata["path"] == "package-lock.json"
    assert result.to_dict()["metadata"]["line_start"] == 42


class UnitEmbeddingProvider:
    dimension = 3

    def embed_text(self, text: str) -> list[float]:
        if "frontend-widget" in text:
            return [0.0, 1.0, 0.0]
        return [1.0, 0.0, 0.0]


@dataclass
class FakeEmbeddingRow:
    id: str
    repo_id: str | None
    source_id: str | None
    source_type: str
    content: str
    metadata_json: dict[str, object] | None
    embedding: str | None


class FakeQuery:
    def __init__(
        self,
        rows: list[FakeEmbeddingRow],
        events: list[str],
        failure: Exception | None = None,
    ) -> None:
        self._rows = rows
        self._events = events
        self._failure = failure
        self.filter_call_count = 0
        self.limit_value: int | None = None
        self.all_seen_limit: int | None = None

    def filter(self, *criteria: object) -> "FakeQuery":
        self.filter_call_count += len(criteria)
        self._events.append("filter")
        return self

    def limit(self, value: int) -> "FakeQuery":
        self.limit_value = value
        self._events.append("limit")
        return self

    def all(self) -> list[FakeEmbeddingRow]:
        self.all_seen_limit = self.limit_value
        self._events.append("all")
        if self._failure is not None:
            raise self._failure
        if self.limit_value is None:
            return list(self._rows)
        return list(self._rows[: self.limit_value])


class FakeSession:
    def __init__(
        self,
        rows: list[FakeEmbeddingRow],
        failure: Exception | None = None,
    ) -> None:
        self.events: list[str] = []
        self.query_object = FakeQuery(rows=rows, events=self.events, failure=failure)

    def query(self, model: object) -> FakeQuery:
        self.events.append("query")
        return self.query_object


class FakeWriteSession:
    def __init__(self) -> None:
        self.rows: list[object] = []

    def add_all(self, rows: list[object]) -> None:
        self.rows.extend(rows)


def test_default_sqlalchemy_store_writes_pgvector_schema_dimension_and_repo_metadata() -> None:
    session = FakeWriteSession()
    store = SQLAlchemyEmbeddingStore(session=session)
    chunk = EvidenceChunk(
        chunk_id="chunk-1",
        source_type="source_file",
        content="archive-utils upload parser",
        metadata={"file_path": "src/upload.ts"},
    )

    store.add_chunks([chunk], repo_id="payments-api")

    assert len(session.rows) == 1
    row = session.rows[0]
    assert row.repo_id == "payments-api"
    assert row.metadata_json["repo_id"] == "payments-api"
    assert len(vector_from_pgvector_literal(row.embedding)) == PGVECTOR_DIMENSION


def test_sqlalchemy_store_uses_chunk_repo_id_when_no_repo_id_argument_is_given() -> None:
    session = FakeWriteSession()
    store = SQLAlchemyEmbeddingStore(session=session, provider=UnitEmbeddingProvider())
    chunk = EvidenceChunk(
        chunk_id="chunk-1",
        source_type="source_file",
        content="archive-utils upload parser",
        metadata={"repo_id": "payments-api", "file_path": "src/upload.ts"},
    )

    store.add_chunks([chunk])

    row = session.rows[0]
    assert row.repo_id == "payments-api"
    assert row.metadata_json["repo_id"] == "payments-api"


def test_sqlalchemy_search_applies_filters_and_candidate_limit_before_all() -> None:
    rows = [
        FakeEmbeddingRow(
            id="row-1",
            repo_id="payments-api",
            source_id="adv-rce",
            source_type="advisory",
            content="archive-utils remote code execution",
            metadata_json={"repo_id": "payments-api", "package": "archive-utils"},
            embedding="[1,0,0]",
        ),
        FakeEmbeddingRow(
            id="row-2",
            repo_id="payments-api",
            source_id="reachability",
            source_type="reachability",
            content="archive-utils is reachable in production",
            metadata_json={"repo_id": "payments-api", "package": "archive-utils"},
            embedding="[1,0,0]",
        ),
        FakeEmbeddingRow(
            id="row-3",
            repo_id="web-app",
            source_id="adv-xss",
            source_type="advisory",
            content="frontend-widget cross site scripting",
            metadata_json={"repo_id": "web-app", "package": "frontend-widget"},
            embedding="[0,1,0]",
        ),
    ]
    session = FakeSession(rows)
    store = SQLAlchemyEmbeddingStore(session=session, provider=UnitEmbeddingProvider())
    store.candidate_limit = 2

    results = store.search(
        "archive-utils remote code execution",
        top_k=5,
        filters={"source_type": "advisory", "repo_id": "payments-api"},
    )

    assert [result.chunk.chunk_id for result in results] == ["adv-rce"]
    assert session.query_object.filter_call_count == 2
    assert session.query_object.all_seen_limit == 2
    assert session.events.index("filter") < session.events.index("all")
    assert session.events.index("limit") < session.events.index("all")


def test_sqlalchemy_search_reconstructs_repo_id_from_database_column() -> None:
    rows = [
        FakeEmbeddingRow(
            id="row-1",
            repo_id="payments-api",
            source_id="adv-rce",
            source_type="advisory",
            content="archive-utils remote code execution",
            metadata_json={"package": "archive-utils"},
            embedding="[1,0,0]",
        ),
    ]
    session = FakeSession(rows)
    store = SQLAlchemyEmbeddingStore(session=session, provider=UnitEmbeddingProvider())

    results = store.search(
        "archive-utils remote code execution",
        top_k=1,
        filters={"repo_id": "payments-api"},
    )

    assert [result.chunk.chunk_id for result in results] == ["adv-rce"]
    assert results[0].chunk.metadata["repo_id"] == "payments-api"


def test_sqlalchemy_search_skips_bad_stored_vectors_and_returns_valid_row() -> None:
    rows = [
        FakeEmbeddingRow(
            id="row-bad-literal",
            repo_id="payments-api",
            source_id="bad-literal",
            source_type="advisory",
            content="archive-utils bad literal",
            metadata_json={"repo_id": "payments-api"},
            embedding="[not-a-number]",
        ),
        FakeEmbeddingRow(
            id="row-bad-dimension",
            repo_id="payments-api",
            source_id="bad-dimension",
            source_type="advisory",
            content="archive-utils wrong dimension",
            metadata_json={"repo_id": "payments-api"},
            embedding="[1,0]",
        ),
        FakeEmbeddingRow(
            id="row-valid",
            repo_id="payments-api",
            source_id="valid",
            source_type="advisory",
            content="archive-utils remote code execution",
            metadata_json={"repo_id": "payments-api"},
            embedding="[1,0,0]",
        ),
    ]
    session = FakeSession(rows)
    store = SQLAlchemyEmbeddingStore(session=session, provider=UnitEmbeddingProvider())

    results = store.search("archive-utils remote code execution", top_k=3)

    assert [result.chunk.chunk_id for result in results] == ["valid"]


def test_sqlalchemy_search_wraps_database_failures_with_context() -> None:
    retrieval_error = getattr(rag_retrieval, "RetrievalError", None)
    assert retrieval_error is not None
    sensitive_query = "archive-utils " + ("remote-code-execution " * 20)
    filters = {"repo_id": "payments-api", "package": "archive-utils"}
    session = FakeSession(rows=[], failure=RuntimeError("database connection dropped"))
    store = SQLAlchemyEmbeddingStore(session=session, provider=UnitEmbeddingProvider())

    with pytest.raises(retrieval_error) as exc_info:
        store.search(sensitive_query, top_k=3, filters=filters)

    error = exc_info.value
    assert error.context["query"].endswith("...")
    assert error.context["top_k"] == 3
    assert error.context["filters"] == filters
    assert "remote-code-execution " * 10 not in str(error)
    assert isinstance(error.__cause__, RuntimeError)
