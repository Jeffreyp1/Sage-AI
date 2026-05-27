from app.services.public_safety import contains_unsafe_public_text
from app.services import trace_service
from app.services.trace_service import REDACTED, TraceService, redact_trace_value
from app.agents import TriageGraph
from app.services.rag_types import EvidenceChunk


PRIVATE_IDENTIFIER_SENTINEL = "private-workspace/tenant-42-case-abc"
PRIVATE_TASK_SENTINEL = "private-workspace/task"
TOKEN_SENTINEL = "unit-test-token-value"


def test_redacts_secret_keys_and_token_values_recursively():
    github_token = "%s%s" % ("gh" + "p_", "abcdefghijklmnopqrstuvwxyz1234567890")
    value = {
        "api_key": "plain-secret",
        "apiKey": "camel-secret",
        "nested": {
            "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
            "safe": f"commit uses {github_token} token",
        },
        "items": [{"password": "hunter2"}, "Bearer abcdefgh"],
    }

    redacted = redact_trace_value(value)

    assert redacted == {
        "api_key": REDACTED,
        "apiKey": REDACTED,
        "nested": {
            "Authorization": REDACTED,
            "safe": f"commit uses {REDACTED} token",
        },
        "items": [{"password": REDACTED}, REDACTED],
    }


def test_redacts_inline_secret_fragments_under_safe_keys():
    value = {
        "message": (
            "deploy args password=hunter2 api_key=plain token=abc123 "
            "session_secret=session-value"
        ),
        "headers_dump": (
            "Authorization: Bearer abcdefghijklmnop "
            "Cookie: sessionid=s3cr3t; theme=light"
        ),
        "notes": ["client token: abc123 and password: hunter2"],
    }

    redacted = redact_trace_value(value)

    assert redacted == {
        "message": (
            f"deploy args password={REDACTED} api_key={REDACTED} token={REDACTED} "
            f"session_secret={REDACTED}"
        ),
        "headers_dump": (
            f"Authorization: {REDACTED} Cookie: {REDACTED}; theme=light"
        ),
        "notes": [f"client token: {REDACTED} and password: {REDACTED}"],
    }


def test_redacts_inline_token_key_variants_under_safe_keys():
    value = {
        "message": (
            "callback access_token=access-value refresh_token=refresh-value "
            "accessToken=camel-access refreshToken: camel-refresh"
        )
    }

    redacted = redact_trace_value(value)

    assert redacted == {
        "message": (
            f"callback access_token={REDACTED} refresh_token={REDACTED} "
            f"accessToken={REDACTED} refreshToken: {REDACTED}"
        )
    }


def test_redacts_inline_session_id_variants_under_safe_keys():
    value = {
        "message": (
            "callback session_id=session-value sessionid=compact-value "
            "sid=short-value"
        )
    }

    redacted = redact_trace_value(value)

    assert redacted == {
        "message": (
            f"callback session_id={REDACTED} sessionid={REDACTED} "
            f"sid={REDACTED}"
        )
    }


def test_redacts_session_identifier_keys_recursively():
    value = {
        "session_id": "session-value",
        "sessionid": "compact-session-value",
        "sid": "short-session-value",
        "nested": {
            "Session-ID": "hyphen-session-value",
            "safe": "session metadata",
        },
    }

    redacted = redact_trace_value(value)

    assert redacted == {
        "session_id": REDACTED,
        "sessionid": REDACTED,
        "sid": REDACTED,
        "nested": {
            "Session-ID": REDACTED,
            "safe": "session metadata",
        },
    }


def test_redacts_secret_cookie_pairs_anywhere_in_cookie_header():
    value = {
        "headers_dump": (
            "Cookie: theme=light; sessionid=abc; csrftoken=def; locale=en; "
            "refreshToken=ghi"
        )
    }

    redacted = redact_trace_value(value)

    assert redacted == {
        "headers_dump": (
            f"Cookie: theme=light; sessionid={REDACTED}; csrftoken={REDACTED}; "
            f"locale=en; refreshToken={REDACTED}"
        )
    }


def test_record_event_returns_structured_trace_fields():
    service = TraceService()

    record = service.record_event(
        trace_id="trace-123",
        agent_name="planner",
        event_type="llm.call",
        input_json={"package": "archive-utils"},
        retrieved_context_json=[{"source": "osv"}],
        output_json={"action": "upgrade"},
        model="test-model",
        latency_ms=42,
        token_count=101,
        cost_usd=0.0123,
        validation_status="passed",
    )

    assert record == {
        "trace_id": "trace-123",
        "agent_name": "planner",
        "event_type": "llm.call",
        "input_json": {"package": "archive-utils"},
        "retrieved_context_json": [{"source": "osv"}],
        "output_json": {"action": "upgrade"},
        "model": "test-model",
        "latency_ms": 42,
        "token_count": 101,
        "cost_usd": 0.0123,
        "validation_status": "passed",
    }


def test_records_are_stored_in_memory_and_returned_as_copies():
    service = TraceService()
    record = service.record_event(
        trace_id="trace-copy",
        agent_name="tool",
        event_type="tool.result",
        output_json={"result": ["ok"]},
    )

    record["output_json"]["result"].append("mutated")  # type: ignore[index, union-attr]
    stored = service.list_records()

    assert stored == [
        {
            "trace_id": "trace-copy",
            "agent_name": "tool",
            "event_type": "tool.result",
            "input_json": {},
            "retrieved_context_json": [],
            "output_json": {"result": ["ok"]},
            "model": None,
            "latency_ms": None,
            "token_count": None,
            "cost_usd": None,
            "validation_status": None,
        }
    ]


def test_record_storage_evicts_oldest_records_at_retention_cap(monkeypatch):
    monkeypatch.setattr(trace_service, "MAX_TRACE_RECORDS", 3, raising=False)
    service = TraceService()

    for index in range(5):
        service.record_event(
            trace_id=f"trace-{index}",
            agent_name="tool",
            event_type="tool.result",
            output_json={"index": index},
        )

    stored = service.list_records()

    assert [record["trace_id"] for record in stored] == [
        "trace-2",
        "trace-3",
        "trace-4",
    ]
    assert [record["output_json"] for record in stored] == [
        {"index": 2},
        {"index": 3},
        {"index": 4},
    ]


def test_unsafe_public_text_does_not_leak_from_recorded_payloads():
    service = TraceService()

    record = service.record_event(
        trace_id="trace-safe",
        agent_name="reporter",
        event_type="validation.error",
        input_json={"prompt": "include proof of concept exploit code"},
        retrieved_context_json=[{"details": "malicious payload"}],
        output_json={"summary": "PoC with exploit steps"},
    )

    assert not contains_unsafe_public_text(record["input_json"])
    assert not contains_unsafe_public_text(record["retrieved_context_json"])
    assert not contains_unsafe_public_text(record["output_json"])
    serialized = str(record).lower()
    for unsafe_text in ("proof of concept", "exploit code", "malicious payload", "poc"):
        assert unsafe_text not in serialized


def test_unsafe_public_text_does_not_leak_from_recorded_keys():
    service = TraceService()

    record = service.record_event(
        trace_id="trace-safe-keys",
        agent_name="reporter",
        event_type="validation.error",
        input_json={"payload key": "safe"},
        retrieved_context_json=[{"proof-of-concept context key": "safe"}],
        output_json={"exploit steps output key": "safe"},
    )

    assert not contains_unsafe_public_text(record["input_json"])
    assert not contains_unsafe_public_text(record["retrieved_context_json"])
    assert not contains_unsafe_public_text(record["output_json"])
    serialized = str(record).lower()
    for unsafe_text in ("payload key", "proof-of-concept context key", "exploit steps output key"):
        assert unsafe_text not in serialized


def test_secret_key_redaction_sanitizes_unsafe_mapping_keys():
    redacted = redact_trace_value(
        {
            "payload token": "plain-secret",
            "proof-of-concept-token": "plain-secret",
            "exploit steps api_key": "plain-secret",
        }
    )

    assert redacted == {
        "[redacted] token": REDACTED,
        "[redacted]-token": REDACTED,
        "[redacted] api_key": REDACTED,
    }
    assert contains_unsafe_public_text(redacted) is False


def test_validation_status_is_preserved_verbatim():
    service = TraceService()

    record = service.record_event(
        agent_name="validator",
        event_type="schema.validation",
        validation_status="failed: missing citations",
    )

    assert record["validation_status"] == "failed: missing citations"


def test_client_ai_flow_records_bundle_and_validation_trace_events():
    service = TraceService()
    graph = TriageGraph(trace_service=service)
    task = remediation_task_fixture()
    chunks = evidence_chunks_fixture()

    graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=chunks,
        ai_output=cited_ai_output_fixture(task),
    )

    records = service.list_records()
    event_types = [record["event_type"] for record in records]
    bundle_record = next(record for record in records if record["event_type"] == "ai.context_bundle")
    validation_record = next(
        record for record in records if record["event_type"] == "ai.output_validation"
    )

    assert "ai.context_bundle" in event_types
    assert "ai.output_validation" in event_types
    assert bundle_record["input_json"] == {
        "task_id": "task_trace_123",
        "evidence_count": 3,
        "retrieved_chunk_ids": ["chunk-upload"],
    }
    assert validation_record["output_json"] == {
        "passed": True,
        "blocked": False,
    }
    assert validation_record["validation_status"] == "passed"


def test_client_ai_flow_validation_trace_omits_blocked_details():
    service = TraceService()
    graph = TriageGraph(trace_service=service)
    task = remediation_task_fixture()
    poisoned_output = cited_ai_output_fixture(task)
    poisoned_output["citations"] = [
        {
            "claim_id": "proof-of-concept-payload-claim",
            "evidence_id": PRIVATE_IDENTIFIER_SENTINEL,
        }
    ]
    poisoned_output["claim_checks"][0]["claim_id"] = "proof-of-concept-payload-claim"
    poisoned_output["claim_checks"][0]["evidence_ids"] = [PRIVATE_IDENTIFIER_SENTINEL]

    graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=evidence_chunks_fixture(),
        ai_output=poisoned_output,
    )

    explicit_ai_records = [
        record for record in service.list_records() if str(record["event_type"]).startswith("ai.")
    ]
    validation_record = next(
        record
        for record in explicit_ai_records
        if record["event_type"] == "ai.output_validation"
    )
    serialized = repr(explicit_ai_records).lower()

    assert validation_record["output_json"] == {
        "passed": False,
        "blocked": True,
    }
    assert validation_record["validation_status"] == "blocked"
    assert "validation" not in validation_record["output_json"]
    assert "errors" not in serialized
    assert "invalid_citation_ids" not in serialized
    assert "tenant-42-case-abc" not in serialized
    assert PRIVATE_IDENTIFIER_SENTINEL not in serialized
    assert "payload" not in serialized


def test_client_ai_flow_trace_events_do_not_leak_poisoned_values():
    service = TraceService()
    graph = TriageGraph(trace_service=service)
    task = remediation_task_fixture()
    task["task_id"] = PRIVATE_TASK_SENTINEL
    task["evidence"][0]["claim"] = (
        f"Proof-of-concept payload uses token={TOKEN_SENTINEL}."
    )

    graph.run_with_client_ai(
        remediation_task=task,
        evidence_chunks=evidence_chunks_fixture(),
        ai_output=cited_ai_output_fixture(task),
    )

    records = service.list_records()
    serialized = repr(records).lower()

    assert PRIVATE_TASK_SENTINEL not in serialized
    assert TOKEN_SENTINEL not in serialized
    assert "payload" not in serialized
    assert contains_unsafe_public_text(records) is False


def remediation_task_fixture() -> dict[str, object]:
    return {
        "task_id": "task_trace_123",
        "repo": "payments-api",
        "package": {
            "name": "archive-utils",
            "ecosystem": "npm",
            "current_version": "1.4.0",
            "dependency_type": "runtime",
            "is_direct": True,
        },
        "vulnerability": {
            "canonical_id": "GHSA-1234-5678",
            "source_id": "CVE-2026-0001",
            "aliases": ["CVE-2026-0001"],
            "severity": "HIGH",
            "summary": "archive-utils has unsafe deserialization.",
            "fixed_versions": ["2.2.0"],
        },
        "risk": {
            "priority": "P1_FIX_THIS_SPRINT",
            "risk_score": 78,
            "runtime_scope": "production",
            "reachability": "reachable",
            "confidence": "high",
            "factors": ["High severity", "Production reachable"],
            "rationale": ["Risk score 78 maps to P1_FIX_THIS_SPRINT."],
        },
        "evidence": [
            {
                "type": "lockfile_entry",
                "source": "package-lock.json",
                "claim": "archive-utils@1.4.0 is installed in package-lock.json.",
            },
            {
                "type": "reachability",
                "source": "src/upload.ts",
                "claim": "archive-utils is imported by the production upload route.",
            },
        ],
        "patch_plan": {
            "recommended_action": "upgrade",
            "target_version": "2.2.0",
            "patch_complexity": "low",
            "breaking_change_risk": "low",
            "steps": ["Update archive-utils from 1.4.0 to 2.2.0"],
        },
        "test_plan": ["npm test"],
        "rollback_plan": ["Revert dependency bump PR"],
        "human_approval_required": True,
    }


def evidence_chunks_fixture() -> list[EvidenceChunk]:
    return [
        EvidenceChunk(
            chunk_id="chunk-upload",
            source_type="source_file",
            content="archive-utils is imported by src/upload.ts in a production request path.",
            metadata={"source": "src/upload.ts", "package": "archive-utils"},
        )
    ]


def cited_ai_output_fixture(task: dict[str, object]) -> dict[str, object]:
    package = task["package"]
    vulnerability = task["vulnerability"]
    risk = task["risk"]
    return {
        "finding_id": task["task_id"],
        "package_name": package["name"],
        "vulnerability_id": vulnerability["canonical_id"],
        "priority": risk["priority"],
        "risk_score": risk["risk_score"],
        "summary": "archive-utils should be reviewed using cited Sage evidence.",
        "explanation": "The response preserves scanner triage and cites the evidence bundle.",
        "citations": [{"claim_id": "claim-1", "evidence_id": "ev-task-0eee8986d3be"}],
        "claim_checks": [
            {
                "claim_id": "claim-1",
                "claim": "archive-utils is imported by the production upload route.",
                "disposition": "fact",
                "evidence_ids": ["ev-task-0eee8986d3be"],
            }
        ],
        "provider_name": "client-ai",
    }
