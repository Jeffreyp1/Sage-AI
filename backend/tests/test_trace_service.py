from app.services.public_safety import contains_unsafe_public_text
from app.services.trace_service import REDACTED, TraceService, redact_trace_value


def test_redacts_secret_keys_and_token_values_recursively():
    value = {
        "api_key": "plain-secret",
        "apiKey": "camel-secret",
        "nested": {
            "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz",
            "safe": "commit uses ghp_abcdefghijklmnopqrstuvwxyz1234567890 token",
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


def test_validation_status_is_preserved_verbatim():
    service = TraceService()

    record = service.record_event(
        agent_name="validator",
        event_type="schema.validation",
        validation_status="failed: missing citations",
    )

    assert record["validation_status"] == "failed: missing citations"
