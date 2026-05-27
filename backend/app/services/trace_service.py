"""Local trace recording for future AI and tool events."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import TypeAlias
from uuid import uuid4

from app.services.public_safety import sanitize_text


JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

REDACTED = "[redacted]"
MAX_TRACE_RECORDS = 1000
SECRET_KEY_ALIASES = (
    "session_id",
    "sessionid",
    "sid",
)
SECRET_KEY_MARKERS = (
    "token",
    "api_key",
    "password",
    "secret",
    "authorization",
    "cookie",
    "session_secret",
)
GITHUB_TOKEN_PATTERN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
)
BEARER_TOKEN_PATTERN = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.IGNORECASE)
TOKEN_KEY_PATTERN = r"(?:token|[A-Za-z][A-Za-z0-9_-]*(?:[_-]token|Token))"
COOKIE_SECRET_NAME_PATTERN = (
    r"(?:session(?:id)?|session[_-]?secret|sid|csrf[_-]?token|csrftoken|"
    r"xsrf[_-]?token|auth(?:entication)?[_-]?token|access[_-]?token|"
    r"refresh[_-]?token|%s)"
) % TOKEN_KEY_PATTERN
AUTHORIZATION_FRAGMENT_PATTERN = re.compile(
    r"(?P<prefix>\bauthorization\b\s*[:=]\s*)"
    r"(?P<secret>(?:Bearer|Basic|Digest|Token)\s+[A-Za-z0-9._~+/=-]+|[^\s,;]+)",
    re.IGNORECASE,
)
COOKIE_SECRET_FRAGMENT_PATTERN = re.compile(
    r"(?P<prefix>\bcookie\b\s*[:=]\s*)"
    r"%s\s*=\s*[^\s,;]+" % COOKIE_SECRET_NAME_PATTERN,
    re.IGNORECASE,
)
COOKIE_SECRET_PAIR_PATTERN = re.compile(
    r"(?P<prefix>(?:^|[;,]\s*)%s\s*=\s*)" % COOKIE_SECRET_NAME_PATTERN
    + r"(?P<secret>[^\s,;]+)",
    re.IGNORECASE,
)
INLINE_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?P<prefix>\b(?:password|api[_-]?key|session[_-]?id|sid|"
    r"session[_-]?secret|%s)\b\s*[:=]\s*)"
    % TOKEN_KEY_PATTERN
    + r"(?P<secret>[^\s,;&]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class TraceRecord:
    trace_id: str
    agent_name: str
    event_type: str
    input_json: JsonValue = field(default_factory=dict)
    retrieved_context_json: JsonValue = field(default_factory=list)
    output_json: JsonValue = field(default_factory=dict)
    model: str | None = None
    latency_ms: int | None = None
    token_count: int | None = None
    cost_usd: float | None = None
    validation_status: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "trace_id": self.trace_id,
            "agent_name": self.agent_name,
            "event_type": self.event_type,
            "input_json": copy.deepcopy(self.input_json),
            "retrieved_context_json": copy.deepcopy(self.retrieved_context_json),
            "output_json": copy.deepcopy(self.output_json),
            "model": self.model,
            "latency_ms": self.latency_ms,
            "token_count": self.token_count,
            "cost_usd": self.cost_usd,
            "validation_status": self.validation_status,
        }


class TraceService:
    """In-memory trace recorder with deterministic redaction boundaries."""

    def __init__(self) -> None:
        self._records: list[TraceRecord] = []

    def record_event(
        self,
        *,
        agent_name: str,
        event_type: str,
        input_json: object | None = None,
        retrieved_context_json: object | None = None,
        output_json: object | None = None,
        model: str | None = None,
        latency_ms: int | None = None,
        token_count: int | None = None,
        cost_usd: float | None = None,
        validation_status: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, object]:
        record = TraceRecord(
            trace_id=trace_id or str(uuid4()),
            agent_name=agent_name,
            event_type=event_type,
            input_json=redact_trace_value(input_json if input_json is not None else {}),
            retrieved_context_json=redact_trace_value(
                retrieved_context_json if retrieved_context_json is not None else []
            ),
            output_json=redact_trace_value(output_json if output_json is not None else {}),
            model=model,
            latency_ms=latency_ms,
            token_count=token_count,
            cost_usd=cost_usd,
            validation_status=validation_status,
        )
        self._evict_records_before_append()
        self._records.append(record)
        return record.to_dict()

    def list_records(self) -> list[dict[str, object]]:
        return [record.to_dict() for record in self._records]

    def clear(self) -> None:
        self._records.clear()

    def _evict_records_before_append(self) -> None:
        if len(self._records) < MAX_TRACE_RECORDS:
            return
        records_to_remove = len(self._records) - MAX_TRACE_RECORDS + 1
        del self._records[:records_to_remove]


def redact_trace_value(value: object) -> JsonValue:
    if isinstance(value, str):
        return sanitize_text(redact_secret_text(value))
    if isinstance(value, bool | int | float) or value is None:
        return value
    if isinstance(value, list | tuple):
        redacted_items: list[JsonValue] = []
        for item in value:
            redacted_items.append(redact_trace_value(item))
        return redacted_items
    if isinstance(value, dict):
        redacted_mapping: dict[str, JsonValue] = {}
        for key, child in value.items():
            normalized_key = str(key)
            if is_secret_key(normalized_key):
                redacted_mapping[sanitize_text(normalized_key)] = REDACTED
                continue
            redacted_mapping[sanitize_text(normalized_key)] = redact_trace_value(child)
        return redacted_mapping
    return sanitize_text(str(value))


def is_secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    compact = normalized.replace("_", "")
    if normalized in SECRET_KEY_ALIASES or compact in SECRET_KEY_ALIASES:
        return True
    for marker in SECRET_KEY_MARKERS:
        if marker in normalized or marker.replace("_", "") in compact:
            return True
    return False


def redact_secret_text(value: str) -> str:
    redacted = GITHUB_TOKEN_PATTERN.sub(REDACTED, value)
    redacted = BEARER_TOKEN_PATTERN.sub(REDACTED, redacted)
    redacted = AUTHORIZATION_FRAGMENT_PATTERN.sub(
        lambda match: "%s%s" % (match.group("prefix"), REDACTED),
        redacted,
    )
    redacted = COOKIE_SECRET_PAIR_PATTERN.sub(
        lambda match: "%s%s" % (match.group("prefix"), REDACTED),
        redacted,
    )
    redacted = COOKIE_SECRET_FRAGMENT_PATTERN.sub(
        lambda match: "%s%s" % (match.group("prefix"), REDACTED),
        redacted,
    )
    return INLINE_SECRET_ASSIGNMENT_PATTERN.sub(
        lambda match: "%s%s" % (match.group("prefix"), REDACTED),
        redacted,
    )
