"""Public-output sanitization for defensive security reports."""

from collections.abc import Mapping


UNSAFE_PUBLIC_MARKERS = (
    "malicious payload",
    "proof-of-concept",
    "exploit payload",
    "exploit steps",
    "payload",
    "poc",
)


def sanitize_text(value: str) -> str:
    sanitized = value
    for marker in UNSAFE_PUBLIC_MARKERS:
        sanitized = replace_case_insensitive(sanitized, marker, "[redacted]")
    return sanitized


def sanitize_public_value(value: object) -> object:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_public_value(item) for item in value]
    if isinstance(value, Mapping):
        return {str(key): sanitize_public_value(child) for key, child in value.items()}
    return value


def contains_unsafe_public_text(value: object) -> bool:
    for text in walk_strings(value):
        lowered = text.lower()
        if any(marker in lowered for marker in UNSAFE_PUBLIC_MARKERS):
            return True
    return False


def walk_strings(value: object):
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for child in value.values():
            yield from walk_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from walk_strings(child)


def replace_case_insensitive(value: str, marker: str, replacement: str) -> str:
    lowered = value.lower()
    marker_lowered = marker.lower()
    start = lowered.find(marker_lowered)
    if start == -1:
        return value
    end = start + len(marker)
    return (
        value[:start]
        + replacement
        + replace_case_insensitive(value[end:], marker, replacement)
    )
