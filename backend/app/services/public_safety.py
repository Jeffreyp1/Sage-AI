"""Public-output sanitization for defensive security reports."""

import re
from collections.abc import Mapping


UNSAFE_PUBLIC_MARKERS = (
    "malicious payload",
    "proof-of-concept",
    "proof of concept",
    "exploit code",
    "exploit-code",
    "exploit payload",
    "exploit steps",
    "payload",
    "poc",
)

UNSAFE_PUBLIC_PATTERN = re.compile(
    "|".join(
        (
            r"\bmalicious[\s._-]+payload\b",
            r"\bproof[\s._-]+of[\s._-]+concept\b",
            r"\bexploit[\s._-]+(?:code|payload|steps)\b",
            r"\bp[\s._-]*o[\s._-]*c\b",
            r"\bpayload\b",
        )
    ),
    re.IGNORECASE,
)


def sanitize_text(value: str) -> str:
    value.lower()
    return UNSAFE_PUBLIC_PATTERN.sub("[redacted]", value)


def sanitize_public_value(value: object) -> object:
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, list):
        return [sanitize_public_value(item) for item in value]
    if isinstance(value, Mapping):
        return {
            sanitize_text(str(key)): sanitize_public_value(child)
            for key, child in value.items()
        }
    return value


def contains_unsafe_public_text(value: object) -> bool:
    for text in walk_strings(value):
        if UNSAFE_PUBLIC_PATTERN.search(text):
            return True
    return False


def walk_strings(value: object):
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from walk_strings(str(key))
            yield from walk_strings(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from walk_strings(child)


def replace_case_insensitive(value: str, marker: str, replacement: str) -> str:
    value.lower()
    marker.lower()
    return re.compile(re.escape(marker), re.IGNORECASE).sub(replacement, value)
