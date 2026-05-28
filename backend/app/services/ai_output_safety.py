"""Safety checks for client-provided AI output."""

from collections.abc import Mapping

from app.ai.contracts import UNSAFE_RESPONSE_MARKERS, unsafe_marker_found


def unsafe_client_output_markers(value: Mapping[str, object]) -> list[str]:
    text = "\n".join(client_generated_strings(value)).lower()
    markers: list[str] = []
    for marker in UNSAFE_RESPONSE_MARKERS:
        if unsafe_marker_found(marker, text):
            markers.append(marker)
    return markers


def client_generated_strings(value: Mapping[str, object]) -> list[str]:
    strings: list[str] = []
    for key in ("summary", "explanation", "errors"):
        strings.extend(strings_from_value(value.get(key)))

    for citation in list_value(value.get("citations")):
        citation_mapping = mapping_value(citation)
        strings.extend(strings_from_value(citation_mapping.get("quote")))
        strings.extend(strings_from_value(citation_mapping.get("note")))

    for claim_check in list_value(value.get("claim_checks")):
        claim_mapping = mapping_value(claim_check)
        strings.extend(strings_from_value(claim_mapping.get("claim")))
        strings.extend(strings_from_value(claim_mapping.get("rationale")))

    return strings


def strings_from_value(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        strings: list[str] = []
        for item in value:
            strings.extend(strings_from_value(item))
        return strings
    return []


def mapping_value(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def list_value(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return []
