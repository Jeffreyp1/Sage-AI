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
IDENTIFIER_UNSAFE_PUBLIC_PATTERN = re.compile(
    "|".join(
        (
            r"\bmalicious[\s._-]+payload\b",
            r"\bproof[\s._-]+of[\s._-]+concept\b",
            r"\bexploit[\s._-]+(?:code|payload|steps)\b",
            r"\bp[\s._-]*o[\s._-]*c\b",
        )
    ),
    re.IGNORECASE,
)
SECRET_LIKE_NAME_MARKERS = (
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private",
)
SAFE_PUBLIC_IDENTIFIER_NAMES = {
    "token_count",
}
SECRET_IDENTIFIER_PATTERN = re.compile(
    r"^(?:token|secret|password|api[_-]?key|apikey|authorization|cookie|private)"
    r"(?:[._-][A-Za-z0-9._-]+)?$",
    re.IGNORECASE,
)
LOCAL_PATH_PATTERN = re.compile(
    r"(?<![\w])(?:/(?:Users|home|private|tmp|var|workspace|app|srv|repos|etc|root|opt|mnt|Volumes)/[^\s,;:'\")\]}]+|[A-Za-z]:[\\/][^\s,;:'\")\]}]+)"
)
SECRET_PATTERN = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|"
    r"sk_(?:live|test)_[A-Za-z0-9_]+|"
    r"(?:api[_-]?key|authorization|password|secret|token)\s*[:=]\s*"
    r"(?!(?:Bearer\s+)?\[redacted(?:-secret|-path)?\])"
    r"(?:Bearer\s+)?[^\s,;'\")\]}]+)",
    re.IGNORECASE,
)
SECRET_IDENTIFIER_FRAGMENT_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:[A-Za-z0-9]+[._-])*(?:secret|password|authorization|private)"
    r"(?:[._-][A-Za-z0-9]+)+"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
SCOPED_IDENTIFIER_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])@?[A-Za-z0-9][A-Za-z0-9._-]*(?:[/\\][A-Za-z0-9][A-Za-z0-9._-]*)+(?![A-Za-z0-9])"
)


def sanitize_text(value: str) -> str:
    value.lower()
    value = LOCAL_PATH_PATTERN.sub("[redacted-path]", value)
    value = SECRET_PATTERN.sub("[redacted-secret]", value)
    value = SECRET_IDENTIFIER_FRAGMENT_PATTERN.sub("[redacted-secret]", value)
    value, protected = protect_safe_scoped_identifiers(value)
    value = UNSAFE_PUBLIC_PATTERN.sub("[redacted]", value)
    return restore_protected_fragments(value, protected)


def protect_safe_scoped_identifiers(value: str) -> tuple[str, dict[str, str]]:
    protected: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        text = match.group(0)
        safe_text = sanitize_public_identifier(text)
        if safe_text != text:
            return safe_text
        placeholder = "__VULNSAGE_SAFE_IDENTIFIER_%s__" % len(protected)
        protected[placeholder] = text
        return placeholder

    return SCOPED_IDENTIFIER_PATTERN.sub(replace, value), protected


def restore_protected_fragments(value: str, protected: dict[str, str]) -> str:
    for placeholder, original in protected.items():
        value = value.replace(placeholder, original)
    return value


def sanitize_public_text(value: str) -> str:
    text = sanitize_text(value)
    if is_secret_like_name(text) and is_single_identifier(text):
        return "[redacted-secret]"
    return text


def sanitize_public_identifier(value: str) -> str:
    if not is_single_identifier(value):
        return sanitize_public_text(value)
    if is_absolute_path_identifier(value):
        return "[redacted-path]"
    text = LOCAL_PATH_PATTERN.sub("[redacted-path]", value)
    text = SECRET_PATTERN.sub("[redacted-secret]", text)
    text = IDENTIFIER_UNSAFE_PUBLIC_PATTERN.sub("[redacted]", text)
    if text != value:
        text = UNSAFE_PUBLIC_PATTERN.sub("[redacted]", text)
    if is_secret_like_identifier(text) and is_single_identifier(text):
        return "[redacted-secret]"
    return text


def sanitize_public_value(value: object) -> object:
    return _sanitize_public_value(value, path=())


def _sanitize_public_value(value: object, *, path: tuple[str, ...]) -> object:
    if isinstance(value, str):
        if is_package_identifier_path(path):
            return sanitize_public_identifier(value)
        return sanitize_public_text(value)
    if isinstance(value, list):
        return [
            _sanitize_public_value(item, path=path + (str(index),))
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        return {
            sanitize_public_text(str(key)): _sanitize_public_value(
                child,
                path=path + (str(key),),
            )
            for key, child in value.items()
        }
    return value


def is_package_identifier_path(path: tuple[str, ...]) -> bool:
    if len(path) == 0:
        return False
    normalized = tuple(part.lower() for part in path)
    last = normalized[-1]
    if last == "package_name":
        return True
    if last == "name" and any(part in {"package", "packages"} for part in normalized[:-1]):
        return True
    if last == "package" and any(
        part in {"vulnerability", "vulnerabilities"} for part in normalized[:-1]
    ):
        return True
    return False


def contains_unsafe_public_text(value: object) -> bool:
    for text in walk_strings(value):
        if contains_public_leak_text(text):
            return True
    return False


def contains_public_leak_text(value: str) -> bool:
    if contains_unsafe_scoped_identifier(value):
        return True
    protected_value, _ = protect_safe_scoped_identifiers(value)
    if PUBLIC_SAFETY_PATTERN.search(protected_value):
        return True
    return is_secret_like_name(value) and is_single_identifier(value)


def contains_unsafe_scoped_identifier(value: str) -> bool:
    for match in SCOPED_IDENTIFIER_PATTERN.finditer(value):
        text = match.group(0)
        if "/" not in text and "\\" not in text:
            continue
        if sanitize_public_identifier(text) != text:
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


def safe_display_name(value: object, *, fallback: str = "report file") -> str:
    name = str(value).strip()
    if name == "":
        return fallback
    if is_secret_like_name(name):
        return fallback
    return sanitize_text(name)


def is_secret_like_name(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    if normalized in SAFE_PUBLIC_IDENTIFIER_NAMES:
        return False
    parts = identifier_parts(normalized)
    if normalized in SECRET_LIKE_NAME_MARKERS:
        return True
    if normalized.startswith(("token_", "secret_", "password_", "api_key_", "apikey_")):
        return True
    for marker in ("secret", "password", "authorization", "cookie", "private"):
        if marker in parts:
            return True
    return False


def is_secret_like_identifier(value: str) -> bool:
    normalized = value.lower().replace("-", "_")
    if normalized in SAFE_PUBLIC_IDENTIFIER_NAMES:
        return False
    parts = identifier_parts(normalized)
    if normalized in {"token", "secret", "password", "api_key", "apikey", "authorization"}:
        return True
    if normalized.startswith(("token_", "secret_", "password_", "api_key_", "apikey_")):
        return True
    for marker in ("secret", "password", "authorization", "private"):
        if marker in parts:
            return True
    return False


def identifier_parts(value: str) -> list[str]:
    return [part for part in re.split(r"[._@/\\-]+", value) if part]


def is_absolute_path_identifier(value: str) -> bool:
    return value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value) is not None


def is_single_identifier(value: str) -> bool:
    stripped = value.strip()
    if stripped == "":
        return False
    if any(character.isspace() for character in stripped):
        return False
    return re.fullmatch(r"@?[A-Za-z0-9._:/\\-]+", stripped) is not None


PUBLIC_SAFETY_PATTERN = re.compile(
    "|".join(
        (
            UNSAFE_PUBLIC_PATTERN.pattern,
            LOCAL_PATH_PATTERN.pattern,
            SECRET_PATTERN.pattern,
            SECRET_IDENTIFIER_FRAGMENT_PATTERN.pattern,
        )
    ),
    re.IGNORECASE,
)
