"""Deterministic evidence chunking for retrieval-augmented triage."""

import heapq
import logging
from collections.abc import Iterable, Mapping
from hashlib import sha256
from pathlib import Path

from app.services.public_safety import sanitize_text
from app.services.rag_types import EvidenceChunk
from app.services.vulnerability_normalizer import NormalizedVulnerability


DEFAULT_MAX_CHARS = 2_000
DEFAULT_MAX_FILE_BYTES = 1_048_576
logger = logging.getLogger(__name__)

SKIPPED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".next",
    "__pycache__",
}

SOURCE_EXTENSIONS = {
    ".bash",
    ".c",
    ".cc",
    ".cjs",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".mjs",
    ".php",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".ts",
    ".tsx",
    ".zsh",
}


def chunk_repository(
    repo_path: str | Path,
    *,
    repo_id: str | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[EvidenceChunk]:
    """Chunk supported repository files into stable evidence chunks."""

    root = Path(repo_path).resolve()
    if not root.is_dir():
        raise ValueError(f"repository path is not a directory: {repo_path}")
    if max_chars <= 0:
        raise ValueError("max_chars must be positive")
    if max_file_bytes <= 0:
        raise ValueError("max_file_bytes must be positive")

    chunks: list[EvidenceChunk] = []
    for path in _iter_repository_files(root, repo_id=repo_id):
        if _has_skipped_dir(path, root):
            continue

        resolved_path = path.resolve()
        if not _is_relative_to(resolved_path, root):
            continue

        relative_path = resolved_path.relative_to(root).as_posix()
        if not _is_safe_relative_path(relative_path):
            continue

        source_type = source_type_for_path(relative_path)
        if source_type is None:
            continue

        try:
            file_size = resolved_path.stat().st_size
        except OSError as exc:
            _log_file_read_warning(relative_path, repo_id, exc)
            continue

        if file_size > max_file_bytes:
            _log_file_size_warning(relative_path, repo_id, file_size, max_file_bytes)
            continue

        try:
            text = resolved_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _log_file_read_warning(relative_path, repo_id, exc)
            continue
        file_metadata: dict[str, object] = {
            "source_type": source_type,
            "file_path": relative_path,
        }
        if repo_id is not None:
            file_metadata["repo_id"] = repo_id

        chunks.extend(
            _chunk_lines(
                source_type=source_type,
                content=text,
                metadata=file_metadata,
                chunk_key_parts=[repo_id or "", relative_path],
                max_chars=max_chars,
            )
        )

    return chunks


def _iter_repository_files(root: Path, *, repo_id: str | None = None) -> Iterable[Path]:
    pending: list[tuple[str, int, Path]] = []
    sequence = 0

    def push(path: Path) -> None:
        nonlocal sequence
        heapq.heappush(pending, (path.as_posix(), sequence, path))
        sequence += 1

    def push_directory_entries(directory: Path) -> None:
        try:
            for child in directory.iterdir():
                push(child)
        except OSError as exc:
            _log_directory_listing_warning(directory, root, repo_id, exc)
            return

    push_directory_entries(root)

    while len(pending) > 0:
        _, _, path = heapq.heappop(pending)
        if path.name in SKIPPED_DIRS and path.is_dir():
            continue
        if path.is_symlink():
            if path.is_file():
                yield path
            continue
        if path.is_dir():
            push_directory_entries(path)
            continue
        if path.is_file():
            yield path


def chunk_advisory(
    vulnerability: NormalizedVulnerability | None = None,
    *,
    vulnerability_id: str | None = None,
    package: str | None = None,
    ecosystem: str | None = None,
    current_version: str | None = None,
    fixed_versions: Iterable[str] | None = None,
    summary: str | None = None,
    details: str | None = None,
    aliases: Iterable[str] | None = None,
    severity: str | None = None,
    references: Iterable[Mapping[str, str]] | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> list[EvidenceChunk]:
    """Chunk a normalized vulnerability or structured advisory fields."""

    if max_chars <= 0:
        raise ValueError("max_chars must be positive")

    advisory = _advisory_fields_from_vulnerability(vulnerability)
    advisory.update(
        _clean_override_fields(
            vulnerability_id=vulnerability_id,
            package=package,
            ecosystem=ecosystem,
            current_version=current_version,
            fixed_versions=fixed_versions,
            summary=summary,
            details=details,
            aliases=aliases,
            severity=severity,
            references=references,
        )
    )

    advisory_id = str(advisory.get("vulnerability_id") or "UNKNOWN")
    advisory_package = str(advisory.get("package") or "UNKNOWN")
    advisory_ecosystem = str(advisory.get("ecosystem") or "UNKNOWN")
    advisory_current_version = _optional_string(advisory.get("current_version"))
    advisory_fixed_versions = _string_list(advisory.get("fixed_versions"))

    content = _advisory_content(
        vulnerability_id=advisory_id,
        package=advisory_package,
        ecosystem=advisory_ecosystem,
        current_version=advisory_current_version,
        fixed_versions=advisory_fixed_versions,
        summary=_optional_string(advisory.get("summary")),
        details=_optional_string(advisory.get("details")),
        aliases=_string_list(advisory.get("aliases")),
        severity=_optional_string(advisory.get("severity")),
        references=_reference_lines(advisory.get("references")),
    )
    metadata: dict[str, object] = {
        "source_type": "advisory",
        "vulnerability_id": advisory_id,
        "package": advisory_package,
        "ecosystem": advisory_ecosystem,
        "current_version": advisory_current_version,
        "fixed_versions": advisory_fixed_versions,
    }

    return _chunk_lines(
        source_type="advisory",
        content=content,
        metadata=metadata,
        chunk_key_parts=[advisory_id, advisory_package, advisory_ecosystem],
        max_chars=max_chars,
    )


def source_type_for_path(relative_path: str) -> str | None:
    """Return the supported evidence source type for a safe repo-relative path."""

    path = Path(relative_path)
    parts = path.parts
    name = path.name
    lower_name = name.lower()

    if len(parts) >= 3 and parts[0] == ".github" and parts[1] == "workflows":
        if path.suffix.lower() in {".yml", ".yaml"}:
            return "ci_workflow"
        return None

    if name == "package.json":
        return "package_json"
    if name == "package-lock.json":
        return "package_lock"
    if lower_name == "dockerfile" or lower_name.startswith("dockerfile."):
        return "dockerfile"
    if lower_name == "readme" or lower_name.startswith("readme."):
        return "readme"
    if name == "CODEOWNERS" and parts in {("CODEOWNERS",), (".github", "CODEOWNERS")}:
        return "codeowners"
    if path.suffix.lower() in SOURCE_EXTENSIONS:
        return "source_file"

    return None


def chunk_repository_files(
    repo_path: str | Path,
    *,
    repo_id: str | None = None,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> list[EvidenceChunk]:
    """Compatibility wrapper for callers that name the source of the chunks."""

    return chunk_repository(
        repo_path,
        repo_id=repo_id,
        max_chars=max_chars,
        max_file_bytes=max_file_bytes,
    )


def chunk_vulnerability_advisory(
    vulnerability: NormalizedVulnerability,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> list[EvidenceChunk]:
    """Compatibility wrapper for NormalizedVulnerability advisory chunks."""

    return chunk_advisory(vulnerability, max_chars=max_chars)


def _chunk_lines(
    *,
    source_type: str,
    content: str,
    metadata: Mapping[str, object],
    chunk_key_parts: list[str],
    max_chars: int,
) -> list[EvidenceChunk]:
    lines = content.splitlines()
    if len(lines) == 0:
        return []

    chunks: list[EvidenceChunk] = []
    current_lines: list[str] = []
    current_start = 1
    current_length = 0

    for index, line in enumerate(lines, start=1):
        if len(line) > max_chars:
            if len(current_lines) > 0:
                chunks.append(
                    _make_chunk(
                        source_type=source_type,
                        lines=current_lines,
                        line_start=current_start,
                        line_end=index - 1,
                        metadata=metadata,
                        chunk_key_parts=chunk_key_parts,
                    )
                )
                current_lines = []
                current_length = 0

            for segment_index, segment in enumerate(_split_long_line(line, max_chars)):
                chunks.append(
                    _make_chunk(
                        source_type=source_type,
                        lines=[segment],
                        line_start=index,
                        line_end=index,
                        metadata=metadata,
                        chunk_key_parts=[
                            *chunk_key_parts,
                            "line-segment",
                            str(index),
                            str(segment_index),
                        ],
                    )
                )
            current_start = index + 1
            continue

        line_length = len(line) if len(current_lines) == 0 else len(line) + 1
        would_exceed = current_length + line_length > max_chars
        if would_exceed and len(current_lines) > 0:
            chunks.append(
                _make_chunk(
                    source_type=source_type,
                    lines=current_lines,
                    line_start=current_start,
                    line_end=index - 1,
                    metadata=metadata,
                    chunk_key_parts=chunk_key_parts,
                )
            )
            current_lines = []
            current_start = index
            current_length = 0

        current_lines.append(line)
        current_length += len(line) if current_length == 0 else len(line) + 1

    if len(current_lines) > 0:
        chunks.append(
            _make_chunk(
                source_type=source_type,
                lines=current_lines,
                line_start=current_start,
                line_end=len(lines),
                metadata=metadata,
                chunk_key_parts=chunk_key_parts,
            )
        )

    return chunks


def _split_long_line(line: str, max_chars: int) -> list[str]:
    return [line[start : start + max_chars] for start in range(0, len(line), max_chars)]


def _make_chunk(
    *,
    source_type: str,
    lines: list[str],
    line_start: int,
    line_end: int,
    metadata: Mapping[str, object],
    chunk_key_parts: list[str],
) -> EvidenceChunk:
    content = "\n".join(lines)
    content_hash = sha256(content.encode("utf-8")).hexdigest()
    chunk_id = _stable_hash(
        [
            source_type,
            *chunk_key_parts,
            str(line_start),
            str(line_end),
            content_hash,
        ]
    )
    chunk_metadata = dict(metadata)
    chunk_metadata["line_start"] = line_start
    chunk_metadata["line_end"] = line_end
    chunk_metadata["content_hash"] = content_hash
    return EvidenceChunk(
        chunk_id=chunk_id,
        source_type=source_type,
        content=content,
        metadata=chunk_metadata,
    )


def _stable_hash(parts: Iterable[str]) -> str:
    value = "\x1f".join(parts)
    return sha256(value.encode("utf-8")).hexdigest()[:32]


def _has_skipped_dir(path: Path, root: Path) -> bool:
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in SKIPPED_DIRS for part in relative_parts[:-1])


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _is_safe_relative_path(relative_path: str) -> bool:
    path = Path(relative_path)
    return not path.is_absolute() and ".." not in path.parts


def _log_file_read_warning(relative_path: str, repo_id: str | None, error: OSError) -> None:
    extra: dict[str, object] = {
        "file_path": relative_path,
        "error_type": type(error).__name__,
    }
    if repo_id is not None:
        extra["repo_id"] = repo_id
    logger.warning("skipping unreadable supported file", extra=extra)


def _log_file_size_warning(
    relative_path: str,
    repo_id: str | None,
    file_size: int,
    max_file_bytes: int,
) -> None:
    extra: dict[str, object] = {
        "file_path": relative_path,
        "error_type": "FileTooLarge",
        "file_size": file_size,
        "max_file_bytes": max_file_bytes,
    }
    if repo_id is not None:
        extra["repo_id"] = repo_id
    logger.warning("skipping oversized supported file", extra=extra)


def _log_directory_listing_warning(
    directory: Path,
    root: Path,
    repo_id: str | None,
    error: OSError,
) -> None:
    try:
        directory_path = directory.relative_to(root).as_posix()
    except ValueError:
        directory_path = directory.as_posix()
    if directory_path == "":
        directory_path = "."

    extra: dict[str, object] = {
        "directory_path": directory_path,
        "error_type": type(error).__name__,
    }
    if repo_id is not None:
        extra["repo_id"] = repo_id
    logger.warning("pruning unreadable repository directory", extra=extra)


def _advisory_fields_from_vulnerability(
    vulnerability: NormalizedVulnerability | None,
) -> dict[str, object]:
    if vulnerability is None:
        return {}

    return {
        "vulnerability_id": vulnerability.canonical_id or vulnerability.source_id,
        "package": vulnerability.package,
        "ecosystem": vulnerability.ecosystem,
        "current_version": vulnerability.current_version,
        "fixed_versions": vulnerability.fixed_versions,
        "summary": vulnerability.summary,
        "details": vulnerability.details,
        "aliases": vulnerability.aliases,
        "severity": vulnerability.severity,
        "references": vulnerability.references,
    }


def _clean_override_fields(
    *,
    vulnerability_id: str | None,
    package: str | None,
    ecosystem: str | None,
    current_version: str | None,
    fixed_versions: Iterable[str] | None,
    summary: str | None,
    details: str | None,
    aliases: Iterable[str] | None,
    severity: str | None,
    references: Iterable[Mapping[str, str]] | None,
) -> dict[str, object]:
    fields: dict[str, object] = {}
    if vulnerability_id is not None:
        fields["vulnerability_id"] = vulnerability_id
    if package is not None:
        fields["package"] = package
    if ecosystem is not None:
        fields["ecosystem"] = ecosystem
    if current_version is not None:
        fields["current_version"] = current_version
    if fixed_versions is not None:
        fields["fixed_versions"] = list(fixed_versions)
    if summary is not None:
        fields["summary"] = summary
    if details is not None:
        fields["details"] = details
    if aliases is not None:
        fields["aliases"] = list(aliases)
    if severity is not None:
        fields["severity"] = severity
    if references is not None:
        if isinstance(references, str):
            fields["references"] = [references]
        else:
            fields["references"] = list(references)
    return fields


def _advisory_content(
    *,
    vulnerability_id: str,
    package: str,
    ecosystem: str,
    current_version: str | None,
    fixed_versions: list[str],
    summary: str | None,
    details: str | None,
    aliases: list[str],
    severity: str | None,
    references: list[str],
) -> str:
    lines = [
        f"Vulnerability: {sanitize_text(vulnerability_id)}",
        f"Package: {sanitize_text(package)}",
        f"Ecosystem: {sanitize_text(ecosystem)}",
    ]
    if current_version is not None:
        lines.append(f"Current version: {sanitize_text(current_version)}")
    if len(fixed_versions) > 0:
        lines.append(f"Fixed versions: {sanitize_text(', '.join(fixed_versions))}")
    if severity is not None:
        lines.append(f"Severity: {sanitize_text(severity)}")
    if len(aliases) > 0:
        lines.append(f"Aliases: {sanitize_text(', '.join(aliases))}")
    if summary is not None:
        lines.append(f"Summary: {sanitize_text(summary)}")
    if details is not None:
        lines.append(f"Details: {sanitize_text(details)}")
    for reference in references:
        lines.append(f"Reference: {sanitize_text(reference)}")
    return "\n".join(lines)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item) for item in value]
    return [str(value)]


def _reference_lines(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, Iterable):
        return [str(value)]

    references: list[str] = []
    for item in value:
        if isinstance(item, Mapping):
            reference_type = item.get("type")
            reference_url = item.get("url")
            if reference_type is not None and reference_url is not None:
                references.append(f"{reference_type}: {reference_url}")
                continue
            if reference_url is not None:
                references.append(str(reference_url))
                continue
        references.append(str(item))
    return references
