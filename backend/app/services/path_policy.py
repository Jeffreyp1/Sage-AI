"""Path policy helpers for local tool adapters."""

from __future__ import annotations

from pathlib import Path


class PathPolicyError(ValueError):
    """Raised when a requested repo path violates local safety policy."""


def resolve_repo_path(
    requested_path: str | Path,
    *,
    workspace_root: str | Path | None = None,
) -> Path:
    """Resolve a repo path while preventing escapes outside the allowed workspace."""

    root = resolve_existing_workspace(workspace_root)
    raw_path = Path(requested_path)
    candidate = raw_path if raw_path.is_absolute() else root / raw_path

    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise PathPolicyError("Repository path does not exist") from error
    except OSError as error:
        raise PathPolicyError("Repository path is not accessible") from error

    if not resolved.is_dir():
        raise PathPolicyError("Repository path is not a directory")

    ensure_inside_workspace(resolved, root)
    return resolved


def resolve_existing_workspace(workspace_root: str | Path | None) -> Path:
    root_candidate = Path.cwd() if workspace_root is None else Path(workspace_root)
    try:
        root = root_candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise PathPolicyError("Allowed workspace does not exist") from error
    except OSError as error:
        raise PathPolicyError("Allowed workspace is not accessible") from error

    if not root.is_dir():
        raise PathPolicyError("Allowed workspace is not a directory")
    return root


def ensure_inside_workspace(path: Path, workspace_root: Path) -> None:
    try:
        path.relative_to(workspace_root)
    except ValueError as error:
        raise PathPolicyError("Repository path is outside the allowed workspace") from error
