"""Safe GitHub repository ingestion helpers."""

from dataclasses import dataclass
from hashlib import sha256
import logging
from pathlib import Path
import re
import subprocess
from urllib.parse import urlparse


logger = logging.getLogger(__name__)

OWNER_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPO_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


class GitHubIngestionError(ValueError):
    """Base error for GitHub repository ingestion."""


class InvalidGitHubUrlError(GitHubIngestionError):
    """Raised when a GitHub URL is not accepted for ingestion."""


class GitHubCloneError(GitHubIngestionError):
    """Raised when a GitHub repository cannot be cloned."""


@dataclass(frozen=True)
class GitHubRepository:
    owner: str
    repo: str

    @property
    def clone_url(self) -> str:
        return "https://github.com/%s/%s.git" % (self.owner, self.repo)

    @property
    def full_name(self) -> str:
        return "%s/%s" % (self.owner, self.repo)

    @property
    def safe_directory_name(self) -> str:
        canonical = self.full_name.lower()
        digest = sha256(canonical.encode("utf-8")).hexdigest()[:12]
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "-", canonical)
        return "%s-%s" % (safe_name, digest)


def parse_github_repo_url(url: str) -> GitHubRepository:
    if url.strip() != url:
        raise InvalidGitHubUrlError("GitHub URL must not contain leading or trailing whitespace.")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise InvalidGitHubUrlError("GitHub URL must use https.")
    if parsed.hostname != "github.com":
        raise InvalidGitHubUrlError("GitHub URL host must be github.com.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidGitHubUrlError("GitHub URL port is malformed.") from exc
    if parsed.username is not None or parsed.password is not None or port is not None:
        raise InvalidGitHubUrlError("GitHub URL must not include credentials or a port.")
    if parsed.params != "" or parsed.query != "" or parsed.fragment != "":
        raise InvalidGitHubUrlError("GitHub URL must not include params, query, or fragment.")

    path = parsed.path
    if path.endswith("/"):
        path = path[:-1]
    if not path.startswith("/"):
        raise InvalidGitHubUrlError("GitHub URL must be https://github.com/<owner>/<repo>.")
    parts = path[1:].split("/")
    if len(parts) != 2:
        raise InvalidGitHubUrlError("GitHub URL must be https://github.com/<owner>/<repo>.")

    owner = parts[0]
    repo = parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]

    if OWNER_PATTERN.fullmatch(owner) is None:
        raise InvalidGitHubUrlError("GitHub owner name is malformed.")
    if REPO_PATTERN.fullmatch(repo) is None or repo in {".", ".."} or ".." in repo:
        raise InvalidGitHubUrlError("GitHub repository name is malformed.")

    return GitHubRepository(owner=owner, repo=repo)


def clone_github_repo(url: str, base_directory: str | Path, timeout_seconds: int = 120) -> Path:
    repository = parse_github_repo_url(url)
    base_path = Path(base_directory).resolve()
    base_path.mkdir(parents=True, exist_ok=True)
    destination = base_path / repository.safe_directory_name

    command = [
        "git",
        "clone",
        "--depth",
        "1",
        repository.clone_url,
        str(destination),
    ]
    log_extra = {
        "github_owner": repository.owner,
        "github_repo": repository.repo,
        "destination_name": destination.name,
    }
    logger.info("github_clone_start", extra=log_extra)
    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "github_clone_failure",
            extra={
                **log_extra,
                "returncode": exc.returncode,
                "stderr_length": len(exc.stderr or ""),
            },
        )
        raise GitHubCloneError("Unable to clone GitHub repository.") from exc
    except subprocess.TimeoutExpired as exc:
        logger.warning(
            "github_clone_failure",
            extra={**log_extra, "timeout_seconds": timeout_seconds},
        )
        raise GitHubCloneError("Unable to clone GitHub repository: clone timed out.") from exc
    except OSError as exc:
        logger.warning(
            "github_clone_failure",
            extra={**log_extra, "error_type": type(exc).__name__},
        )
        raise GitHubCloneError(
            "Unable to clone GitHub repository: git could not be executed."
        ) from exc

    logger.info("github_clone_success", extra=log_extra)
    return destination
