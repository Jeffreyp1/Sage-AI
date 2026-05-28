"""Repository profiling helpers for the scan MVP."""

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class RepoProfile:
    repo_name: str
    root_path: str
    languages: List[str]
    package_managers: List[str]
    dependency_files: List[str]
    lockfiles: List[str]
    service_type: str
    test_commands: List[str]
    codeowners: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def profile_repo(repo_path: str) -> RepoProfile:
    root = Path(repo_path).resolve()
    package_json_path = safe_repo_file(root, root / "package.json")
    dependency_files = []
    lockfiles = []
    package_managers = []
    languages = []
    test_commands = []

    if package_json_path is not None:
        dependency_files.append("package.json")
        package_managers.append("npm")
        languages.extend(detect_node_languages(root))
        test_commands.extend(detect_npm_test_commands(package_json_path))
    if safe_repo_file(root, root / "package-lock.json") is not None:
        lockfiles.append("package-lock.json")

    service_type = infer_service_type(root)
    codeowners = parse_codeowners(root)

    return RepoProfile(
        repo_name=root.name,
        root_path=str(root),
        languages=sorted(set(languages)) or ["unknown"],
        package_managers=sorted(set(package_managers)),
        dependency_files=dependency_files,
        lockfiles=lockfiles,
        service_type=service_type,
        test_commands=test_commands,
        codeowners=codeowners,
    )


def detect_node_languages(root: Path) -> List[str]:
    extensions = {
        path.suffix
        for path in root.rglob("*")
        if safe_repo_file(root, path) is not None
    }
    languages = []
    if ".ts" in extensions or ".tsx" in extensions:
        languages.append("TypeScript")
    if ".js" in extensions or ".jsx" in extensions or ".mjs" in extensions or ".cjs" in extensions:
        languages.append("JavaScript")
    return languages


def detect_npm_test_commands(package_json_path: Path) -> List[str]:
    try:
        data = json.loads(package_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
    if not isinstance(scripts, dict):
        return []
    commands = []
    for script_name in sorted(scripts):
        if "test" in script_name:
            commands.append("npm run %s" % script_name)
    if "test" in scripts and "npm run test" not in commands:
        commands.insert(0, "npm test")
    return commands


def infer_service_type(root: Path) -> str:
    has_dockerfile = safe_repo_file(root, root / "Dockerfile") is not None
    has_routes = safe_repo_dir(root, root / "src" / "routes") is not None
    has_workers = safe_repo_dir(root, root / "src" / "workers") is not None
    if has_dockerfile and has_routes:
        return "backend_api"
    if has_routes:
        return "api"
    if has_workers:
        return "worker"
    return "unknown"


def parse_codeowners(root: Path) -> Dict[str, str]:
    candidates = [
        root / "CODEOWNERS",
        root / ".github" / "CODEOWNERS",
        root / "docs" / "CODEOWNERS",
    ]
    for path in candidates:
        if safe_repo_file(root, path) is not None:
            return _parse_codeowners_file(path)
    return {}


def _parse_codeowners_file(path: Path) -> Dict[str, str]:
    owners = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        owners[parts[0].lstrip("/")] = " ".join(parts[1:])
    return owners


def safe_repo_file(root: Path, path: Path) -> Optional[Path]:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file():
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return path


def safe_repo_dir(root: Path, path: Path) -> Optional[Path]:
    try:
        resolved = path.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_dir():
        return None
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return path


def owner_for_path(codeowners: Dict[str, str], file_path: Optional[str]) -> Optional[str]:
    if not file_path:
        return None
    normalized = file_path.replace("\\", "/").lstrip("/")
    matches = []
    for pattern, owner in codeowners.items():
        prefix = pattern.rstrip("*").rstrip("/")
        if normalized.startswith(prefix.rstrip("/") + "/") or normalized == prefix.rstrip("/"):
            matches.append((len(prefix), owner))
    if not matches:
        return None
    return sorted(matches, reverse=True)[0][1]
