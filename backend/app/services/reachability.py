"""Lightweight reachability analysis for dependency findings."""

from dataclasses import asdict, dataclass, field
from pathlib import Path
import re
from typing import Dict, Iterable, List, Optional

from app.services.dependency_parser import ParsedDependency
from app.services.repo_ingestion import owner_for_path


SOURCE_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "coverage", ".next"}
NON_PRODUCTION_DIRS = {"test", "tests", "spec", "specs", "e2e", "cypress", "__tests__"}
PRODUCTION_DIRS = {"src", "app", "routes", "controllers", "services", "lib"}
PRODUCTION_ENTRYPOINTS = {
    "app.cjs",
    "app.js",
    "app.mjs",
    "app.ts",
    "index.cjs",
    "index.js",
    "index.mjs",
    "index.ts",
    "main.cjs",
    "main.js",
    "main.mjs",
    "main.ts",
    "server.cjs",
    "server.js",
    "server.mjs",
    "server.ts",
}
TEST_FILE_MARKERS = (".test.", ".spec.", ".e2e.", ".cy.")


@dataclass
class ReachabilityResult:
    reachability: str
    runtime_scope: str
    confidence: float
    evidence: List[Dict[str, str]] = field(default_factory=list)
    owner: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def analyze_reachability(
    repo_path: str,
    dependency: ParsedDependency,
    codeowners: Optional[Dict[str, str]] = None,
) -> ReachabilityResult:
    root = Path(repo_path).resolve()
    codeowners = codeowners or {}
    import_hits = find_imports(root, dependency.name)
    production_hits = [hit for hit in import_hits if is_production_source(hit["source"])]
    test_hits = [hit for hit in import_hits if not is_production_source(hit["source"])]
    docker_hit = dependency.name in read_optional_repo_file(root, root / "Dockerfile")

    evidence = list(dependency.evidence)
    evidence.extend(import_hits)
    route_hits = []
    for hit in production_hits:
        route_hits.extend(find_internal_references(root, hit["source"]))
    evidence.extend(route_hits)
    if docker_hit:
        evidence.append(
            {
                "type": "dockerfile",
                "source": "Dockerfile",
                "claim": "%s appears in Dockerfile" % dependency.name,
            }
        )

    if production_hits:
        reachability = "possibly_reachable"
        runtime_scope = "production"
        confidence = 0.78 if route_hits and dependency.is_direct else 0.72 if dependency.is_direct else 0.58
    elif dependency.dependency_type == "devDependency" and test_hits:
        reachability = "unlikely_reachable"
        runtime_scope = "development"
        confidence = 0.74
    elif dependency.dependency_type == "devDependency":
        reachability = "unlikely_reachable"
        runtime_scope = "development"
        confidence = 0.66
    elif dependency.is_direct:
        reachability = "unknown"
        runtime_scope = "production"
        confidence = 0.42
    else:
        reachability = "unknown"
        runtime_scope = "unknown"
        confidence = 0.30

    owner = None
    if production_hits:
        owner = owner_for_path(codeowners, production_hits[0].get("source"))

    return ReachabilityResult(
        reachability=reachability,
        runtime_scope=runtime_scope,
        confidence=confidence,
        evidence=evidence,
        owner=owner,
    )


def find_imports(root: Path, package_name: str) -> List[Dict[str, str]]:
    hits = []
    pattern = re.compile(
        r"(?:from\s+['\"]%s(?:/[^'\"]*)?['\"]|require\(\s*['\"]%s(?:/[^'\"]*)?['\"]\s*\)|import\(\s*['\"]%s(?:/[^'\"]*)?['\"]\s*\))"
        % (re.escape(package_name), re.escape(package_name), re.escape(package_name))
    )
    for path in iter_source_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        match = pattern.search(text)
        if not match:
            continue
        relative = path.relative_to(root).as_posix()
        hits.append(
            {
                "type": "source_file",
                "source": relative,
                "claim": "%s is imported by %s" % (package_name, relative),
                "quote": trim_quote(match.group(0)),
            }
        )
    return hits


def find_internal_references(root: Path, relative_source: str) -> List[Dict[str, str]]:
    target = Path(relative_source)
    stem = target.stem
    hits = []
    import_pattern = re.compile(
        r"(?:from\s+['\"][^'\"]*%s['\"]|require\(\s*['\"][^'\"]*%s['\"]\s*\))"
        % (re.escape(stem), re.escape(stem))
    )
    endpoint_pattern = re.compile(r"router\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]")
    for path in iter_source_files(root):
        current_relative = path.relative_to(root).as_posix()
        if current_relative == relative_source:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if not import_pattern.search(text):
            continue
        endpoint_match = endpoint_pattern.search(text)
        if endpoint_match:
            claim = "%s is referenced by %s endpoint %s in %s" % (
                relative_source,
                endpoint_match.group(1).upper(),
                endpoint_match.group(2),
                current_relative,
            )
            evidence_type = "route"
        else:
            claim = "%s is referenced by %s" % (relative_source, current_relative)
            evidence_type = "source_file"
        hits.append(
            {
                "type": evidence_type,
                "source": current_relative,
                "claim": claim,
            }
        )
    return hits


def iter_source_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.suffix not in SOURCE_SUFFIXES:
            continue
        if safe_repo_file(root, path) is None:
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in relative_parts):
            continue
        yield path


def is_production_source(relative_path: str) -> bool:
    path = relative_path.replace("\\", "/").strip("/").lower()
    parts = [part for part in path.split("/") if part and part != "."]
    if not parts:
        return False
    if any(part in SKIP_DIRS or part in NON_PRODUCTION_DIRS for part in parts):
        return False
    if is_test_source_file(parts[-1]):
        return False
    if parts[-1] in PRODUCTION_ENTRYPOINTS:
        return True
    return any(part in PRODUCTION_DIRS for part in parts)


def is_test_source_file(filename: str) -> bool:
    return any(marker in filename for marker in TEST_FILE_MARKERS)


def read_optional(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def read_optional_repo_file(root: Path, path: Path) -> str:
    safe_path = safe_repo_file(root, path)
    if safe_path is None:
        return ""
    return read_optional(safe_path)


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


def trim_quote(value: str, limit: int = 180) -> str:
    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."
