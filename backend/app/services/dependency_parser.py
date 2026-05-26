"""Dependency parsers for repository manifests and lockfiles."""

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
from typing import Dict, Iterable, List, Optional, Tuple


class DependencyParserError(ValueError):
    """Raised when dependency files cannot be parsed."""


@dataclass
class ParsedDependency:
    name: str
    current_version: Optional[str]
    ecosystem: str
    dependency_type: str
    is_direct: bool
    parent_package: Optional[str] = None
    manifest_path: Optional[str] = None
    lockfile_path: Optional[str] = None
    version_spec: Optional[str] = None
    lockfile_entry_path: Optional[str] = None
    evidence: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


@dataclass
class DirectDependency:
    name: str
    dependency_type: str
    version_spec: str


DEPENDENCY_GROUPS = {
    "dependencies": "dependencies",
    "devDependencies": "devDependency",
    "peerDependencies": "peerDependency",
    "optionalDependencies": "optionalDependency",
}


class NodeDependencyParser:
    """Parse npm package manifests and package-lock files."""

    ecosystem = "npm"

    def parse(self, repo_path: str) -> List[ParsedDependency]:
        root = Path(repo_path).resolve()
        package_json_path = root / "package.json"
        package_lock_path = root / "package-lock.json"

        if not package_json_path.exists():
            return []

        package_json = self._read_json(package_json_path)
        direct_deps = self._direct_dependencies(package_json)

        if package_lock_path.exists():
            lock = self._read_json(package_lock_path)
            dependencies = self._parse_lockfile(
                package_lock_path=package_lock_path,
                lock=lock,
                direct_deps=direct_deps,
                manifest_path=package_json_path,
            )
        else:
            dependencies = []

        dependencies_by_key = {
            self._dependency_key(dep): dep
            for dep in dependencies
        }

        for direct in direct_deps.values():
            direct_key_prefix = (direct.name, None)
            has_direct_lock_entry = any(
                name == direct_key_prefix[0] and dep.is_direct
                for (name, _version, _parent), dep in dependencies_by_key.items()
            )
            if has_direct_lock_entry:
                continue
            dep = ParsedDependency(
                name=direct.name,
                current_version=None,
                ecosystem=self.ecosystem,
                dependency_type=direct.dependency_type,
                is_direct=True,
                manifest_path=str(package_json_path),
                version_spec=direct.version_spec,
                evidence=[
                    {
                        "type": "manifest",
                        "source": "package.json",
                        "claim": "%s is listed in %s" % (direct.name, direct.dependency_type),
                    }
                ],
            )
            dependencies_by_key[self._dependency_key(dep)] = dep

        return sorted(
            dependencies_by_key.values(),
            key=lambda dep: (not dep.is_direct, dep.name, dep.current_version or "", dep.parent_package or ""),
        )

    def _parse_lockfile(
        self,
        package_lock_path: Path,
        lock: Dict[str, object],
        direct_deps: Dict[str, DirectDependency],
        manifest_path: Path,
    ) -> List[ParsedDependency]:
        if isinstance(lock.get("packages"), dict):
            return self._parse_lockfile_v2(package_lock_path, lock, direct_deps, manifest_path)
        if isinstance(lock.get("dependencies"), dict):
            return self._parse_lockfile_v1(package_lock_path, lock, direct_deps, manifest_path)
        return []

    def _parse_lockfile_v2(
        self,
        package_lock_path: Path,
        lock: Dict[str, object],
        direct_deps: Dict[str, DirectDependency],
        manifest_path: Path,
    ) -> List[ParsedDependency]:
        packages = lock.get("packages", {})
        dependencies = []
        if not isinstance(packages, dict):
            return dependencies

        for lock_path, metadata in packages.items():
            if lock_path == "" or not isinstance(metadata, dict):
                continue
            name = package_name_from_lock_path(lock_path)
            if not name:
                continue

            version = string_or_none(metadata.get("version"))
            is_root_entry = lock_path == "node_modules/%s" % name
            is_direct = name in direct_deps and is_root_entry
            direct = direct_deps.get(name)
            parent_package = package_parent_from_lock_path(lock_path)

            if direct and is_direct:
                dependency_type = direct.dependency_type
                version_spec = direct.version_spec
            elif metadata.get("dev") is True:
                dependency_type = "devDependency"
                version_spec = None
            elif metadata.get("peer") is True:
                dependency_type = "peerDependency"
                version_spec = None
            else:
                dependency_type = "transitive"
                version_spec = None

            evidence = [
                {
                    "type": "lockfile",
                    "source": "package-lock.json",
                    "claim": "%s@%s is installed" % (name, version or "unknown"),
                }
            ]
            if is_direct:
                evidence.append(
                    {
                        "type": "manifest",
                        "source": "package.json",
                        "claim": "%s is a direct %s" % (name, dependency_type),
                    }
                )

            dependencies.append(
                ParsedDependency(
                    name=name,
                    current_version=version,
                    ecosystem=self.ecosystem,
                    dependency_type=dependency_type,
                    is_direct=is_direct,
                    parent_package=parent_package,
                    manifest_path=str(manifest_path) if is_direct else None,
                    lockfile_path=str(package_lock_path),
                    version_spec=version_spec,
                    lockfile_entry_path=lock_path,
                    evidence=evidence,
                )
            )

        return dependencies

    def _parse_lockfile_v1(
        self,
        package_lock_path: Path,
        lock: Dict[str, object],
        direct_deps: Dict[str, DirectDependency],
        manifest_path: Path,
    ) -> List[ParsedDependency]:
        root_dependencies = lock.get("dependencies", {})
        if not isinstance(root_dependencies, dict):
            return []
        parsed = []
        self._walk_lockfile_v1(
            parsed=parsed,
            dependencies=root_dependencies,
            direct_deps=direct_deps,
            manifest_path=manifest_path,
            package_lock_path=package_lock_path,
            parent_package=None,
            inherited_type=None,
        )
        return parsed

    def _walk_lockfile_v1(
        self,
        parsed: List[ParsedDependency],
        dependencies: Dict[str, object],
        direct_deps: Dict[str, DirectDependency],
        manifest_path: Path,
        package_lock_path: Path,
        parent_package: Optional[str],
        inherited_type: Optional[str],
    ) -> None:
        for name, metadata in dependencies.items():
            if not isinstance(metadata, dict):
                continue
            direct = direct_deps.get(name)
            is_direct = parent_package is None and direct is not None
            version = string_or_none(metadata.get("version"))
            if is_direct and direct:
                dependency_type = direct.dependency_type
                version_spec = direct.version_spec
            elif inherited_type == "devDependency" or metadata.get("dev") is True:
                dependency_type = "devDependency"
                version_spec = None
            else:
                dependency_type = "transitive"
                version_spec = None

            parsed.append(
                ParsedDependency(
                    name=name,
                    current_version=version,
                    ecosystem=self.ecosystem,
                    dependency_type=dependency_type,
                    is_direct=is_direct,
                    parent_package=parent_package,
                    manifest_path=str(manifest_path) if is_direct else None,
                    lockfile_path=str(package_lock_path),
                    version_spec=version_spec,
                    evidence=[
                        {
                            "type": "lockfile",
                            "source": "package-lock.json",
                            "claim": "%s@%s is installed" % (name, version or "unknown"),
                        }
                    ],
                )
            )
            nested = metadata.get("dependencies", {})
            if isinstance(nested, dict):
                self._walk_lockfile_v1(
                    parsed=parsed,
                    dependencies=nested,
                    direct_deps=direct_deps,
                    manifest_path=manifest_path,
                    package_lock_path=package_lock_path,
                    parent_package=name,
                    inherited_type=dependency_type,
                )

    def _direct_dependencies(self, package_json: Dict[str, object]) -> Dict[str, DirectDependency]:
        direct = {}
        for group, dependency_type in DEPENDENCY_GROUPS.items():
            values = package_json.get(group, {})
            if not isinstance(values, dict):
                continue
            for name, version_spec in values.items():
                if not isinstance(version_spec, str):
                    continue
                direct[name] = DirectDependency(
                    name=name,
                    dependency_type=dependency_type,
                    version_spec=version_spec,
                )
        return direct

    def _read_json(self, path: Path) -> Dict[str, object]:
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise DependencyParserError("Invalid JSON in %s: %s" % (path, exc)) from exc
        if not isinstance(data, dict):
            raise DependencyParserError("%s must contain a JSON object" % path)
        return data

    def _dependency_key(self, dep: ParsedDependency) -> Tuple[str, Optional[str], Optional[str]]:
        return (dep.name, dep.current_version, dep.parent_package)


def parse_dependencies(repo_path: str) -> List[ParsedDependency]:
    return NodeDependencyParser().parse(repo_path)


def package_name_from_lock_path(lock_path: str) -> Optional[str]:
    marker = "node_modules/"
    if marker not in lock_path:
        return None
    tail = lock_path.rsplit(marker, 1)[-1].strip("/")
    if not tail:
        return None
    parts = tail.split("/")
    if parts[0].startswith("@") and len(parts) >= 2:
        return "%s/%s" % (parts[0], parts[1])
    return parts[0]


def package_parent_from_lock_path(lock_path: str) -> Optional[str]:
    marker = "node_modules/"
    if lock_path.count(marker) < 2:
        return None
    parent_path = lock_path.rsplit(marker, 1)[0].rstrip("/")
    return package_name_from_lock_path(parent_path)


def string_or_none(value: object) -> Optional[str]:
    if isinstance(value, str):
        return value
    return None


def infer_version_from_spec(version_spec: str) -> Optional[str]:
    match = re.search(r"(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)", version_spec)
    if match:
        return match.group(1)
    return None


def unique_dependencies(dependencies: Iterable[ParsedDependency]) -> List[ParsedDependency]:
    by_key = {}
    for dep in dependencies:
        key = (dep.name, dep.current_version, dep.parent_package)
        existing = by_key.get(key)
        if existing is None or (dep.is_direct and not existing.is_direct):
            by_key[key] = dep
    return list(by_key.values())
