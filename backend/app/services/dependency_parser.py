"""Dependency parsers for repository manifests and lockfiles."""

from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
import re
import tomllib
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

PYTHON_REQUIREMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(.*)$"
)
PYTHON_VERSION_OPERATOR_PATTERN = re.compile(r"^(===|==|~=|!=|<=|>=|<|>)\s*(.+)$")


class NodeDependencyParser:
    """Parse npm package manifests and package-lock files."""

    ecosystem = "npm"

    def parse(self, repo_path: str) -> List[ParsedDependency]:
        root = Path(repo_path).resolve()
        package_json_path = root / "package.json"
        package_lock_path = root / "package-lock.json"

        if not package_json_path.exists():
            return []
        self._ensure_dependency_file_inside_repo(package_json_path, root)

        package_json = self._read_json(package_json_path)
        direct_deps = self._direct_dependencies(package_json)

        if package_lock_path.exists():
            self._ensure_dependency_file_inside_repo(package_lock_path, root)
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
        except UnicodeDecodeError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc
        except OSError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc
        except json.JSONDecodeError as exc:
            raise DependencyParserError(
                "Invalid JSON in dependency file: %s" % exc.msg
            ) from exc
        if not isinstance(data, dict):
            raise DependencyParserError("Dependency file must contain a JSON object")
        return data

    def _ensure_dependency_file_inside_repo(self, path: Path, root: Path) -> None:
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc
        if not resolved.is_file():
            raise DependencyParserError("Dependency path is not a file")
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise DependencyParserError("Dependency file is outside the repository") from exc

    def _dependency_key(self, dep: ParsedDependency) -> Tuple[str, Optional[str], Optional[str]]:
        return (dep.name, dep.current_version, dep.parent_package)


class PythonDependencyParser:
    """Parse Python requirements and PEP 621 project metadata."""

    ecosystem = "PyPI"

    def parse(self, repo_path: str) -> List[ParsedDependency]:
        root = Path(repo_path).resolve()
        dependencies = []

        requirements_path = root / "requirements.txt"
        if requirements_path.exists():
            self._ensure_dependency_file_inside_repo(requirements_path, root)
            dependencies.extend(self._parse_requirements(requirements_path))

        pyproject_path = root / "pyproject.toml"
        if pyproject_path.exists():
            self._ensure_dependency_file_inside_repo(pyproject_path, root)
            pyproject = self._read_toml(pyproject_path)
            dependencies.extend(self._parse_pyproject(pyproject_path, pyproject))

        return sorted(
            unique_python_dependencies(dependencies),
            key=lambda dep: (dep.name, dep.dependency_type, dep.current_version or ""),
        )

    def _parse_requirements(self, path: Path) -> List[ParsedDependency]:
        content = self._read_text(path)
        dependencies = []
        for line in content.splitlines():
            requirement = self._clean_requirement_line(line)
            if not requirement:
                continue
            parsed = self._parse_requirement(
                requirement=requirement,
                manifest_path=path,
                dependency_type="dependencies",
                source="requirements.txt",
            )
            if parsed is not None:
                dependencies.append(parsed)
        return dependencies

    def _parse_pyproject(
        self,
        path: Path,
        pyproject: Dict[str, object],
    ) -> List[ParsedDependency]:
        project = pyproject.get("project")
        if not isinstance(project, dict):
            return []

        dependencies = []
        project_dependencies = project.get("dependencies", [])
        if isinstance(project_dependencies, list):
            dependencies.extend(
                self._parse_dependency_list(
                    requirements=project_dependencies,
                    manifest_path=path,
                    dependency_type="dependencies",
                    source="pyproject.toml",
                )
            )

        optional_groups = project.get("optional-dependencies", {})
        if isinstance(optional_groups, dict):
            for group_name, group_dependencies in optional_groups.items():
                if not isinstance(group_dependencies, list):
                    continue
                dependencies.extend(
                    self._parse_dependency_list(
                        requirements=group_dependencies,
                        manifest_path=path,
                        dependency_type=python_optional_dependency_type(group_name),
                        source="pyproject.toml",
                    )
                )
        return dependencies

    def _parse_dependency_list(
        self,
        requirements: List[object],
        manifest_path: Path,
        dependency_type: str,
        source: str,
    ) -> List[ParsedDependency]:
        dependencies = []
        for requirement in requirements:
            if not isinstance(requirement, str):
                continue
            parsed = self._parse_requirement(
                requirement=requirement,
                manifest_path=manifest_path,
                dependency_type=dependency_type,
                source=source,
            )
            if parsed is not None:
                dependencies.append(parsed)
        return dependencies

    def _parse_requirement(
        self,
        requirement: str,
        manifest_path: Path,
        dependency_type: str,
        source: str,
    ) -> Optional[ParsedDependency]:
        requirement = requirement.split(";", 1)[0].strip()
        if not requirement or requirement.startswith(("-", ".")):
            return None

        match = PYTHON_REQUIREMENT_PATTERN.match(requirement)
        if not match:
            return None

        name = normalize_python_package_name(match.group(1))
        suffix = match.group(2).strip()
        version_spec = python_version_spec_from_suffix(suffix)
        current_version = pinned_python_version(version_spec)

        return ParsedDependency(
            name=name,
            current_version=current_version,
            ecosystem=self.ecosystem,
            dependency_type=dependency_type,
            is_direct=True,
            manifest_path=str(manifest_path),
            version_spec=version_spec,
            evidence=[
                {
                    "type": "manifest",
                    "source": source,
                    "claim": "%s is listed in %s" % (name, dependency_type),
                }
            ],
        )

    def _clean_requirement_line(self, line: str) -> str:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return ""
        return re.split(r"\s+#", stripped, maxsplit=1)[0].strip()

    def _read_text(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc
        except OSError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc

    def _read_toml(self, path: Path) -> Dict[str, object]:
        try:
            with path.open("rb") as handle:
                data = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise DependencyParserError("Invalid TOML in dependency file") from exc
        except OSError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc
        if not isinstance(data, dict):
            raise DependencyParserError("Dependency file must contain a TOML object")
        return data

    def _ensure_dependency_file_inside_repo(self, path: Path, root: Path) -> None:
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise DependencyParserError("Unable to read dependency file") from exc
        if not resolved.is_file():
            raise DependencyParserError("Dependency path is not a file")
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise DependencyParserError("Dependency file is outside the repository") from exc


def parse_dependencies(repo_path: str) -> List[ParsedDependency]:
    dependencies = []
    dependencies.extend(NodeDependencyParser().parse(repo_path))
    dependencies.extend(PythonDependencyParser().parse(repo_path))
    return sorted(
        dependencies,
        key=lambda dep: (dep.ecosystem, not dep.is_direct, dep.name, dep.current_version or ""),
    )


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


def normalize_python_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def python_version_spec_from_suffix(suffix: str) -> Optional[str]:
    if not suffix:
        return None
    match = PYTHON_VERSION_OPERATOR_PATTERN.match(suffix)
    if not match:
        return suffix
    operator, version = match.groups()
    return "%s%s" % (operator, version.strip())


def pinned_python_version(version_spec: Optional[str]) -> Optional[str]:
    if version_spec is None:
        return None
    match = re.match(r"^==\s*([^,\s]+)$", version_spec)
    if match:
        return match.group(1)
    return None


def python_optional_dependency_type(group_name: object) -> str:
    if not isinstance(group_name, str):
        return "optionalDependency"
    if group_name.lower() in {"dev", "test", "tests", "testing"}:
        return "devDependency"
    return "optionalDependency"


def unique_python_dependencies(dependencies: Iterable[ParsedDependency]) -> List[ParsedDependency]:
    by_key = {}
    for dep in dependencies:
        key = (dep.ecosystem, dep.name, dep.current_version, dep.version_spec, dep.dependency_type)
        by_key.setdefault(key, dep)
    return list(by_key.values())


def unique_dependencies(dependencies: Iterable[ParsedDependency]) -> List[ParsedDependency]:
    by_key = {}
    for dep in dependencies:
        key = (dep.name, dep.current_version, dep.parent_package)
        existing = by_key.get(key)
        if existing is None or (dep.is_direct and not existing.is_direct):
            by_key[key] = dep
    return list(by_key.values())
