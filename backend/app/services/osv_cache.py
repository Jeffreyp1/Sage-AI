"""Deterministic in-memory cache for OSV-compatible clients."""

from copy import deepcopy
from dataclasses import dataclass
from typing import Dict, List, Optional, Protocol, Tuple


class OsvLikeClient(Protocol):
    def query(
        self,
        package_name: str,
        version: Optional[str],
        ecosystem: str,
    ) -> List[Dict[str, object]]:
        ...


@dataclass(frozen=True)
class OsvCacheKey:
    ecosystem: str
    package_name: str
    version: str


class CachedOsvClient:
    """Cache successful OSV queries by ecosystem, package name, and exact version."""

    def __init__(self, client: OsvLikeClient) -> None:
        self.client = client
        self._cache: Dict[OsvCacheKey, List[Dict[str, object]]] = {}

    def query(
        self,
        package_name: str,
        version: Optional[str],
        ecosystem: str,
    ) -> List[Dict[str, object]]:
        if version is None or version.strip() == "":
            return []

        key = build_osv_cache_key(
            package_name=package_name,
            version=version,
            ecosystem=ecosystem,
        )
        if key in self._cache:
            return deepcopy(self._cache[key])

        vulnerabilities = self.client.query(
            package_name=package_name,
            version=version,
            ecosystem=ecosystem,
        )
        self._cache[key] = deepcopy(vulnerabilities)
        return deepcopy(vulnerabilities)

    def clear(self) -> None:
        self._cache.clear()

    def cache_keys(self) -> Tuple[OsvCacheKey, ...]:
        return tuple(self._cache.keys())


def build_osv_cache_key(package_name: str, version: str, ecosystem: str) -> OsvCacheKey:
    return OsvCacheKey(
        ecosystem=ecosystem.strip().casefold(),
        package_name=package_name,
        version=version,
    )
