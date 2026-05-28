"""Small OSV API client using the Python standard library."""

from dataclasses import dataclass
import json
from typing import Dict, List, Optional
from urllib import error, request


class OsvClientError(RuntimeError):
    """Raised when OSV cannot be queried."""


@dataclass
class OsvQuery:
    package_name: str
    version: str
    ecosystem: str

    def to_payload(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "package": {
                "name": self.package_name,
                "ecosystem": self.ecosystem,
            },
        }


class OsvClient:
    def __init__(
        self,
        api_url: str = "https://api.osv.dev/v1/query",
        timeout_seconds: int = 20,
        opener=None,
    ) -> None:
        self.api_url = api_url
        self.timeout_seconds = timeout_seconds
        self.opener = opener or request.urlopen

    def query(self, package_name: str, version: Optional[str], ecosystem: str) -> List[Dict[str, object]]:
        if not version:
            return []
        query = OsvQuery(package_name=package_name, version=version, ecosystem=ecosystem)
        payload = json.dumps(query.to_payload()).encode("utf-8")
        req = request.Request(
            self.api_url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "sage-ai/0.1",
            },
        )
        try:
            with self.opener(req, timeout=self.timeout_seconds) as response:
                body = response.read().decode("utf-8")
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OsvClientError("OSV HTTP %s: %s" % (exc.code, detail)) from exc
        except error.URLError as exc:
            raise OsvClientError("OSV request failed: %s" % exc.reason) from exc
        except UnicodeDecodeError as exc:
            raise OsvClientError("OSV returned undecodable response") from exc
        except TimeoutError as exc:
            raise OsvClientError("OSV request timed out: %s" % exc) from exc
        except OSError as exc:
            raise OsvClientError("OSV request failed: %s" % exc) from exc
        except OsvClientError:
            raise
        except Exception as exc:
            raise OsvClientError("OSV request failed: %s" % exc) from exc

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise OsvClientError("OSV returned invalid JSON") from exc

        vulnerabilities = data.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise OsvClientError("OSV returned malformed vulnerability list")
        if not all(isinstance(item, dict) for item in vulnerabilities):
            raise OsvClientError("OSV returned malformed vulnerability entries")
        return [item for item in vulnerabilities if isinstance(item, dict)]
