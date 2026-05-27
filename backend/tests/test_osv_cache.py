import unittest

from app.services.osv_cache import CachedOsvClient, OsvCacheKey, build_osv_cache_key
from app.services.osv_client import OsvClientError


class RecordingOsvClient:
    def __init__(self):
        self.calls = []
        self.responses = {}

    def query(self, package_name, version, ecosystem):
        self.calls.append(
            {
                "package_name": package_name,
                "version": version,
                "ecosystem": ecosystem,
            }
        )
        key = (ecosystem, package_name, version)
        return self.responses.get(key, [])


class FailsOnceOsvClient:
    def __init__(self):
        self.calls = 0

    def query(self, package_name, version, ecosystem):
        self.calls += 1
        if self.calls == 1:
            raise OsvClientError("provider unavailable")
        return [{"id": "GHSA-retry"}]


class CachedOsvClientTest(unittest.TestCase):
    def test_cache_hit_avoids_upstream_call(self):
        upstream = RecordingOsvClient()
        upstream.responses[("npm", "lodash", "4.17.20")] = [{"id": "GHSA-test"}]
        client = CachedOsvClient(upstream)

        first = client.query("lodash", "4.17.20", "npm")
        second = client.query("lodash", "4.17.20", "npm")

        self.assertEqual(first, [{"id": "GHSA-test"}])
        self.assertEqual(second, [{"id": "GHSA-test"}])
        self.assertEqual(len(upstream.calls), 1)

    def test_separate_versions_and_packages_do_not_collide(self):
        upstream = RecordingOsvClient()
        upstream.responses[("npm", "lodash", "4.17.20")] = [{"id": "GHSA-lodash-old"}]
        upstream.responses[("npm", "lodash", "4.17.21")] = [{"id": "GHSA-lodash-new"}]
        upstream.responses[("npm", "left-pad", "4.17.20")] = [{"id": "GHSA-left-pad"}]
        client = CachedOsvClient(upstream)

        self.assertEqual(client.query("lodash", "4.17.20", "npm"), [{"id": "GHSA-lodash-old"}])
        self.assertEqual(client.query("lodash", "4.17.21", "npm"), [{"id": "GHSA-lodash-new"}])
        self.assertEqual(client.query("left-pad", "4.17.20", "npm"), [{"id": "GHSA-left-pad"}])

        self.assertEqual(len(upstream.calls), 3)

    def test_empty_version_bypasses_upstream(self):
        upstream = RecordingOsvClient()
        client = CachedOsvClient(upstream)

        self.assertEqual(client.query("lodash", None, "npm"), [])
        self.assertEqual(client.query("lodash", "", "npm"), [])
        self.assertEqual(client.query("lodash", "   ", "npm"), [])
        self.assertEqual(upstream.calls, [])

    def test_upstream_errors_are_not_cached(self):
        upstream = FailsOnceOsvClient()
        client = CachedOsvClient(upstream)

        with self.assertRaises(OsvClientError):
            client.query("lodash", "4.17.20", "npm")

        self.assertEqual(client.query("lodash", "4.17.20", "npm"), [{"id": "GHSA-retry"}])
        self.assertEqual(upstream.calls, 2)

    def test_ecosystem_case_is_normalized_but_package_name_is_exact(self):
        upstream = RecordingOsvClient()
        upstream.responses[("PyPI", "Django", "4.2.0")] = [{"id": "GHSA-django-upper"}]
        upstream.responses[("pypi", "django", "4.2.0")] = [{"id": "GHSA-django-lower"}]
        client = CachedOsvClient(upstream)

        self.assertEqual(client.query("Django", "4.2.0", "PyPI"), [{"id": "GHSA-django-upper"}])
        self.assertEqual(client.query("Django", "4.2.0", "pypi"), [{"id": "GHSA-django-upper"}])
        self.assertEqual(client.query("django", "4.2.0", "pypi"), [{"id": "GHSA-django-lower"}])
        self.assertEqual(len(upstream.calls), 2)
        self.assertEqual(
            build_osv_cache_key("Django", "4.2.0", " PyPI "),
            OsvCacheKey(ecosystem="pypi", package_name="Django", version="4.2.0"),
        )


if __name__ == "__main__":
    unittest.main()
