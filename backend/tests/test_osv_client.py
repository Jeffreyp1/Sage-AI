import json
import unittest

from app.services.osv_client import OsvClient


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class OsvClientTest(unittest.TestCase):
    def test_query_posts_expected_payload_and_returns_vulns(self):
        captured = {}

        def opener(request, timeout):
            captured["timeout"] = timeout
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse({"vulns": [{"id": "GHSA-test"}]})

        client = OsvClient(api_url="https://example.test/query", timeout_seconds=7, opener=opener)
        vulns = client.query("lodash", "4.17.20", "npm")

        self.assertEqual(vulns, [{"id": "GHSA-test"}])
        self.assertEqual(captured["timeout"], 7)
        self.assertEqual(
            captured["payload"],
            {
                "version": "4.17.20",
                "package": {"name": "lodash", "ecosystem": "npm"},
            },
        )

    def test_query_without_version_returns_no_results(self):
        client = OsvClient(opener=lambda _request, _timeout: self.fail("should not call opener"))
        self.assertEqual(client.query("lodash", None, "npm"), [])


if __name__ == "__main__":
    unittest.main()

