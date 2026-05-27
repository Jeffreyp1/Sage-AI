"""Run deterministic backend MVP evaluation cases."""

import argparse
import json
from pathlib import Path
import tempfile
from typing import Optional

from app.eval.metrics import summarize_scores
from app.eval.verifier import verify_report
from app.services.dependency_parser import package_name_from_lock_path
from app.services.scan_service import ScanService


DEFAULT_CASE_PATH = Path(__file__).parent / "cases" / "backend_mvp.jsonl"


class FixtureOsvClient:
    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.queries: list[dict[str, object]] = []

    def query(self, package_name: str, version: Optional[str], ecosystem: str) -> list[dict[str, object]]:
        self.queries.append(
            {
                "package": package_name,
                "version": version,
                "ecosystem": ecosystem,
            }
        )
        if version is not None:
            explicit_key = "%s@%s#%s" % (package_name, version, ecosystem)
            if explicit_key in self.responses:
                return self.responses[explicit_key]
        return self.responses.get(package_name, [])


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.eval.run_eval")
    parser.add_argument("--cases", default=str(DEFAULT_CASE_PATH), help="Path to JSONL eval cases.")
    parser.add_argument("--verbose", action="store_true", help="Print per-case verifier output.")
    args = parser.parse_args(argv)

    cases = load_cases(Path(args.cases))
    results = [run_case(case) for case in cases]
    scores = [result["scores"] for result in results if isinstance(result.get("scores"), dict)]
    output = {
        "summary": summarize_scores(scores),
        "results": results if args.verbose else compact_results(results),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["summary"].get("passed") is True else 1


def run_case(case: dict[str, object]) -> dict[str, object]:
    fixture = case.get("repo_fixture")
    if not isinstance(fixture, dict):
        raise ValueError("case %s missing repo_fixture" % case.get("case_id"))
    with tempfile.TemporaryDirectory() as tmp:
        repo_path = Path(tmp)
        write_fixture_repo(repo_path, fixture)
        responses = case.get("osv_responses", {})
        if not isinstance(responses, dict):
            responses = {}
        client = FixtureOsvClient(responses=responses)
        report = ScanService(osv_client=client).scan_local(
            str(repo_path),
            workspace_root=repo_path.parent,
        ).to_dict()
    result = verify_report(case=case, report=report)
    query_findings = verify_query_inputs(case=case, actual_queries=client.queries)
    if query_findings:
        result["passed"] = False
        findings = result.get("findings", [])
        if isinstance(findings, list):
            findings.extend(query_findings)
        scores = result.get("scores", {})
        if isinstance(scores, dict):
            scores["passed"] = False
            scores["finding_count"] = int(scores.get("finding_count", 0)) + len(query_findings)
    return result


def load_cases(path: Path) -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        data = json.loads(stripped)
        if not isinstance(data, dict):
            raise ValueError("case line %s must be a JSON object" % line_number)
        cases.append(data)
    return cases


def write_fixture_repo(root: Path, fixture: dict[str, object]) -> None:
    package_json = fixture.get("package_json")
    if not isinstance(package_json, dict):
        raise ValueError("repo_fixture requires package_json")

    write_json(root / "package.json", package_json)

    lock_packages = fixture.get("lock_packages")
    if isinstance(lock_packages, dict):
        packages = {"": {}}
        packages.update(lock_packages)
        write_json(
            root / "package-lock.json",
            {
                "name": package_json.get("name", "eval-repo"),
                "lockfileVersion": 3,
                "packages": packages,
            },
        )

    files = fixture.get("files", {})
    if isinstance(files, dict):
        root = root.resolve()
        for relative_path, content in files.items():
            if not isinstance(relative_path, str) or not isinstance(content, str):
                continue
            fixture_path = Path(relative_path)
            if fixture_path.is_absolute():
                raise ValueError("fixture file path must be relative")
            path = (root / fixture_path).resolve()
            if not path.is_relative_to(root):
                raise ValueError("fixture file path must stay under repo root")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")


def write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def compact_results(results: list[dict[str, object]]) -> list[dict[str, object]]:
    compact = []
    for result in results:
        compact.append(
            {
                "case_id": result.get("case_id"),
                "passed": result.get("passed"),
                "finding_count": result.get("scores", {}).get("finding_count")
                if isinstance(result.get("scores"), dict)
                else None,
            }
        )
    return compact


def verify_query_inputs(
    case: dict[str, object],
    actual_queries: list[dict[str, object]],
) -> list[dict[str, str]]:
    expected_queries = expected_osv_queries(case)
    if sorted(actual_queries, key=query_sort_key) == sorted(expected_queries, key=query_sort_key):
        return []
    return [
        {
            "severity": "high",
            "code": "osv_query_mismatch",
            "message": "Expected OSV queries %s but got %s" % (expected_queries, actual_queries),
            "path": "osv_queries",
        }
    ]


def expected_osv_queries(case: dict[str, object]) -> list[dict[str, object]]:
    if "expected_osv_queries" in case:
        expected_queries = case.get("expected_osv_queries")
        if isinstance(expected_queries, list):
            return [query for query in expected_queries if isinstance(query, dict)]
        return []

    fixture = case.get("repo_fixture")
    if not isinstance(fixture, dict):
        return []
    lock_packages = fixture.get("lock_packages")
    if not isinstance(lock_packages, dict):
        return []

    queries: list[dict[str, object]] = []
    for lock_path, metadata in lock_packages.items():
        if not isinstance(lock_path, str) or not isinstance(metadata, dict):
            continue
        package_name = package_name_from_lock_path(lock_path)
        version = metadata.get("version")
        if package_name is None or not isinstance(version, str):
            continue
        queries.append(
            {
                "package": package_name,
                "version": version,
                "ecosystem": "npm",
            }
        )
    return queries


def query_sort_key(query: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(query.get("package")),
        str(query.get("version")),
        str(query.get("ecosystem")),
    )


if __name__ == "__main__":
    raise SystemExit(main())
