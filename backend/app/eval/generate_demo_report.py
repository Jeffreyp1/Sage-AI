"""Generate the deterministic public Wave 1 demo scan report."""

import argparse
import json
from pathlib import Path
from typing import Optional

from app.eval.report_validator import validate_report
from app.eval.run_eval import FixtureOsvClient
from app.services.scan_service import ScanService


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_REPO_PATH = PROJECT_ROOT / "demo-repos" / "payments-api"
DEFAULT_FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "demo_osv_responses.json"


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.eval.generate_demo_report")
    parser.add_argument(
        "--output",
        required=True,
        help="Path for the generated public scan report JSON.",
    )
    parser.add_argument(
        "--repo",
        default=str(DEFAULT_REPO_PATH),
        help="Demo repository path to scan.",
    )
    parser.add_argument(
        "--fixtures",
        default=str(DEFAULT_FIXTURE_PATH),
        help="Fixture OSV response JSON path.",
    )
    args = parser.parse_args(argv)

    report = generate_report(repo_path=Path(args.repo), fixture_path=Path(args.fixtures))
    validation = validate_report(report)
    if validation["passed"] is not True:
        print(json.dumps(validation, indent=2, sort_keys=True))
        return 1

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def generate_report(repo_path: Path, fixture_path: Path = DEFAULT_FIXTURE_PATH) -> dict[str, object]:
    responses = load_fixture_responses(fixture_path)
    report = ScanService(osv_client=FixtureOsvClient(responses)).scan_local(str(repo_path)).to_dict()
    return canonicalize_demo_report(report)


def load_fixture_responses(path: Path) -> dict[str, list[dict[str, object]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("fixture OSV responses must be a JSON object")

    responses: dict[str, list[dict[str, object]]] = {}
    for package_name, vulnerabilities in data.items():
        if not isinstance(package_name, str) or not isinstance(vulnerabilities, list):
            continue
        responses[package_name] = [
            vulnerability for vulnerability in vulnerabilities if isinstance(vulnerability, dict)
        ]
    return responses


def canonicalize_demo_report(report: dict[str, object]) -> dict[str, object]:
    report["scan_id"] = "scan_wave1_demo_payments_api"

    repo_profile = report.get("repo_profile")
    if isinstance(repo_profile, dict):
        repo_profile["root_path"] = "demo-repos/payments-api"

    remediation_tasks = report.get("remediation_tasks")
    if isinstance(remediation_tasks, list):
        for index, task in enumerate(remediation_tasks, start=1):
            if isinstance(task, dict):
                task["task_id"] = "task_wave1_demo_%02d" % index

    canonicalize_public_path_fields(report)
    return report


def canonicalize_public_path_fields(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and key.endswith("_path") and isinstance(item, str):
                value[key] = canonicalize_public_path(item)
                continue
            canonicalize_public_path_fields(item)
        return

    if isinstance(value, list):
        for item in value:
            canonicalize_public_path_fields(item)


def canonicalize_public_path(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        return value

    resolved_path = path.resolve(strict=False)
    try:
        return resolved_path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        stable_name = resolved_path.name
        if stable_name != "":
            return stable_name
        return path.name or value


if __name__ == "__main__":
    raise SystemExit(main())
