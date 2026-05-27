import json
from pathlib import Path

from app.eval.generate_demo_report import (
    DEFAULT_FIXTURE_PATH,
    generate_report,
    load_fixture_responses,
)
from app.eval.run_eval import FixtureOsvClient
from app.schemas.report import REPORT_SCHEMA_VERSION, ScanReport
from app.schemas.scan import ScanLocalResponse
from app.services.scan_service import ScanService


def test_demo_scan_report_matches_frozen_schema():
    project_root = Path(__file__).resolve().parents[2]
    report = generate_report(
        repo_path=project_root / "demo-repos" / "payments-api",
        fixture_path=DEFAULT_FIXTURE_PATH,
    )

    parsed = ScanReport.model_validate(report)

    assert parsed.schema_version == REPORT_SCHEMA_VERSION
    assert parsed.scan_id == "scan_wave1_demo_payments_api"
    assert parsed.summary.complete is True
    assert parsed.summary.scan_status == "complete"
    assert parsed.summary.error_count == 0
    assert len(parsed.remediation_tasks) == 2
    assert parsed.remediation_tasks[0].risk.priority == "P0_RELEASE_BLOCKER"
    assert parsed.remediation_tasks[0].evidence[0].claim


def test_scan_result_public_report_does_not_expose_absolute_local_paths():
    project_root = Path(__file__).resolve().parents[2]
    repo_path = project_root / "demo-repos" / "payments-api"
    responses = load_fixture_responses(DEFAULT_FIXTURE_PATH)

    report = ScanService(osv_client=FixtureOsvClient(responses)).scan_local(
        str(repo_path),
        workspace_root=repo_path.parent,
    ).to_dict()
    serialized = json.dumps(report)

    assert str(project_root) not in serialized
    assert report["repo_profile"]["root_path"] == "payments-api"
    for package in report["packages"]:
        manifest_path = package.get("manifest_path")
        lockfile_path = package.get("lockfile_path")
        if manifest_path is not None:
            assert not Path(manifest_path).is_absolute()
        if lockfile_path is not None:
            assert not Path(lockfile_path).is_absolute()


def test_scan_report_schema_rejects_missing_completion_status():
    raw_report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scan_id": "scan_missing_summary_status",
        "repo_profile": {"repo_name": "repo"},
        "packages": [],
        "vulnerabilities": [],
        "remediation_tasks": [],
        "summary": {
            "packages": 0,
            "raw_alerts": 0,
            "deduped_remediation_tasks": 0,
            "release_blockers": 0,
        },
        "errors": [],
    }

    try:
        ScanReport.model_validate(raw_report)
    except Exception as error:
        message = str(error)
    else:
        raise AssertionError("ScanReport should require complete and scan_status")

    assert "complete" in message
    assert "scan_status" in message


def test_scan_report_schema_rejects_unknown_top_level_fields():
    project_root = Path(__file__).resolve().parents[2]
    report = generate_report(
        repo_path=project_root / "demo-repos" / "payments-api",
        fixture_path=DEFAULT_FIXTURE_PATH,
    )
    report["unexpected"] = "not allowed"

    try:
        ScanReport.model_validate(report)
    except Exception as error:
        message = str(error)
    else:
        raise AssertionError("ScanReport should reject unknown top-level fields")

    assert "unexpected" in message


def test_scan_report_schema_rejects_unknown_nested_fields():
    project_root = Path(__file__).resolve().parents[2]
    report = generate_report(
        repo_path=project_root / "demo-repos" / "payments-api",
        fixture_path=DEFAULT_FIXTURE_PATH,
    )
    report["summary"]["unexpected"] = "not allowed"

    try:
        ScanReport.model_validate(report)
    except Exception as error:
        message = str(error)
    else:
        raise AssertionError("ScanReport should reject unknown nested fields")

    assert "unexpected" in message


def test_scan_report_schema_is_json_schema_exportable():
    schema = ScanReport.model_json_schema()

    encoded = json.dumps(schema)

    assert "ScanReport" in encoded
    assert "remediation_tasks" in encoded
    assert "schema_version" in encoded


def test_scan_local_response_schema_uses_typed_projection_models():
    schema = ScanLocalResponse.model_json_schema()
    properties = schema["properties"]

    assert schema["additionalProperties"] is False
    assert "$ref" in properties["repo_profile"]
    assert "$ref" in properties["summary"]
    assert "$ref" in properties["remediation_tasks"]["items"]
