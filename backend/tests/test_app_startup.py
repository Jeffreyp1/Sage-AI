from app.main import create_app
from app.config import Settings, get_local_scan_workspace_root


def test_create_app_registers_remediation_routes() -> None:
    app = create_app()

    schema = app.openapi()

    assert "/remediation-tasks/{task_id}" in schema["paths"]
    assert "/remediation-tasks/{task_id}/approve" in schema["paths"]
    assert "/remediation-tasks/{task_id}/reject" in schema["paths"]
    assert "/remediation-tasks/{task_id}/accept-risk" in schema["paths"]
    assert "/remediation-tasks/{task_id}/draft" in schema["paths"]
    assert "requestBody" not in schema["paths"]["/remediation-tasks/{task_id}/draft"]["post"]


def test_local_scan_workspace_root_requires_explicit_root_outside_local() -> None:
    settings = Settings(environment="production", local_scan_workspace_root=None)

    try:
        get_local_scan_workspace_root(settings)
    except RuntimeError as error:
        assert "Local scan workspace root is not configured" in str(error)
    else:
        raise AssertionError("expected production settings without workspace root to fail")


def test_local_environment_defaults_workspace_root_to_current_directory() -> None:
    settings = Settings(environment="local", local_scan_workspace_root=None)

    assert get_local_scan_workspace_root(settings) == "."
