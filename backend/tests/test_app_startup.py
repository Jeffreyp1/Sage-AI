from app.main import create_app


def test_create_app_registers_remediation_routes() -> None:
    app = create_app()

    schema = app.openapi()

    assert "/remediation-tasks/{task_id}" in schema["paths"]
    assert "/remediation-tasks/{task_id}/approve" in schema["paths"]
    assert "/remediation-tasks/{task_id}/reject" in schema["paths"]
    assert "/remediation-tasks/{task_id}/accept-risk" in schema["paths"]
    assert "/remediation-tasks/{task_id}/draft" in schema["paths"]
    assert "requestBody" not in schema["paths"]["/remediation-tasks/{task_id}/draft"]["post"]
