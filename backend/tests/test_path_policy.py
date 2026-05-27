from pathlib import Path

import pytest
from pydantic import ValidationError
from unittest.mock import patch

from app.cli import main
from app.api.routes_repos import scan_local
from app.schemas.scan import ScanLocalRequest
from app.services.scan_service import ScanService
from app.services.path_policy import PathPolicyError, resolve_repo_path


class ApiSettings:
    def __init__(self, local_scan_workspace_root: str) -> None:
        self.local_scan_workspace_root = local_scan_workspace_root


def test_resolve_repo_path_allows_directory_inside_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "repo"
    repo.mkdir(parents=True)

    resolved = resolve_repo_path(".", workspace_root=repo)

    assert resolved == repo.resolve()


def test_resolve_repo_path_rejects_path_outside_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()

    with pytest.raises(PathPolicyError, match="outside the allowed workspace"):
        resolve_repo_path("../outside", workspace_root=workspace)


def test_resolve_repo_path_rejects_symlink_escape(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    (workspace / "escape").symlink_to(outside, target_is_directory=True)

    with pytest.raises(PathPolicyError, match="outside the allowed workspace"):
        resolve_repo_path("escape", workspace_root=workspace)


def test_resolve_repo_path_rejects_files(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_path = workspace / "package.json"
    file_path.write_text("{}", encoding="utf-8")

    with pytest.raises(PathPolicyError, match="not a directory"):
        resolve_repo_path("package.json", workspace_root=workspace)


def test_resolve_repo_path_rejects_absolute_file_without_leaking_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    file_path = workspace / "package.json"
    file_path.write_text("{}", encoding="utf-8")

    with pytest.raises(PathPolicyError) as caught:
        resolve_repo_path(file_path, workspace_root=workspace)

    message = str(caught.value)
    assert "not a directory" in message
    assert str(file_path) not in message
    assert str(tmp_path) not in message


def test_resolve_repo_path_rejects_missing_path(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(PathPolicyError, match="does not exist"):
        resolve_repo_path("missing", workspace_root=workspace)


def test_resolve_existing_workspace_errors_do_not_leak_absolute_paths(tmp_path):
    missing_workspace = tmp_path / "missing"

    with pytest.raises(PathPolicyError) as caught:
        resolve_repo_path(".", workspace_root=missing_workspace)

    message = str(caught.value)
    assert "Allowed workspace does not exist" in message
    assert str(missing_workspace) not in message
    assert str(tmp_path) not in message


def test_resolve_existing_workspace_os_error_does_not_leak_absolute_paths(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    def raise_os_error(self, *, strict=False):
        raise OSError("/Users/auditor/private-token permission denied")

    monkeypatch.setattr(Path, "resolve", raise_os_error)

    with pytest.raises(PathPolicyError) as caught:
        resolve_repo_path(".", workspace_root=workspace)

    message = str(caught.value)
    assert "Allowed workspace is not accessible" in message
    assert "/Users/auditor" not in message
    assert "private-token" not in message


def test_resolve_repo_path_os_error_does_not_leak_absolute_paths(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    repo = workspace / "repo"
    repo.mkdir(parents=True)
    original_resolve = Path.resolve

    def raise_for_repo(self, *, strict=False):
        if self.name == "repo":
            raise OSError("/Users/auditor/private-token permission denied")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", raise_for_repo)

    with pytest.raises(PathPolicyError) as caught:
        resolve_repo_path("repo", workspace_root=workspace)

    message = str(caught.value)
    assert "Repository path is not accessible" in message
    assert "/Users/auditor" not in message
    assert "private-token" not in message


def test_scan_service_can_enforce_workspace_path_policy(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()

    with pytest.raises(PathPolicyError, match="outside the allowed workspace"):
        ScanService().scan_local("../outside", workspace_root=workspace)


def test_scan_service_rejects_outside_absolute_path_without_workspace_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(PathPolicyError, match="outside the allowed workspace"):
        ScanService().scan_local(str(outside))


def test_cli_scan_can_enforce_workspace_path_policy(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()

    exit_code = main(
        [
            "scan",
            "../outside",
            "--offline",
            "--workspace-root",
            str(workspace),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "outside the allowed workspace" in captured.err
    assert "Traceback" not in captured.err


def test_cli_scan_rejects_outside_absolute_path_without_workspace_root(tmp_path, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()

    exit_code = main(["scan", str(outside), "--offline"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "outside the allowed workspace" in captured.err
    assert "Traceback" not in captured.err


def test_scan_local_request_rejects_client_supplied_workspace_root():
    with pytest.raises(ValidationError):
        ScanLocalRequest(
            path="repo",
            persist=False,
            workspace_root="/tmp/client-controlled",
        )


def test_api_scan_local_can_enforce_workspace_path_policy(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()

    with (
        patch(
            "app.api.routes_repos.get_settings",
            return_value=ApiSettings(str(workspace)),
        ),
        pytest.raises(Exception) as caught,
    ):
        scan_local(ScanLocalRequest(path="../outside", persist=False), db=None)

    assert getattr(caught.value, "status_code", None) == 400
    assert "outside the allowed workspace" in str(getattr(caught.value, "detail", ""))


def test_api_scan_local_rejects_outside_absolute_path_without_workspace_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(Exception) as caught:
        scan_local(
            ScanLocalRequest(path=str(outside), persist=False),
            db=None,
        )

    assert getattr(caught.value, "status_code", None) == 400
    assert "outside the allowed workspace" in str(getattr(caught.value, "detail", ""))
