import io
import json
import logging
from collections.abc import Mapping
from pathlib import Path
import tomllib

from app.mcp.handlers import McpToolHandlers
from app.mcp.handlers import ToolHandlerError
from app.mcp.stdio_server import (
    JsonRpcMcpServer,
    error_response,
    response_for_line,
    run_stdio_server,
    success_response,
)


class FakeHandlers:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def list_tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": "scan_repo",
                "description": "Scan a repository.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "repo_path": {"type": "string"},
                    },
                },
            }
        ]

    def call_tool_dict(
        self,
        name: str,
        arguments: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        payload = {} if arguments is None else dict(arguments)
        self.calls.append((name, payload))
        if name == "explode":
            raise ToolHandlerError("controlled failure")
        if name == "unexpected":
            raise RuntimeError("/Users/example/private/repo secret-ish internal detail")
        return {"tool_name": name, "arguments": payload}


class FailingListToolsHandlers(FakeHandlers):
    def list_tools(self) -> list[dict[str, object]]:
        raise RuntimeError("/Users/example/private/repo list tools crash")


class FailingScanService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Path | None]] = []

    def scan_local(
        self,
        repo_path: str,
        *,
        workspace_root: str | Path | None = None,
    ) -> object:
        root_path = None if workspace_root is None else Path(workspace_root)
        self.calls.append((repo_path, root_path))
        raise AssertionError("scan service should not be called")


def test_initialize_returns_tools_capability_and_server_info():
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
        }
    )

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    result = response["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"] == {"tools": {"listChanged": False}}
    assert result["serverInfo"]["name"] == "sage-ai"
    assert "defensive" in result["instructions"].lower()


def test_initialized_notification_returns_no_response():
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )

    assert response is None


def test_tools_list_returns_handler_tool_schemas():
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"}
    )

    assert response["id"] == "tools"
    assert response["result"]["tools"][0]["name"] == "scan_repo"
    assert response["result"]["tools"][0]["inputSchema"]["type"] == "object"


def test_tools_list_real_handler_exposes_mcp_usability_tools(tmp_path):
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=tmp_path,
            storage_dir=tmp_path / "reports",
        )
    )

    response = server.handle_message(
        {"jsonrpc": "2.0", "id": "tools", "method": "tools/list"}
    )

    tools = response["result"]["tools"]
    by_name = {tool["name"]: tool for tool in tools}
    assert "scan_current_repo" in by_name
    assert "get_vulnerability_brief" in by_name
    assert "explain_top_risks" in by_name
    assert "repo_path" not in by_name["scan_current_repo"]["inputSchema"]["properties"]


def test_tools_call_returns_text_and_structured_content():
    handlers = FakeHandlers()
    server = JsonRpcMcpServer(handlers=handlers)

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "scan_repo",
                "arguments": {"repo_path": "demo-repos/payments-api", "offline": True},
            },
        }
    )

    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"] == {
        "tool_name": "scan_repo",
        "arguments": {"repo_path": "demo-repos/payments-api", "offline": True},
    }
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]
    assert handlers.calls == [
        ("scan_repo", {"repo_path": "demo-repos/payments-api", "offline": True})
    ]


def test_tools_call_controlled_handler_error_returns_tool_error_result():
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "explode", "arguments": {}},
        }
    )

    assert "error" not in response
    result = response["result"]
    assert result["isError"] is True
    assert result["content"] == [{"type": "text", "text": "controlled failure"}]


def test_tools_call_validation_error_does_not_echo_rejected_input(tmp_path):
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=tmp_path,
            storage_dir=tmp_path / "reports",
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": {
                "name": "scan_repo",
                "arguments": {
                    "repo_path": 123,
                    "secret": "/Users/example/private/repo-secret",
                },
            },
        }
    )

    assert "error" not in response
    serialized = json.dumps(response)
    assert "Invalid input for scan_repo" in serialized
    assert "repo_path:string_type" in serialized
    assert "repo-secret" not in serialized
    assert "/Users/example" not in serialized


def test_scan_current_repo_stdio_rejects_repo_path_extra_field_before_scanning(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    scan_service = FailingScanService()
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=workspace,
            storage_dir=workspace / "reports",
            scan_service=scan_service,
        )
    )

    response = response_for_line(
        server,
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {
                    "name": "scan_current_repo",
                    "arguments": {"repo_path": "payments-api", "max_findings": 1},
                },
            }
        ),
    )

    assert "error" not in response
    result = response["result"]
    assert result["isError"] is True
    assert "Invalid input for scan_current_repo" in result["content"][0]["text"]
    assert "repo_path:extra_forbidden" in result["content"][0]["text"]
    assert scan_service.calls == []


def test_tools_call_unknown_tool_does_not_echo_tool_name(tmp_path):
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=tmp_path,
            storage_dir=tmp_path / "reports",
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": {"name": "/Users/example/token-tool", "arguments": {}},
        }
    )

    assert "error" not in response
    serialized = json.dumps(response)
    assert "Unknown MCP tool" in serialized
    assert "token-tool" not in serialized
    assert "/Users/example" not in serialized


def test_unknown_method_returns_json_rpc_method_error():
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {"jsonrpc": "2.0", "id": 4, "method": "resources/list"}
    )

    assert response["error"]["code"] == -32601
    assert response["error"]["message"] == "Method not found"


def test_tools_call_unexpected_exception_hides_internal_details():
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "unexpected", "arguments": {}},
        }
    )

    assert response["error"]["code"] == -32603
    assert response["error"]["message"] == "Internal error"
    assert "data" not in response["error"]
    assert "/Users/example" not in json.dumps(response)
    assert "secret-ish" not in json.dumps(response)


def test_tools_call_unexpected_exception_logs_sanitized_context(caplog):
    caplog.set_level(logging.ERROR, logger="app.mcp.stdio_server")
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "unexpected", "arguments": {}},
        }
    )

    assert response["error"]["message"] == "Internal error"
    assert "unexpected_mcp_tool_error" in caplog.text
    assert "unexpected" in caplog.text
    assert "/Users/example" not in caplog.text
    assert "secret-ish" not in caplog.text


def test_tools_list_unexpected_exception_hides_internal_details():
    server = JsonRpcMcpServer(handlers=FailingListToolsHandlers())

    response = response_for_line(
        server,
        '{"jsonrpc":"2.0","id":6,"method":"tools/list"}',
    )

    assert response["error"]["code"] == -32603
    assert response["error"]["message"] == "Internal error"
    assert "data" not in response["error"]
    serialized = json.dumps(response)
    assert "/Users/example" not in serialized
    assert "private" not in serialized


def test_tools_list_unexpected_exception_logs_sanitized_context(caplog):
    caplog.set_level(logging.ERROR, logger="app.mcp.stdio_server")
    server = JsonRpcMcpServer(handlers=FailingListToolsHandlers())

    response = response_for_line(
        server,
        '{"jsonrpc":"2.0","id":"tools","method":"tools/list"}',
    )

    assert response["error"]["message"] == "Internal error"
    assert "unexpected_mcp_message_error" in caplog.text
    assert "tools/list" in caplog.text
    assert "request_id=tools" in caplog.text
    assert "RuntimeError" in caplog.text
    assert "/Users/example" not in caplog.text
    assert "private" not in caplog.text


def test_message_error_logs_redacted_token_like_request_id(caplog):
    caplog.set_level(logging.ERROR, logger="app.mcp.stdio_server")
    token_id = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    server = JsonRpcMcpServer(handlers=FailingListToolsHandlers())

    response = response_for_line(
        server,
        json.dumps({"jsonrpc": "2.0", "id": token_id, "method": "tools/list"}),
    )

    assert response["error"]["message"] == "Internal error"
    assert response["id"] == "redacted"
    assert "unexpected_mcp_message_error" in caplog.text
    assert "request_id=redacted" in caplog.text
    assert token_id not in caplog.text


def test_response_ids_redact_token_like_strings_but_preserve_safe_ids():
    success = success_response("request-token-123", {})
    bearer_error = error_response("Bearer abcdefghijklmnop", -32603, "Internal error")
    safe = success_response("safe-request-123", {})
    numeric = success_response(123, {})

    assert success["id"] == "redacted"
    assert bearer_error["id"] == "redacted"
    assert safe["id"] == "safe-request-123"
    assert numeric["id"] == 123


def test_response_ids_redact_local_path_strings_but_preserve_safe_ids():
    path_success = success_response("/Users/auditor/repo", {})
    private_error = error_response("/private/tmp/repo", -32603, "Internal error")
    safe = success_response("safe-request-123", {})
    numeric = success_response(123, {})

    assert path_success["id"] == "redacted"
    assert private_error["id"] == "redacted"
    assert safe["id"] == "safe-request-123"
    assert numeric["id"] == 123


def test_response_ids_redact_unsafe_string_values_but_preserve_safe_ids():
    etc_path = success_response("/etc/passwd", {})
    unsafe_phrase = error_response("proof-of-concept-payload-lib", -32603, "Internal error")
    safe = success_response("safe-request-123", {})

    assert etc_path["id"] == "redacted"
    assert unsafe_phrase["id"] == "redacted"
    assert safe["id"] == "safe-request-123"
    serialized = json.dumps({"etc": etc_path, "unsafe": unsafe_phrase})
    assert "/etc/passwd" not in serialized
    assert "proof-of-concept-payload-lib" not in serialized


def test_response_ids_redact_non_scalar_values():
    object_error = error_response(
        {"path": "/Users/auditor/private-token"},
        -32600,
        "Invalid Request",
    )
    list_error = error_response(
        ["/Users/auditor/private-token"],
        -32600,
        "Invalid Request",
    )

    assert object_error["id"] == "redacted"
    assert list_error["id"] == "redacted"
    assert "/Users/auditor" not in json.dumps(object_error)
    assert "private-token" not in json.dumps(list_error)


def test_scan_repo_path_escape_error_does_not_leak_local_paths(tmp_path):
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside"
    workspace.mkdir()
    outside.mkdir()
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=workspace,
            storage_dir=workspace / "reports",
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "scan_repo", "arguments": {"repo_path": "../outside"}},
        }
    )

    result = response["result"]
    assert result["isError"] is True
    serialized = json.dumps(response)
    assert "outside the allowed workspace" in serialized
    assert str(tmp_path) not in serialized
    assert str(outside) not in serialized


def test_scan_repo_missing_absolute_path_does_not_leak_local_paths(tmp_path):
    workspace = tmp_path / "workspace"
    missing = tmp_path / "missing-outside-repo"
    workspace.mkdir()
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=workspace,
            storage_dir=workspace / "reports",
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {"name": "scan_repo", "arguments": {"repo_path": str(missing)}},
        }
    )

    result = response["result"]
    assert result["isError"] is True
    serialized = json.dumps(response)
    assert "Repository path does not exist" in serialized
    assert str(tmp_path) not in serialized
    assert str(missing) not in serialized


def test_scan_repo_malformed_manifest_error_does_not_leak_local_paths(tmp_path):
    workspace = tmp_path / "workspace"
    repo = workspace / "repo"
    repo.mkdir(parents=True)
    (repo / "package.json").write_text("{not-json", encoding="utf-8")
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=workspace,
            storage_dir=workspace / "reports",
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "scan_repo",
                "arguments": {"repo_path": "repo", "offline": True},
            },
        }
    )

    result = response["result"]
    assert result["isError"] is True
    serialized = json.dumps(response)
    assert "Invalid JSON" in serialized
    assert str(tmp_path) not in serialized
    assert "package.json" not in serialized


def test_validate_report_path_escape_error_does_not_leak_local_paths(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside_report = tmp_path / "outside-report.json"
    outside_report.write_text("{}", encoding="utf-8")
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=workspace,
            storage_dir=workspace / "reports",
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "validate_report",
                "arguments": {"report_path": str(outside_report)},
            },
        }
    )

    result = response["result"]
    assert result["isError"] is True
    serialized = json.dumps(response)
    assert "store-relative" in serialized
    assert str(tmp_path) not in serialized
    assert str(outside_report) not in serialized


def test_validate_report_non_utf8_file_returns_controlled_tool_error(tmp_path):
    workspace = tmp_path / "workspace"
    storage = workspace / "reports"
    workspace.mkdir()
    storage.mkdir()
    report_path = storage / "bad-report.json"
    report_path.write_bytes(b"\xff\xfe\xfa")
    server = JsonRpcMcpServer(
        handlers=McpToolHandlers(
            workspace_root=workspace,
            storage_dir=storage,
        )
    )

    response = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "validate_report",
                "arguments": {"report_path": report_path.name},
            },
        }
    )

    assert "error" not in response
    result = response["result"]
    assert result["isError"] is True
    serialized = json.dumps(response)
    assert "Scan report is not valid JSON" in serialized
    assert "bad-report.json" in serialized
    assert str(tmp_path) not in serialized


def test_stdio_server_writes_only_json_rpc_lines_to_stdout():
    stdin = io.StringIO(
        "\n".join(
            [
                '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                '{"jsonrpc":"2.0","method":"notifications/initialized"}',
                "{not-json",
            ]
        )
        + "\n"
    )
    stdout = io.StringIO()
    stderr = io.StringIO()
    server = JsonRpcMcpServer(handlers=FakeHandlers())

    exit_code = run_stdio_server(server=server, stdin=stdin, stdout=stdout, stderr=stderr)

    assert exit_code == 0
    assert stderr.getvalue() == ""
    lines = stdout.getvalue().splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed[0]["result"]["tools"][0]["name"] == "scan_repo"
    assert parsed[1]["error"]["code"] == -32700


def test_pyproject_exposes_vulnsage_mcp_console_script():
    pyproject_path = Path(__file__).parents[1] / "pyproject.toml"
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["vulnsage-mcp"] == "app.mcp.stdio_server:main"
