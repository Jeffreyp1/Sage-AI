"""Minimal newline-delimited JSON-RPC stdio adapter for Sage MCP tools."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
import logging
import sys
from pathlib import Path
from typing import Protocol, TextIO

from app.mcp.handlers import McpToolHandlers, ToolHandlerError
from app.services.public_safety import LOCAL_PATH_PATTERN, contains_public_leak_text
from app.services.trace_service import redact_secret_text


PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "sage-ai"
SERVER_TITLE = "Sage AI Vulnerability Triage"
SERVER_VERSION = "0.1.0"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
logger = logging.getLogger(__name__)
TOKEN_LIKE_REQUEST_ID_MARKERS = (
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private",
)


class ToolHandlerSet(Protocol):
    def list_tools(self) -> list[dict[str, object]]:
        ...

    def call_tool_dict(
        self,
        name: str,
        arguments: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        ...


class JsonRpcMcpServer:
    """Handle the MCP JSON-RPC methods supported by the local stdio adapter."""

    def __init__(self, *, handlers: ToolHandlerSet) -> None:
        self.handlers = handlers

    def handle_message(self, message: object) -> dict[str, object] | None:
        if not isinstance(message, Mapping):
            return error_response(None, INVALID_REQUEST, "Invalid Request")

        request_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return error_response(request_id, INVALID_REQUEST, "Invalid Request")

        if "id" not in message:
            return self._handle_notification(method)

        if method == "initialize":
            return success_response(request_id, initialize_result(message.get("params")))
        if method == "ping":
            return success_response(request_id, {})
        if method == "tools/list":
            return success_response(request_id, {"tools": self.handlers.list_tools()})
        if method == "tools/call":
            return self._handle_tool_call(request_id, message.get("params"))
        return error_response(request_id, METHOD_NOT_FOUND, "Method not found")

    def _handle_notification(self, method: str) -> None:
        if method == "notifications/initialized":
            return None
        return None

    def _handle_tool_call(
        self,
        request_id: object,
        params: object,
    ) -> dict[str, object]:
        if not isinstance(params, Mapping):
            return error_response(request_id, INVALID_PARAMS, "Invalid params")

        name = params.get("name")
        if not isinstance(name, str) or name.strip() == "":
            return error_response(request_id, INVALID_PARAMS, "Invalid tool name")

        arguments = params.get("arguments")
        if arguments is not None and not isinstance(arguments, Mapping):
            return error_response(request_id, INVALID_PARAMS, "Invalid tool arguments")

        try:
            output = self.handlers.call_tool_dict(name, arguments)
        except ToolHandlerError as error:
            return success_response(request_id, tool_error_result(str(error)))
        except Exception as error:
            log_unexpected_tool_error(name=name, error=error)
            return error_response(request_id, INTERNAL_ERROR, "Internal error")

        return success_response(request_id, tool_success_result(output))


def initialize_result(params: object) -> dict[str, object]:
    requested_version = None
    if isinstance(params, Mapping):
        requested = params.get("protocolVersion")
        if isinstance(requested, str) and requested.strip() != "":
            requested_version = requested

    return {
        "protocolVersion": requested_version or PROTOCOL_VERSION,
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {
            "name": SERVER_NAME,
            "title": SERVER_TITLE,
            "version": SERVER_VERSION,
        },
        "instructions": (
            "Use these tools for defensive dependency vulnerability triage. "
            "Do not request exploit payloads, offensive steps, auto-merge, or risk acceptance."
        ),
    }


def tool_success_result(output: dict[str, object]) -> dict[str, object]:
    text = json.dumps(output, sort_keys=True, separators=(",", ":"))
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": output,
        "isError": False,
    }


def log_unexpected_tool_error(*, name: str, error: Exception) -> None:
    logger.error(
        "unexpected_mcp_tool_error tool=%s error_type=%s",
        safe_request_id(name),
        type(error).__name__,
    )


def log_unexpected_message_error(
    *,
    method: object,
    request_id: object,
    error: Exception,
) -> None:
    logger.error(
        "unexpected_mcp_message_error method=%s request_id=%s error_type=%s",
        safe_method_name(method),
        safe_request_id(request_id),
        type(error).__name__,
    )


def safe_method_name(value: object) -> str:
    known_methods = {
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/call",
        "tools/list",
    }
    if isinstance(value, str) and value in known_methods:
        return value
    return "unknown"


def safe_request_id(value: object) -> str:
    if isinstance(value, int | float | bool):
        return str(value)
    if not isinstance(value, str):
        return "none"
    if len(value) > 80:
        return "redacted"
    if is_token_like_request_id(value):
        return "redacted"
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
    if all(character in allowed for character in value):
        return value
    return "redacted"


def is_token_like_request_id(value: str) -> bool:
    if redact_secret_text(value) != value:
        return True
    normalized = value.lower().replace("-", "_")
    compact = normalized.replace("_", "")
    for marker in TOKEN_LIKE_REQUEST_ID_MARKERS:
        if marker in normalized or marker in compact:
            return True
    return False


def tool_error_result(message: str) -> dict[str, object]:
    return {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def success_response(request_id: object, result: dict[str, object]) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": public_response_id(request_id), "result": result}


def error_response(
    request_id: object,
    code: int,
    message: str,
    data: dict[str, object] | None = None,
) -> dict[str, object]:
    error: dict[str, object] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": public_response_id(request_id), "error": error}


def public_response_id(request_id: object) -> object:
    if isinstance(request_id, str):
        if (
            safe_request_id(request_id) != request_id
            or is_local_path_request_id(request_id)
            or contains_public_leak_text(request_id)
        ):
            return "redacted"
        return request_id
    if isinstance(request_id, bool):
        return "redacted"
    if isinstance(request_id, int | float):
        return request_id
    if request_id is None:
        return None
    return "redacted"


def is_local_path_request_id(value: str) -> bool:
    return LOCAL_PATH_PATTERN.search(value) is not None


def run_stdio_server(
    *,
    server: JsonRpcMcpServer,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    for raw_line in stdin:
        line = raw_line.strip()
        if line == "":
            continue

        response = response_for_line(server, line)
        if response is None:
            continue

        stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
        stdout.flush()
    return 0


def response_for_line(
    server: JsonRpcMcpServer,
    line: str,
) -> dict[str, object] | None:
    try:
        message = json.loads(line)
    except json.JSONDecodeError as error:
        return error_response(None, PARSE_ERROR, "Parse error", {"detail": error.msg})

    try:
        return server.handle_message(message)
    except Exception as error:
        request_id = message.get("id") if isinstance(message, Mapping) else None
        method = message.get("method") if isinstance(message, Mapping) else None
        log_unexpected_message_error(
            method=method,
            request_id=request_id,
            error=error,
        )
        return error_response(request_id, INTERNAL_ERROR, "Internal error")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnsage-mcp")
    parser.add_argument(
        "--workspace-root",
        default=".",
        help="Allowed repository workspace root for local MCP scans.",
    )
    parser.add_argument(
        "--storage-dir",
        help="Optional directory for MCP scan reports. Defaults under the workspace root.",
    )
    args = parser.parse_args(argv)

    try:
        handlers = McpToolHandlers(
            workspace_root=Path(args.workspace_root),
            storage_dir=None if args.storage_dir is None else Path(args.storage_dir),
        )
    except ToolHandlerError as error:
        print("vulnsage-mcp: %s" % error, file=sys.stderr)
        return 1

    server = JsonRpcMcpServer(handlers=handlers)
    return run_stdio_server(server=server)


if __name__ == "__main__":
    raise SystemExit(main())
