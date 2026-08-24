"""Dependency-free MCP stdio server for the Kiro Security workbench."""

import json
import sys

from .errors import WorkbenchError
from .mcp_tools import (
    SERVER_NAME,
    SERVER_VERSION,
    TOOL_DEFINITIONS,
    WorkbenchTools,
)

MAX_MESSAGE_BYTES = 4 * 1024 * 1024
SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
)
LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[-1]
TOOL_NAMES = frozenset(tool["name"] for tool in TOOL_DEFINITIONS)


class McpServer:
    """Synchronous newline-delimited JSON-RPC server."""

    def __init__(self, tools=None):
        # type: (object) -> None
        self.tools = tools if tools is not None else WorkbenchTools()
        self.initialize_responded = False
        self.initialized = False

    def handle(self, message):
        # type: (object) -> object
        if not isinstance(message, dict):
            return _error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        method = message.get("method")
        if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
            return _error(request_id, -32600, "Invalid Request")

        is_notification = "id" not in message
        if is_notification:
            if method == "notifications/initialized":
                if self.initialize_responded:
                    self.initialized = True
            return None

        if method == "initialize":
            return self._initialize(request_id, message.get("params"))
        if method == "ping":
            return _result(request_id, {})
        if not self.initialized:
            return _error(
                request_id,
                -32002,
                "Server is not initialized.",
            )
        if method == "tools/list":
            params = message.get("params")
            if params is not None and not isinstance(params, dict):
                return _error(request_id, -32602, "Invalid tools/list parameters.")
            return _result(request_id, {"tools": list(TOOL_DEFINITIONS)})
        if method == "tools/call":
            return self._call_tool(request_id, message.get("params"))
        return _error(request_id, -32601, "Method not found.")

    def _initialize(self, request_id, params):
        if self.initialize_responded:
            return _error(request_id, -32600, "Server is already initialized.")
        if not isinstance(params, dict):
            return _error(request_id, -32602, "Invalid initialize parameters.")
        requested = params.get("protocolVersion")
        if not isinstance(requested, str):
            return _error(request_id, -32602, "protocolVersion is required.")
        negotiated = (
            requested
            if requested in SUPPORTED_PROTOCOL_VERSIONS
            else LATEST_PROTOCOL_VERSION
        )
        self.initialize_responded = True
        return _result(
            request_id,
            {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "title": "Kiro Security Power",
                    "version": SERVER_VERSION,
                },
                "instructions": (
                    "Keep the opaque logical workspace and scan identifiers returned "
                    "by this server within the active security workflow. "
                    "After start, call kiro_security_get_scan_context with the "
                    "returned scanId before semantic work."
                ),
            },
        )

    def _call_tool(self, request_id, params):
        if not isinstance(params, dict):
            return _error(request_id, -32602, "Invalid tools/call parameters.")
        name = params.get("name")
        if not isinstance(name, str) or name not in TOOL_NAMES:
            return _error(request_id, -32602, "Unknown Kiro Security tool.")
        arguments = params.get("arguments", {})
        try:
            value = self.tools.call(name, arguments)
            return _result(request_id, _tool_result(value, False))
        except WorkbenchError as exc:
            return _result(
                request_id,
                _tool_result(
                    {
                        "error": {
                            "code": exc.code,
                            "message": str(exc),
                        }
                    },
                    True,
                ),
            )
        except Exception:
            print(
                "Kiro Security MCP tool failed unexpectedly.",
                file=sys.stderr,
                flush=True,
            )
            return _result(
                request_id,
                _tool_result(
                    {
                        "error": {
                            "code": "internal_error",
                            "message": "The Kiro Security tool failed unexpectedly.",
                        }
                    },
                    True,
                ),
            )


def serve(stdin=None, stdout=None):
    input_stream = stdin if stdin is not None else sys.stdin.buffer
    output_stream = stdout if stdout is not None else sys.stdout.buffer
    try:
        server = McpServer()
    except WorkbenchError as exc:
        print(
            "Kiro Security MCP startup failed: %s: %s" % (exc.code, exc),
            file=sys.stderr,
            flush=True,
        )
        return 2

    while True:
        raw = input_stream.readline(MAX_MESSAGE_BYTES + 1)
        if not raw:
            return 0
        if len(raw) > MAX_MESSAGE_BYTES and not raw.endswith(b"\n"):
            _write(output_stream, _error(None, -32700, "MCP message is too large."))
            _discard_line(input_stream)
            continue
        if not raw.strip():
            continue
        try:
            message = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _write(output_stream, _error(None, -32700, "Parse error"))
            continue
        if isinstance(message, list):
            _write(output_stream, _error(None, -32600, "JSON-RPC batches are unsupported."))
            continue
        response = server.handle(message)
        if response is not None:
            _write(output_stream, response)


def _discard_line(stream):
    while True:
        remainder = stream.readline(MAX_MESSAGE_BYTES + 1)
        if not remainder or remainder.endswith(b"\n"):
            return


def _tool_result(value, is_error):
    text = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    result = {
        "content": [{"type": "text", "text": text}],
        "structuredContent": value,
    }
    if is_error:
        result["isError"] = True
    return result


def _result(request_id, value):
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


def _error(request_id, code, message):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _write(stream, message):
    payload = json.dumps(
        message,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    stream.write(payload + b"\n")
    stream.flush()


def main():
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
