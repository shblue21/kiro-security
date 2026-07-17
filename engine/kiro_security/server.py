from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from typing import Any

from .constants import PROTOCOL_VERSION
from .errors import EngineError
from .protocol import MAX_MESSAGE_BYTES, reject_non_finite, validate_method, validate_protocol_version, validate_request_envelope, validate_request_id
from .service import SecurityService


class RpcServer:
    def __init__(self, workspace: str, client_kind: str) -> None:
        self._write_lock = threading.Lock()
        self._stop = threading.Event()
        self._initialized = False
        self.service = SecurityService(workspace, client_kind, self.notify)

    def write(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        with self._write_lock:
            sys.stdout.write(encoded + "\n")
            sys.stdout.flush()

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self.write({"jsonrpc": "2.0", "protocolVersion": PROTOCOL_VERSION, "method": method, "params": params})

    @staticmethod
    def _error_code(error: EngineError) -> int:
        if error.code == "method_not_found":
            return -32601
        if error.code == "invalid_request":
            return -32600
        if error.code in {"invalid_params", "invalid_argument", "invalid_path", "invalid_git_ref"}:
            return -32602
        if error.code == "protocol_version_mismatch":
            return -32001
        return -32000

    def handle(self, request: Any) -> bool:
        request_id: Any = None
        try:
            if isinstance(request, dict):
                candidate_id = request.get("id")
                if isinstance(candidate_id, int) and not isinstance(candidate_id, bool):
                    request_id = candidate_id
            request = validate_request_envelope(request)
            request_id = validate_request_id(request.get("id"))
            method = request.get("method")
            if not isinstance(method, str) or not method:
                raise EngineError("invalid_request", "method must be a non-empty string.")
            validate_protocol_version(request.get("protocolVersion"))
            params = validate_method(method, request.get("params"))
            if not self._initialized and method != "initialize":
                raise EngineError("not_initialized", "initialize must be the first RPC request.")
            if self._initialized and method == "initialize":
                raise EngineError("already_initialized", "The engine is already initialized.")
            result = self.service.dispatch(method, params)
            if method == "initialize":
                self._initialized = True
            self.write({"jsonrpc": "2.0", "protocolVersion": PROTOCOL_VERSION, "id": request_id, "result": result})
            if method == "shutdown":
                self._stop.set()
                return False
            return True
        except EngineError as error:
            self.write(
                {
                    "jsonrpc": "2.0",
                    "protocolVersion": PROTOCOL_VERSION,
                    "id": request_id,
                    "error": {
                        "code": self._error_code(error),
                        "message": error.message,
                        "data": {"engineCode": error.code, **(error.data or {})},
                    },
                }
            )
            return True
        except Exception as error:
            self.write(
                {
                    "jsonrpc": "2.0",
                    "protocolVersion": PROTOCOL_VERSION,
                    "id": request_id,
                    "error": {"code": -32603, "message": f"Internal RPC error: {type(error).__name__}: {error}"},
                }
            )
            return True

    def run(self) -> int:
        self.notify("engine.ready", {"protocolVersion": PROTOCOL_VERSION, "capabilities": self.service.capabilities()})
        while not self._stop.is_set():
            line = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_MESSAGE_BYTES:
                self.write(
                    {
                        "jsonrpc": "2.0",
                        "protocolVersion": PROTOCOL_VERSION,
                        "id": None,
                        "error": {"code": -32600, "message": "RPC message exceeds the maximum size."},
                    }
                )
                continue
            try:
                request = json.loads(line.decode("utf-8"), parse_constant=reject_non_finite)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                self.write(
                    {
                        "jsonrpc": "2.0",
                        "protocolVersion": PROTOCOL_VERSION,
                        "id": None,
                        "error": {"code": -32700, "message": f"Invalid JSON: {error}"},
                    }
                )
                continue
            if not self.handle(request):
                break
        try:
            self.service.shutdown({})
        except Exception:
            pass
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Kiro Security Power JSON-RPC engine")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--client-kind", choices=("extension", "mcp", "cli", "test"), default="cli")
    args = parser.parse_args()
    server = RpcServer(args.workspace, args.client_kind)

    def stop_handler(_signum: int, _frame: Any) -> None:
        server._stop.set()  # signal-safe flag only

    signal.signal(signal.SIGTERM, stop_handler)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, stop_handler)
    return server.run()


if __name__ == "__main__":
    raise SystemExit(main())
