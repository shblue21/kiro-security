"""Stable global-storage launcher for the Kiro Security MCP runtime."""

import json
import os
import sys
from pathlib import Path


def _engine_root():
    root = Path(__file__).resolve(strict=True).parent / "engine"
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("Kiro Security runtime engine is unavailable.")
    return root


def _required_environment(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError("%s is required." % name)
    return value


def _admin_request():
    raw = sys.stdin.buffer.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise RuntimeError("Kiro Security admin request is too large.")
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise RuntimeError("Kiro Security admin request must be UTF-8 JSON.")
    return request


def main():
    sys.path.insert(0, str(_engine_root()))
    if len(sys.argv) == 2 and sys.argv[1] == "--initialize":
        from kiro_security.workbench import Workbench

        state = Workbench(
            _required_environment("KIRO_SECURITY_STATE_ROOT"),
            _required_environment("KIRO_SECURITY_SCAN_ROOT"),
        ).schema_state()
        print(json.dumps(state, sort_keys=True, separators=(",", ":")))
        return 0
    if len(sys.argv) == 2 and sys.argv[1] == "--admin":
        from kiro_security.workbench import Workbench

        request = _admin_request()
        if not isinstance(request, dict):
            raise RuntimeError("Kiro Security admin request must be an object.")
        operation = request.get("operation")
        arguments = request.get("arguments", {})
        if not isinstance(arguments, dict):
            raise RuntimeError("Kiro Security admin arguments must be an object.")
        workbench = Workbench(
            _required_environment("KIRO_SECURITY_STATE_ROOT"),
            _required_environment("KIRO_SECURITY_SCAN_ROOT"),
        )
        if operation == "dashboard":
            result = workbench.dashboard_projection()
        elif operation == "createRecovery":
            result = workbench.create_scan_recovery_request(
                arguments.get("scanId"),
            )
        elif operation == "cancelRecovery":
            result = workbench.cancel_scan_recovery_request(
                arguments.get("requestId"),
            )
        elif operation == "setTriage":
            result = workbench.set_finding_triage(
                arguments.get("occurrenceId"),
                arguments.get("status"),
                arguments.get("closeReason"),
                arguments.get("note"),
            )
        elif operation == "requestRemediation":
            result = workbench.request_finding_remediation(
                arguments.get("occurrenceId"),
                arguments.get("action"),
                arguments.get("requestId"),
            )
        elif operation == "createTracking":
            result = workbench.create_finding_tracking_request(
                arguments.get("occurrenceId"),
            )
        elif operation == "export":
            result = workbench.export_scan_local(
                arguments.get("scanId"),
                arguments.get("format"),
            )
        else:
            raise RuntimeError("Unsupported Kiro Security admin operation.")
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    if len(sys.argv) != 1:
        raise RuntimeError("Unsupported Kiro Security launcher arguments.")
    from kiro_security.mcp_server import main as serve

    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
