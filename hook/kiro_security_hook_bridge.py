"""Kiro PreToolUse transport guard for Kiro Security Power calls.

The bridge intentionally does not persist Kiro's session_id yet. The later
identity phase will turn a validated Hook invocation into a one-time
attestation consumed by MCP. Until then this process only validates the Hook
transport and fails closed for calls addressed to this Power.
"""

from __future__ import annotations

import json
import sys
from typing import Any


MAX_SESSION_ID_LENGTH = 512
POWER_WRAPPER_TOOL = "kiro_powers"
POWER_NAME = "kiro-security-power"
SERVER_NAME = "kiro-security-workbench"
ALLOWED_TOOL_NAMES = frozenset(
    {
        "kiro_security_get_capabilities",
        "kiro_security_create_workspace",
        "kiro_security_get_workspace",
        "kiro_security_save_workspace",
        "kiro_security_start_scan",
        "kiro_security_get_scan_context",
        "kiro_security_update_scan_progress",
        "kiro_security_fail_scan",
        "kiro_security_cancel_scan",
    }
)


class HookInputError(ValueError):
    """Raised when a Kiro Security invocation lacks trusted Hook input."""


def _read_payload() -> dict[str, Any]:
    raw = sys.stdin.buffer.read()
    try:
        decoded = raw.decode("utf-8")
        payload = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HookInputError("Hook input must be one UTF-8 JSON object.") from error
    if not isinstance(payload, dict):
        raise HookInputError("Hook input must be a JSON object.")
    return payload


def _is_our_power_call(payload: dict[str, Any]) -> bool:
    if payload.get("tool_name") != POWER_WRAPPER_TOOL:
        return False
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return False
    return (
        tool_input.get("action") == "use"
        and tool_input.get("powerName") == POWER_NAME
    )


def _validate_our_power_call(payload: dict[str, Any]) -> None:
    event_name = payload.get("hook_event_name")
    if not isinstance(event_name, str) or event_name not in {
        "PreToolUse",
        "preToolUse",
    }:
        raise HookInputError("Kiro Security requires a PreToolUse Hook event.")

    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        raise HookInputError("Kiro did not provide a non-empty session_id.")
    if len(session_id) > MAX_SESSION_ID_LENGTH:
        raise HookInputError("Kiro session_id exceeds the supported length.")

    tool_input = payload["tool_input"]
    if tool_input.get("serverName") != SERVER_NAME:
        raise HookInputError("The requested Kiro Security MCP server is not allowed.")
    tool_name = tool_input.get("toolName")
    if not isinstance(tool_name, str) or tool_name not in ALLOWED_TOOL_NAMES:
        raise HookInputError("The requested Kiro Security Power tool is not allowed.")
    arguments = tool_input.get("arguments", {})
    if not isinstance(arguments, dict):
        raise HookInputError("Kiro Security Power arguments must be a JSON object.")


def main() -> int:
    try:
        payload = _read_payload()
        # Kiro's matcher sees the outer `kiro_powers` tool. Other Powers must
        # continue untouched; exact Power/server/tool filtering happens here.
        if not _is_our_power_call(payload):
            return 0
        _validate_our_power_call(payload)
        return 0
    except HookInputError as error:
        print(f"Kiro Security Hook rejected the call: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
