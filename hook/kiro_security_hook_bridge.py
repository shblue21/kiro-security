"""Issue one-time Kiro chat attestations before direct MCP calls."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import time
from pathlib import Path
from typing import Any


MAX_SESSION_ID_LENGTH = 512
ATTESTATION_TTL_SECONDS = 15 * 60
MCP_SERVER_KEY_PATTERN = re.compile(r"^ksp_[a-z2-7]{20}$")
MCP_TOOL_NAMES = (
    "kiro_security_get_capabilities",
    "kiro_security_create_workspace",
    "kiro_security_get_workspace",
    "kiro_security_save_workspace",
    "kiro_security_start_scan",
    "kiro_security_get_scan_context",
    "kiro_security_update_scan_progress",
    "kiro_security_get_artifact_contract",
    "kiro_security_write_scan_artifact",
    "kiro_security_complete_scan",
    "kiro_security_export_scan",
    "kiro_security_claim_scan_recovery",
    "kiro_security_release_scan_recovery",
    "kiro_security_claim_remediation",
    "kiro_security_get_remediation",
    "kiro_security_set_remediation",
    "kiro_security_release_remediation",
    "kiro_security_claim_tracking",
    "kiro_security_get_tracking",
    "kiro_security_fail_scan",
    "kiro_security_cancel_scan",
)
REQUEST_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


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


def _parse_server_key() -> str:
    arguments = sys.argv[1:]
    if (
        len(arguments) != 2
        or arguments[0] != "--server-key"
        or MCP_SERVER_KEY_PATTERN.fullmatch(arguments[1]) is None
    ):
        raise HookInputError(
            "The Hook bridge requires its installation-specific MCP server key."
        )
    return arguments[1]


def _direct_tool_map(server_key: str) -> dict[str, str]:
    if MCP_SERVER_KEY_PATTERN.fullmatch(server_key) is None:
        raise HookInputError("The Kiro Security MCP server key is invalid.")
    result = {}
    for tool_name in MCP_TOOL_NAMES:
        normalized = re.sub(r"[\s-]", "_", f"{server_key}_{tool_name}")
        normalized = re.sub(r"[^a-zA-Z0-9_]", "", normalized).lower()
        identifier = f"mcp_{normalized}"
        if len(identifier) > 64:
            raise HookInputError("A Kiro Security direct MCP tool ID is too long.")
        result[identifier] = tool_name
    if len(result) != len(MCP_TOOL_NAMES):
        raise HookInputError("Kiro Security direct MCP tool IDs are not unique.")
    return result


def _is_our_direct_call(
    payload: dict[str, Any], direct_tool_map: dict[str, str]
) -> bool:
    tool_name = payload.get("tool_name")
    return isinstance(tool_name, str) and tool_name in direct_tool_map


def _validate_our_direct_call(
    payload: dict[str, Any],
    direct_tool_map: dict[str, str],
) -> tuple[str, str, dict[str, Any], str]:
    event_name = payload.get("hook_event_name")
    if not isinstance(event_name, str) or event_name not in {
        "PreToolUse",
        "preToolUse",
    }:
        raise HookInputError("Kiro Security requires a PreToolUse Hook event.")

    raw_session_id = payload.get("session_id")
    if not isinstance(raw_session_id, str) or not raw_session_id.strip():
        raise HookInputError("Kiro did not provide a non-empty session_id.")
    session_id = raw_session_id.strip()
    if len(session_id) > MAX_SESSION_ID_LENGTH:
        raise HookInputError("Kiro session_id exceeds the supported length.")

    direct_tool_name = payload.get("tool_name")
    if not isinstance(direct_tool_name, str):
        raise HookInputError("Kiro Security requires a direct MCP tool name.")
    tool_name = direct_tool_map.get(direct_tool_name)
    if tool_name is None:
        raise HookInputError("The requested Kiro Security MCP tool is not allowed.")
    arguments = payload.get("tool_input")
    if not isinstance(arguments, dict):
        raise HookInputError("Kiro Security MCP arguments must be a JSON object.")
    nonce = arguments.get("requestNonce")
    if not isinstance(nonce, str) or REQUEST_NONCE_PATTERN.fullmatch(nonce) is None:
        raise HookInputError("Kiro Security requires a fresh requestNonce.")
    return session_id, tool_name, arguments, nonce


def _arguments_hash(arguments: dict[str, Any]) -> str:
    bound_arguments = dict(arguments)
    bound_arguments.pop("requestNonce", None)
    try:
        canonical = json.dumps(
            bound_arguments,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise HookInputError(
            "Kiro Security MCP arguments must be canonical JSON values."
        ) from error
    return hashlib.sha256(canonical).hexdigest()


def _state_root() -> Path:
    bridge_path = Path(__file__).resolve(strict=True)
    bridge_directory = bridge_path.parent
    if (
        bridge_directory.name != "hook-bridge"
        or bridge_directory.parent.name != "runtime"
    ):
        raise HookInputError(
            "The Hook bridge is not installed in extension global storage."
        )
    return bridge_directory.parent.parent


def _database_path() -> Path:
    database_path = _state_root() / "workbench.sqlite3"
    if database_path.is_symlink():
        raise HookInputError("The Kiro Security database path is unsafe.")
    if not database_path.exists():
        raise HookInputError("The Kiro Security workbench is not initialized.")
    metadata = database_path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HookInputError("The Kiro Security database path is unsafe.")
    return database_path


def _store_attestation(
    session_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    nonce: str,
) -> None:
    database_path = _database_path()
    now = int(time.time())
    connection = None
    try:
        connection = sqlite3.connect(
            str(database_path),
            timeout=5,
            isolation_level=None,
        )
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM chat_attestations WHERE expires_at <= ?",
            (now,),
        )
        connection.execute(
            """
            INSERT INTO chat_attestations (
                nonce, session_hash, tool_name, arguments_hash, expires_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                nonce,
                hashlib.sha256(session_id.encode("utf-8")).hexdigest(),
                tool_name,
                _arguments_hash(arguments),
                now + ATTESTATION_TTL_SECONDS,
            ),
        )
        connection.commit()
        os.chmod(database_path, 0o600)
    except (OSError, sqlite3.Error) as error:
        if connection is not None:
            connection.rollback()
        raise HookInputError("Unable to record Kiro chat attestation.") from error
    finally:
        if connection is not None:
            connection.close()


def main() -> int:
    try:
        server_key = _parse_server_key()
        direct_tool_map = _direct_tool_map(server_key)
        payload = _read_payload()
        # The registration matcher is exact, and the bridge repeats the direct
        # tool allowlist check before trusting host session identity.
        if not _is_our_direct_call(payload, direct_tool_map):
            return 0
        session_id, tool_name, arguments, nonce = _validate_our_direct_call(
            payload, direct_tool_map
        )
        _store_attestation(session_id, tool_name, arguments, nonce)
        return 0
    except HookInputError as error:
        print(f"Kiro Security Hook rejected the call: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
