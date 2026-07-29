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
from typing import Any, Optional


MAX_SESSION_ID_LENGTH = 512
MAX_GUARD_BYTES = 1024 * 1024
MAX_GUARD_FILES = 128
MAX_CONFIG_BYTES = 1024 * 1024
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
    "kiro_security_fail_scan",
    "kiro_security_cancel_scan",
)
REQUEST_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
GUARD_FILE_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.json$"
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


def _validate_shadow_guard(server_key: str, payload: dict[str, Any]) -> None:
    guard_directory = _state_root() / "runtime" / "mcp-shadow-guards"
    if guard_directory.is_symlink() or not guard_directory.exists():
        raise HookInputError("The MCP shadow guard is unavailable.")
    metadata = guard_directory.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (os.name != "nt" and metadata.st_mode & 0o077)
    ):
        raise HookInputError("The MCP shadow guard is unsafe.")
    cwd = payload.get("cwd")
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        raise HookInputError("Kiro did not provide an absolute workspace cwd.")
    resolved_cwd = Path(cwd).resolve(strict=False)
    try:
        guard_paths = [
            candidate
            for candidate in guard_directory.iterdir()
            if GUARD_FILE_PATTERN.fullmatch(candidate.name) is not None
        ]
    except OSError as error:
        raise HookInputError("Unable to read MCP shadow guard leases.") from error
    if len(guard_paths) > MAX_GUARD_FILES:
        raise HookInputError("Too many MCP shadow guard leases are active.")
    active_guards = 0
    cwd_guarded = False
    for guard_path in guard_paths:
        guard = _read_shadow_guard(guard_path, server_key)
        if guard is None:
            continue
        active_guards += 1
        workspace_roots = guard.get("workspaceRoots")
        if not isinstance(workspace_roots, list) or not all(
            isinstance(value, str) and os.path.isabs(value)
            for value in workspace_roots
        ):
            raise HookInputError("The MCP shadow guard workspace roots are invalid.")
        cwd_guarded = cwd_guarded or any(
            _is_path_within(resolved_cwd, Path(root).resolve(strict=False))
            for root in workspace_roots
        )
        _validate_shadow_guard_sources(guard)
    if active_guards == 0:
        raise HookInputError("The MCP shadow guard is stale.")
    if not cwd_guarded:
        raise HookInputError("The current Kiro workspace is not guarded.")


def _read_shadow_guard(
    path: Path, server_key: str
) -> Optional[dict[str, Any]]:
    if path.is_symlink():
        raise HookInputError("The MCP shadow guard is unsafe.")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_GUARD_BYTES
        or (os.name != "nt" and metadata.st_mode & 0o077)
    ):
        raise HookInputError("The MCP shadow guard is unsafe.")
    try:
        guard = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HookInputError("The MCP shadow guard is invalid.") from error
    if not isinstance(guard, dict) or guard.get("version") != 1:
        raise HookInputError("The MCP shadow guard has an unsupported format.")
    expires_at = guard.get("expiresAt")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise HookInputError("The MCP shadow guard expiry is invalid.")
    if expires_at <= int(time.time() * 1000):
        return None
    if guard.get("serverKey") != server_key or guard.get("safe") is not True:
        raise HookInputError("An MCP configuration shadows this installation.")
    return guard


def _validate_shadow_guard_sources(guard: dict[str, Any]) -> None:
    sources = guard.get("sources")
    if not isinstance(sources, list):
        raise HookInputError("The MCP shadow guard sources are invalid.")
    seen_paths = set()
    for source in sources:
        if not isinstance(source, dict):
            raise HookInputError("The MCP shadow guard source is invalid.")
        source_path = source.get("path")
        expected_digest = source.get("sha256")
        if (
            not isinstance(source_path, str)
            or not os.path.isabs(source_path)
            or source_path in seen_paths
            or (
                expected_digest is not None
                and (
                    not isinstance(expected_digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
                )
            )
        ):
            raise HookInputError("The MCP shadow guard source is invalid.")
        seen_paths.add(source_path)
        _validate_guarded_source(Path(source_path), expected_digest)


def _validate_guarded_source(path: Path, expected_digest: Any) -> None:
    if expected_digest is None:
        if path.is_symlink() or path.exists():
            raise HookInputError("An MCP configuration changed after inspection.")
        return
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise HookInputError("A guarded MCP configuration is unsafe.")
        if metadata.st_size > MAX_CONFIG_BYTES:
            raise HookInputError("A guarded MCP configuration is too large.")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise HookInputError("Unable to read a guarded MCP configuration.") from error
    if digest != expected_digest:
        raise HookInputError("An MCP configuration changed after inspection.")


def _is_path_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


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
        _validate_shadow_guard(server_key, payload)
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
