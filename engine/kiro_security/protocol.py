from __future__ import annotations

import math
from typing import Any

from .constants import EXPORT_FORMATS, MODES, PROTOCOL_VERSION, TRIAGE_DECISIONS
from .errors import EngineError

MAX_MESSAGE_BYTES = 2 * 1024 * 1024


def require_object(value: Any, field: str = "params") -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EngineError("invalid_params", f"{field} must be an object.")
    return value


def optional_string(params: dict[str, Any], name: str, *, max_length: int = 4096) -> str | None:
    value = params.get(name)
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise EngineError("invalid_params", f"{name} must be a string of at most {max_length} characters.")
    return value


def required_string(params: dict[str, Any], name: str, *, max_length: int = 4096) -> str:
    value = optional_string(params, name, max_length=max_length)
    if value is None or not value:
        raise EngineError("invalid_params", f"{name} is required.")
    return value


def optional_int(params: dict[str, Any], name: str, *, minimum: int, maximum: int) -> int | None:
    value = params.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise EngineError("invalid_params", f"{name} must be an integer between {minimum} and {maximum}.")
    return value


def validate_protocol_version(value: Any) -> str:
    if value != PROTOCOL_VERSION:
        raise EngineError(
            "protocol_version_mismatch",
            f"Protocol version {value!r} is not supported; expected {PROTOCOL_VERSION!r}.",
            {"supported": [PROTOCOL_VERSION], "received": value},
        )
    return PROTOCOL_VERSION


def validate_method(method: str, raw_params: Any) -> dict[str, Any]:
    params = require_object(raw_params or {})
    if method == "initialize":
        validate_protocol_version(params.get("protocolVersion"))
        client = require_object(params.get("clientInfo", {}), "clientInfo")
        required_string(client, "name", max_length=128)
        optional_string(client, "version", max_length=64)
    elif method == "register_workspace":
        optional_string(params, "workspaceRoot", max_length=8192)
        optional_string(params, "defaultScope", max_length=4096)
        default_mode = optional_string(params, "defaultMode", max_length=16)
        if default_mode is not None and default_mode not in MODES:
            raise EngineError("invalid_params", f"defaultMode must be one of {MODES}.")
    elif method == "start_scan":
        mode = required_string(params, "mode", max_length=16)
        if mode not in MODES:
            raise EngineError("invalid_params", f"mode must be one of {MODES}.")
        optional_string(params, "scope", max_length=4096)
        kind = optional_string(params, "diffTargetKind", max_length=32)
        if kind is not None and kind not in ("working_tree", "commit", "range"):
            raise EngineError("invalid_params", "diffTargetKind must be working_tree, commit, or range.")
        optional_string(params, "diffBaseRevision", max_length=256)
        optional_string(params, "diffHeadRevision", max_length=256)
        optional_int(params, "maxFiles", minimum=1, maximum=100_000)
        optional_int(params, "maxFileBytes", minimum=1024, maximum=10_485_760)
    elif method in {"resume_scan", "cancel_scan", "get_scan", "get_progress", "create_hardening_proposal", "cleanup_scan"}:
        required_string(params, "scanId", max_length=256)
    elif method == "list_scans":
        optional_int(params, "limit", minimum=1, maximum=200)
    elif method == "list_findings":
        required_string(params, "scanId", max_length=256)
        optional_string(params, "search", max_length=200)
        optional_int(params, "limit", minimum=1, maximum=2000)
    elif method in {"get_finding", "validate_finding", "create_remediation", "create_tracking_handoff"}:
        if "occurrenceId" not in params and "findingId" not in params:
            raise EngineError("invalid_params", "occurrenceId or findingId is required.")
        optional_string(params, "occurrenceId", max_length=256)
        optional_string(params, "findingId", max_length=256)
        if method == "create_tracking_handoff":
            provider = optional_string(params, "provider", max_length=32)
            if provider is not None and provider not in ("manual", "github", "linear", "jira"):
                raise EngineError("invalid_params", "provider must be manual, github, linear, or jira.")
            optional_string(params, "destination", max_length=512)
            optional_string(params, "stableLink", max_length=4096)
    elif method == "triage_finding":
        required_string(params, "occurrenceId", max_length=256)
        decision = required_string(params, "decision", max_length=32)
        if decision not in TRIAGE_DECISIONS:
            raise EngineError("invalid_params", f"decision must be one of {TRIAGE_DECISIONS}.")
        optional_string(params, "note", max_length=4000)
    elif method == "export_report":
        required_string(params, "scanId", max_length=256)
        format_name = required_string(params, "format", max_length=16)
        if format_name not in EXPORT_FORMATS:
            raise EngineError("invalid_params", f"format must be one of {EXPORT_FORMATS}.")
        optional_string(params, "destination", max_length=8192)
        optional_string(params, "allowedRoot", max_length=8192)
        optional_string(params, "occurrenceId", max_length=256)
    elif method in {"get_capabilities", "get_dashboard", "database_info", "poll_events", "refresh_threat_model", "shutdown"}:
        if method == "poll_events":
            optional_int(params, "afterSequence", minimum=0, maximum=2_147_483_647)
            optional_int(params, "limit", minimum=1, maximum=1000)
        if method == "refresh_threat_model":
            optional_string(params, "scope", max_length=4096)
    else:
        raise EngineError("method_not_found", f"Unknown RPC method: {method}")
    return params


def reject_non_finite(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")
