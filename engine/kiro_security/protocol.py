from __future__ import annotations

import math
from typing import Any

from .constants import EXPORT_FORMATS, MODES, PROTOCOL_VERSION, TRIAGE_DECISIONS
from .errors import EngineError

MAX_MESSAGE_BYTES = 2 * 1024 * 1024
ENGINE_EVENT_NAMES = frozenset({
    "engine.ready", "scan.started", "scan.phaseChanged", "scan.progress", "finding.discovered",
    "finding.updated", "artifact.created", "scan.completed", "scan.cancelled", "scan.failed",
    "scan.integrityIssue", "engine.log",
})
_REQUEST_FIELDS = frozenset({"jsonrpc", "protocolVersion", "id", "method", "params"})
_METHOD_PARAMS = {
    "initialize": {"protocolVersion", "clientInfo"},
    "register_workspace": {"workspaceRoot", "defaultScope", "defaultMode"},
    "start_scan": {"mode", "scope", "diffTargetKind", "diffBaseRevision", "diffHeadRevision", "maxFiles", "maxFileBytes", "analysisProfile", "modelId", "runtime"},
    **{method: {"scanId"} for method in ("resume_scan", "cancel_scan", "get_scan", "get_progress", "create_hardening_proposal", "cleanup_scan", "deep_get_status", "deep_claim_merge")},
    "deep_claim_worker": {"scanId", "modelId", "delegationId", "runtime"},
    "deep_submit_worker": {"scanId", "workerId", "claimToken", "rowReceipts", "threatModel", "summary", "seedResearch", "dedupeReport", "candidates", "completionAttestation"},
    "deep_retry_worker": {"scanId", "workerIndex", "reason"},
    "deep_submit_merge": {"scanId", "claimToken", "canonicalCandidates"},
    "deep_get_tail_assignment": {"scanId", "modelId", "delegationId", "runtime"},
    "deep_submit_tail_result": {"scanId", "assignmentId", "claimToken", "modelId", "delegationId", "runtime", "completionAttestation", "result"},
    "deep_retry_writeup": {"scanId", "assignmentId", "reason"},
    "list_scans": {"limit"},
    "list_findings": {"scanId", "search", "limit"},
    **{method: {"occurrenceId", "findingId"} for method in ("get_finding", "validate_finding", "create_remediation")},
    "create_tracking_handoff": {"occurrenceId", "findingId", "provider", "destination", "stableLink", "trackingProof"},
    "triage_finding": {"occurrenceId", "decision", "note"},
    "create_triage_intake": {"sourceType", "inputId", "occurrenceId", "input"},
    "submit_triage_assessment": {"assessmentId", "result"},
    "prepare_remediation_patch": {"occurrenceId", "patch", "plan", "verificationPlan"},
    "apply_remediation_patch": {"remediationId", "expectedVersion"},
    "verify_remediation_patch": {"remediationId", "expectedVersion", "verification"},
    "record_tracking_result": {"recordId", "payloadSha256", "outcome", "externalMutationPerformed", "externalId", "externalUrl", "reason", "approval", "readback"},
    "export_report": {"scanId", "format", "destination", "allowedRoot", "occurrenceId"},
    **{method: set() for method in ("get_capabilities", "database_info", "shutdown")},
    "get_dashboard": {"limit"},
    "poll_events": {"afterSequence", "limit"},
    "refresh_threat_model": {"scope"},
}


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


def validate_request_id(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EngineError("invalid_request", "RPC request id must be an integer.")
    return value


def validate_request_envelope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EngineError("invalid_request", "RPC request must be an object.")
    request = value
    if set(request) != _REQUEST_FIELDS:
        raise EngineError("invalid_request", "RPC request fields must be exactly jsonrpc, protocolVersion, id, method, and params.")
    if request.get("jsonrpc") != "2.0":
        raise EngineError("invalid_request", "jsonrpc must be '2.0'.")
    return request


def validate_method(method: str, raw_params: Any) -> dict[str, Any]:
    if method in ENGINE_EVENT_NAMES:
        raise EngineError("invalid_request", "Event notifications must not include a request id.")
    allowed = _METHOD_PARAMS.get(method)
    if allowed is None:
        raise EngineError("method_not_found", f"Unknown RPC method: {method}")
    params = require_object(raw_params)
    unexpected = sorted(set(params) - allowed)
    if unexpected:
        raise EngineError("invalid_params", f"Unexpected parameter(s) for {method}: {', '.join(unexpected)}.")
    if method == "initialize":
        validate_protocol_version(params.get("protocolVersion"))
        client = require_object(params.get("clientInfo", {}), "clientInfo")
        if set(client) - {"name", "version"}:
            raise EngineError("invalid_params", "clientInfo contains unsupported fields.")
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
        profile = optional_string(params, "analysisProfile", max_length=16) or ("model" if mode == "deep" else "fast")
        if profile not in ("fast", "model") or (mode == "deep" and profile != "model"):
            raise EngineError("invalid_params", "analysisProfile must be model for Deep and fast or model otherwise.")
        params["analysisProfile"] = profile
        if profile == "model":
            required_string(params, "modelId", max_length=256)
            require_object(params.get("runtime"), "runtime")
    elif method in {"resume_scan", "cancel_scan", "get_scan", "get_progress", "create_hardening_proposal", "cleanup_scan"}:
        required_string(params, "scanId", max_length=256)
    elif method in {"deep_get_status", "deep_claim_merge"}:
        required_string(params, "scanId", max_length=256)
    elif method == "deep_claim_worker":
        required_string(params, "scanId", max_length=256)
        required_string(params, "modelId", max_length=256)
        required_string(params, "delegationId", max_length=256)
        require_object(params.get("runtime"), "runtime")
    elif method == "deep_submit_worker":
        required_string(params, "scanId", max_length=256)
        required_string(params, "workerId", max_length=256)
        required_string(params, "claimToken", max_length=256)
        if not isinstance(params.get("rowReceipts"), list) or not isinstance(params.get("candidates"), list):
            raise EngineError("invalid_params", "rowReceipts and candidates must be arrays.")
        required_string(params, "threatModel", max_length=200000)
        optional_string(params, "summary", max_length=20000)
        optional_string(params, "seedResearch", max_length=200000)
        optional_string(params, "dedupeReport", max_length=200000)
        require_object(params.get("completionAttestation"), "completionAttestation")
    elif method == "deep_retry_worker":
        required_string(params, "scanId", max_length=256)
        if optional_int(params, "workerIndex", minimum=1, maximum=6) is None:
            raise EngineError("invalid_params", "workerIndex is required.")
        optional_string(params, "reason", max_length=4000)
    elif method == "deep_submit_merge":
        required_string(params, "scanId", max_length=256)
        required_string(params, "claimToken", max_length=256)
        if not isinstance(params.get("canonicalCandidates"), list):
            raise EngineError("invalid_params", "canonicalCandidates must be an array.")
    elif method == "deep_get_tail_assignment":
        required_string(params, "scanId", max_length=256)
        required_string(params, "modelId", max_length=256)
        required_string(params, "delegationId", max_length=256)
        require_object(params.get("runtime"), "runtime")
    elif method == "deep_submit_tail_result":
        for name in ("scanId", "assignmentId", "claimToken", "modelId", "delegationId"):
            required_string(params, name, max_length=256)
        require_object(params.get("runtime"), "runtime")
        require_object(params.get("completionAttestation"), "completionAttestation")
        require_object(params.get("result"), "result")
    elif method == "deep_retry_writeup":
        required_string(params, "scanId", max_length=256)
        required_string(params, "assignmentId", max_length=256)
        optional_string(params, "reason", max_length=4000)
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
            require_object(params.get("trackingProof"), "trackingProof")
    elif method == "triage_finding":
        required_string(params, "occurrenceId", max_length=256)
        decision = required_string(params, "decision", max_length=32)
        if decision not in TRIAGE_DECISIONS:
            raise EngineError("invalid_params", f"decision must be one of {TRIAGE_DECISIONS}.")
        optional_string(params, "note", max_length=4000)
    elif method == "create_triage_intake":
        required_string(params, "sourceType", max_length=64)
        required_string(params, "inputId", max_length=512)
        optional_string(params, "occurrenceId", max_length=256)
        require_object(params.get("input"), "input")
    elif method == "submit_triage_assessment":
        required_string(params, "assessmentId", max_length=256)
        require_object(params.get("result"), "result")
    elif method == "prepare_remediation_patch":
        required_string(params, "occurrenceId", max_length=256)
        required_string(params, "patch", max_length=600000)
        required_string(params, "plan", max_length=12000)
        if not isinstance(params.get("verificationPlan"), list):
            raise EngineError("invalid_params", "verificationPlan must be an array.")
    elif method in {"apply_remediation_patch", "verify_remediation_patch"}:
        required_string(params, "remediationId", max_length=256)
        if optional_int(params, "expectedVersion", minimum=1, maximum=2_147_483_647) is None:
            raise EngineError("invalid_params", "expectedVersion is required.")
        if method == "verify_remediation_patch":
            require_object(params.get("verification"), "verification")
    elif method == "record_tracking_result":
        required_string(params, "recordId", max_length=256)
        digest = required_string(params, "payloadSha256", max_length=64)
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise EngineError("invalid_params", "payloadSha256 must be 64 lowercase hexadecimal characters.")
        outcome = required_string(params, "outcome", max_length=32)
        if not isinstance(params.get("externalMutationPerformed"), bool):
            raise EngineError("invalid_params", "externalMutationPerformed must be a boolean.")
        optional_string(params, "externalId", max_length=512)
        optional_string(params, "externalUrl", max_length=4096)
        optional_string(params, "reason", max_length=4000)
        readback = params.get("readback")
        if readback is not None:
            require_object(readback, "readback")
        approval = params.get("approval")
        if outcome in ("created", "updated", "reused"):
            require_object(approval, "approval")
        elif approval is not None:
            require_object(approval, "approval")
    elif method == "export_report":
        required_string(params, "scanId", max_length=256)
        format_name = required_string(params, "format", max_length=16)
        if format_name not in EXPORT_FORMATS:
            raise EngineError("invalid_params", f"format must be one of {EXPORT_FORMATS}.")
        optional_string(params, "destination", max_length=8192)
        optional_string(params, "allowedRoot", max_length=8192)
        optional_string(params, "occurrenceId", max_length=256)
    elif method in {"get_capabilities", "get_dashboard", "database_info", "poll_events", "refresh_threat_model", "shutdown"}:
        if method == "get_dashboard":
            optional_int(params, "limit", minimum=1, maximum=200)
        if method == "poll_events":
            optional_int(params, "afterSequence", minimum=0, maximum=2_147_483_647)
            optional_int(params, "limit", minimum=1, maximum=1000)
        if method == "refresh_threat_model":
            optional_string(params, "scope", max_length=4096)
    return params


def reject_non_finite(value: str) -> None:
    raise ValueError(f"Non-finite JSON number is not allowed: {value}")
