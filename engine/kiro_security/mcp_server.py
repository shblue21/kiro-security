from __future__ import annotations

import json
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from . import __version__
from .errors import EngineError
from .security import canonical_workspace
from .service import SecurityService

MAX_LINE_BYTES = 2 * 1024 * 1024
MAX_BUFFER_BYTES = 8 * 1024 * 1024
SUPPORTED_PROTOCOLS = {"2024-11-05", "2025-03-26", "2025-06-18"}
DEFAULT_PROTOCOL = "2024-11-05"


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Tool arguments must be a JSON object.")
    return value


def _bounded_string(value: Any, name: str, maximum: int = 4096, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters.")
    return value


def _safe_git_ref(value: Any, name: str) -> str | None:
    if value in (None, ""):
        return None
    text = _bounded_string(value, name, 256)
    assert text is not None
    if text.startswith("-") or not all(character.isalnum() or character in "._/@+-~^:" for character in text):
        raise ValueError(f"{name} is not a safe Git revision.")
    return text


def _integer(value: Any, name: str, default: int, minimum: int, maximum: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}.")
    return value


def _request_id(value: Any) -> str | int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("JSON-RPC requests require a string or integer id.")
    return value


def _workspace_from(params: dict[str, Any]) -> Path:
    requested = (
        params["workspaceRoot"]
        if "workspaceRoot" in params
        else os.environ.get("KIRO_SECURITY_WORKSPACE") or os.getcwd()
    )
    if not isinstance(requested, str) or not requested or len(requested) > 8192 or "\x00" in requested:
        raise ValueError("workspaceRoot must identify a bounded local directory path.")
    return canonical_workspace(requested)


def _id_schema(name: str) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "workspaceRoot": {"type": "string"},
            name: {"type": "string"},
        },
        "required": [name],
        "additionalProperties": False,
    }


def _lease_schema(*, extra: dict[str, Any] | None = None, required_extra: list[str] | None = None) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "workspaceRoot": {"type": "string"},
        "scanId": {"type": "string"},
        "coordinatorToken": {"type": "string", "minLength": 64, "maxLength": 128},
        "coordinatorGeneration": {"type": "integer", "minimum": 1},
    }
    properties.update(extra or {})
    return {
        "type": "object",
        "properties": properties,
        "required": ["scanId", "coordinatorToken", "coordinatorGeneration", *(required_extra or [])],
        "additionalProperties": False,
    }


def _lease_request(params: dict[str, Any]) -> dict[str, Any]:
    if "coordinatorGeneration" not in params:
        raise ValueError("coordinatorGeneration is required.")
    return {
        "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
        "coordinatorToken": _bounded_string(params.get("coordinatorToken"), "coordinatorToken", 128),
        "coordinatorGeneration": _integer(
            params.get("coordinatorGeneration"), "coordinatorGeneration", 0, 1, 2_147_483_647
        ),
    }


TOOLS: list[dict[str, Any]] = [
    {
        "name": "security_get_capabilities",
        "description": "Report deterministic Engine, Python, SQLite, Git, workspace, supported-mode, and canonical-finalizer facts only.",
        "inputSchema": {
            "type": "object",
            "properties": {"workspaceRoot": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "security_start_scan",
        "description": "Start a chat-coordinated Skill-driven Standard, Deep, or Git-diff scan and create its deterministic context and worklists.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string", "description": "Optional. Defaults to the workspace bound by the VSIX installer."},
                "mode": {"type": "string", "enum": ["standard", "deep", "diff"]},
                "scope": {"type": "string", "minLength": 1, "default": "."},
                "diffTargetKind": {"type": "string", "enum": ["working_tree", "commit", "range"]},
                "diffBaseRevision": {"type": "string"},
                "diffHeadRevision": {"type": "string"},
                "userContext": {"type": "string", "description": "Optional bounded user-supplied scan context."},
            },
            "required": ["mode"],
            "additionalProperties": False,
        },
    },
    {"name": "security_acquire_scan_coordinator", "description": "Acquire an available or expired transient coordinator lease for a durable running scan.", "inputSchema": _id_schema("scanId")},
    {"name": "security_renew_scan_coordinator", "description": "Renew the current transient coordinator lease with generation-based CAS.", "inputSchema": _lease_schema()},
    {"name": "security_release_scan_coordinator", "description": "Release coordinator execution authority without changing scan lifecycle state.", "inputSchema": _lease_schema()},
    {"name": "security_cancel_scan", "description": "Cancel a running scan while atomically releasing its coordinator lease.", "inputSchema": _lease_schema()},
    {"name": "security_get_scan", "description": "Get scan lifecycle, progress, coverage, and artifact records.", "inputSchema": _id_schema("scanId")},
    {"name": "security_get_progress", "description": "Get the latest progress record for a scan.", "inputSchema": _id_schema("scanId")},
    {
        "name": "security_get_scan_context",
        "description": "Get immutable target identity, phase artifact paths, deterministic worklists, canonical output paths, lifecycle, and other running Deep scans.",
        "inputSchema": _id_schema("scanId"),
    },
    {
        "name": "security_update_scan_progress",
        "description": "Update user-visible lifecycle progress only; this is not workflow authority and accepts no result or receipt bodies.",
        "inputSchema": _lease_schema(extra={
            "phase": {"type": "string", "enum": ["preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"]},
            "phasePercent": {"type": "number", "minimum": 0, "maximum": 100},
            "itemsTotal": {"type": "integer", "minimum": 0}, "itemsCompleted": {"type": "integer", "minimum": 0},
            "reportableFindingsCount": {"type": "integer", "minimum": 0}, "message": {"type": "string", "maxLength": 1000}
        }),
    },
    {"name": "security_complete_scan", "description": "One-shot validate, index, project, and seal fixed Agent-authored canonical artifacts under the current coordinator lease.", "inputSchema": _lease_schema()},
    {"name": "security_fail_scan", "description": "Fail a running scan with an explicit reason and atomically release its coordinator lease.", "inputSchema": _lease_schema(extra={"reason": {"type": "string", "minLength": 1, "maxLength": 4000}}, required_extra=["reason"])},
    {
        "name": "security_list_findings",
        "description": "List findings indexed from the sealed canonical document.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "scanId": {"type": "string"},
                "search": {"type": "string", "minLength": 1, "maxLength": 200},
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
            },
            "required": ["scanId"],
            "additionalProperties": False,
        },
    },
    {"name": "security_get_finding", "description": "Get one finding with evidence, validation, attack path, triage, remediation, and tracking records.", "inputSchema": _id_schema("occurrenceId")},
    {
        "name": "security_triage_finding",
        "description": "Record an auditable triage decision for a finding.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "occurrenceId": {"type": "string"},
                "decision": {"type": "string", "enum": ["open", "accepted_risk", "false_positive", "already_fixed", "wont_fix"]},
                "note": {"type": "string", "maxLength": 4000},
            },
            "required": ["occurrenceId", "decision"],
            "additionalProperties": False,
        },
    },
    {"name": "security_create_remediation", "description": "Create finding-specific remediation guidance in the shared artifact directory.", "inputSchema": _id_schema("occurrenceId")},
    {
        "name": "security_prepare_remediation_patch",
        "description": "Prepare and drift-check one bounded existing-file unified diff without changing the workspace.",
        "inputSchema": {"type": "object", "properties": {
            "workspaceRoot": {"type": "string"}, "occurrenceId": {"type": "string"},
            "patch": {"type": "string", "maxLength": 600000}, "plan": {"type": "string", "maxLength": 12000},
            "verificationPlan": {"type": "array", "minItems": 1, "maxItems": 50, "items": {"type": "string", "maxLength": 2000}},
        }, "required": ["occurrenceId", "patch", "plan", "verificationPlan"], "additionalProperties": False},
    },
    {"name": "security_apply_remediation_patch", "description": "Apply exactly one prepared patch after digest, revision, touched-file, and state revalidation.", "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "remediationId": {"type": "string"}, "expectedVersion": {"type": "integer", "minimum": 1}}, "required": ["remediationId", "expectedVersion"], "additionalProperties": False}},
    {"name": "security_verify_remediation_patch", "description": "Record a bounded Agent-submitted verification receipt; incomplete proof cannot become verified.", "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "remediationId": {"type": "string"}, "expectedVersion": {"type": "integer", "minimum": 1}, "verification": {"type": "object"}}, "required": ["remediationId", "expectedVersion", "verification"], "additionalProperties": False}},
    {"name": "security_create_triage_intake", "description": "Persist one bounded untrusted external finding intake without inventing scan finding fields.", "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "occurrenceId": {"type": "string"}, "sourceType": {"type": "string", "enum": ["sarif", "cve", "advisory", "scanner_ticket", "bug_bounty", "kiro_security_finding", "freeform", "unknown"]}, "inputId": {"type": "string", "maxLength": 512}, "input": {"type": "object"}}, "required": ["sourceType", "inputId", "input"], "additionalProperties": False}},
    {"name": "security_submit_triage_assessment", "description": "Complete one pending intake with a static source/control/sink/boundary proof chain.", "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "assessmentId": {"type": "string"}, "result": {"type": "object"}}, "required": ["assessmentId", "result"], "additionalProperties": False}},
    {
        "name": "security_create_tracking_handoff",
        "description": "Seal an approved connector, destination, duplicate-search, visibility, and audience proof without an external write.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "occurrenceId": {"type": "string"},
                "provider": {"type": "string", "enum": ["manual", "github", "linear", "jira"]},
                "destination": {"type": "string", "maxLength": 512},
                "stableLink": {"type": "string", "maxLength": 4096},
                "trackingProof": {"type": "object"},
            },
            "required": ["occurrenceId", "provider", "trackingProof"],
            "additionalProperties": False,
        },
    },
    {"name": "security_record_tracking_result", "description": "Record sanitized same-connector readback for an approved handoff; this tool performs no provider network write.", "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "recordId": {"type": "string"}, "payloadSha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}, "outcome": {"type": "string", "enum": ["created", "updated", "reused", "blocked", "failed", "uncertain"]}, "externalMutationPerformed": {"type": "boolean"}, "externalId": {"type": "string", "maxLength": 512}, "externalUrl": {"type": "string", "maxLength": 4096}, "reason": {"type": "string", "maxLength": 4000}, "approval": {"type": "object", "properties": {"approved": {"const": True}, "approvedPreviewDigest": {"type": "string", "pattern": "^[a-f0-9]{64}$"}, "approvedPayloadSha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}, "approvedBy": {"type": "string", "maxLength": 512}, "approvedAt": {"type": "string", "maxLength": 128}, "scope": {"type": "string", "maxLength": 2000}}, "required": ["approved", "approvedPreviewDigest", "approvedPayloadSha256", "approvedBy", "approvedAt", "scope"], "additionalProperties": False}, "readback": {"type": "object"}}, "required": ["recordId", "payloadSha256", "outcome", "externalMutationPerformed"], "additionalProperties": False}},
    {
        "name": "security_export_report",
        "description": "Export a scan or one finding as Markdown, JSON, CSV, or SARIF.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "scanId": {"type": "string"},
                "occurrenceId": {"type": "string"},
                "format": {"type": "string", "enum": ["markdown", "json", "csv", "sarif"]},
                "destination": {"type": "string"},
            },
            "required": ["scanId", "format"],
            "additionalProperties": False,
        },
    },
]

_TOOL_STRING_LIMITS = {
    "workspaceRoot": 8192, "mode": 16, "scope": 4096,
    "diffTargetKind": 32, "diffBaseRevision": 256, "diffHeadRevision": 256,
    "userContext": 4000, "scanId": 256, "reason": 4000, "phase": 32, "message": 1000,
    "search": 200, "occurrenceId": 256, "findingId": 256,
    "decision": 32, "sourceType": 64, "inputId": 512, "assessmentId": 256,
    "patch": 600000, "plan": 12000, "remediationId": 256, "recordId": 256,
    "payloadSha256": 64, "outcome": 32, "externalId": 512, "externalUrl": 4096,
    "provider": 32, "destination": 8192, "stableLink": 4096, "format": 16,
}
for _tool in TOOLS:
    for _name, _schema in _tool["inputSchema"].get("properties", {}).items():
        if _schema.get("type") == "string" and _name in _TOOL_STRING_LIMITS:
            _schema.setdefault("maxLength", _TOOL_STRING_LIMITS[_name])
        if _name == "workspaceRoot":
            _schema.setdefault("minLength", 1)


class McpServer:
    def __init__(self) -> None:
        self.initialized = False
        self.protocol_version = DEFAULT_PROTOCOL
        self._services: dict[Path, SecurityService] = {}
        self._lock = threading.RLock()
        self._closing = False
        self._write_lock = threading.Lock()

    def service_for(self, params: dict[str, Any]) -> SecurityService:
        workspace = _workspace_from(params)
        with self._lock:
            service = self._services.get(workspace)
            if service is None:
                service = SecurityService(str(workspace), "mcp", self._emit_engine_event)
                self._services[workspace] = service
            return service

    def _emit_engine_event(self, event: str, payload: dict[str, Any]) -> None:
        # MCP clients do not need the engine's internal notification stream. The
        # durable SQLite event ledger remains available to the VSIX poller.
        _ = (event, payload)

    def write(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        with self._write_lock:
            sys.stdout.write(encoded + "\n")
            sys.stdout.flush()

    def success(self, request_id: Any, result: Any) -> None:
        self.write({"jsonrpc": "2.0", "id": request_id, "result": result})

    def failure(self, request_id: Any, code: int, message: str, data: Any = None) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        self.write({"jsonrpc": "2.0", "id": request_id, "error": error})

    def handle(self, request: Any) -> None:
        request_id: str | int | None = None
        try:
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("Invalid JSON-RPC request.")
            method = _bounded_string(request.get("method"), "method", 256)
            assert method is not None
            params = request["params"] if "params" in request else {}
            if not isinstance(params, dict):
                raise ValueError("params must be a JSON object.")
            if method in ("notifications/initialized", "notifications/cancelled"):
                if "id" in request:
                    raise ValueError("JSON-RPC notifications must not include an id.")
                return
            request_id = _request_id(request.get("id"))
            if method == "initialize":
                requested = params.get("protocolVersion")
                self.protocol_version = requested if isinstance(requested, str) and requested in SUPPORTED_PROTOCOLS else DEFAULT_PROTOCOL
                self.initialized = True
                self.success(
                    request_id,
                    {
                        "protocolVersion": self.protocol_version,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "kiro-security-power", "version": __version__},
                        "instructions": "Use security_* tools to operate the same durable workbench shown by the Kiro Security Power VSIX.",
                    },
                )
                return
            if not self.initialized:
                self.failure(request_id, -32002, "MCP server has not been initialized.")
                return
            if method == "ping":
                self.success(request_id, {})
                return
            if method == "tools/list":
                self.success(request_id, {"tools": TOOLS})
                return
            if method == "tools/call":
                name = _bounded_string(params.get("name"), "tool name", 128)
                assert name is not None
                try:
                    result = self.call_tool(name, params["arguments"] if "arguments" in params else {})
                    text = json.dumps(result, indent=2, ensure_ascii=False)
                    self.success(
                        request_id,
                        {
                            "content": [{"type": "text", "text": text}],
                            "structuredContent": {"result": result},
                            "isError": False,
                        },
                    )
                except Exception as exc:  # MCP tool failures are returned as tool results.
                    self.success(
                        request_id,
                        {
                            "content": [{"type": "text", "text": _safe_error(exc)}],
                            "isError": True,
                        },
                    )
                return
            if method in ("resources/list", "prompts/list"):
                self.success(request_id, {"resources" if method.startswith("resources") else "prompts": []})
                return
            self.failure(request_id, -32601, f"Method not found: {method}")
        except Exception as exc:
            self.failure(request_id, -32602, _safe_error(exc))

    def call_tool(self, name: str, raw_arguments: Any) -> Any:
        params = _object(raw_arguments)
        tool = next((item for item in TOOLS if item["name"] == name), None)
        if tool is None:
            raise ValueError(f"Unknown security tool: {name}")
        unexpected = sorted(set(params) - set(tool["inputSchema"].get("properties", {})))
        if unexpected:
            raise ValueError(f"Unexpected tool argument(s): {', '.join(unexpected)}.")
        service = self.service_for(params)
        if name == "security_get_capabilities":
            return service.capabilities()
        if name == "security_start_scan":
            mode = _bounded_string(params.get("mode"), "mode", 16)
            if mode not in ("standard", "deep", "diff"):
                raise ValueError("mode must be standard, deep, or diff.")
            scope = _bounded_string(params["scope"], "scope") if "scope" in params else "."
            request = {"mode": mode, "scope": scope}
            if "userContext" in params:
                request["userContext"] = _bounded_string(params.get("userContext"), "userContext", 4000)
            if mode == "diff":
                kind = params.get("diffTargetKind") or "working_tree"
                if kind not in ("working_tree", "commit", "range"):
                    raise ValueError("diffTargetKind must be working_tree, commit, or range.")
                request.update(
                    {
                        "diffTargetKind": kind,
                        "diffBaseRevision": _safe_git_ref(params.get("diffBaseRevision"), "diffBaseRevision"),
                        "diffHeadRevision": _safe_git_ref(params.get("diffHeadRevision"), "diffHeadRevision"),
                    }
                )
            return service.start_scan(request)
        if name == "security_acquire_scan_coordinator":
            return service.acquire_scan_coordinator({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_renew_scan_coordinator":
            return service.renew_scan_coordinator(_lease_request(params))
        if name == "security_release_scan_coordinator":
            return service.release_scan_coordinator(_lease_request(params))
        if name == "security_cancel_scan":
            return service.cancel_scan(_lease_request(params))
        if name == "security_get_scan":
            return service.get_scan({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_get_progress":
            return service.get_progress({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_get_scan_context":
            return service.get_scan_context({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_update_scan_progress":
            request: dict[str, Any] = _lease_request(params)
            if "phase" in params:
                phase = _bounded_string(params.get("phase"), "phase", 32)
                if phase not in ("preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"):
                    raise ValueError("Unsupported progress phase.")
                request["phase"] = phase
            if "phasePercent" in params:
                percent = params["phasePercent"]
                if isinstance(percent, bool) or not isinstance(percent, (int, float)) or not 0 <= percent <= 100:
                    raise ValueError("phasePercent must be a number between 0 and 100.")
                request["phasePercent"] = percent
            for field in ("itemsTotal", "itemsCompleted", "reportableFindingsCount"):
                if field in params:
                    request[field] = _integer(params[field], field, 0, 0, 2_147_483_647)
            if "message" in params:
                request["message"] = _bounded_string(params.get("message"), "message", 1000)
            return service.update_scan_progress(request)
        if name == "security_complete_scan":
            return service.complete_scan(_lease_request(params))
        if name == "security_fail_scan":
            return service.fail_scan({
                **_lease_request(params), "reason": _bounded_string(params.get("reason"), "reason", 4000),
            })
        if name == "security_list_findings":
            search = _bounded_string(params["search"], "search", 200) if "search" in params else None
            return service.list_findings(
                {
                    "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                    "search": search,
                    "limit": _integer(params.get("limit"), "limit", 500, 1, 2000),
                }
            )
        if name == "security_get_finding":
            return service.get_finding({"occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256)})
        if name == "security_triage_finding":
            decision = _bounded_string(params.get("decision"), "decision", 32)
            if decision not in ("open", "accepted_risk", "false_positive", "already_fixed", "wont_fix"):
                raise ValueError("Invalid triage decision.")
            note = params.get("note")
            if note is not None and (
                not isinstance(note, str) or len(note) > 4000 or "\x00" in note
            ):
                raise ValueError("note must be a string of at most 4000 characters.")
            return service.triage_finding(
                {
                    "occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256),
                    "decision": decision,
                    "note": note,
                }
            )
        if name == "security_create_remediation":
            return service.create_remediation({"occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256)})
        if name == "security_prepare_remediation_patch":
            return service.prepare_remediation_patch({
                "occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256),
                "patch": _bounded_string(params.get("patch"), "patch", 600000),
                "plan": _bounded_string(params.get("plan"), "plan", 12000),
                "verificationPlan": params.get("verificationPlan"),
            })
        if name == "security_apply_remediation_patch":
            return service.apply_remediation_patch({
                "remediationId": _bounded_string(params.get("remediationId"), "remediationId", 256),
                "expectedVersion": _integer(params.get("expectedVersion"), "expectedVersion", 0, 1, 2_147_483_647),
            })
        if name == "security_verify_remediation_patch":
            return service.verify_remediation_patch({
                "remediationId": _bounded_string(params.get("remediationId"), "remediationId", 256),
                "expectedVersion": _integer(params.get("expectedVersion"), "expectedVersion", 0, 1, 2_147_483_647),
                "verification": params.get("verification"),
            })
        if name == "security_create_triage_intake":
            occurrence_id = params.get("occurrenceId")
            return service.create_triage_intake({
                "occurrenceId": None if occurrence_id is None else _bounded_string(occurrence_id, "occurrenceId", 256),
                "sourceType": _bounded_string(params.get("sourceType"), "sourceType", 64),
                "inputId": _bounded_string(params.get("inputId"), "inputId", 512),
                "input": params.get("input"),
            })
        if name == "security_submit_triage_assessment":
            return service.submit_triage_assessment({
                "assessmentId": _bounded_string(params.get("assessmentId"), "assessmentId", 256),
                "result": params.get("result"),
            })
        if name == "security_create_tracking_handoff":
            provider = _bounded_string(params.get("provider"), "provider", 32)
            if provider not in ("manual", "github", "linear", "jira"):
                raise ValueError("Invalid tracking provider.")
            destination = params.get("destination") or "manual-review"
            stable_link = params.get("stableLink")
            if stable_link is not None:
                stable_link = _bounded_string(stable_link, "stableLink", 4096)
            return service.create_tracking_handoff(
                {
                    "occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256),
                    "provider": provider,
                    "destination": _bounded_string(destination, "destination", 512),
                    "stableLink": stable_link,
                    "trackingProof": params.get("trackingProof"),
                }
            )
        if name == "security_record_tracking_result":
            return service.record_tracking_result({
                "recordId": _bounded_string(params.get("recordId"), "recordId", 256),
                "payloadSha256": _bounded_string(params.get("payloadSha256"), "payloadSha256", 64),
                "outcome": _bounded_string(params.get("outcome"), "outcome", 32),
                "externalMutationPerformed": params.get("externalMutationPerformed"),
                "externalId": params.get("externalId"), "externalUrl": params.get("externalUrl"),
                "reason": params.get("reason"), "approval": params.get("approval"),
                "readback": params.get("readback"),
            })
        if name == "security_export_report":
            export_format = _bounded_string(params.get("format"), "format", 16)
            if export_format not in ("markdown", "json", "csv", "sarif"):
                raise ValueError("Invalid export format.")
            destination = params.get("destination")
            if destination is not None:
                destination = _bounded_string(destination, "destination", 8192)
            occurrence_id = params.get("occurrenceId")
            if occurrence_id is not None:
                occurrence_id = _bounded_string(occurrence_id, "occurrenceId", 256)
            return service.export_report(
                {
                    "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                    "occurrenceId": occurrence_id,
                    "format": export_format,
                    "destination": destination,
                    "allowedRoot": str(Path(destination).expanduser().resolve().parent) if destination else None,
                }
            )
        raise ValueError(f"Unknown security tool: {name}")

    def shutdown(self) -> None:
        with self._lock:
            if self._closing:
                return
            self._closing = True
            services = list(self._services.values())
            self._services.clear()
        for service in services:
            try:
                service.shutdown({})
            except Exception:
                pass


def _safe_error(error: Exception) -> str:
    if isinstance(error, EngineError):
        return f"{error.message} ({error.code})"
    return str(error)


def main() -> int:
    server = McpServer()

    def stop(_signum: int, _frame: Any) -> None:
        server.shutdown()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    buffer = b""
    try:
        while True:
            chunk = sys.stdin.buffer.read1(65536)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > MAX_BUFFER_BYTES:
                server.failure(None, -32600, "Input buffer exceeded safety limit.")
                buffer = b""
                continue
            while b"\n" in buffer:
                raw, buffer = buffer.split(b"\n", 1)
                raw = raw.strip()
                if not raw:
                    continue
                if len(raw) > MAX_LINE_BYTES:
                    server.failure(None, -32600, "Message exceeds the 2 MiB limit.")
                    continue
                try:
                    request = json.loads(raw.decode("utf-8"))
                except Exception as exc:
                    server.failure(None, -32700, f"Invalid JSON: {exc}")
                    continue
                server.handle(request)
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
