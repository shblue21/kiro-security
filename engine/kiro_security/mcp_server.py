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


def _workspace_from(params: dict[str, Any]) -> Path:
    requested = params.get("workspaceRoot") or os.environ.get("KIRO_SECURITY_WORKSPACE") or os.getcwd()
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


TOOLS: list[dict[str, Any]] = [
    {
        "name": "security_get_capabilities",
        "description": "Check the shared Kiro Security Power engine, Python, SQLite, Git, modes, phases, and export capabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {"workspaceRoot": {"type": "string"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "security_start_scan",
        "description": "Start a Standard, Deep, or Git-diff repository security scan. Deep requires the same truthful modelId/runtime host attestation used by worker claims.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string", "description": "Optional. Defaults to the workspace bound by the VSIX installer."},
                "mode": {"type": "string", "enum": ["standard", "deep", "diff"]},
                "scope": {"type": "string", "default": "."},
                "diffTargetKind": {"type": "string", "enum": ["working_tree", "commit", "range"]},
                "diffBaseRevision": {"type": "string"},
                "diffHeadRevision": {"type": "string"},
                "modelId": {"type": "string", "description": "Required for Deep host capability preflight."},
                "runtime": {"type": "object", "description": "Required for Deep; uses the deep-worker/v2 claim runtime contract."},
            },
            "required": ["mode"],
            "additionalProperties": False,
        },
    },
    {
        "name": "security_list_scans",
        "description": "List recent scans, including scans started by the VSIX or another MCP session.",
        "inputSchema": {
            "type": "object",
            "properties": {"workspaceRoot": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 200}},
            "additionalProperties": False,
        },
    },
    {"name": "security_resume_scan", "description": "Resume an interrupted or failed scan using durable handoff state.", "inputSchema": _id_schema("scanId")},
    {"name": "security_cancel_scan", "description": "Request cooperative cancellation of an active scan.", "inputSchema": _id_schema("scanId")},
    {"name": "security_get_scan", "description": "Get scan lifecycle, progress, coverage, and artifact records.", "inputSchema": _id_schema("scanId")},
    {"name": "security_get_progress", "description": "Get the latest progress record for a scan.", "inputSchema": _id_schema("scanId")},
    {"name": "security_deep_get_status", "description": "Get durable Deep round, worker, novelty, and next-action state.", "inputSchema": _id_schema("scanId")},
    {
        "name": "security_deep_claim_worker",
        "description": (
            "Claim one of exactly six independent model discovery workers for the active Deep round. "
            "Requires a host-attested runtime (contractVersion deep-worker/v2, delegationMode fresh, capability flags, "
            "usableWorkerSlots >= 6). All six workers in a round must share one modelId/agentType/reasoningEffort/"
            "hostVersion profile, and all six must be claimed before the first result is submitted."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "scanId": {"type": "string"},
                "modelId": {"type": "string"},
                "delegationId": {"type": "string"},
                "runtime": {
                    "type": "object",
                    "description": "Host-attested worker runtime profile.",
                    "properties": {
                        "contractVersion": {"type": "string", "const": "deep-worker/v2"},
                        "agentType": {"type": "string"},
                        "reasoningEffort": {"type": "string"},
                        "hostVersion": {"type": "string"},
                        "delegationMode": {"type": "string", "const": "fresh"},
                        "capabilities": {
                            "type": "object",
                            "properties": {
                                "delegatedAgentAvailable": {"type": "boolean"},
                                "freshContextMode": {"type": "boolean"},
                                "usableWorkerSlots": {"type": "integer", "minimum": 6},
                                "goalSupport": {"type": "boolean"},
                            },
                            "required": ["delegatedAgentAvailable", "freshContextMode", "usableWorkerSlots", "goalSupport"],
                            "additionalProperties": True,
                        },
                    },
                    "required": ["contractVersion", "agentType", "reasoningEffort", "hostVersion", "delegationMode", "capabilities"],
                    "additionalProperties": True,
                },
            },
            "required": ["scanId", "modelId", "delegationId", "runtime"],
            "additionalProperties": False,
        },
    },
    {
        "name": "security_deep_submit_worker_result",
        "description": (
            "Submit a completed independent Deep discovery worker with one auditable disposition receipt per worklist "
            "row, evidence-grounded candidates (non-empty codeEvidence with explicit origin/control and sink/impact "
            "roles, impact, root cause, severity/confidence rationales), and a host completionAttestation. All six "
            "workers of the round must already be claimed before the first submit."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "scanId": {"type": "string"},
                "workerId": {"type": "string"},
                "claimToken": {"type": "string"},
                "completionAttestation": {
                    "type": "object",
                    "description": "Host-attested worker completion state.",
                    "properties": {
                        "freshContext": {"type": "boolean", "const": True},
                        "coordinatorHistoryInherited": {"type": "boolean", "const": False},
                        "workerState": {"type": "string", "const": "completed_idle"},
                    },
                    "required": ["freshContext", "coordinatorHistoryInherited", "workerState"],
                    "additionalProperties": True,
                },
                "rowReceipts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "rowId": {"type": "string"},
                            "disposition": {"type": "string", "enum": ["reportable", "suppressed", "not_applicable", "deferred"]},
                            "reason": {"type": "string"},
                            "evidenceRefs": {"type": "array", "items": {"type": "string"}},
                            "candidateIds": {"type": "array", "items": {"type": "string"}},
                            "entrypoint": {"type": "string"},
                            "rootControl": {"type": "string"},
                            "sink": {"type": "string"},
                        },
                        "required": ["rowId", "disposition", "reason"],
                        "additionalProperties": False,
                    },
                },
                "threatModel": {"type": "string"},
                "summary": {"type": "string"},
                "seedResearch": {"type": "string"},
                "dedupeReport": {"type": "string"},
                "candidates": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["scanId", "workerId", "claimToken", "rowReceipts", "threatModel", "candidates", "completionAttestation"],
            "additionalProperties": False,
        },
    },
    {
        "name": "security_deep_retry_worker",
        "description": "Replace only an incomplete Deep worker. Completed worker artifacts are immutable.",
        "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "scanId": {"type": "string"}, "workerIndex": {"type": "integer", "minimum": 1, "maximum": 6}, "reason": {"type": "string"}}, "required": ["scanId", "workerIndex"], "additionalProperties": False},
    },
    {"name": "security_deep_claim_merge", "description": "Claim semantic merge after all six workers are complete.", "inputSchema": _id_schema("scanId")},
    {
        "name": "security_deep_submit_merge",
        "description": (
            "Submit canonical merge, consume every current sourceRef exactly once, preserve prior candidates, and "
            "continue rounds until zero novelty or round 10. Every canonical candidate requires mergeRationale, "
            "identityRationale, and remediationSubsumption; retained canonical IDs must keep their fingerprint and "
            "semantic identity, and prior identities cannot be re-registered under new IDs."
        ),
        "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "scanId": {"type": "string"}, "claimToken": {"type": "string"}, "canonicalCandidates": {"type": "array", "items": {"type": "object"}}}, "required": ["scanId", "claimToken", "canonicalCandidates"], "additionalProperties": False},
    },
    {
        "name": "security_deep_get_tail_assignment",
        "description": "Claim the next eligible fresh-context Deep tail assignment after canonical discovery.",
        "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "scanId": {"type": "string"}, "modelId": {"type": "string"}, "delegationId": {"type": "string"}, "runtime": {"type": "object"}}, "required": ["scanId", "modelId", "delegationId", "runtime"], "additionalProperties": False},
    },
    {
        "name": "security_deep_submit_tail_result",
        "description": "Submit one kind-checked Deep tail result with the same claim profile and a truthful completion attestation.",
        "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "scanId": {"type": "string"}, "assignmentId": {"type": "string"}, "claimToken": {"type": "string"}, "modelId": {"type": "string"}, "delegationId": {"type": "string"}, "runtime": {"type": "object"}, "completionAttestation": {"type": "object"}, "result": {"type": "object"}}, "required": ["scanId", "assignmentId", "claimToken", "modelId", "delegationId", "runtime", "completionAttestation", "result"], "additionalProperties": False},
    },
    {
        "name": "security_deep_retry_writeup",
        "description": "Retry only the latest incomplete or failed Deep writeup attempt; completed writeups are immutable.",
        "inputSchema": {"type": "object", "properties": {"workspaceRoot": {"type": "string"}, "scanId": {"type": "string"}, "assignmentId": {"type": "string"}, "reason": {"type": "string"}}, "required": ["scanId", "assignmentId"], "additionalProperties": False},
    },
    {
        "name": "security_list_findings",
        "description": "List normalized findings for a scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "scanId": {"type": "string"},
                "search": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 2000},
            },
            "required": ["scanId"],
            "additionalProperties": False,
        },
    },
    {"name": "security_get_finding", "description": "Get one finding with evidence, validation, attack path, triage, remediation, and tracking records.", "inputSchema": _id_schema("occurrenceId")},
    {"name": "security_validate_finding", "description": "Validate a finding and produce an attack-path record where applicable.", "inputSchema": _id_schema("occurrenceId")},
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
        "name": "security_create_tracking_handoff",
        "description": "Prepare an approval-ready manual, GitHub, Linear, or Jira tracking payload without writing to an external service.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspaceRoot": {"type": "string"},
                "occurrenceId": {"type": "string"},
                "provider": {"type": "string", "enum": ["manual", "github", "linear", "jira"]},
                "destination": {"type": "string", "maxLength": 512},
                "stableLink": {"type": "string", "maxLength": 4096},
            },
            "required": ["occurrenceId", "provider"],
            "additionalProperties": False,
        },
    },
    {"name": "security_create_hardening_proposal", "description": "Create a structural hardening proposal for a scan.", "inputSchema": _id_schema("scanId")},
    {
        "name": "security_create_threat_model",
        "description": "Create or refresh a workspace threat model.",
        "inputSchema": {
            "type": "object",
            "properties": {"workspaceRoot": {"type": "string"}, "scope": {"type": "string", "default": "."}},
            "additionalProperties": False,
        },
    },
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
        request_id = request.get("id") if isinstance(request, dict) else None
        try:
            if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
                raise ValueError("Invalid JSON-RPC request.")
            method = _bounded_string(request.get("method"), "method", 256)
            assert method is not None
            params = request.get("params") or {}
            if not isinstance(params, dict):
                raise ValueError("params must be a JSON object.")
            if method in ("notifications/initialized", "notifications/cancelled"):
                return
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
                    result = self.call_tool(name, params.get("arguments") or {})
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
        service = self.service_for(params)
        if name == "security_get_capabilities":
            return service.capabilities()
        if name == "security_start_scan":
            mode = _bounded_string(params.get("mode"), "mode", 16)
            if mode not in ("standard", "deep", "diff"):
                raise ValueError("mode must be standard, deep, or diff.")
            scope = _bounded_string(params.get("scope") or ".", "scope")
            request = {"mode": mode, "scope": scope}
            if mode == "deep":
                runtime = params.get("runtime")
                if not isinstance(runtime, dict):
                    raise ValueError("Deep start requires a host-attested runtime object.")
                request.update({
                    "modelId": _bounded_string(params.get("modelId"), "modelId", 256),
                    "runtime": runtime,
                })
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
        if name == "security_list_scans":
            return service.list_scans({"limit": _integer(params.get("limit"), "limit", 50, 1, 200)})
        if name == "security_resume_scan":
            return service.resume_scan({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_cancel_scan":
            return service.cancel_scan({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_get_scan":
            return service.get_scan({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_get_progress":
            return service.get_progress({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_deep_get_status":
            return service.deep_get_status({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_deep_claim_worker":
            runtime = params.get("runtime")
            if not isinstance(runtime, dict):
                raise ValueError("runtime must be a host-attested object (contractVersion deep-worker/v2).")
            return service.deep_claim_worker({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "modelId": _bounded_string(params.get("modelId"), "modelId", 256),
                "delegationId": _bounded_string(params.get("delegationId"), "delegationId", 256),
                "runtime": runtime,
            })
        if name == "security_deep_submit_worker_result":
            row_receipts = params.get("rowReceipts")
            candidates = params.get("candidates")
            if not isinstance(row_receipts, list) or not isinstance(candidates, list):
                raise ValueError("rowReceipts and candidates must be arrays.")
            completion_attestation = params.get("completionAttestation")
            if not isinstance(completion_attestation, dict):
                raise ValueError("completionAttestation must be a host-attested object.")
            return service.deep_submit_worker({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "workerId": _bounded_string(params.get("workerId"), "workerId", 256),
                "claimToken": _bounded_string(params.get("claimToken"), "claimToken", 256),
                "rowReceipts": row_receipts,
                "threatModel": _bounded_string(params.get("threatModel"), "threatModel", 200000),
                "summary": _bounded_string(params.get("summary"), "summary", 20000, required=False) or "",
                "seedResearch": _bounded_string(params.get("seedResearch"), "seedResearch", 200000, required=False) or "",
                "dedupeReport": _bounded_string(params.get("dedupeReport"), "dedupeReport", 200000, required=False) or "",
                "candidates": candidates,
                "completionAttestation": completion_attestation,
            })
        if name == "security_deep_retry_worker":
            return service.deep_retry_worker({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "workerIndex": _integer(params.get("workerIndex"), "workerIndex", 1, 1, 6),
                "reason": _bounded_string(params.get("reason"), "reason", 4000, required=False) or "Worker replacement requested",
            })
        if name == "security_deep_claim_merge":
            return service.deep_claim_merge({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_deep_submit_merge":
            candidates = params.get("canonicalCandidates")
            if not isinstance(candidates, list):
                raise ValueError("canonicalCandidates must be an array.")
            return service.deep_submit_merge({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "claimToken": _bounded_string(params.get("claimToken"), "claimToken", 256),
                "canonicalCandidates": candidates,
            })
        if name == "security_deep_get_tail_assignment":
            runtime = params.get("runtime")
            if not isinstance(runtime, dict):
                raise ValueError("runtime must be a host-attested object.")
            return service.deep_get_tail_assignment({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "modelId": _bounded_string(params.get("modelId"), "modelId", 256),
                "delegationId": _bounded_string(params.get("delegationId"), "delegationId", 256),
                "runtime": runtime,
            })
        if name == "security_deep_submit_tail_result":
            runtime = params.get("runtime")
            completion = params.get("completionAttestation")
            result = params.get("result")
            if not isinstance(runtime, dict) or not isinstance(completion, dict) or not isinstance(result, dict):
                raise ValueError("runtime, completionAttestation, and result must be objects.")
            return service.deep_submit_tail_result({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "assignmentId": _bounded_string(params.get("assignmentId"), "assignmentId", 256),
                "claimToken": _bounded_string(params.get("claimToken"), "claimToken", 256),
                "modelId": _bounded_string(params.get("modelId"), "modelId", 256),
                "delegationId": _bounded_string(params.get("delegationId"), "delegationId", 256),
                "runtime": runtime, "completionAttestation": completion, "result": result,
            })
        if name == "security_deep_retry_writeup":
            return service.deep_retry_writeup({
                "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                "assignmentId": _bounded_string(params.get("assignmentId"), "assignmentId", 256),
                "reason": _bounded_string(params.get("reason"), "reason", 4000, required=False) or "Incomplete writeup retry requested.",
            })
        if name == "security_list_findings":
            search = params.get("search")
            if search is not None:
                search = _bounded_string(search, "search", 512)
            return service.list_findings(
                {
                    "scanId": _bounded_string(params.get("scanId"), "scanId", 256),
                    "search": search,
                    "limit": _integer(params.get("limit"), "limit", 500, 1, 2000),
                }
            )
        if name == "security_get_finding":
            return service.get_finding({"occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256)})
        if name == "security_validate_finding":
            return service.validate_finding({"occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256)})
        if name == "security_triage_finding":
            decision = _bounded_string(params.get("decision"), "decision", 32)
            if decision not in ("open", "accepted_risk", "false_positive", "already_fixed", "wont_fix"):
                raise ValueError("Invalid triage decision.")
            note = params.get("note")
            if note is not None:
                note = _bounded_string(note, "note", 4000)
            return service.triage_finding(
                {
                    "occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256),
                    "decision": decision,
                    "note": note,
                }
            )
        if name == "security_create_remediation":
            return service.create_remediation({"occurrenceId": _bounded_string(params.get("occurrenceId"), "occurrenceId", 256)})
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
                }
            )
        if name == "security_create_hardening_proposal":
            return service.create_hardening_proposal({"scanId": _bounded_string(params.get("scanId"), "scanId", 256)})
        if name == "security_create_threat_model":
            return service.refresh_threat_model({"scope": _bounded_string(params.get("scope") or ".", "scope")})
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
